// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package ssh is a helper for working with ssh in go.  The client implementation
// is a modified version of `docker/machine/libmachine/ssh/client.go` and only
// uses golang's native ssh client. It has also been improved to resize the tty
// accordingly.  The key functions are meant to be used by either client or server
// and will generate/store keys if not found.
package ssh

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/pkg/term"
	"github.com/docker/machine/libmachine/log"
	"github.com/docker/machine/libmachine/mcnutils"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

// ExitError is a conveniance wrapper for (crypto/ssh).ExitError type.
type ExitError struct {
	Err      error
	ExitCode int
}

// Error implements error interface.
func (err *ExitError) Error() string {
	return err.Err.Error()
}

// Cause implements errors.Causer interface.
func (err *ExitError) Cause() error {
	return err.Err
}

func wrapError(err error) error {
	switch err := err.(type) {
	case *ssh.ExitError:
		e, s := &ExitError{Err: err, ExitCode: -1}, strings.TrimSpace(err.Error())
		// Best-effort attempt to parse exit code from os/exec error string,
		// like "Process exited with status 127".
		if i := strings.LastIndex(s, " "); i != -1 {
			if n, err := strconv.Atoi(s[i+1:]); err == nil {
				e.ExitCode = n
			}
		}
		return e
	default:
		return err
	}
}

// Client is a relic interface that both native and external client matched
type Client interface {
	// Output returns the output of the command run on the remote host.
	Output(command string) (string, error)

	// Shell requests a shell from the remote. If an arg is passed, it tries to
	// exec them on the server.
	Shell(sin io.Reader, sout, serr io.Writer, args ...string) error

	// Start starts the specified command without waiting for it to finish. You
	// have to call the Wait function for that.
	//
	// The first two io.ReadCloser are the standard output and the standard
	// error of the executing command respectively. The returned error follows
	// the same logic as in the exec.Cmd.Start function.
	Start(command string) (io.ReadCloser, io.ReadCloser, io.WriteCloser, error)

	// Wait waits for the command started by the Start function to exit. The
	// returned error follows the same logic as in the exec.Cmd.Wait function.
	Wait() error
}

// NativeClient is the structure for native client use
type NativeClient struct {
	Config        ssh.ClientConfig // Config defines the golang ssh client config
	Hostname      string           // Hostname is the host to connect to
	Port          int              // Port is the port to connect to
	ClientVersion string           // ClientVersion is the version string to send to the server when identifying
	openSession   *ssh.Session
	openConn      *ssh.Client
}

// Auth contains auth info
type Auth struct {
	Passwords []string // Passwords is a slice of passwords to submit to the server
	Keys      []string // Keys is a slice of filenames of keys to try
	RawKeys   [][]byte // RawKeys is a slice of private keys to try
}

// Config is used to create new client.
type Config struct {
	User    string              // username to connect as, required
	Host    string              // hostname to connect to, required
	Version string              // ssh client version, "SSH-2.0-Go" by default
	Port    int                 // port to connect to, 22 by default
	Auth    *Auth               // authentication methods to use
	Timeout time.Duration       // connect timeout, 30s by default
	HostKey ssh.HostKeyCallback // callback for verifying server keys, ssh.InsecureIgnoreHostKey by default
}

func (cfg *Config) version() string {
	if cfg.Version != "" {
		return cfg.Version
	}
	return "SSH-2.0-Go"
}

func (cfg *Config) port() int {
	if cfg.Port != 0 {
		return cfg.Port
	}
	return 22
}

func (cfg *Config) timeout() time.Duration {
	if cfg.Timeout != 0 {
		return cfg.Timeout
	}
	return 30 * time.Second
}

func (cfg *Config) hostKey() ssh.HostKeyCallback {
	if cfg.HostKey != nil {
		return cfg.HostKey
	}
	return ssh.InsecureIgnoreHostKey()
}

// NewClient creates a new Client using the golang ssh library.
func NewClient(cfg *Config) (Client, error) {
	config, err := NewNativeConfig(cfg.User, cfg.version(), cfg.Auth, cfg.hostKey())
	if err != nil {
		return nil, fmt.Errorf("Error getting config for native Go SSH: %s", err)
	}
	config.Timeout = cfg.timeout()

	return &NativeClient{
		Config:        config,
		Hostname:      cfg.Host,
		Port:          cfg.port(),
		ClientVersion: cfg.version(),
	}, nil
}

// NewNativeClient creates a new Client using the golang ssh library
func NewNativeClient(user, host, clientVersion string, port int, auth *Auth, hostKeyCallback ssh.HostKeyCallback) (Client, error) {
	if clientVersion == "" {
		clientVersion = "SSH-2.0-Go"
	}

	config, err := NewNativeConfig(user, clientVersion, auth, hostKeyCallback)
	if err != nil {
		return nil, fmt.Errorf("Error getting config for native Go SSH: %s", err)
	}

	return &NativeClient{
		Config:        config,
		Hostname:      host,
		Port:          port,
		ClientVersion: clientVersion,
	}, nil
}

// NewNativeConfig returns a golang ssh client config struct for use by the NativeClient
func NewNativeConfig(user, clientVersion string, auth *Auth, hostKeyCallback ssh.HostKeyCallback) (ssh.ClientConfig, error) {
	var (
		authMethods []ssh.AuthMethod
	)

	if auth != nil {
		rawKeys := auth.RawKeys
		for _, k := range auth.Keys {
			key, err := ioutil.ReadFile(k)
			if err != nil {
				return ssh.ClientConfig{}, err
			}

			rawKeys = append(rawKeys, key)
		}

		for _, key := range rawKeys {
			privateKey, err := ssh.ParsePrivateKey(key)
			if err != nil {
				return ssh.ClientConfig{}, err
			}

			authMethods = append(authMethods, ssh.PublicKeys(privateKey))
		}

		for _, p := range auth.Passwords {
			authMethods = append(authMethods, ssh.Password(p))
		}
	}

	if hostKeyCallback == nil {
		hostKeyCallback = ssh.InsecureIgnoreHostKey()
	}

	return ssh.ClientConfig{
		User:            user,
		Auth:            authMethods,
		ClientVersion:   clientVersion,
		HostKeyCallback: hostKeyCallback,
	}, nil
}

func (client *NativeClient) dialSuccess() bool {
	if _, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", client.Hostname, client.Port), &client.Config); err != nil {
		log.Debugf("Error dialing TCP: %s", err)
		return false
	}
	return true
}

func (client *NativeClient) Connect() (*ssh.Client, error) {
	if err := mcnutils.WaitFor(client.dialSuccess); err != nil {
		return nil, fmt.Errorf("Error attempting SSH client dial: %s", err)
	}

	conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", client.Hostname, client.Port), &client.Config)
	if err != nil {
		return nil, fmt.Errorf("Mysterious error dialing TCP for SSH (we already succeeded at least once) : %s", err)
	}

	return conn, nil
}

func (client *NativeClient) Session() (*ssh.Session, *ssh.Client, error) {
	conn, err := client.Connect()
	if err != nil {
		return nil, nil, err
	}
	session, err := conn.NewSession()
	if err != nil {
		conn.Close()
		return nil, nil, err
	}
	return session, conn, nil
}

// Output returns the output of the command run on the remote host.
func (client *NativeClient) Output(command string) (string, error) {
	session, conn, err := client.Session()
	if err != nil {
		return "", err
	}
	defer session.Close()
	defer conn.Close()

	output, err := session.CombinedOutput(command)

	return string(bytes.TrimSpace(output)), wrapError(err)
}

// Output returns the output of the command run on the remote host as well as a pty.
func (client *NativeClient) OutputWithPty(command string) (string, error) {
	session, conn, err := client.Session()
	if err != nil {
		return "", nil
	}
	defer session.Close()
	defer conn.Close()

	fd := int(os.Stdin.Fd())

	termWidth, termHeight, err := terminal.GetSize(fd)
	if err != nil {
		return "", err
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	// request tty -- fixes error with hosts that use
	// "Defaults requiretty" in /etc/sudoers - I'm looking at you RedHat
	if err := session.RequestPty("xterm", termHeight, termWidth, modes); err != nil {
		return "", err
	}

	output, err := session.CombinedOutput(command)

	return string(bytes.TrimSpace(output)), wrapError(err)
}

// Start starts the specified command without waiting for it to finish. You
// have to call the Wait function for that.
func (client *NativeClient) Start(command string) (sout io.ReadCloser, serr io.ReadCloser, sin io.WriteCloser, reterr error) {
	session, conn, err := client.Session()
	if err != nil {
		return nil, nil, nil, err
	}
	defer func() {
		if reterr != nil {
			session.Close()
			conn.Close()
		}
	}()

	stdout, err := session.StdoutPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	stderr, err := session.StderrPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return nil, nil, nil, err
	}
	if err := session.Start(command); err != nil {
		return nil, nil, nil, err
	}

	client.openSession = session
	client.openConn = conn
	return ioutil.NopCloser(stdout), ioutil.NopCloser(stderr), stdin, nil
}

// Wait waits for the command started by the Start function to exit. The
// returned error follows the same logic as in the exec.Cmd.Wait function.
func (client *NativeClient) Wait() error {
	err := client.openSession.Wait()
	_ = client.openSession.Close()
	client.openConn.Close()
	client.openSession = nil
	client.openConn = nil
	return err
}

// Shell requests a shell from the remote. If an arg is passed, it tries to
// exec them on the server.
func (client *NativeClient) Shell(sin io.Reader, sout, serr io.Writer, args ...string) error {
	var (
		termWidth, termHeight = 80, 24
	)
	conn, err := ssh.Dial("tcp", fmt.Sprintf("%s:%d", client.Hostname, client.Port), &client.Config)
	if err != nil {
		return err
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()

	session.Stdout = sout
	session.Stderr = serr
	session.Stdin = sin

	modes := ssh.TerminalModes{
		ssh.ECHO: 1,
	}

	fd := os.Stdin.Fd()

	if term.IsTerminal(fd) {
		oldState, err := term.MakeRaw(fd)
		if err != nil {
			return err
		}

		defer term.RestoreTerminal(fd, oldState)

		winsize, err := term.GetWinsize(fd)
		if err == nil {
			termWidth = int(winsize.Width)
			termHeight = int(winsize.Height)
		}
	}

	if err := session.RequestPty("xterm", termHeight, termWidth, modes); err != nil {
		return err
	}

	if len(args) == 0 {
		if err := session.Shell(); err != nil {
			return err
		}

		// monitor for sigwinch
		go monWinCh(session, os.Stdout.Fd())

		session.Wait()
	} else {
		session.Run(strings.Join(args, " "))
	}

	return nil
}

// termSize gets the current window size and returns it in a window-change friendly
// format.
func termSize(fd uintptr) []byte {
	size := make([]byte, 16)

	winsize, err := term.GetWinsize(fd)
	if err != nil {
		binary.BigEndian.PutUint32(size, uint32(80))
		binary.BigEndian.PutUint32(size[4:], uint32(24))
		return size
	}

	binary.BigEndian.PutUint32(size, uint32(winsize.Width))
	binary.BigEndian.PutUint32(size[4:], uint32(winsize.Height))

	return size
}
