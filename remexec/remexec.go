package remexec

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"golang.org/x/crypto/ssh"
)

type SSHConnection struct {
	client *ssh.Client
	config *ssh.ClientConfig
	addr   string
	mu     sync.Mutex
}

type CommandResult struct {
	Command string
	Output  string
	Error   error
}

// EvalCommandResult returns "PASS" if output is empty, "FAIL" otherwise
func EvalCommandResult(r CommandResult) string {
	if len(strings.TrimSpace(r.Output)) == 0 {
		return "PASS"
	}
	return "FAIL"
}

func NewSSHConnection(user string, addr string, pass string, privateKey string) (*SSHConnection, error) {
	var auths []ssh.AuthMethod

	if privateKey != "" {
		if fi, err := os.Stat(privateKey); err == nil && !fi.IsDir() {
			if data, err := os.ReadFile(privateKey); err == nil {
				if signer, err := ssh.ParsePrivateKey(data); err == nil {
					auths = append(auths, ssh.PublicKeys(signer))
					fmt.Printf("DEBUG: Using SSH key from file: %s\n", privateKey)
				}
			}
		}
		if len(auths) == 0 {
			if signer, err := ssh.ParsePrivateKey([]byte(privateKey)); err == nil {
				auths = append(auths, ssh.PublicKeys(signer))
				fmt.Printf("DEBUG: Using SSH key from content\n")
			}
		}
	}

	if len(auths) == 0 && pass != "" {
		auths = append(auths, ssh.Password(pass))
		fmt.Printf("DEBUG: Using password authentication for user %s@%s\n", user, addr)
	}

	if len(auths) == 0 {
		return nil, fmt.Errorf("no authentication provided: supply password or private key")
	}

	config := &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth:            auths,
	}

	fmt.Printf("DEBUG: Connecting to %s:22 as user %s\n", addr, user)
	client, err := ssh.Dial("tcp", net.JoinHostPort(addr, "22"), config)
	if err != nil {
		fmt.Printf("DEBUG: SSH connection failed: %v\n", err)
		return nil, err
	}
	fmt.Printf("DEBUG: SSH connection successful\n")

	return &SSHConnection{
		client: client,
		config: config,
		addr:   addr,
	}, nil
}

func (conn *SSHConnection) Close() error {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	if conn.client != nil {
		return conn.client.Close()
	}
	return nil
}

func (conn *SSHConnection) RunCommand(cmd string) (string, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	session, err := conn.client.NewSession()
	if err != nil {
		fmt.Printf("DEBUG: Session creation failed: %v\n", err)
		return "", err
	}
	defer session.Close()

	fmt.Printf("DEBUG: Running command: %s\n", cmd)
	var b bytes.Buffer
	session.Stdout = &b
	err = session.Run(cmd)
	if err != nil {
		fmt.Printf("DEBUG: Command execution failed: %v\n", err)
	} else {
		fmt.Printf("DEBUG: Command executed successfully, output length: %d\n", len(b.String()))
	}
	return b.String(), err
}

func RemoteRun(user string, addr string, pass string, privateKey string, cmd string) (string, error) {
	conn, err := NewSSHConnection(user, addr, pass, privateKey)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	return conn.RunCommand(cmd)
}

func init() {

}
