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

// SSHConnection represents a reusable SSH connection
type SSHConnection struct {
	client *ssh.Client
	config *ssh.ClientConfig
	addr   string
	mu     sync.Mutex
}

// CommandResult represents the result of a command execution
type CommandResult struct {
	Command string
	Output  string
	Error   error
}

// BatchResult contains results for multiple commands
type BatchResult struct {
	Results []CommandResult
	Error   error
}

// NewSSHConnection creates a new SSH connection that can be reused
func NewSSHConnection(user string, addr string, pass string, privateKey string) (*SSHConnection, error) {
	// Authentication methods: prefer SSH key, fall back to password
	var auths []ssh.AuthMethod

	// Try SSH key authentication first if privateKey is provided
	if privateKey != "" {
		// If privateKey is a path to a file, try reading it
		if fi, err := os.Stat(privateKey); err == nil && !fi.IsDir() {
			if data, err := os.ReadFile(privateKey); err == nil {
				if signer, err := ssh.ParsePrivateKey(data); err == nil {
					auths = append(auths, ssh.PublicKeys(signer))
					fmt.Printf("DEBUG: Using SSH key from file: %s\n", privateKey)
				}
			}
		}
		// If no key was loaded yet, try to parse the string as a PEM private key
		if len(auths) == 0 {
			if signer, err := ssh.ParsePrivateKey([]byte(privateKey)); err == nil {
				auths = append(auths, ssh.PublicKeys(signer))
				fmt.Printf("DEBUG: Using SSH key from content\n")
			}
		}
	}
	
	// If no key authentication succeeded and password is provided, use password
	if len(auths) == 0 && pass != "" {
		auths = append(auths, ssh.Password(pass))
		fmt.Printf("DEBUG: Using password authentication for user %s@%s\n", user, addr)
	}
	
	// If neither key nor password worked/provided, return error
	if len(auths) == 0 {
		return nil, fmt.Errorf("no authentication provided: supply password or private key")
	}

	// Authentication config
	config := &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth:            auths,
	}
	
	fmt.Printf("DEBUG: Connecting to %s:22 as user %s\n", addr, user)
	// Connect
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

// Close closes the SSH connection
func (conn *SSHConnection) Close() error {
	conn.mu.Lock()
	defer conn.mu.Unlock()
	
	if conn.client != nil {
		return conn.client.Close()
	}
	return nil
}

// RunCommand executes a single command on the SSH connection
func (conn *SSHConnection) RunCommand(cmd string) (string, error) {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	// Create a session. It is one session per command.
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

// RunCommandsBatch executes multiple commands in a single session for better performance
func (conn *SSHConnection) RunCommandsBatch(commands []string) *BatchResult {
	conn.mu.Lock()
	defer conn.mu.Unlock()

	result := &BatchResult{
		Results: make([]CommandResult, len(commands)),
	}

	// Create a single session for all commands
	session, err := conn.client.NewSession()
	if err != nil {
		fmt.Printf("DEBUG: Batch session creation failed: %v\n", err)
		result.Error = err
		return result
	}
	defer session.Close()

	// Build a script that runs all commands and separates output
	separator := "===CMD_SEPARATOR==="
	var scriptBuilder strings.Builder
	
	for i, cmd := range commands {
		if i > 0 {
			scriptBuilder.WriteString(" && ")
		}
		// Wrap each command to capture both stdout and stderr, with separators
		scriptBuilder.WriteString(fmt.Sprintf("echo '%s%d%s'; (%s) 2>&1; echo '%s%d%s'", 
			separator, i, separator, cmd, separator, i, "_END"))
	}
	
	script := scriptBuilder.String()
	fmt.Printf("DEBUG: Running batch script with %d commands\n", len(commands))
	
	var output bytes.Buffer
	session.Stdout = &output
	session.Stderr = &output
	
	err = session.Run(script)
	if err != nil {
		fmt.Printf("DEBUG: Batch execution failed: %v\n", err)
		// Don't return error here, parse what we can
	}
	
	// Parse the output to separate results for each command
	outputStr := output.String()
	for i, cmd := range commands {
		startMarker := fmt.Sprintf("%s%d%s", separator, i, separator)
		endMarker := fmt.Sprintf("%s%d_END", separator, i)
		
		startIdx := strings.Index(outputStr, startMarker)
		endIdx := strings.Index(outputStr, endMarker)
		
		var cmdOutput string
		if startIdx != -1 && endIdx != -1 && endIdx > startIdx {
			cmdOutput = outputStr[startIdx+len(startMarker):endIdx]
			cmdOutput = strings.TrimSpace(cmdOutput)
		}
		
		result.Results[i] = CommandResult{
			Command: cmd,
			Output:  cmdOutput,
			Error:   nil, // Individual command errors are captured in output
		}
	}
	
	fmt.Printf("DEBUG: Batch execution completed, processed %d commands\n", len(commands))
	return result
}

// RemoteRun Function - Updated to use optimized connection handling
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
