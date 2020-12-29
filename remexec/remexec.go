package remexec

import (
	"bytes"
	"net"
	"golang.org/x/crypto/ssh"
)

// RemoteRun Function
func RemoteRun(user string, addr string, privateKey string, cmd string) (string, error) {
	/*
		// privateKey could be read from a file, or retrieved from another storage
		// source, such as the Secret Service / GNOME Keyring

		key, err := ssh.ParsePrivateKey([]byte(privateKey))
		if err != nil {
			return "", err
		}
	*/
	// Authentication
	config := &ssh.ClientConfig{
		User:            user,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth: []ssh.AuthMethod{
			//ssh.PublicKeys(key),
			ssh.Password(privateKey),
		},
		//alternatively, you could use a password
		/*
		   Auth: []ssh.AuthMethod{
		       ssh.Password("PASSWORD"),
		   },
		*/
	}
	// Connect
	client, err := ssh.Dial("tcp", net.JoinHostPort(addr, "22"), config)
	if err != nil {
		return "", err
	}
	// Create a session. It is one session per command.
	session, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer session.Close()
	var b bytes.Buffer
	session.Stdout = &b
	err = session.Run(cmd)
	return b.String(), err
}

func init() {

}
