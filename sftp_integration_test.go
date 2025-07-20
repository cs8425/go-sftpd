package main

import (
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func startTestServer(t *testing.T, addr, keyPath, rootDir string) net.Listener {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	go func() {
		privateBytes, _ := os.ReadFile(keyPath)
		private, _ := ssh.ParsePrivateKey(privateBytes)
		users := []*UserConfig{{Username: "testuser", Password: "testpass", HomeDir: ""}}
		srv := NewSftpSrv(users, rootDir)
		srv.config.AddHostKey(private)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go srv.HandleConn(conn, rootDir)
		}
	}()
	return listener
}

func TestSSHAndSFTP(t *testing.T) {
	keyFile, err := os.CreateTemp("", "testkey_*.pem")
	if err != nil {
		t.Fatalf("TempFile error: %v", err)
	}
	defer os.Remove(keyFile.Name())
	keyFile.Close()
	if err := generateED25519Key(keyFile.Name()); err != nil {
		t.Fatalf("generateED25519Key failed: %v", err)
	}

	tmpDir, err := os.MkdirTemp("", "sftproot_")
	if err != nil {
		t.Fatalf("TempDir error: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	listener := startTestServer(t, "127.0.0.1:0", keyFile.Name(), tmpDir)
	defer listener.Close()
	addr := listener.Addr().String()
	// Give server a moment to start
	time.Sleep(200 * time.Millisecond)

	sshConfig := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("testpass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}
	client, err := ssh.Dial("tcp", addr, sshConfig)
	if err != nil {
		t.Fatalf("SSH dial failed: %v", err)
	}
	defer client.Close()

	sftpClient, err := sftp.NewClient(client)
	if err != nil {
		t.Fatalf("SFTP client failed: %v", err)
	}
	defer sftpClient.Close()

	// SFTP put/get test
	f, err := sftpClient.Create("hello.txt")
	if err != nil {
		t.Fatalf("SFTP create failed: %v", err)
	}
	f.Write([]byte("world"))
	f.Close()

	f2, err := sftpClient.Open("hello.txt")
	if err != nil {
		t.Fatalf("SFTP open failed: %v", err)
	}
	data, err := io.ReadAll(f2)
	f2.Close()
	if err != nil {
		t.Fatalf("SFTP read failed: %v", err)
	}
	if string(data) != "world" {
		t.Fatalf("SFTP file content mismatch: %s", string(data))
	}
}
