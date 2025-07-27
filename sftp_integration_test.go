package main

import (
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
		users := []*UserConfig{{
			Username:                "testuser",
			Password:                "testpass",
			HomeDir:                 "",
			EnablePortForward:       true,
			EnableRemotePortForward: true,
		},
		}
		config := &Config{
			Users:                   users,
			RootDir:                 rootDir,
			EnablePortForward:       true,
			EnableRemotePortForward: true,
		}
		srv := NewSftpSrv(config)
		srv.enablePortForward = true
		srv.enableRemotePortForward = true
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

	// Rename file
	err = sftpClient.Rename("hello.txt", "renamed.txt")
	if err != nil {
		t.Fatalf("SFTP rename failed: %v", err)
	}

	// Remove file
	err = sftpClient.Remove("renamed.txt")
	if err != nil {
		t.Fatalf("SFTP remove failed: %v", err)
	}

	// Create directory
	err = sftpClient.Mkdir("testdir")
	if err != nil {
		t.Fatalf("SFTP mkdir failed: %v", err)
	}

	// Create file in directory
	f3, err := sftpClient.Create("testdir/file1.txt")
	if err != nil {
		t.Fatalf("SFTP create in dir failed: %v", err)
	}
	f3.Write([]byte("abc"))
	f3.Close()

	// List directory
	files, err := sftpClient.ReadDir("testdir")
	if err != nil {
		t.Fatalf("SFTP readdir failed: %v", err)
	}
	if len(files) != 1 || files[0].Name() != "file1.txt" {
		t.Fatalf("SFTP dir listing incorrect: %+v", files)
	}

	// Remove file in directory
	err = sftpClient.Remove("testdir/file1.txt")
	if err != nil {
		t.Fatalf("SFTP remove in dir failed: %v", err)
	}

	// Remove directory
	err = sftpClient.RemoveDirectory("testdir")
	if err != nil {
		t.Fatalf("SFTP rmdir failed: %v", err)
	}
}
