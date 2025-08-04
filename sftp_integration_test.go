package main

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func startTestServer(addr, keyPath, rootDir string) (net.Listener, error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
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
	return listener, nil
}

func TestSSHAndSFTP(t *testing.T) {
	sshConfig := &ssh.ClientConfig{
		User:            "testuser",
		Auth:            []ssh.AuthMethod{ssh.Password("testpass")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         2 * time.Second,
	}
	client, err := ssh.Dial("tcp", sftpServerAddr, sshConfig)
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
