package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Helper: start a test TCP echo server
func startEchoServer(t *testing.T) (addr string, closeFn func()) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				io.Copy(conn, conn)
				conn.Close()
			}(c)
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

func TestSSHLPortForward(t *testing.T) {
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
	time.Sleep(200 * time.Millisecond)

	echoAddr, closeEcho := startEchoServer(t)
	defer closeEcho()

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

	// ssh -L: local port forward
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("local listen: %v", err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				remote, err := client.Dial("tcp", echoAddr)
				if err != nil {
					conn.Close()
					return
				}
				go io.Copy(remote, conn)
				io.Copy(conn, remote)
				conn.Close()
				remote.Close()
			}(c)
		}
	}()
	// Test local forward
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatalf("local forward dial: %v", err)
	}
	msg := []byte("helloL")
	conn.Write(msg)
	buf := make([]byte, len(msg))
	n, err := io.ReadFull(conn, buf)
	if n != len(buf) {
		t.Fatalf("local forward echo data length mismatch: got %v, expected %v", n, len(buf))
	}
	if err != nil {
		t.Fatalf("local forward echo err: got %q", err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("local forward echo mismatch: got %q", buf)
	}
	conn.Close()

	// ssh -D: dynamic port forward (SOCKS5)
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socks5 listen: %v", err)
	}
	defer socksListener.Close()
	go func() {
		for {
			c, err := socksListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				sshConn, err := handleSocks5Connection(conn, client.Dial)
				if err != nil {
					conn.Close()
					return
				}
				go io.Copy(sshConn, conn)
				io.Copy(conn, sshConn)
				conn.Close()
				sshConn.Close()
			}(c)
		}
	}()

	// 使用 dialViaSocks5 測試 socks5 代理
	socksAddr := socksListener.Addr().String()
	socksConn, err := dialViaSocks5(echoAddr, socksAddr)
	if err != nil {
		t.Fatalf("SOCKS5 dial failed: %v", err)
	}
	msgD := []byte("helloD")
	socksConn.Write(msgD)
	bufD := make([]byte, len(msgD))
	io.ReadFull(socksConn, bufD)
	if string(bufD) != string(msgD) {
		t.Fatalf("SOCKS5 echo mismatch: got %q", bufD)
	}
	socksConn.Close()

	// ssh -R: remote port forward
	// 在 client 端請求 remote forward (ssh -R)
	remoteListener, err := client.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("remote forward listen failed: %v", err)
	}
	// defer remoteListener.Close()
	Vln(0, "remote listen addr", remoteListener.Addr().String())

	// 在 server 端連到 remoteListener，資料會被轉發到 client，再由 client 轉發到 echoAddr
	go func() {
		for {
			conn, err := remoteListener.Accept()
			Vln(0, "remote listen accept", conn, err, echoAddr)
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				// 由 client 端連到 echoAddr
				remote, err := net.Dial("tcp", echoAddr)
				Vln(0, "remote listen Dial to echo", remote.RemoteAddr(), remote.LocalAddr(), err, echoAddr)
				if err != nil {
					return
				}
				defer remote.Close()
				go io.Copy(remote, conn)
				io.Copy(conn, remote)
			}(conn)
		}
	}()

	// 在 server 端連到 remoteListener 的地址，驗證資料來回
	serverSideConn, err := net.Dial("tcp", remoteListener.Addr().String())
	if err != nil {
		t.Fatalf("server side dial to remoteListener failed: %v", err)
	}
	Vln(0, "server-side dial", serverSideConn.RemoteAddr(), serverSideConn.LocalAddr())
	msgR := []byte("helloR")
	serverSideConn.Write(msgR)
	bufR := make([]byte, len(msgR))
	io.ReadFull(serverSideConn, bufR)
	if string(bufR) != string(msgR) {
		t.Fatalf("remote forward echo mismatch: got %q", bufR)
	}
	serverSideConn.Close()
	Vln(0, "test end")
}

func dialViaSocks5(targetAddr string, socksAddr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	if port < 1 || port > 0xffff {
		return nil, fmt.Errorf("port number out of range: %v", portStr)
	}
	socksReq := []byte{0x05, 0x01, 0x00, 0x03}
	socksReq = append(socksReq, byte(len(host)))
	socksReq = append(socksReq, host...)
	socksReq = append(socksReq, byte(port>>8), byte(port))

	conn, err := net.DialTimeout("tcp", socksAddr, 5*time.Second)
	if err != nil {
		Vln(2, "connect to ", socksAddr, err)
		return nil, err
	}

	var b [10]byte

	// send request
	conn.Write([]byte{0x05, 0x01, 0x00})

	// read reply
	_, err = conn.Read(b[:2])
	if err != nil {
		return conn, err
	}

	// send server addr
	conn.Write(socksReq)

	// read reply
	n, err := conn.Read(b[:10])
	if n < 10 {
		Vln(2, "Dial err replay:", socksAddr, n)
		return conn, err
	}
	if err != nil || b[1] != 0x00 {
		Vln(2, "Dial err:", socksAddr, n, b[1], err)
		return conn, fmt.Errorf("protocol error: %02X", b)
	}
	return conn, nil
}

func replyAndClose(p1 net.Conn, rpy int) {
	p1.Write([]byte{0x05, byte(rpy), 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	p1.Close()
}

func handleSocks5Connection(p1 net.Conn, dialer func(network string, address string) (net.Conn, error)) (net.Conn, error) {
	var b [1024]byte
	n, err := p1.Read(b[:])
	if err != nil {
		p1.Close()
		return nil, err
	}
	if b[0] != 0x05 { //only Socks5
		p1.Close()
		return nil, fmt.Errorf("not socks5")
	}

	//reply: NO AUTHENTICATION REQUIRED
	p1.Write([]byte{0x05, 0x00})

	n, err = p1.Read(b[:])
	if b[1] != 0x01 { // 0x01: CONNECT
		replyAndClose(p1, 0x07) // X'07' Command not supported
		return nil, fmt.Errorf("command not supported")
	}

	var host, port string
	switch b[3] {
	case 0x01: //IP V4
		host = net.IPv4(b[4], b[5], b[6], b[7]).String()
	case 0x03: //DOMAINNAME
		host = string(b[5 : n-2]) //b[4] domain name length
	case 0x04: //IP V6
		host = net.IP{b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16], b[17], b[18], b[19]}.String()
	default:
		replyAndClose(p1, 0x08) // X'08' Address type not supported
		return nil, fmt.Errorf("address type not supported")
	}
	port = strconv.Itoa(int(b[n-2])<<8 | int(b[n-1]))
	backend := net.JoinHostPort(host, port)
	p2, err := dialer("tcp", backend)
	if err != nil {
		Vln(2, backend, err)
		replyAndClose(p1, 0x05) // X'05'
		return nil, err
	}

	reply := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	p1.Write(reply) // reply OK
	return p2, err
}
