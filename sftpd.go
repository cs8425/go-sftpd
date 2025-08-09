package main

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// UserConfig represents a user account
type UserConfig struct {
	Username  string `json:"user,omitempty"`
	Password  string `json:"pwd,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
	HomeDir   string `json:"home,omitempty"`
	Disable   bool   `json:"disable,omitempty"`

	EnablePortForward       bool `json:"allow-port-forward,omitempty"`
	EnableRemotePortForward bool `json:"allow-remote-port-forward,omitempty"`
}

func (u *UserConfig) String() string {
	return fmt.Sprintf("{user=%v root=%v key=%v hasPwd=%v disable=%v}", u.Username, u.HomeDir, u.PublicKey, u.Password != "", u.Disable)
}

// TODO: multiple line for multiple public keys
func (u *UserConfig) CheckPublicKey(pubKeyType string, pubKey string) bool {
	if u.PublicKey == "" {
		return false
	}
	if !strings.HasPrefix(u.PublicKey, pubKeyType) {
		return false
	}
	parts := strings.Fields(u.PublicKey)
	if len(parts) < 2 {
		return false
	}
	if parts[1] == pubKey {
		return true
	}
	return false
}

// user session object
type User struct {
	Username string
	RootDir  string

	EnablePortForward       bool
	EnableRemotePortForward bool

	// RemotePortForward ref
	mx            sync.Mutex
	remoteForward map[string]net.Listener
}

func (u *User) String() string {
	u.mx.Lock()
	defer u.mx.Unlock()
	return fmt.Sprintf("{user=%v root=%v forward=%v remote-forward=%v ln=%v}", u.Username, u.RootDir, u.EnablePortForward, u.EnableRemotePortForward, len(u.remoteForward))
}

func (u *User) AddListener(ln net.Listener) {
	addr := ln.Addr().String()
	u.mx.Lock()
	defer u.mx.Unlock()
	ln0, ok := u.remoteForward[addr]
	if ok {
		// ???
		// ln0.Close()
		_ = ln0
		return
	}
	u.remoteForward[addr] = ln
}

func (u *User) CloseListener(addr string) {
	u.mx.Lock()
	ln0, ok := u.remoteForward[addr]
	if ok {
		ln0.Close()
		delete(u.remoteForward, addr)
	}
	u.mx.Unlock()
}

func (u *User) Close() error {
	u.mx.Lock()
	for _, ln := range u.remoteForward {
		ln.Close()
	}
	u.mx.Unlock()
	return nil
}

type SftpSrv struct {
	config                  *ssh.ServerConfig
	rootDir                 string
	enablePortForward       bool
	enableRemotePortForward bool

	// set file permission on server (644 / 600)
	// directory will not remove 'x'
	hostUmask fs.FileMode

	// force show file permission on client, eg: always executable (755)
	// do OR on permission
	clientFileMask fs.FileMode

	Users []*UserConfig
}

func NewSftpSrv(config *Config) *SftpSrv {
	srv := &SftpSrv{
		Users:                   config.Users,
		rootDir:                 config.RootDir,
		enablePortForward:       config.EnablePortForward,
		enableRemotePortForward: config.EnableRemotePortForward,
	}

	umask, err := strconv.ParseUint(config.HostFileUmask, 8, 32)
	if err != nil {
		umask = 0o113
	}
	srv.hostUmask = fs.FileMode(umask)

	cfmask, err := strconv.ParseUint(config.ClientFileMask, 8, 32)
	if err != nil {
		cfmask = 0o511
	}
	srv.clientFileMask = fs.FileMode(cfmask)

	srv.config = &ssh.ServerConfig{
		PasswordCallback:  srv.PasswordAuth,
		PublicKeyCallback: srv.PublicKeyAuth,
		ServerVersion:     "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13",
	}
	return srv
}

func (srv *SftpSrv) GetUser(name string) *User {
	for _, u := range srv.Users {
		if u.Username == name {
			userRootDir := filepath.Join(srv.rootDir, filepath.Clean("/"+u.HomeDir))
			userSess := &User{
				Username:                u.Username,
				RootDir:                 userRootDir,
				EnablePortForward:       u.EnablePortForward,
				EnableRemotePortForward: u.EnableRemotePortForward,
			}
			if userSess.EnableRemotePortForward {
				userSess.mx.Lock()
				userSess.remoteForward = make(map[string]net.Listener)
				userSess.mx.Unlock()
			}
			return userSess
		}
	}
	return nil
}

func (srv *SftpSrv) PasswordAuth(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
	user := c.User()
	for _, u := range srv.Users {
		if u.Disable {
			continue
		}
		if u.Password == "" {
			continue
		}
		if u.Username != user {
			continue
		}
		if subtle.ConstantTimeCompare(pass, []byte(u.Password)) == 1 {
			Vln(3, "[auth]Accept PasswordAuth", string(c.ClientVersion()), c.RemoteAddr(), user)
			return &ssh.Permissions{Extensions: map[string]string{"user": u.Username}}, nil
		}
	}
	return nil, fmt.Errorf("password rejected for %q", c.User())
}

func (srv *SftpSrv) PublicKeyAuth(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
	user := c.User()
	pubKeyType := pubKey.Type()
	pubKeyData := base64.StdEncoding.EncodeToString(pubKey.Marshal())
	for _, u := range srv.Users {
		if u.Disable {
			continue
		}
		if u.Username != user {
			continue
		}
		if u.CheckPublicKey(pubKeyType, pubKeyData) {
			Vln(3, "[auth]Accept PublicKeyAuth", string(c.ClientVersion()), c.RemoteAddr(), user, pubKeyType, pubKeyData)
			return &ssh.Permissions{Extensions: map[string]string{"user": u.Username}}, nil
		}
	}
	return nil, fmt.Errorf("public key rejected for %q", c.User())
}

func (srv *SftpSrv) HandleConn(conn net.Conn, rootDir string) {
	defer conn.Close()
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, srv.config)
	if err != nil {
		Vf(1, "[conn][err]Failed to handshake: %v", err)
		return
	}
	defer sshConn.Close()

	user := srv.GetUser(sshConn.User())
	Vln(3, "[conn]New SSH connection from", conn.RemoteAddr(), user)
	go srv.handleRequests(sshConn, reqs, user)

	for newChannel := range chans {
		switch newChannel.ChannelType() {
		case "session":
			channel, requests, err := newChannel.Accept()
			if err != nil {
				Vf(1, "Could not accept channel: %v", err)
				continue
			}
			Vln(3, "New session channel", channel)
			go srv.handleSession(channel, requests, user)
		case "direct-tcpip":
			if srv.enablePortForward && user.EnablePortForward {
				go handleDirectTCPIP(newChannel)
			} else {
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			}
		default:
			Vln(3, "New channel", newChannel.ChannelType(), newChannel.ExtraData())
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
		}
	}
	Vln(3, "[conn]SSH connection end", conn.RemoteAddr(), sshConn)
}

func (srv *SftpSrv) handleSession(channel ssh.Channel, requests <-chan *ssh.Request, user *User) {
	defer channel.Close()
	for req := range requests {
		Vln(3, "[session]Received request:", req.Type, req.WantReply, req.Payload)
		switch req.Type {
		case "subsystem":
			if string(req.Payload[4:]) == "sftp" {
				h, err := customSFTPHandlers(user.RootDir, user.Username, srv.hostUmask, srv.clientFileMask)
				if err != nil {
					Vln(3, "[session]SFTP server init error", err)
					req.Reply(false, nil)
					continue
				}
				req.Reply(true, nil)
				rs := sftp.NewRequestServer(channel, sftp.Handlers{
					FileGet:  h,
					FilePut:  h,
					FileCmd:  h,
					FileList: h,
				}, sftp.WithStartDirectory("/"))
				if err := rs.Serve(); err != nil && err != io.EOF {
					Vf(1, "[session]SFTP request server completed with error: %v", err)
				}
				Vln(3, "[session]SFTP server completed")
				return
			}
		case "shell":
			go io.Copy(io.Discard, channel)
			// We only accept the default shell (i.e. no command in the Payload)
			if len(req.Payload) == 0 {
				req.Reply(true, nil)
				continue
			}
		default:
		}
		req.Reply(false, nil)
	}
}

func (srv *SftpSrv) handleRequests(sshConn *ssh.ServerConn, reqs <-chan *ssh.Request, user *User) {
	for req := range reqs {
		if user.EnableRemotePortForward {
			switch req.Type {
			case "tcpip-forward":
				go srv.handleForwardedTCPIP(sshConn, req, user)
				continue
			case "cancel-tcpip-forward":
				// TODO:
				// user.CloseListener()
				continue
			default:
			}
		}
		if req.WantReply {
			req.Reply(false, nil)
		}
	}
	if user.EnableRemotePortForward {
		user.Close()
		Vf(2, "[requests]close all listener for client: %v", user)
	}
}

// handleForwardedTCPIP implements ssh -R (remote port forward)
func (srv *SftpSrv) handleForwardedTCPIP(sshConn *ssh.ServerConn, req *ssh.Request, user *User) {
	var d struct {
		BindAddr string
		BindPort uint32
	}
	ssh.Unmarshal(req.Payload, &d)
	Vf(2, "[requests]tcpip-forward: %s:%d", d.BindAddr, d.BindPort)
	ln, err := net.Listen("tcp", net.JoinHostPort(d.BindAddr, fmt.Sprintf("%d", d.BindPort)))
	if err != nil {
		req.Reply(false, []byte(err.Error()))
		return
	}

	// track for resource release
	user.AddListener(ln)

	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	bindPort, _ := strconv.ParseUint(portStr, 10, 32)
	req.Reply(true, ssh.Marshal(struct {
		BindPort uint32
	}{
		BindPort: uint32(bindPort),
	}))

	// accept from ln and open channel
	for {
		conn, err := ln.Accept()
		if err != nil {
			break
		}
		go handleRemoteAccept(sshConn, conn, d.BindAddr, uint32(bindPort))
	}
}

func handleRemoteAccept(sshConn *ssh.ServerConn, conn net.Conn, bindAddr string, bindPort uint32) {
	originAddr, orignPortStr, _ := net.SplitHostPort(conn.RemoteAddr().String())
	originPort, _ := strconv.ParseUint(orignPortStr, 10, 32)
	reqPayload := ssh.Marshal(struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}{
		DestAddr:   bindAddr,
		DestPort:   bindPort,
		OriginAddr: originAddr,
		OriginPort: uint32(originPort),
	})
	ch, reqs, err := sshConn.OpenChannel("forwarded-tcpip", reqPayload)
	if err != nil {
		conn.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	go proxyCopy(ch, conn)
	go proxyCopy(conn, ch)
}

// handleDirectTCPIP implements ssh -L/ssh -D (local/ dynamic port forward)
func handleDirectTCPIP(newChannel ssh.NewChannel) {
	var d struct {
		DestAddr string
		DestPort uint32
		SrcAddr  string
		SrcPort  uint32
	}
	ssh.Unmarshal(newChannel.ExtraData(), &d)
	Vf(2, "[channel]direct-tcpip: %s:%d -> %s:%d", d.SrcAddr, d.SrcPort, d.DestAddr, d.DestPort)
	remote, err := net.Dial("tcp", net.JoinHostPort(d.DestAddr, fmt.Sprintf("%d", d.DestPort)))
	if err != nil {
		newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := newChannel.Accept()
	if err != nil {
		remote.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	go proxyCopy(ch, remote)
	go proxyCopy(remote, ch)
}

// proxyCopy copies data between two ReadWriteClosers
func proxyCopy(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}
