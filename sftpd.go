package main

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"

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

type SftpSrv struct {
	config                  *ssh.ServerConfig
	rootDir                 string
	enablePortForward       bool
	enableRemotePortForward bool
	Users                   []*UserConfig
}

func NewSftpSrv(users []*UserConfig, rootDir string) *SftpSrv {
	srv := &SftpSrv{
		Users:   users,
		rootDir: rootDir,
	}
	srv.config = &ssh.ServerConfig{
		PasswordCallback:  srv.PasswordAuth,
		PublicKeyCallback: srv.PublicKeyAuth,
		ServerVersion:     "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.13",
	}
	return srv
}

func (srv *SftpSrv) GetUser(name string) *UserConfig {
	for _, u := range srv.Users {
		if u.Username == name {
			return u
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
	go srv.handleRequests(sshConn, reqs)

	user := srv.GetUser(sshConn.User())
	userRootDir := filepath.Join(rootDir, user.HomeDir)
	Vln(3, "[conn]New SSH connection from", conn.RemoteAddr(), user, userRootDir)

	for newChannel := range chans {
		switch newChannel.ChannelType() {
		case "session":
			channel, requests, err := newChannel.Accept()
			if err != nil {
				Vf(1, "Could not accept channel: %v", err)
				continue
			}
			Vln(3, "New session channel", channel)
			go handleSession(channel, requests, userRootDir, user.Username)
		case "direct-tcpip":
			if srv.enablePortForward {
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

func handleSession(channel ssh.Channel, requests <-chan *ssh.Request, rootDir string, username string) {
	defer channel.Close()
	for req := range requests {
		Vln(3, "[session]Received request:", req.Type, req.WantReply, req.Payload)
		if req.Type == "subsystem" && string(req.Payload[4:]) == "sftp" {
			h, err := customSFTPHandlers(rootDir, username)
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
		req.Reply(false, nil)
	}
}

func (srv *SftpSrv) handleRequests(sshConn *ssh.ServerConn, reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			go srv.handleForwardedTCPIP(sshConn, req)
			continue
		case "cancel-tcpip-forward":
			fallthrough // TODO:
		default:
		}
		if req.WantReply {
			req.Reply(false, nil)
		}
	}
}

// handleForwardedTCPIP implements ssh -R (remote port forward)
func (srv *SftpSrv) handleForwardedTCPIP(sshConn *ssh.ServerConn, req *ssh.Request) {
	var d struct {
		BindAddr string
		BindPort uint32
	}
	ssh.Unmarshal(req.Payload, &d)
	Vf(2, "[channel]tcpip-forward: %s:%d", d.BindAddr, d.BindPort)
	ln, err := net.Listen("tcp", net.JoinHostPort(d.BindAddr, fmt.Sprintf("%d", d.BindPort)))
	if err != nil {
		req.Reply(false, []byte(err.Error()))
		return
	}
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	n, _ := strconv.ParseUint(portStr, 10, 32)
	req.Reply(true, ssh.Marshal(struct {
		BindPort uint32
	}{
		BindPort: uint32(n),
	}))
	// TODO: accept from ln and open channel
	// sshConn.OpenChannel("forwarded-tcpip", ...)
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
