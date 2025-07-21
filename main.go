package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
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

// Config represents the config file structure
type Config struct {
	Users []*UserConfig `json:"users"`
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
	go ssh.DiscardRequests(reqs)

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
			go handleSession(channel, requests, userRootDir)
		case "direct-tcpip":
			if srv.enablePortForward {
				go handleDirectTCPIP(newChannel)
			} else {
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			}
		// TODO: fix this, this is the type send to ssh client
		case "forwarded-tcpip":
			if srv.enableRemotePortForward {
				go handleForwardedTCPIP(newChannel)
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

var (
	verbosity = flag.Int("v", 3, "verbosity")
)

func loadConfig(configPath string) ([]*UserConfig, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	return cfg.Users, nil
}

func addUserFromCLI(user, pass, pubkeyPath string) ([]*UserConfig, error) {
	uc := &UserConfig{Username: user, Password: pass}
	if pubkeyPath != "" {
		keyData, err := os.ReadFile(pubkeyPath)
		if err != nil {
			return nil, err
		}
		uc.PublicKey = strings.TrimSpace(string(keyData))
	}
	return []*UserConfig{uc}, nil
}

func generateECDSAKey(path string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return err
	}
	keyBlock := pem.Block{Type: "EC PRIVATE KEY", Bytes: der}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &keyBlock)
}

func generateED25519Key(path string) error {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return err
	}
	keyBlock := pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &keyBlock)
}

func generateRSAKey(path string) error {
	priv, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	keyBlock := pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	return pem.Encode(f, &keyBlock)
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
	var (
		bindAddr   = flag.String("bind", ":2022", "Bind address")
		keyPath    = flag.String("hostkey", "server_ed25519.key,server_ecdsa.key,server_rsa.key", "Path to SSH host private key")
		rootDir    = flag.String("root", ".", "Root directory for SFTP access")
		configPath = flag.String("config", "", "Path to JSON config file")
		cliUser    = flag.String("user", "", "Username (CLI mode)")
		cliPass    = flag.String("password", "", "Password (CLI mode)")
		cliPubKey  = flag.String("pubkey", "", "Path to public key file (CLI mode)")
		genKey     = flag.Bool("genkey", false, "Auto-generate ECDSA server key if not exist")

		portForward       = flag.Bool("port-forward", false, "enable local/ dynamic port forward feature (ssh -L/ssh -D)")
		remoteRortForward = flag.Bool("remote-port-forward", false, "enable remote port forward feature (ssh -R)")
	)
	flag.Parse()

	if *genKey {
		fps := strings.SplitSeq(*keyPath, ",")
		for fp := range fps {
			if _, err := os.Stat(fp); os.IsNotExist(err) {
				keyType, genFn := "ED25519", generateED25519Key
				ext := filepath.Ext(fp)
				nameNoExt := fp[:len(fp)-len(ext)]
				switch {
				case strings.HasSuffix(nameNoExt, "_rsa"):
					keyType, genFn = "RSA", generateRSAKey
				case strings.HasSuffix(nameNoExt, "_ecdsa"):
					keyType, genFn = "P256", generateECDSAKey
				case strings.HasSuffix(nameNoExt, "_ed25519"):
					fallthrough
				default:
					keyType, genFn = "ED25519", generateED25519Key
				}
				Vf(1, "[gnekey]key not found, generating %v key: %s\n", keyType, fp)
				if err := genFn(fp); err != nil {
					Vln(0, "[gnekey][err]Failed to generate key:", fp, keyType, err)
				}
			}
		}
	}

	var users []*UserConfig
	if *configPath != "" {
		u, err := loadConfig(*configPath)
		if err != nil {
			Vf(0, "Failed to load config: %v", err)
			os.Exit(1)
		}
		users = u
		Vf(2, "[config]Loaded users from config: %d", len(users))
	} else if *cliUser != "" {
		u, err := addUserFromCLI(*cliUser, *cliPass, *cliPubKey)
		if err != nil {
			Vf(0, "[config][err]Failed to add user from CLI: %v", err)
			os.Exit(1)
		}
		users = u
		Vf(2, "[config]Loaded user from CLI: %s", *cliUser)
	} else {
		Vf(0, "[config][err]No user config provided. Use -config or -user")
		os.Exit(1)
	}

	srv := NewSftpSrv(users, *rootDir)
	srv.enablePortForward = *portForward
	srv.enableRemotePortForward = *remoteRortForward
	privateKeys := strings.SplitSeq(*keyPath, ",")
	for k := range privateKeys {
		if _, err := os.Stat(k); err == nil {
			keyBytes, err := os.ReadFile(k)
			if err != nil {
				Vf(0, "[key][err]Failed to load private key %s: %v", k, err)
				continue
			}
			key, err := ssh.ParsePrivateKey(keyBytes)
			if err != nil {
				Vf(0, "[key][err]Failed to parse private key %s: %v", k, err)
				continue
			}
			srv.config.AddHostKey(key)

			pubkey := key.PublicKey()
			Vln(0, "[key][fingerprint]", k, pubkey.Type(), ssh.FingerprintSHA256(pubkey), ssh.FingerprintLegacyMD5(pubkey))
		}
	}

	listener, err := net.Listen("tcp", *bindAddr)
	if err != nil {
		Vf(0, "[sftpd][err]Failed to listen on %s: %v", *bindAddr, err)
		os.Exit(1)
	}
	Vln(1, "[sftpd]Listening on", *bindAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			Vf(1, "[accept][err]Failed to accept incoming connection: %v", err)
			continue
		}
		go srv.HandleConn(conn, *rootDir)
	}
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

// handleForwardedTCPIP implements ssh -R (remote port forward)
// TODO: fix this
func handleForwardedTCPIP(newChannel ssh.NewChannel) {
	var d struct {
		DestAddr string
		DestPort uint32
		SrcAddr  string
		SrcPort  uint32
	}
	ssh.Unmarshal(newChannel.ExtraData(), &d)
	Vf(2, "forwarded-tcpip: %s:%d -> %s:%d", d.SrcAddr, d.SrcPort, d.DestAddr, d.DestPort)
	local, err := net.Dial("tcp", fmt.Sprintf("%s:%d", d.DestAddr, d.DestPort))
	if err != nil {
		newChannel.Reject(ssh.ConnectionFailed, err.Error())
		return
	}
	ch, reqs, err := newChannel.Accept()
	if err != nil {
		local.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	go proxyCopy(ch, local)
	go proxyCopy(local, ch)
}

// proxyCopy copies data between two ReadWriteClosers
func proxyCopy(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

func handleSession(channel ssh.Channel, requests <-chan *ssh.Request, rootDir string) {
	defer channel.Close()
	for req := range requests {
		Vln(3, "[session]Received request:", req.Type, req.WantReply, req.Payload)
		if req.Type == "subsystem" && string(req.Payload[4:]) == "sftp" {
			req.Reply(true, nil)
			sftpServer, err := sftp.NewServer(channel, sftp.WithServerWorkingDirectory(rootDir))
			if err != nil {
				Vf(1, "[session]Failed to start SFTP subsystem: %v", err)
				return
			}
			if err := sftpServer.Serve(); err != nil && err != io.EOF {
				Vf(1, "[session]SFTP server completed with error: %v", err)
			}
			Vln(3, "[session]SFTP server completed")
			return
		}
		req.Reply(false, nil)
	}
}

func Vf(level int, format string, v ...interface{}) {
	if level <= *verbosity {
		log.Printf(format, v...)
	}
}
func V(level int, v ...interface{}) {
	if level <= *verbosity {
		log.Print(v...)
	}
}
func Vln(level int, v ...interface{}) {
	if level <= *verbosity {
		log.Println(v...)
	}
}
func VRun(level int, fn func()) {
	if level <= *verbosity {
		fn()
	}
}
