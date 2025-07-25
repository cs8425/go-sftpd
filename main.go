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
			go handleSession(channel, requests, userRootDir)
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

		portForward       = flag.Bool("port-forward", false, "enable local/dynamic port forward feature (ssh -L/ssh -D)")
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

// proxyCopy copies data between two ReadWriteClosers
func proxyCopy(dst io.WriteCloser, src io.ReadCloser) {
	defer dst.Close()
	defer src.Close()
	io.Copy(dst, src)
}

// RootedHandler implements sftp.FileReader, FileWriter, FileCmder, LstatFileLister(FileLister) for rootDir restriction
type RootedHandler struct {
	rootDir string
}

func (h *RootedHandler) cleanPath(fp string) string {
	return filepath.Join(h.rootDir, filepath.Join("/", fp))
}

func (h *RootedHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	path := h.cleanPath(r.Filepath)
	Vln(3, "[Fileread]", r.Method, r.Filepath, path)
	return os.Open(path)
}
func (h *RootedHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	path := h.cleanPath(r.Filepath)
	Vln(3, "[Filewrite]", r.Method, r.Filepath, path)
	return os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
}
func (h *RootedHandler) Filecmd(r *sftp.Request) error {
	path := h.cleanPath(r.Filepath)
	Vln(3, "[Filecmd]", r.Method, r.Filepath, path)
	switch r.Method {
	case "Setstat":
		return h.setstat(r)
	case "Rename":
		newPath := h.cleanPath(r.Target)
		return os.Rename(path, newPath)
	case "Rmdir":
		return os.Remove(path)
	case "Remove":
		return os.Remove(path)
	case "Mkdir":
		return os.Mkdir(path, 0755)
	case "Symlink":
		// os.Symlink(s.toLocalPath(p.Targetpath), s.toLocalPath(p.Linkpath))
	case "Link":
	// case "PosixRename":
	// case "StatVFS":
	default:
	}
	return sftp.ErrSSHFxOpUnsupported
}

func (h *RootedHandler) setstat(r *sftp.Request) error {
	attr := r.Attributes()
	if attr == nil {
		return nil
	}
	flags := r.AttrFlags()
	path := h.cleanPath(r.Filepath)
	var err error
	if flags.Permissions {
		err = os.Chmod(path, attr.FileMode())
	}
	if err == nil && flags.UidGid {
		err = os.Chown(path, int(attr.UID), int(attr.GID))
	}
	if err == nil && flags.Acmodtime {
		err = os.Chtimes(path, attr.AccessTime(), attr.ModTime())
	}
	if err == nil && flags.Size {
		err = os.Truncate(path, int64(attr.Size))
	}
	return err
}

var _ sftp.ReadlinkFileLister = (*RootedHandler)(nil)

func (h *RootedHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	path := h.cleanPath(r.Filepath)
	Vln(3, "[Filecmd]", r.Method, r.Filepath, path)
	// "Readlink" handle by h.Readlink(fp string) (string, error)
	switch r.Method {
	case "List":
		f, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		fis, err := f.Readdir(-1)
		f.Close()
		if err != nil {
			return nil, err
		}
		return listerAt(fis), nil

	case "Stat":
		fis, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		return listerAt([]os.FileInfo{fis}), nil
	case "Lstat": // should call h.Lstat(r *sftp.Request) (sftp.ListerAt, error)
		return h.Lstat(r)
	}
	return nil, os.ErrInvalid
}

func (h *RootedHandler) Readlink(fp string) (string, error) {
	path := h.cleanPath(fp)
	dst, err := os.Readlink(path)
	return dst, err
}

func (h *RootedHandler) Lstat(r *sftp.Request) (sftp.ListerAt, error) {
	path := h.cleanPath(r.Filepath)
	fis, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	return listerAt([]os.FileInfo{fis}), nil
}

type listerAt []os.FileInfo

func (l listerAt) ListAt(ls []os.FileInfo, off int64) (int, error) {
	if int(off) >= len(l) {
		return 0, io.EOF
	}
	n := copy(ls, l[off:])
	if n < len(ls) {
		return n, io.EOF
	}
	return n, nil
}

func customSFTPHandlers(rootDir string) sftp.Handlers {
	h := &RootedHandler{rootDir: rootDir}
	return sftp.Handlers{
		FileGet:  h,
		FilePut:  h,
		FileCmd:  h,
		FileList: h,
	}
}

func handleSession(channel ssh.Channel, requests <-chan *ssh.Request, rootDir string) {
	defer channel.Close()
	for req := range requests {
		Vln(3, "[session]Received request:", req.Type, req.WantReply, req.Payload)
		if req.Type == "subsystem" && string(req.Payload[4:]) == "sftp" {
			req.Reply(true, nil)
			hs := customSFTPHandlers(rootDir)
			rs := sftp.NewRequestServer(channel, hs, sftp.WithStartDirectory("/"))
			if err := rs.Serve(); err != nil && err != io.EOF {
				Vf(1, "[session]SFTP request server completed with error: %v", err)
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
