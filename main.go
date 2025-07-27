package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Config represents the config file structure
type Config struct {
	Users []*UserConfig `json:"users"`
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
		u[0].EnablePortForward = *portForward
		u[0].EnableRemotePortForward = *remoteRortForward
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
