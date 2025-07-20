package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"testing"
)

func TestGenerateED25519Key(t *testing.T) {
	tmpfile, err := os.CreateTemp("", "ed25519key_*.pem")
	if err != nil {
		t.Fatalf("TempFile error: %v", err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Close()

	if err := generateED25519Key(tmpfile.Name()); err != nil {
		t.Fatalf("generateED25519Key failed: %v", err)
	}
	data, err := os.ReadFile(tmpfile.Name())
	if err != nil || len(data) == 0 {
		t.Fatalf("Key file not created or empty: %v", err)
	}
}

func TestAddUserFromCLI(t *testing.T) {
	users = nil
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	pubFile, err := os.CreateTemp("", "pubkey_*.pub")
	if err != nil {
		t.Fatalf("TempFile error: %v", err)
	}
	defer os.Remove(pubFile.Name())
	pubFile.Write([]byte("ssh-ed25519 " + string(pub)))
	pubFile.Close()

	err = addUserFromCLI("testuser", "testpass", pubFile.Name())
	if err != nil {
		t.Fatalf("addUserFromCLI failed: %v", err)
	}
	if len(users) != 1 || users[0].Username != "testuser" {
		t.Fatalf("User not added correctly")
	}
}

func TestLoadConfig(t *testing.T) {
	users = nil
	jsonData := `{"users":[{"username":"a","password":"b","public_key":"c"}]}`
	tmpfile, err := os.CreateTemp("", "config_*.json")
	if err != nil {
		t.Fatalf("TempFile error: %v", err)
	}
	defer os.Remove(tmpfile.Name())
	tmpfile.Write([]byte(jsonData))
	tmpfile.Close()

	if err := loadConfig(tmpfile.Name()); err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}
	if len(users) != 1 || users[0].Username != "a" {
		t.Fatalf("Config not loaded correctly")
	}
}
