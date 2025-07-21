# go-sftpd

A cross-platform, simple and easy-to-use SFTP server written in Go.

## Features

- **Cross-platform**: Runs on Linux, Windows, macOS and more.
- **Simple & Easy to Use**: Quick setup with CLI flags or JSON config, no complex configuration required.
- **Authentication**: Supports password, public key authentication.
- **Multi-key Support**: Server can use ED25519, ECDSA, and RSA keys simultaneously.
- **User Home Directory**: Each user can be restricted to their own home directory.
- **Port Forwarding**: Supports SSH -L, -D port forwarding.

## Quick Start

1. **Build**

```bash
go build -o go-sftpd main.go
```

2. **Run with CLI options**

```bash
./go-sftpd -bind=:2022 -user=testuser -password=testpass -root=/data/sftp
```

3. **Run with JSON config**

Create `config.json`:
```json
{
  "users": [
    {
      "user": "testuser",
      "pwd": "testpass",
      "public_key": "ssh-ed25519 AAAA...",
      "home": "userdir"
    }
  ]
}
```
Run:
```bash
./go-sftpd -config=config.json -root=/data/sftp
```

4. **Auto-generate server keys**

```bash
./go-sftpd -genkey -hostkey=server_ed25519.key,server_ecdsa.key,server_rsa.key
```

5. **Run with local/dynamic port forward enabled**

```bash
./go-sftpd -bind=:2022 -user=testuser -password=testpass -root=/data/sftp -port-forward
```

## TODO

* [ ] SSH -R port forwarding
* [ ] only port forwarding without sftp

## License

MIT
