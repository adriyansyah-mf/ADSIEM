// siem-update-sign makes and checks the .sig files agents require before they
// install an update.
//
//	siem-update-sign keygen -out update.key          # prints the public key
//	siem-update-sign sign -key update.key PKG...      # writes PKG.sig
//	siem-update-sign verify -pub <base64> PKG...
//
// The private key is the base64 ed25519 seed, from -key or SIEM_UPDATE_SIGNING_KEY.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/siem-platform/agent/internal/update"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "siem-update-sign:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: siem-update-sign keygen -out FILE | sign [-key FILE] PKG... | verify -pub KEYS PKG...")
	os.Exit(2)
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ExitOnError)
	out := fs.String("out", "", "file for the private key (base64 seed, mode 0600)")
	_ = fs.Parse(args)
	if *out == "" {
		return errors.New("keygen needs -out")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(*out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintln(f, base64.StdEncoding.EncodeToString(priv.Seed())); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	fmt.Printf("public key (key id %s):\n%s\n", update.KeyID(pub), base64.StdEncoding.EncodeToString(pub))
	return nil
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	raw := os.Getenv("SIEM_UPDATE_SIGNING_KEY")
	if path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		raw = string(b)
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("signing key: need a base64 ed25519 seed (-key or SIEM_UPDATE_SIGNING_KEY)")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// Package names written by packaging/build-{deb,rpm}.sh and build-msi.ps1.
var names = []struct {
	format, os string
	rx         *regexp.Regexp
}{
	{"deb", "linux", regexp.MustCompile(`^siem-agent_(?P<version>[^_]+)_(?P<arch>[^_.]+)\.deb$`)},
	{"rpm", "linux", regexp.MustCompile(`^siem-agent-(?P<version>[^-]+)-[^.]+\.(?P<arch>[^.]+)\.rpm$`)},
	{"msi", "windows", regexp.MustCompile(`^siem-agent-(?P<version>\d[\d.]*)-(?P<arch>x64)\.msi$`)},
}

var goarch = map[string]string{"amd64": "amd64", "x86_64": "amd64", "x64": "amd64", "arm64": "arm64", "aarch64": "arm64"}

// describe is the manifest for a package file, from its name and content.
func describe(path string) (update.Manifest, error) {
	base := filepath.Base(path)
	for _, n := range names {
		m := n.rx.FindStringSubmatch(base)
		if m == nil {
			continue
		}
		arch, ok := goarch[m[n.rx.SubexpIndex("arch")]]
		if !ok {
			return update.Manifest{}, fmt.Errorf("%s: unknown architecture", base)
		}
		f, err := os.Open(path)
		if err != nil {
			return update.Manifest{}, err
		}
		defer f.Close()
		h := sha256.New()
		size, err := io.Copy(h, f)
		if err != nil {
			return update.Manifest{}, err
		}
		return update.Manifest{Version: m[n.rx.SubexpIndex("version")], OS: n.os, Arch: arch, Format: n.format,
			File: base, SHA256: hex.EncodeToString(h.Sum(nil)), Size: size}, nil
	}
	return update.Manifest{}, fmt.Errorf("%s: not an agent package name (deb, rpm or msi)", base)
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	keyPath := fs.String("key", "", "private key file (default: SIEM_UPDATE_SIGNING_KEY)")
	_ = fs.Parse(args)
	priv, err := loadKey(*keyPath)
	if err != nil {
		return err
	}
	for _, pkg := range fs.Args() {
		m, err := describe(pkg)
		if err != nil {
			return err
		}
		s, err := update.Sign(m, priv)
		if err != nil {
			return err
		}
		raw, _ := json.MarshalIndent(s, "", "  ")
		if err := os.WriteFile(pkg+".sig", append(raw, '\n'), 0o644); err != nil {
			return err
		}
		fmt.Printf("%s.sig  %s %s/%s %s  key %s\n", pkg, m.Version, m.OS, m.Arch, m.Format, s.KeyID)
	}
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubs := fs.String("pub", "", "trusted public keys (base64, comma separated)")
	_ = fs.Parse(args)
	keys, err := update.ParseKeys(*pubs)
	if err != nil || len(keys) == 0 {
		return fmt.Errorf("verify needs -pub: %v", err)
	}
	for _, pkg := range fs.Args() {
		raw, err := os.ReadFile(pkg + ".sig")
		if err != nil {
			return err
		}
		var s update.Signed
		if err := json.Unmarshal(raw, &s); err != nil {
			return fmt.Errorf("%s.sig: %w", pkg, err)
		}
		m, err := update.Verify(s, keys)
		if err != nil {
			return fmt.Errorf("%s: %w", pkg, err)
		}
		actual, err := describe(pkg)
		if err != nil {
			return err
		}
		actual.Schema, actual.Product = m.Schema, m.Product
		if actual != m {
			return fmt.Errorf("%s: file does not match its signed manifest", pkg)
		}
		fmt.Printf("%s  ok  %s %s/%s %s\n", pkg, m.Version, m.OS, m.Arch, m.Format)
	}
	return nil
}
