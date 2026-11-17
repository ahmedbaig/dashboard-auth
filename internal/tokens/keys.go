package tokens

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

func ID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

func block(path string) (*pem.Block, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode(b)
	if p == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	return p, nil
}

func LoadPrivate(path string) (Private, error) {
	p, err := block(path)
	if err != nil {
		return Private{}, err
	}
	k, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		return Private{}, fmt.Errorf("%s: %w", path, err)
	}
	ed, ok := k.(ed25519.PrivateKey)
	if !ok {
		return Private{}, errors.New(path + ": not an Ed25519 key")
	}
	return Private{Key: ed, ID: ID(ed.Public().(ed25519.PublicKey))}, nil
}

func LoadPublic(path string) (Public, error) {
	p, err := block(path)
	if err != nil {
		return Public{}, err
	}
	k, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		return Public{}, fmt.Errorf("%s: %w", path, err)
	}
	ed, ok := k.(ed25519.PublicKey)
	if !ok {
		return Public{}, errors.New(path + ": not an Ed25519 key")
	}
	return Public{Key: ed, ID: ID(ed)}, nil
}

func Generate() (Private, Public) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	return Private{Key: priv, ID: ID(pub)}, Public{Key: pub, ID: ID(pub)}
}
