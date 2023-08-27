/*
 * Copyright (c) 2023 Zander Schwid & Co. LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package sealmod

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"github.com/codeallergy/seal"
	"github.com/pkg/errors"
	"reflect"
)

func WithRSAPublicKey(pub *rsa.PublicKey) seal.SealerOption {
	return sealerOptionFunc(func(opt *seal.SealerOptions) error {
		opt.Algorithm = "rsa"
		opt.PublicKey = pub
		return nil
	})
}

func WithEncodedRSAPublicKey(pubPEM string) seal.SealerOption {
	return sealerOptionFunc(func(opt *seal.SealerOptions) error {
		block, _ := pem.Decode([]byte(pubPEM))
		b := block.Bytes
		var err error
		if x509.IsEncryptedPEMBlock(block) {
			b, err = x509.DecryptPEMBlock(block, nil)
			if err != nil {
				return errors.Errorf("decrypt encrypted pem block, %v", err)
			}
		}
		ifc, err := x509.ParsePKIXPublicKey(b)
		if err != nil {
			return errors.Errorf("parse PKIX public key, %v", err)
		}
		key, ok := ifc.(*rsa.PublicKey)
		if !ok {
			return errors.Errorf("not a RSA public key, %v", reflect.TypeOf(ifc))
		}
		opt.Algorithm = "rsa"
		opt.PublicKey = key
		return nil
	})
}

func WithRSAPrivateKey(priv *rsa.PrivateKey) seal.SealerOption {
	return sealerOptionFunc(func(opt *seal.SealerOptions) error {
		opt.Algorithm = "rsa"
		opt.PrivateKey = priv
		return nil
	})
}

func WithEncodedRSAPrivateKey(privPEM string) seal.SealerOption {
	return sealerOptionFunc(func(opt *seal.SealerOptions) error {
		block, _ := pem.Decode([]byte(privPEM))
		b := block.Bytes
		var err error
		if x509.IsEncryptedPEMBlock(block) {
			b, err = x509.DecryptPEMBlock(block, nil)
			if err != nil {
				return errors.Errorf("decrypt encrypted pem block, %v", err)
			}
		}
		key, err := x509.ParsePKCS1PrivateKey(b)
		if err != nil {
			return errors.Errorf("parse PKCS1 private key, %v", err)
		}
		opt.Algorithm = "rsa"
		opt.PrivateKey = key
		return nil
	})
}


type implRSASealer struct {
	pub   *rsa.PublicKey
	priv  *rsa.PrivateKey
}

func RSASealer(opt *seal.SealerOptions) (seal.AsymmetricSealer, error) {
	t := &implRSASealer{}

	if opt.PublicKey != nil {
		var ok bool
		t.pub, ok = opt.PublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.Errorf("not a RSA public key, %v", reflect.TypeOf(opt.PublicKey))
		}
	}
	if opt.PrivateKey != nil {
		var ok bool
		t.priv, ok = opt.PrivateKey.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.Errorf("not a RSA private key, %v", reflect.TypeOf(opt.PrivateKey))
		}
	}

	return t, nil
}

func RSASealerIssue(bits int) (seal.AsymmetricSealer, error) {
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return &implRSASealer{
		pub: &priv.PublicKey,
		priv: priv,
	}, nil
}

func (t *implRSASealer) PublicKey() crypto.PublicKey {
	return t.pub
}

func (t *implRSASealer) PrivateKey() crypto.PrivateKey {
	return t.priv
}

func (t *implRSASealer) EncodePublicKey() (string, error) {

	if t.pub == nil {
		return "", errors.New("public key is empty")
	}

	pubASN1, err := x509.MarshalPKIXPublicKey(t.pub)
	if err != nil {
		return "", errors.Errorf("marshal PKIX public key, %v", err)
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubASN1,
	})

	return string(pubBytes), nil
}

func (t *implRSASealer) EncodePrivateKey() (string, error) {
	if t.priv == nil {
		return "", errors.New("private key is empty")
	}
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(t.priv),
		},
	)
	return string(privBytes), nil
}

func (t *implRSASealer) Seal(plaintext []byte, recipient crypto.PublicKey) (ciphertext []byte, err error) {
	pub, ok := recipient.(*rsa.PublicKey)
	if !ok {
		return nil, errors.Errorf("not a RSA public key, %v", reflect.TypeOf(recipient))
	}
	hash := sha512.New()
	ciphertext, err = rsa.EncryptOAEP(hash, rand.Reader, pub, plaintext, nil)
	return
}

func (t *implRSASealer) Open(ciphertext []byte, _ crypto.PublicKey) (plaintext []byte, err error) {
	if t.priv == nil {
		return nil, errors.New("private key is empty")
	}
	hash := sha512.New()
	plaintext, err = rsa.DecryptOAEP(hash, rand.Reader, t.priv, ciphertext, nil)
	return
}


