/*
 * Copyright (c) 2023 Zander Schwid & Co. LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package sealmod

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"github.com/sprintframework/seal"
	"github.com/pkg/errors"
	"reflect"
)

func WithECDSAPublicKey(pub *ecdsa.PublicKey) seal.SealerOption {
	return sealerOptionFunc(func(opt *seal.SealerOptions) error {
		opt.Algorithm = "ecdsa"
		opt.PublicKey = pub
		return nil
	})
}

func WithEncodedECDSAPublicKey(pubPEM string) seal.SealerOption {
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
			return errors.Errorf("parse EC public key, %v", err)
		}
		key, ok := ifc.(*ecdsa.PublicKey)
		if !ok {
			return errors.Errorf("not a RSA public key, %v", reflect.TypeOf(ifc))
		}
		opt.Algorithm = "ecdsa"
		opt.PublicKey = key
		return nil
	})
}

func WithECDSAPrivateKey(priv *ecdsa.PrivateKey) seal.SealerOption {
	return sealerOptionFunc(func(opt *seal.SealerOptions) error {
		opt.Algorithm = "ecdsa"
		opt.PrivateKey = priv
		return nil
	})
}

func WithEncodedECDSAPrivateKey(privPEM string) seal.SealerOption {
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
		key, err := x509.ParseECPrivateKey(b)
		if err != nil {
			return errors.Errorf("parse EC private key, %v", err)
		}
		opt.Algorithm = "ecdsa"
		opt.PrivateKey = key
		return nil
	})
}

type implECDSASigner struct {
	pub   *ecdsa.PublicKey
	priv  *ecdsa.PrivateKey
}

func ECDSASigner(opt *seal.SealerOptions) (seal.AsymmetricSigner, error) {
	t := &implECDSASigner{}

	if opt.PublicKey != nil {
		var ok bool
		t.pub, ok = opt.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, errors.Errorf("not a ECDSA public key, %v", reflect.TypeOf(opt.PublicKey))
		}
	}
	if opt.PrivateKey != nil {
		var ok bool
		t.priv, ok = opt.PrivateKey.(*ecdsa.PrivateKey)
		if !ok {
			return nil, errors.Errorf("not a ECDSA private key, %v", reflect.TypeOf(opt.PrivateKey))
		}
	}

	return t, nil
}

func ECDSASignerIssue(bits int) (seal.AsymmetricSigner, error) {
	var c elliptic.Curve
	switch bits {
		case 224:
			c = elliptic.P224()
		case 256:
			c = elliptic.P256()
		case 384:
			c = elliptic.P384()
		case 521:
			c = elliptic.P521()
		default:
			return nil, errors.Errorf("unsupported curve bits %d", bits)
	}

	priv, err := ecdsa.GenerateKey(c, rand.Reader)
	if err != nil {
		return nil, err
	}
	return &implECDSASigner{
		pub: &priv.PublicKey,
		priv: priv,
	}, nil
}

func (t *implECDSASigner) PublicKey() crypto.PublicKey {
	return t.pub
}

func (t *implECDSASigner) PrivateKey() crypto.PrivateKey {
	return t.priv
}

func (t *implECDSASigner) EncodePublicKey() (string, error) {

	if t.pub == nil {
		return "", errors.New("public key is empty")
	}

	pubASN1, err := x509.MarshalPKIXPublicKey(t.pub)
	if err != nil {
		return "", errors.Errorf("marshal PKIX public key, %v", err)
	}

	pubBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PUBLIC KEY",
		Bytes: pubASN1,
	})

	return string(pubBytes), nil
}

func (t *implECDSASigner) EncodePrivateKey() (string, error) {
	if t.priv == nil {
		return "", errors.New("private key is empty")
	}
	data, err := x509.MarshalECPrivateKey(t.priv)
	if err != nil {
		return "", err
	}
	privBytes := pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: data,
		},
	)
	return string(privBytes), nil
}

func (t *implECDSASigner) Sign(plaintext []byte) (sign []byte, err error) {
	if t.priv == nil {
		return nil, errors.New("private key is empty")
	}
	hash := sha512.New()
	hash.Write(plaintext)
	sign, err = ecdsa.SignASN1(rand.Reader, t.priv, hash.Sum(nil))
	return
}

func (t *implECDSASigner) Verify(plaintext, sign []byte) (valid bool, err error) {
	if t.pub == nil {
		return false, errors.New("public key is empty")
	}
	hash := sha512.New()
	hash.Write(plaintext)
	valid = ecdsa.VerifyASN1(t.pub, hash.Sum(nil), sign)
	return
}




