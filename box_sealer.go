/*
 * Copyright (c) 2023 Zander Schwid & Co. LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package sealmod

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"github.com/codeallergy/seal"
	"github.com/pkg/errors"
	"golang.org/x/crypto/nacl/box"
	"io"
	"reflect"
)

func WithBoxPublicKey(pub *[32]byte) seal.SealerOption {
	return sealerOptionFunc(func(opt *seal.SealerOptions) error {
		opt.Algorithm = "box"
		opt.PublicKey = pub
		return nil
	})
}

func WithEncodedBoxPublicKey(pubRawURLBase64 string) seal.SealerOption {
	return sealerOptionFunc(func(opt *seal.SealerOptions) error {
		data, err := base64.RawURLEncoding.DecodeString(pubRawURLBase64)
		if err != nil {
			return err
		}
		opt.Algorithm = "box"
		if len(data) != 32 {
			return errors.Errorf("invalid key length %d", len(data))
		}
		var key [32]byte
		copy(key[:], data)
		opt.PublicKey = &key
		return nil
	})
}

func WithBoxPrivateKey(priv *[32]byte) seal.SealerOption {
	return sealerOptionFunc(func(opt *seal.SealerOptions) error {
		opt.Algorithm = "box"
		opt.PrivateKey = priv
		return nil
	})
}

func WithEncodedBoxPrivateKey(privRawURLBase64 string) seal.SealerOption {
	return sealerOptionFunc(func(opt *seal.SealerOptions) error {
		data, err := base64.RawURLEncoding.DecodeString(privRawURLBase64)
		if err != nil {
			return err
		}
		opt.Algorithm = "box"
		if len(data) != 32 {
			return errors.Errorf("invalid key length %d", len(data))
		}
		var key [32]byte
		copy(key[:], data)
		opt.PrivateKey = &key
		return nil
	})
}

type implBOXSealer struct {
	pub   *[32]byte
	priv  *[32]byte
}

func BOXSealer(opt *seal.SealerOptions) (seal.AsymmetricSealer, error) {
	t := &implBOXSealer{}

	if opt.PublicKey != nil {
		var ok bool
		t.pub, ok = opt.PublicKey.(*[32]byte)
		if !ok {
			return nil, errors.Errorf("not *[32]byte nacl box public key, %v", reflect.TypeOf(opt.PublicKey))
		}
	}
	if opt.PrivateKey != nil {
		var ok bool
		t.priv, ok = opt.PrivateKey.(*[32]byte)
		if !ok {
			return nil, errors.Errorf("not *[32]byte nacl box private key, %v", reflect.TypeOf(opt.PrivateKey))
		}
	}

	return t, nil
}

func BOXIssue() (seal.AsymmetricSealer, error)  {
	pub, priv, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &implBOXSealer {
		pub: pub,
		priv: priv,
	}, nil
}

func (t *implBOXSealer) PublicKey() crypto.PublicKey {
	return t.pub
}

func (t *implBOXSealer) PrivateKey() crypto.PrivateKey {
	return t.priv
}

func (t *implBOXSealer) EncodePublicKey() (string, error) {
	if t.pub == nil {
		return "", errors.New("public key is empty")
	}
	return  base64.RawURLEncoding.EncodeToString(t.pub[:]), nil
}

func (t *implBOXSealer) EncodePrivateKey() (string, error) {
	if t.priv == nil {
		return "", errors.New("private key is empty")
	}
	return base64.RawURLEncoding.EncodeToString(t.priv[:]), nil
}

func (t *implBOXSealer) Seal(plaintext []byte, recipient crypto.PublicKey) (ciphertext []byte, err error) {
	pub, ok := recipient.(*[32]byte)
	if !ok {
		return nil, errors.Errorf("not *[32]byte nacl box public key, %v", reflect.TypeOf(recipient))
	}
	var nonce [24]byte
	_, err = io.ReadFull(rand.Reader, nonce[:])
	if err != nil {
		return nil, err
	}
	ciphertext = box.Seal(nonce[:], plaintext, &nonce, pub, t.priv)
	return ciphertext, nil
}

func (t *implBOXSealer) Open(ciphertext []byte, sender crypto.PublicKey) (plaintext []byte, err error) {
	pub, ok := sender.(*[32]byte)
	if !ok {
		return nil, errors.Errorf("not *[32]byte nacl box sender public key, %v", reflect.TypeOf(sender))
	}

	if len(ciphertext) < 24 {
		return nil, errors.Errorf("ciphertext len %d is less than nacl box nonce size %d", len(ciphertext), 24)
	}

	var decryptNonce [24]byte
	copy(decryptNonce[:], ciphertext[:24])

	plaintext, ok = box.Open(nil, ciphertext[24:], &decryptNonce, pub, t.priv)
	if !ok {
		return nil, errors.New("unseal nacl box error")
	}
	return plaintext, nil

}
