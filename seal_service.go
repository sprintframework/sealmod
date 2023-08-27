/*
 * Copyright (c) 2023 Zander Schwid & Co. LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package sealmod

import (
	"crypto/aes"
	"crypto/cipher"
	"github.com/sprintframework/seal"
	"github.com/pkg/errors"
	"strings"
)

// OptionFunc implements SealerOption interface.
type sealerOptionFunc func(*seal.SealerOptions) error

// apply the configuration to the provided config.
func (fn sealerOptionFunc) Apply(opt *seal.SealerOptions) error {
	return fn(opt)
}

func WithSealer(algorithm string) seal.SealerOption {
	return sealerOptionFunc(func(opt *seal.SealerOptions) error {
		opt.Algorithm = algorithm
		return nil
	})
}

// OptionFunc implements CipherOption interface.
type cipherOptionFunc func(*seal.CipherOptions) error

// apply the configuration to the provided config.
func (fn cipherOptionFunc) Apply(opt *seal.CipherOptions) error {
	return fn(opt)
}

func WithCipher(algorithm string) seal.CipherOption {
	return cipherOptionFunc(func(opt *seal.CipherOptions) error {
		opt.Algorithm = algorithm
		return nil
	})
}

func WithBlock(block cipher.Block) seal.CipherOption {
	return cipherOptionFunc(func(opt *seal.CipherOptions) error {
		opt.Block = block
		return nil
	})
}

func WithAESKey(key []byte) seal.CipherOption {
	return cipherOptionFunc(func(opt *seal.CipherOptions) (err error) {
		opt.Block, err = aes.NewCipher(key)
		return
	})
}

type implSealService struct {
}

func SealService() seal.SealService {
	return &implSealService{}
}

func (t *implSealService) IssueSealer(algorithm string, bits int) (seal.AsymmetricSealer, error) {

	switch strings.ToUpper(algorithm) {
	case "RSA":
		return RSASealerIssue(bits)
	case "BOX":
		return BOXIssue()
	default:
		return nil, errors.Errorf("unsupported algorithm '%s'", algorithm)
	}

}

func (t *implSealService) Sealer(options ...seal.SealerOption) (seal.AsymmetricSealer, error) {

	opt := new(seal.SealerOptions)

	for _, o := range options {
		o.Apply(opt)
	}

	switch strings.ToUpper(opt.Algorithm) {
	case "RSA":
		return RSASealer(opt)
	case "BOX":
		return BOXSealer(opt)
	default:
		return nil, errors.Errorf("unsupported algorithm '%s'", opt.Algorithm)
	}

}

func (t *implSealService) IssueSigner(algorithm string, bits int) (seal.AsymmetricSigner, error) {

	switch strings.ToUpper(algorithm) {
	case "RSA":
		return RSASignerIssue(bits)
	case "EC":
		return ECDSASignerIssue(bits)
	default:
		return nil, errors.Errorf("unsupported algorithm '%s'", algorithm)
	}

}

func (t *implSealService) Signer(options ...seal.SealerOption) (seal.AsymmetricSigner, error) {

	opt := new(seal.SealerOptions)

	for _, o := range options {
		o.Apply(opt)
	}

	switch strings.ToUpper(opt.Algorithm) {
	case "RSA":
		return RSASigner(opt)
	case "EC":
		return ECDSASigner(opt)
	default:
		return nil, errors.Errorf("unsupported algorithm '%s'", opt.Algorithm)
	}

}

func (t *implSealService) AuthenticatedCipher(options ...seal.CipherOption) (seal.AuthenticatedCipher, error) {

	opt := new(seal.CipherOptions)

	for _, o := range options {
		o.Apply(opt)
	}

	switch strings.ToUpper(opt.Algorithm) {
	case "GCM":
		return GCMCipher(opt)
	default:
		return nil, errors.Errorf("unsupported algorithm '%s'", opt.Algorithm)
	}

}
