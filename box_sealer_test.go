/*
 * Copyright (c) 2023 Zander Schwid & Co. LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package sealmod_test

import (
	"bytes"
	"crypto/rand"
	"github.com/codeallergy/sealmod"
	"github.com/stretchr/testify/require"
	"io"
	"testing"
)

func TestBOXSealer(t *testing.T) {

	key := make([]byte, 32)
	_, err := io.ReadFull(rand.Reader, key)
	require.NoError(t, err)

	text := "Hello World"
	plaintext := []byte(text)

	ss := sealmod.SealService()
	// box do not need key length, always 256 bit
	alice, err := ss.IssueSealer("BOX", 0)
	require.NoError(t, err)

	bob, err := ss.IssueSealer("BOX", 0)
	require.NoError(t, err)

	ciphertext, err := alice.Seal(plaintext, bob.PublicKey())
	require.NoError(t, err)

	actual, err := bob.Open(ciphertext, alice.PublicKey())
	require.NoError(t, err)

	require.True(t, bytes.Equal(plaintext, actual))
}
