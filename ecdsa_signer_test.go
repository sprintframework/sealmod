/*
 * Copyright (c) 2023 Zander Schwid & Co. LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package sealmod_test

import (
	"github.com/sprintframework/sealmod"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestECDSASigner(t *testing.T) {

	text := "Hello World"
	plaintext := []byte(text)

	ss := sealmod.SealService()
	alice, err := ss.IssueSigner("EC", 256)
	require.NoError(t, err)

	sign, err := alice.Sign(plaintext)
	require.NoError(t, err)

	valid, err := alice.Verify(plaintext, sign)
	require.NoError(t, err)

	require.True(t, valid)
}







