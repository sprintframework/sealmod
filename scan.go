/*
 * Copyright (c) 2023 Zander Schwid & Co. LLC.
 * SPDX-License-Identifier: BUSL-1.1
 */

package sealmod

import (
	"github.com/codeallergy/glue"
	"github.com/sprintframework/seal"
)

type sealScanner struct {
	Scan     []interface{}
}

func SealScanner(scan... interface{}) glue.Scanner {
	return &sealScanner{
		Scan: scan,
	}
}

func (t *sealScanner) Beans() []interface{} {

	beans := []interface{}{
		SealService(),
		&struct {
			SealService []seal.SealService `inject`
		}{},
	}

	return append(beans, t.Scan...)
}

