// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service_account

import (
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
)

type (
	Repo   = kachorepo.Repository
	Reader = kachorepo.Reader
	Writer = kachorepo.Writer
)
