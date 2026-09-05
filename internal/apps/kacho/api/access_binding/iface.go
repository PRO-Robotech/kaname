// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

import (
	kachorepo "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho"
)

type (
	Repo   = kachorepo.Repository
	Reader = kachorepo.Reader
	Writer = kachorepo.Writer
)
