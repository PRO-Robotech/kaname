// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package user

// iface.go — re-export CQRS-типов под коротким именем (parity с account/iface.go).

import (
	kachorepo "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho"
)

type (
	Repo   = kachorepo.Repository
	Reader = kachorepo.Reader
	Writer = kachorepo.Writer
)
