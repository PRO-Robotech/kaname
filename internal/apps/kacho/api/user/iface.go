// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// iface.go — re-export CQRS-типов под коротким именем (parity с account/iface.go).

import (
	kachorepo "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho"
)

type (
	Repo   = kachorepo.Repository
	Reader = kachorepo.Reader
	Writer = kachorepo.Writer
)
