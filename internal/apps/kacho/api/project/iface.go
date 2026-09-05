// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package project

// iface.go — re-export CQRS-типов из internal/repo/kacho под коротким именем
// (`Repo` / `Reader` / `Writer`). Parity с account/iface.go.

import (
	kachorepo "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho"
)

type (
	Repo   = kachorepo.Repository
	Reader = kachorepo.Reader
	Writer = kachorepo.Writer
)
