// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

import (
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type (
	Repo   = kanamerepo.Repository
	Reader = kanamerepo.Reader
	Writer = kanamerepo.Writer
)
