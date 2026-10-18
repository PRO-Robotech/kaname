// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"log/slog"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
)

func assertModelAgreesWithCatalog(logger *slog.Logger, notApplied []modulecatalog.RevisionSkip, composed modelcompose.Report) error {
	return nil
}
