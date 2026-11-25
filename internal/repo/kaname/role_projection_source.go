// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
)

// RoleProjectionSourceSnapshot описывает ту же строку, для которой полностью
// сверены checkpoint/catalog/projection. Это наблюдение, НЕ held attestation.
// Физические stamps не входят в computational checkpoint и не меняют его hash.
type RoleProjectionSourceSnapshot struct {
	RoleID           domain.RoleID
	Checkpoint       granteffect.ProjectionCheckpoint
	RowXmin, RowCTID string
}

// Не меняет прежний SemanticSourceReader. Optional порт не добавляет reads;
// источник возвращает stamps из своего уже проверяемого apply snapshot.
type RoleProjectionSourceReader interface {
	SemanticSourceReader
	RoleProjectionCheckpointSource(context.Context, domain.RoleID) (RoleProjectionSourceSnapshot, SourceReadCost, error)
}
