// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Наблюдение точной физической строки, НЕ разрешение и не preclock custody.
type AccessLabelBindingSourceSnapshot struct {
	BindingID         domain.AccessBindingID
	RoleID            domain.RoleID
	CapabilityVersion int
	RowXmin, RowCTID  string
}

// Реализация принадлежит writer; данные не предоставляют constructor proof.
// Validate сверяет попытку и полный исходный header/subjects/version без SQL.
type CapturedAccessLabelBindingSource interface {
	Snapshot() AccessLabelBindingSourceSnapshot
	Validate(SemanticAuthorityWriter, domain.Subject, time.Time, domain.AccessBinding, int) error
}

type AccessLabelBindingSourceReader interface {
	SemanticSourceReader
	AccessLabelBindingSourcesEnabled() bool
	CaptureAccessLabelBindingSource(context.Context, domain.Subject, time.Time, domain.AccessBinding, int) (CapturedAccessLabelBindingSource, SourceReadCost, error)
}
