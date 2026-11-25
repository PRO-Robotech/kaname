// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// UpdateExternalMetadataForTest вызывает адаптер с тем же протоколом записи,
// что и будущий публичный обработчик. Экспорт существует только в тестах.
func (p *MetadataMutationWriters) UpdateExternalMetadataForTest(
	ctx context.Context, root domain.ResourceRef, labels, accessLabels domain.Labels, mask []string, actor domain.Subject,
) (domain.ResourceMetadata, error) {
	return p.updateMirrorAccessLabels(ctx, root, labels, accessLabels, mask, actor)
}
