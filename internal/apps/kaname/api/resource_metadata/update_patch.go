// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package resource_metadata

import (
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Неотмеченная карта остаётся nil; отмеченная пустая карта означает очистку.
func parseMetadataPatch(patch *iamv1.ResourceMetadataPatch) (domain.Labels, domain.Labels, []string, error) {
	mask := patch.GetUpdateMask().GetPaths()
	var labels, access domain.Labels
	// Нормализуем proto3 map: отсутствие и пустая карта без маски эквивалентны.
	if len(patch.GetLabels()) != 0 {
		labels = make(domain.Labels, len(patch.GetLabels()))
		for key, value := range patch.GetLabels() {
			labels[domain.LabelKey(key)] = domain.LabelVal(value)
		}
	}
	if len(patch.GetAccessLabels()) != 0 {
		access = make(domain.Labels, len(patch.GetAccessLabels()))
		for key, value := range patch.GetAccessLabels() {
			access[domain.LabelKey(key)] = domain.LabelVal(value)
		}
	}
	mask, access, applyAccess := shared.ResolveAccessLabelsUpdate(mask, access)
	if err := shared.ValidateUpdateMask(mask, map[string]struct{}{"labels": {}, "access_labels": {}}, nil); err != nil {
		return nil, nil, nil, err
	}
	labels, _ = shared.ResolveLabelsUpdate(mask, labels)
	if !applyAccess {
		access = nil
	}
	if err := labels.Validate(); err != nil {
		return nil, nil, nil, err
	}
	if err := access.Validate(); err != nil {
		return nil, nil, nil, err
	}
	return labels, access, mask, nil
}
