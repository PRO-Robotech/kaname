// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

import (
	"slices"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RejectAccessLabelsWrite закрывает путь, пока обработчик не подключён к
// защищённой записи. Явная маска учитывает очистку с пустым proto3 map.
func RejectAccessLabelsWrite(labels map[string]string, mask []string) error {
	if len(labels) > 0 || AccessLabelsMaskRequested(mask) {
		return status.Error(codes.FailedPrecondition, "Protected accessLabels writer unavailable")
	}
	return nil
}

// AccessLabelsMaskRequested учитывает явную маску и оба имени из API.
func AccessLabelsMaskRequested(mask []string) bool {
	return maskContains(mask, "access_labels") || maskContains(mask, "accessLabels")
}

// ResolveAccessLabelsUpdate использует явную маску для очистки карты. После
// нормализации переписывается только имя поля, порядок маски сохраняется.
func ResolveAccessLabelsUpdate(mask []string, body domain.Labels) ([]string, domain.Labels, bool) {
	if AccessLabelsMaskRequested(mask) {
		if slices.Contains(mask, "accessLabels") {
			mask = slices.Clone(mask)
			for i := range mask {
				if mask[i] == "accessLabels" {
					mask[i] = "access_labels"
				}
			}
		}
		if body == nil {
			body = domain.Labels{}
		}
		return mask, body, true
	}
	return mask, body, len(mask) == 0 && body != nil
}
