// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"encoding/json"
	"slices"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Те же live и stored-selector факты, что читает loadRolesWithLifecycleMode.
// Отсутствующий live не становится объявленной ролью; проекция селекторов
// выбирает сохранённую раскладку, а не подменяет канонические rules.
func resourceCapturedMaterializingRole(raw json.RawMessage, selectors []resourceSourceRow) (domain.Role, error) {
	role, err := resourceCapturedRole(raw)
	if err != nil {
		return domain.Role{}, err
	}
	var row struct {
		Live *bool `json:"live"`
	}
	if err = json.Unmarshal(raw, &row); err != nil {
		return domain.Role{}, err
	}
	if row.Live == nil {
		return domain.Role{}, kaname.ErrSourceUnconfirmed
	}
	if len(selectors) > 4096 {
		return domain.Role{}, kaname.ErrSourceReadLimit
	}
	var fingerprints []string
	for _, selector := range selectors {
		var projection struct {
			RoleID string `json:"role_id"`
			RuleFP string `json:"rule_fp"`
		}
		if err = json.Unmarshal(selector.value, &projection); err != nil {
			return domain.Role{}, err
		}
		if projection.RoleID != string(role.ID) || projection.RuleFP == "" {
			return domain.Role{}, kaname.ErrSourceUnconfirmed
		}
		fingerprints = append(fingerprints, projection.RuleFP)
	}
	role.Rules = domain.RulesForStoredSelectorLayout(role.Rules, fingerprints)
	role.Lifecycle.State = domain.RoleLifecycleWithdrawn
	if *row.Live {
		role.Lifecycle.State = domain.RoleLifecycleDeclared
	}
	return role, nil
}

func resourceCapturedSubjects(binding domain.AccessBinding, rows []resourceSourceRow) ([]domain.Subject, error) {
	type capturedSubject struct {
		BindingID string             `json:"binding_id"`
		Type      domain.SubjectType `json:"subject_type"`
		ID        domain.SubjectID   `json:"subject_id"`
		Ordinal   int                `json:"ordinal"`
	}
	subjects, err := resourceDecodeRows[capturedSubject](rows)
	if err != nil {
		return nil, err
	}
	slices.SortFunc(subjects, func(a, b capturedSubject) int {
		if a.Ordinal < b.Ordinal {
			return -1
		}
		if a.Ordinal > b.Ordinal {
			return 1
		}
		return 0
	})
	var out []domain.Subject
	seen := make(map[domain.Subject]bool, len(subjects))
	for _, row := range subjects {
		subject := domain.Subject{Type: row.Type, ID: row.ID}
		if row.BindingID != string(binding.ID) || row.Ordinal < 0 || seen[subject] {
			return nil, kaname.ErrSourceUnconfirmed
		}
		seen[subject] = true
		out = append(out, subject)
	}
	// Исторический первый субъект строки остаётся fallback только при доказанно
	// пустой таблице subjects, как в действующем bindingSubjects.
	return domain.NormalizeSubjects(out, binding.SubjectType, binding.SubjectID)
}
