// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict

import (
	"encoding/json"
	"strings"
)

// Описание зависит от точного question. Само по себе оно не является proof;
// pg coordinator передаёт его лишь после защиты полного плана источников.
type AdministrativeScope struct {
	Type  string `json:"s_type"`
	ID    string `json:"s_id"`
	Depth int    `json:"depth"`
}
type AdministrativeReadBoundary interface {
	NativeScopes(subject, typ, id, relation string) ([]AdministrativeScope, bool, error)
}

func (a *AdministrativeAsker) BindReadBoundary(boundary AdministrativeReadBoundary, budget *AdministrativeReadBudget) {
	// Даже nil binding включает fail-closed режим; нет возврата к broad query.
	a.bound, a.boundary, a.budget = true, boundary, budget
}

// Оба native arm соединяются только с scope_distinct. Для локального writer
// полностью убираем рекурсивное чтение новых рёбер до выполнения SQL, а не
// фильтруем уже полученные факты. Условия, speakers, selectors и TTL прежние.
func capturedAdministrativeSQL(sql, typ, id string, scopes []AdministrativeScope) (string, []byte, error) {
	if len(scopes) == 0 {
		return "", nil, ErrAdministrativeSourceUnconfirmed
	}
	seen := map[[2]string]bool{}
	root := false
	for _, scope := range scopes {
		key := [2]string{scope.Type, scope.ID}
		if scope.Type == "" || scope.ID == "" || seen[key] || scope.Depth < 0 {
			return "", nil, ErrAdministrativeSourceUnconfirmed
		}
		seen[key] = true
		if scope.Type == typ && scope.ID == id {
			if scope.Depth != 0 {
				return "", nil, ErrAdministrativeSourceUnconfirmed
			}
			root = true
		} else if scope.Depth == 0 {
			return "", nil, ErrAdministrativeSourceUnconfirmed
		}
	}
	if !root {
		return "", nil, ErrAdministrativeSourceUnconfirmed
	}
	start := strings.Index(sql, "scope(s_type, s_id, depth) AS (")
	marker := "scope_distinct(s_type, s_id, depth) AS (\n    SELECT s_type, s_id, min(depth) FROM scope GROUP BY s_type, s_id\n),"
	end := strings.Index(sql, marker)
	if start < 0 || end < start || strings.Count(sql, marker) != 1 {
		return "", nil, ErrAdministrativeSourceUnconfirmed
	}
	raw, err := json.Marshal(scopes)
	if err != nil {
		return "", nil, err
	}
	// После удаления recursive CTE сохраняем типы всех старых параметров:
	// они остаются частью prepared query даже при модели без grant atoms.
	replacement := "scope_distinct(s_type, s_id, depth) AS (SELECT s_type,s_id,depth FROM jsonb_to_recordset($20::jsonb) AS captured(s_type text,s_id text,depth int) WHERE $2::text<>'' AND $3::text<>'' AND $7::int>0 AND $12::int>0),"
	return sql[:start] + replacement + sql[end+len(marker):], raw, nil
}
