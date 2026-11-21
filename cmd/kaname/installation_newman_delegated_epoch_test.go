// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Политика физических последствий задаёт координаты из запроса и независимо
// выведенных кортежей. Множество допустимых ключей не берётся из дельты БД.
func (p rid03DeltaPolicy) epochKeys() (policy, binding map[string]bool) {
	policy = map[string]bool{"scope:" + p.Account: true}
	binding = map[string]bool{}
	if p.Path == "/iam/v1/grantDelegations" {
		policy["service_account:"+p.GDDelegate] = true
		policy["service_account:"+p.Creator] = true
		return policy, binding
	}
	policy["carriers:role:"+p.Role] = true
	policy[p.SubjectType+":"+p.SubjectID] = true
	if p.SubjectType == "system_class" {
		policy["*"] = true
	}
	for tuple := range p.DirectTuples {
		kind, id, ok := strings.Cut(tuple.Subject, ":")
		switch {
		case ok && id != "" && !strings.ContainsAny(id, "#*") && (kind == "user" || kind == "service_account"):
			policy[tuple.Subject] = true
		case ok && (kind == "group" || kind == "iam_group") && strings.HasSuffix(id, "#member"):
			group := strings.TrimSuffix(id, "#member")
			if group != "" && !strings.ContainsAny(group, "#*") {
				policy["group:"+group] = true
			} else {
				policy["*"] = true
			}
		case ok && id != "" && !strings.ContainsAny(id, "#*") && (kind == "account" || kind == "project" || kind == "cluster"):
			// Отношение иерархии меняет область объекта, уже учтённую выше.
		default:
			policy["*"] = true
		}
	}
	binding[p.Account] = true
	if p.GlobalBindingEpoch {
		binding[""] = true
	}
	return policy, binding
}

// rid03EpochTransitionValid допускает только рост revision у доказанных
// координат. Один запрос может вызвать несколько invalidation statements,
// поэтому число приращений не фиксировано. Смена generation, добавление
// или исчезновение ключа, дубликат и любой побочный ключ дают отказ.
func rid03EpochTransitionValid(before, after []rid09PrimaryRow, keyName string, expected map[string]bool) bool {
	if len(before) != len(after) {
		return false
	}
	oldByKey := make(map[string]rid09PrimaryRow, len(before))
	for _, row := range before {
		key, ok := rid03Cell[string](row, keyName)
		if !ok || !rid03SameCell(row, keyName, key) || oldByKey[key] != nil || !rid03Columns(row, keyName+" generation revision") {
			return false
		}
		oldByKey[key] = row
	}
	changes := 0
	for _, row := range after {
		key, ok := rid03Cell[string](row, keyName)
		old, exists := oldByKey[key]
		if !ok || !rid03SameCell(row, keyName, key) || !exists || !rid03Columns(row, keyName+" generation revision") {
			return false
		}
		delete(oldByKey, key)
		if !expected[key] {
			if !reflect.DeepEqual(old, row) {
				return false
			}
			continue
		}
		a, aOK := rid03Cell[int64](old, "revision")
		b, bOK := rid03Cell[int64](row, "revision")
		generation, gOK := rid03Cell[string](old, "generation")
		if !aOK || !bOK || a < 0 || b <= a || !gOK || generation == "" || !rid03SameCell(row, "generation", generation) {
			return false
		}
		changes++
	}
	return changes == len(expected)
}

func TestRID03EpochTransitionIsClosed(t *testing.T) {
	row := func(key, generation string, revision int64) rid09PrimaryRow {
		t.Helper()
		fields := map[string]any{"key": key, "generation": generation, "revision": revision}
		value := rid09PrimaryRow{}
		for name, item := range fields {
			encoded, err := json.Marshal(item)
			require.NoError(t, err)
			value[name] = encoded
		}
		return value
	}
	before := []rid09PrimaryRow{row("scope:tenant", "42", 5), row("*", "18", 3)}
	expected := map[string]bool{"scope:tenant": true}
	require.True(t, rid03EpochTransitionValid(before, []rid09PrimaryRow{before[1], row("scope:tenant", "42", 9)}, "key", expected))
	for _, rejected := range [][]rid09PrimaryRow{
		before,
		{before[1], row("scope:tenant", "42", 4)},
		{before[1], row("scope:tenant", "43", 9)},
		{row("*", "18", 4), row("scope:tenant", "42", 9)},
		{before[1], row("scope:other", "42", 9)},
		{before[1], before[1]},
	} {
		require.False(t, rid03EpochTransitionValid(before, rejected, "key", expected))
	}
}
