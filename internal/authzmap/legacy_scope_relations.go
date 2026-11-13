// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmap

import "strings"

// LegacyScopeTierRelations — прежняя эмиссия яруса роли без rules на якорь
// выдачи. У аккаунта ярус выводится только из прав, называющих сам аккаунт;
// иначе общий admin понижается до editor, чтобы узкое право не стало каскадом.
// Тот же производитель используют кортежи выдачи и компилятор её эффекта.
func LegacyScopeTierRelations(scopeType string, permissions []string) []Relation {
	relations := PermissionsToRelations(permissions)
	const accountAnchor = "account"
	if strings.ToLower(scopeType) != accountAnchor {
		return relations
	}
	if covering := PermissionsCoveringType(permissions, accountAnchor); len(covering) > 0 {
		// Ярус определяют только права, называющие аккаунт, а не прочие права роли.
		return PermissionsToRelations(covering)
	}
	out := make([]Relation, 0, len(relations))
	for _, r := range relations {
		if r == "admin" {
			r = "editor"
		}
		out = append(out, r)
	}
	return out
}

// ScopeDirectRelations переводит ярус в прямое отношение типа области.
// У cluster admin/editor пишутся как system_admin, viewer — system_viewer;
// результат там дедуплицируется. У прочих областей отношения не меняются.
func ScopeDirectRelations(scopeType string, rels []Relation) []Relation {
	if strings.ToLower(scopeType) != "cluster" {
		return rels
	}
	if len(rels) == 0 {
		return rels
	}
	seen := make(map[Relation]struct{}, len(rels))
	out := make([]Relation, 0, len(rels))
	for _, r := range rels {
		mapped := r
		switch r {
		case "admin", "editor":
			mapped = "system_admin"
		case "viewer":
			mapped = "system_viewer"
		}
		if _, dup := seen[mapped]; dup {
			continue
		}
		seen[mapped] = struct{}{}
		out = append(out, mapped)
	}
	return out
}
