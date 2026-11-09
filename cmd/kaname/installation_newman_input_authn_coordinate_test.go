// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"io"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/stretchr/testify/require"
)

// Только наблюдение: без вызовов сравнения, SQL, записей, проверок, повторов
// или расширения полномочий. Не разрешённые явно значения — только хеш, тип и null.
// Первичные ключи: initial.sql и ключ координаты члена из 20261021081500.
var rid11CoordinateKeys = map[string][]string{
	"access_binding_target_members": {"binding_id", "role_id", "rule_fp", "object_type", "object_id"},
	"access_binding_emitted_tuples": {"binding_id", "member_object_type", "member_object_id", "fga_user", "relation", "object"},
	"fga_outbox":                    {"id"},
	"relation_fact":                 {"object_type", "object_id", "relation", "subject"},
	"role_rule_selectors":           {"role_id", "rule_fp"},
	"role_verb":                     {"role_id", "object_type", "verb"},
}

type rid11CoordinateCell struct {
	Type   string `json:"type"`
	SHA256 string `json:"sha256"`
	Null   bool   `json:"null"`
	Safe   any    `json:"safe,omitempty"`
}
type rid11CoordinateRow struct {
	KeySHA256 string                         `json:"keySHA256"`
	KeyValid  bool                           `json:"keyValid"`
	RowSHA256 string                         `json:"rowSHA256"`
	Fields    map[string]rid11CoordinateCell `json:"fields"`
}
type rid11CoordinatePair struct{ Before, After rid11CoordinateRow }
type rid11CoordinateDiff struct {
	BeforeCount, AfterCount, UnchangedCount int
	BeforeSHA256, AfterSHA256               string
	Added, Removed                          []rid11CoordinateRow
	Changed                                 []rid11CoordinatePair
	InvalidBefore, InvalidAfter             []rid11CoordinateRow
	DuplicateBeforeKeys, DuplicateAfterKeys []string
}
type rid11CoordinateKnown struct{ IDs, Types, Names, Relations map[string]bool }

var rid11CoordinateID = regexp.MustCompile(`^(acc|prj|usr|sva|grp|rol|acb|gdl)[A-Za-z0-9_-]{4,80}$`)
var rid11CoordinateToken = regexp.MustCompile(`^[a-z][a-zA-Z0-9_-]{0,63}$`)
var rid11CoordinateFP = regexp.MustCompile(`^[a-f0-9]{64}$`)

func rid11CoordinateType(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case bool:
		return "boolean"
	case json.Number:
		return "number"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	default:
		return "invalid"
	}
}
func rid11CoordinateDecode(raw json.RawMessage) (any, bool) {
	d := json.NewDecoder(strings.NewReader(string(raw)))
	d.UseNumber()
	var v any
	if d.Decode(&v) != nil {
		return nil, false
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, false
	}
	return v, true
}
func rid11CoordinateName(s string) string {
	if rid11CoordinateToken.MatchString(s) {
		return s
	}
	return "name-sha256-" + rid03EvidenceHash(s)
}
func rid11CoordinateKnownBefore(a rid03NewmanSnapshot) rid11CoordinateKnown {
	k := rid11CoordinateKnown{IDs: map[string]bool{"cluster_root": true}, Types: map[string]bool{}, Names: map[string]bool{"*": true}, Relations: map[string]bool{}}
	for _, table := range []string{"accounts", "projects", "users", "service_accounts", "groups", "roles", "access_bindings", "grant_delegations"} {
		for _, r := range a.Raw[table] {
			id := rid03S(r, "id")
			if rid11CoordinateID.MatchString(id) {
				k.IDs[id] = true
			}
		}
	}
	for _, typ := range []string{"account", "project", "cluster", "user", "service_account", "group", "iam.account", "iam.project", "iam.cluster", "iam.user", "iam.serviceAccount", "iam.group", "iam.role", "iam.accessBinding", "iam.grantDelegation"} {
		k.Types[typ] = true
	}
	for _, r := range a.Raw["catalog_resource"] {
		m, res, model := rid03S(r, "module"), rid03S(r, "resource"), rid03S(r, "object_type")
		if rid11CoordinateToken.MatchString(m) && rid11CoordinateToken.MatchString(res) {
			k.Types[m+"."+res] = true
			k.Names[m] = true
			k.Names[res] = true
		}
		if rid11CoordinateToken.MatchString(model) {
			k.Types[model] = true
		}
	}
	for _, r := range a.Raw["catalog_module"] {
		s := rid03S(r, "module")
		if rid11CoordinateToken.MatchString(s) {
			k.Names[s] = true
		}
	}
	for _, r := range a.Raw["catalog_verb"] {
		s := rid03S(r, "verb")
		if rid11CoordinateToken.MatchString(s) {
			k.Names[s] = true
			k.Relations["v_"+s] = true
		}
	}
	for _, s := range []string{"viewer", "editor", "admin", "owner", "reader", "writer", "account", "project", "parent", "subject", "super_admin", "member", "public_reader"} {
		k.Relations[s] = true
	}
	return k
}
func (k rid11CoordinateKnown) ref(s string) bool {
	if s == "" {
		return false
	}
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 {
		return false
	}
	kind, id := parts[0], parts[1]
	if kind == "system_class" {
		return id == "anonymous" || id == "authenticated"
	}
	if !k.Types[kind] {
		return false
	}
	if kind == "group" && strings.HasSuffix(id, "#member") {
		id = strings.TrimSuffix(id, "#member")
	}
	return k.IDs[id]
}
func rid11CoordinateScalar(k rid11CoordinateKnown, field string, v any) (any, bool) {
	switch field {
	case "id":
		if n, ok := v.(json.Number); ok {
			if x, e := n.Int64(); e == nil && x > 0 {
				return x, true
			}
		}
		if s, ok := v.(string); ok && k.IDs[s] {
			return s, true
		}
	case "scope", "ordinal":
		if n, ok := v.(json.Number); ok {
			if x, e := n.Int64(); e == nil && x >= 0 && x <= 1024 {
				return x, true
			}
		}
	case "live", "is_system", "enabled", "created_by_subject", "deletion_protection", "per_object", "public_read_to_children", "permanent_project":
		if b, ok := v.(bool); ok {
			return b, true
		}
	case "created_at", "updated_at", "source_version", "enqueued_at", "expires_at", "revoked_at", "narrowed_at", "retired_at", "added_at":
		if v == nil {
			return nil, true
		}
		if s, ok := v.(string); ok {
			if t, e := time.Parse(time.RFC3339Nano, s); e == nil && !t.IsZero() {
				return t, true
			}
		}
	case "binding_id", "role_id", "object_id", "subject_id", "member_object_id", "account_id", "project_id", "resource_id", "parent_account_id", "parent_project_id", "parent_id", "owner_user_id", "delegate_id", "active_delegate_id", "delegation_id", "granted_by_user_id", "created_by_id", "user_id", "member_id", "group_id":
		if s, ok := v.(string); ok && (s == "" || k.IDs[s]) {
			return s, true
		}
	case "object_type", "member_object_type", "resource_type", "parent_type", "container_type", "container_object_type":
		if s, ok := v.(string); ok && (s == "" || k.Types[s]) {
			return s, true
		}
	case "rule_fp":
		if s, ok := v.(string); ok && (rid11CoordinateFP.MatchString(s) || s == "scope_self") {
			return s, true
		}
	case "relation", "parent_relation", "verb":
		if s, ok := v.(string); ok && (k.Relations[s] || k.Names[s]) {
			return s, true
		}
	case "subject", "fga_user", "object":
		if s, ok := v.(string); ok && k.ref(s) {
			return s, true
		}
	case "subject_type", "created_by_type", "member_type":
		if s, ok := v.(string); ok && (s == "user" || s == "service_account" || s == "group" || s == "system_class" || s == "") {
			return s, true
		}
	case "source":
		if s, ok := v.(string); ok && (s == "member" || s == "binding") {
			return s, true
		}
	case "verification_status", "status":
		if s, ok := v.(string); ok && (s == "ACTIVE" || s == "REVOKED" || s == "PENDING_VERIFICATION" || s == "REJECTED" || s == "PENDING" || s == "SENT") {
			return s, true
		}
	case "arm", "container_arm":
		if s, ok := v.(string); ok && (s == "anchor" || s == "names" || s == "labels") {
			return s, true
		}
	case "module", "resource", "owner_module":
		if s, ok := v.(string); ok && (s == "" || k.Names[s]) {
			return s, true
		}
	case "event_type":
		if s, ok := v.(string); ok && (s == "fga.tuple.write" || s == "fga.tuple.delete") {
			return s, true
		}
	case "name":
		if s, ok := v.(string); ok {
			switch s {
			case "rid-public-issuer", "kacho-registry", "rid-public-readers", "module-relation-writers", "owner", "admin", "viewer", "editor":
				return s, true
			}
		}
	case "condition_name":
		if s, ok := v.(string); ok && s == "" {
			return s, true
		}
	}
	return nil, false
}
func rid11CoordinatePayload(k rid11CoordinateKnown, v any, event string) any {
	m, ok := v.(map[string]any)
	if !ok {
		return map[string]any{"closedShape": false}
	}
	keys := []string{}
	types := map[string]string{}
	for key, x := range m {
		safeKey := rid11CoordinateName(key)
		keys = append(keys, safeKey)
		types[safeKey] = rid11CoordinateType(x)
	}
	sort.Strings(keys)
	unknown := map[string]any{"closedShape": false, "keys": keys, "types": types, "sha256": rid03EvidenceHash(m)}
	user, u := m["user"].(string)
	object, o := m["object"].(string)
	if !u || !o || !k.ref(user) || !k.ref(object) {
		return unknown
	}
	relations := []string{}
	echo, hasEcho := m["relation"].(string)
	if r, has := m["relations"]; has {
		a, ok := r.([]any)
		if !ok || len(a) < 2 || len(a) > 128 {
			return unknown
		}
		for _, v := range a {
			s, ok := v.(string)
			if !ok || !k.Relations[s] {
				return unknown
			}
			relations = append(relations, s)
		}
		if !sort.StringsAreSorted(relations) {
			return unknown
		}
		for i := 1; i < len(relations); i++ {
			if relations[i] == relations[i-1] {
				return unknown
			}
		}
		if event == "fga.tuple.write" {
			if len(m) != 4 || !hasEcho || echo != relations[0] {
				return unknown
			}
		} else if event == "fga.tuple.delete" {
			if len(m) != 3 || hasEcho {
				return unknown
			}
		} else {
			return unknown
		}
	} else {
		if len(m) != 3 || !hasEcho || !k.Relations[echo] || (event != "fga.tuple.write" && event != "fga.tuple.delete") {
			return unknown
		}
		relations = []string{echo}
	}
	return map[string]any{"closedShape": true, "user": user, "object": object, "relations": relations, "scalarEcho": echo}
}

// Вывод безопасного значения разрешается для конкретных таблицы И колонки.
// Новая колонка с именем известного поля другой таблицы остаётся только хешем.
func rid11CoordinateFieldAllowed(table, field string) bool {
	schemas := map[string]string{
		"access_binding_target_members": "binding_id role_id rule_fp object_type object_id verification_status live created_at updated_at",
		"access_binding_emitted_tuples": "binding_id member_object_type member_object_id fga_user relation object source",
		"fga_outbox":                    "id event_type created_at payload",
		"relation_fact":                 "object_type object_id relation subject source_version created_at condition_name condition_params",
		"role_rule_selectors":           "role_id rule_fp object_types match_labels created_at updated_at arm resource_names live container_type container_object_type container_arm container_resource_names container_match_labels verbs_by_type created_by_subject",
		"role_verb":                     "role_id object_type verb live",
		"access_bindings":               "id subject_type subject_id role_id resource_type resource_id created_at status expires_at revoked_at narrowed_at scope target is_system deletion_protection granted_by_user_id delegation_id",
		"access_binding_subjects":       "binding_id subject_type subject_id ordinal resource_type resource_id",
		"grant_delegations":             "id account_id delegate_id active_delegate_id role_ids target_types subject_types module status delegated_by_type delegated_by_id created_at revoked_at",
		"roles":                         "id name cluster_id account_id project_id is_system owner_module created_at updated_at live retired_at",
		"service_accounts":              "id name account_id created_at enabled created_by_type created_by_id",
		"groups":                        "id name account_id created_at",
		"users":                         "id created_at",
		"accounts":                      "id created_at owner_user_id",
		"projects":                      "id account_id created_at",
		"group_members":                 "group_id member_type member_id added_at",
		"memberships":                   "user_id account_id",
		"resource_mirror":               "object_type object_id parent_account_id parent_project_id source_version updated_at created_by_type created_by_id",
		"resource_parent_edge":          "object_type object_id parent_type parent_id relation parent_relation source_version created_at updated_at",
		"catalog_module":                "module live",
		"catalog_resource":              "module resource object_type dotted live parent_types permanent_project public_read_to_children",
		"catalog_verb":                  "module resource verb live per_object container_parent container_relation",
		"declared-selector-proof":       "rule_fp object_types resource_names match_labels created_by_subject verbs_by_type container_type container_resource_names container_match_labels",
	}
	for _, f := range strings.Fields(schemas[table]) {
		if f == field {
			return true
		}
	}
	return false
}
func rid11CoordinateCellOf(k rid11CoordinateKnown, table, field string, raw json.RawMessage, row rid09PrimaryRow) rid11CoordinateCell {
	v, ok := rid11CoordinateDecode(raw)
	c := rid11CoordinateCell{Type: rid11CoordinateType(v), SHA256: rid03EvidenceHash(raw), Null: ok && v == nil}
	if !ok {
		c.Type = "invalid"
		return c
	}
	if !rid11CoordinateFieldAllowed(table, field) {
		return c
	}
	// Специальные структуры наблюдаются по закрытой схеме, без произвольного экспорта JSON.
	if table == "fga_outbox" && field == "payload" {
		c.Safe = rid11CoordinatePayload(k, v, rid03S(row, "event_type"))
		return c
	}
	if safe, valid := rid11CoordinateScalar(k, field, v); valid {
		c.Safe = safe
		return c
	}
	if field == "target" {
		if m, ok := v.(map[string]any); ok {
			if len(m) == 0 {
				c.Safe = map[string]any{"allInScope": true}
				return c
			}
			if len(m) == 1 {
				if b, ok := m["allInScope"].(bool); ok && b {
					c.Safe = m
					return c
				}
				if refs, ok := m["resources"].([]any); ok && len(refs) <= 256 {
					safe := []any{}
					valid := true
					for _, x := range refs {
						r, ok := x.(map[string]any)
						if !ok || len(r) != 2 {
							valid = false
							break
						}
						typ, t := r["type"].(string)
						id, i := r["id"].(string)
						if !t || !i || !k.Types[typ] || !k.IDs[id] {
							valid = false
							break
						}
						safe = append(safe, map[string]string{"type": typ, "id": id})
					}
					if valid {
						c.Safe = map[string]any{"resources": safe}
					}
				}
			}
		}
		return c
	}
	if field == "object_types" || field == "container_resource_names" || field == "resource_names" || field == "parent_types" {
		if a, ok := v.([]any); ok && len(a) <= 256 {
			safe := []string{}
			for _, x := range a {
				s, ok := x.(string)
				if !ok || !(k.Types[s] || k.IDs[s]) {
					return c
				}
				safe = append(safe, s)
			}
			c.Safe = safe
		}
		return c
	}
	if field == "verbs_by_type" {
		if m, ok := v.(map[string]any); ok {
			safe := map[string][]string{}
			for typ, x := range m {
				if !k.Types[typ] {
					return c
				}
				a, ok := x.([]any)
				if !ok || len(a) > 128 {
					return c
				}
				verbs := []string{}
				for _, v := range a {
					s, ok := v.(string)
					if !ok || !k.Names[s] {
						return c
					}
					verbs = append(verbs, s)
				}
				safe[typ] = verbs
			}
			c.Safe = safe
		}
		return c
	}
	return c
}
func rid11CoordinateKey(table string, row rid09PrimaryRow) (string, bool) {
	keys, ok := rid11CoordinateKeys[table]
	if !ok {
		switch table {
		case "accounts", "projects", "users", "service_accounts", "groups", "roles", "access_bindings", "grant_delegations":
			keys = []string{"id"}
			ok = true
		case "access_binding_subjects":
			keys = []string{"binding_id", "subject_type", "subject_id"}
			ok = true
		case "catalog_module":
			keys = []string{"module"}
			ok = true
		case "catalog_resource":
			keys = []string{"module", "resource"}
			ok = true
		case "catalog_verb":
			keys = []string{"module", "resource", "verb"}
			ok = true
		}
	}
	if !ok {
		return "", false
	}
	values := []any{}
	for _, key := range keys {
		raw, ok := row[key]
		if !ok {
			return "", false
		}
		v, ok := rid11CoordinateDecode(raw)
		if !ok {
			return "", false
		}
		if table == "fga_outbox" && key == "id" {
			n, ok := v.(json.Number)
			if !ok {
				return "", false
			}
			id, e := n.Int64()
			if e != nil || id <= 0 {
				return "", false
			}
			values = append(values, id)
		} else {
			s, ok := v.(string)
			if !ok {
				return "", false
			}
			values = append(values, s)
		}
	}
	return rid03EvidenceHash(values), true
}
func rid11CoordinateRowOf(k rid11CoordinateKnown, table string, row rid09PrimaryRow) rid11CoordinateRow {
	key, ok := rid11CoordinateKey(table, row)
	out := rid11CoordinateRow{KeySHA256: key, KeyValid: ok, RowSHA256: rid03EvidenceHash(row), Fields: map[string]rid11CoordinateCell{}}
	for field, raw := range row {
		out.Fields[rid11CoordinateName(field)] = rid11CoordinateCellOf(k, table, field, raw, row)
	}
	return out
}
func rid11CoordinateDifference(k rid11CoordinateKnown, table string, a, b []rid09PrimaryRow) rid11CoordinateDiff {
	d := rid11CoordinateDiff{BeforeCount: len(a), AfterCount: len(b), BeforeSHA256: rid03EvidenceHash(a), AfterSHA256: rid03EvidenceHash(b), Added: []rid11CoordinateRow{}, Removed: []rid11CoordinateRow{}, Changed: []rid11CoordinatePair{}, InvalidBefore: []rid11CoordinateRow{}, InvalidAfter: []rid11CoordinateRow{}, DuplicateBeforeKeys: []string{}, DuplicateAfterKeys: []string{}}
	group := func(rows []rid09PrimaryRow, invalid *[]rid11CoordinateRow, duplicates *[]string) map[string][]rid11CoordinateRow {
		m := map[string][]rid11CoordinateRow{}
		for _, r := range rows {
			s := rid11CoordinateRowOf(k, table, r)
			if !s.KeyValid {
				*invalid = append(*invalid, s)
				continue
			}
			m[s.KeySHA256] = append(m[s.KeySHA256], s)
		}
		for key, v := range m {
			if len(v) > 1 {
				*duplicates = append(*duplicates, key)
			}
			sort.Slice(m[key], func(i, j int) bool { return m[key][i].RowSHA256 < m[key][j].RowSHA256 })
		}
		sort.Strings(*duplicates)
		return m
	}
	aa := group(a, &d.InvalidBefore, &d.DuplicateBeforeKeys)
	bb := group(b, &d.InvalidAfter, &d.DuplicateAfterKeys)
	keys := map[string]bool{}
	for key := range aa {
		keys[key] = true
	}
	for key := range bb {
		keys[key] = true
	}
	ordered := []string{}
	for key := range keys {
		ordered = append(ordered, key)
	}
	sort.Strings(ordered)
	for _, key := range ordered {
		old, now := aa[key], bb[key]
		used := make([]bool, len(now))
		left := []rid11CoordinateRow{}
		for _, r := range old {
			found := false
			for j, s := range now {
				if !used[j] && r.RowSHA256 == s.RowSHA256 {
					used[j] = true
					found = true
					d.UnchangedCount++
					break
				}
			}
			if !found {
				left = append(left, r)
			}
		}
		right := []rid11CoordinateRow{}
		for j, r := range now {
			if !used[j] {
				right = append(right, r)
			}
		}
		if len(old) <= 1 && len(now) <= 1 && len(left) == 1 && len(right) == 1 {
			d.Changed = append(d.Changed, rid11CoordinatePair{left[0], right[0]})
		} else {
			d.Removed = append(d.Removed, left...)
			d.Added = append(d.Added, right...)
		}
	}
	return d
}

func rid11CoordinateRoleProof(a rid03NewmanSnapshot, k rid11CoordinateKnown) []map[string]any {
	out := []map[string]any{}
	for _, row := range a.Raw["roles"] {
		entry := map[string]any{"roleID": rid11CoordinateCellOf(k, "roles", "id", row["id"], row), "fullRowSHA256": rid03EvidenceHash(row), "authoredRulesSHA256": rid03EvidenceHash(row["rules"]), "ownerModule": rid11CoordinateCellOf(k, "roles", "owner_module", row["owner_module"], row)}
		system, sysOK := rid03Cell[bool](row, "is_system")
		owner, ownerOK := rid03Cell[string](row, "owner_module")
		if string(row["owner_module"]) == "null" {
			owner = ""
			ownerOK = true
		}
		rules, e := domain.DecodeRules(row["rules"])
		entry["decoded"] = e == nil
		entry["policyDecoded"] = sysOK && ownerOK
		if e == nil && sysOK && ownerOK {
			policy := domain.PolicyOfRole(system, owner)
			entry["isSystem"] = system
			entry["updateImpliesDelete"] = policy.UpdateImpliesDelete()
			scopes := map[string]domain.Scope{"ACCOUNT": domain.ScopeAccount, "PROJECT": domain.ScopeProject, "CLUSTER": domain.ScopeCluster}
			proof := map[string]any{}
			for label, scope := range scopes {
				selectors := rules.MaterializingSelectorsInScope(scope)
				if a.Facts != nil {
					selectors = a.Facts.GrantSelectors(selectors, policy)
				}
				safe := []map[string]rid11CoordinateCell{}
				for _, s := range selectors {
					values := map[string]any{"rule_fp": s.RuleFP, "object_types": s.ObjectTypes, "resource_names": s.ResourceNames, "match_labels": s.MatchLabels, "created_by_subject": s.CreatedBySubject, "verbs_by_type": s.Grants}
					if s.Container != nil {
						values["container_type"] = s.Container.Type
						values["container_resource_names"] = s.Container.ResourceNames
						values["container_match_labels"] = s.Container.MatchLabels
					}
					r := rid11RestoreRow(values)
					fields := map[string]rid11CoordinateCell{}
					for f, raw := range r {
						fields[f] = rid11CoordinateCellOf(k, "declared-selector-proof", f, raw, r)
					}
					safe = append(safe, fields)
				}
				proof[label] = safe
			}
			entry["beforeDeclaredSelectorProofs"] = proof
			entry["catalogFactsAvailable"] = a.Facts != nil
		}
		out = append(out, entry)
	}
	return out
}
func rid11CoordinateDiagnostic(a, b rid03NewmanSnapshot) map[string]any {
	k := rid11CoordinateKnownBefore(a)
	diffs := map[string]rid11CoordinateDiff{}
	for table := range rid11CoordinateKeys {
		diffs[table] = rid11CoordinateDifference(k, table, a.Raw[table], b.Raw[table])
	}
	// Полная перепись BEFORE без отбора по новым ID из AFTER. Неизвестные поля
	// и значения сохраняются хешами, чтобы подмены не исчезали из наблюдения.
	lineage := map[string][]rid11CoordinateRow{}
	for _, table := range []string{"access_bindings", "access_binding_subjects", "access_binding_target_members", "access_binding_emitted_tuples", "grant_delegations", "roles", "role_rule_selectors", "role_verb", "accounts", "projects", "users", "service_accounts", "groups", "group_members", "memberships", "resource_mirror", "resource_parent_edge", "catalog_module", "catalog_resource", "catalog_verb"} {
		rows := []rid11CoordinateRow{}
		for _, r := range a.Raw[table] {
			rows = append(rows, rid11CoordinateRowOf(k, table, r))
		}
		lineage[table] = rows
	}
	hashes := map[string]map[string]string{}
	for _, table := range []string{"operations", "access_bindings", "access_binding_subjects", "grant_delegations"} {
		hashes[table] = map[string]string{"before": rid03EvidenceHash(a.Raw[table]), "after": rid03EvidenceHash(b.Raw[table])}
	}
	// Приватный, конечный witness остаётся в диагностике 0600 и producer seal.
	// Это независимые исходные SQL bytes и Go raw domain, а не результат оракула.
	private := rid11RetiredPrivateWitness(a, b)
	return map[string]any{"version": 1, "diagnosticOnly": true, "actualNewmanExecuted": false, "wholeDoDAccepted": false, "oracleAllowanceChanged": false, "beforePrimaryStartedAt": a.Whole.PrimaryStartedAt, "beforePrimaryFinishedAt": a.Whole.PrimaryFinishedAt, "afterPrimaryStartedAt": b.Whole.PrimaryStartedAt, "afterPrimaryFinishedAt": b.Whole.PrimaryFinishedAt, "beforeRawSHA256": rid03EvidenceHash(a.Raw), "afterRawSHA256": rid03EvidenceHash(b.Raw), "beforeWholeSHA256": rid03EvidenceHash(a.Whole), "afterWholeSHA256": rid03EvidenceHash(b.Whole), "beforeBusinessSHA256": rid03EvidenceHash(a.BusinessAudit), "afterBusinessSHA256": rid03EvidenceHash(b.BusinessAudit), "preservedHistoryHashes": hashes, "tables": diffs, "beforeLineageAllRows": lineage, "beforeRolePolicyAndSelectorProofs": rid11CoordinateRoleProof(a, k), "retiredHistoryPrivate": private, "limits": []string{"Observation only; no authz or product acceptance inferred.", "Safe coordinates are restricted to typed BEFORE-known fixture IDs/catalog names; unsupported values are hash-only.", "Duplicate/malformed primary keys are retained explicitly, never silently collapsed.", "Public-safe coordinates remain type/null/hash; the closed private retirement witness retains original SQL text only for its ten dependency tables, never Operation/auth/outbox payload rows."}}
}

// Чистые диагностические проверки: без сервера, PG, действий и публичной приёмки.
const rid11CoordinateSecret = "SENSITIVE_CREDENTIAL_SENTINEL_NEVER_PERSIST_81c6d0"
const rid11CoordinateJWT = "eyJhbGciOiJSUzI1NiJ9.SENSITIVE_JWT_SENTINEL.signature"
const rid11CoordinatePEM = "-----BEGIN PRIVATE KEY-----\nSENSITIVE_PEM_SENTINEL\n-----END PRIVATE KEY-----"

func rid11CoordinateFixture() (rid03NewmanSnapshot, rid11CoordinateKnown, rid09PrimaryRow) {
	a := rid03NewmanSnapshot{Raw: map[string][]rid09PrimaryRow{}}
	for table, id := range map[string]string{"users": "usraaaaaaaa", "accounts": "accbbbbbbbb", "roles": "rolcccccccc", "access_bindings": "acbdddddddd", "service_accounts": "svaeeeeeeee", "groups": "grpffffffff"} {
		a.Raw[table] = []rid09PrimaryRow{rid11RestoreRow(map[string]any{"id": id})}
	}
	a.Raw["catalog_module"] = []rid09PrimaryRow{rid11RestoreRow(map[string]any{"module": "iam"})}
	a.Raw["catalog_resource"] = []rid09PrimaryRow{rid11RestoreRow(map[string]any{"module": "iam", "resource": "serviceAccount", "object_type": "iam_service_account"})}
	for _, verb := range []string{"get", "list", "update", "delete"} {
		a.Raw["catalog_verb"] = append(a.Raw["catalog_verb"], rid11RestoreRow(map[string]any{"verb": verb}))
	}
	r := rid11RestoreRow(map[string]any{"binding_id": "acbdddddddd", "role_id": "rolcccccccc", "rule_fp": strings.Repeat("a", 64), "object_type": "iam.serviceAccount", "object_id": "svaeeeeeeee", "verification_status": "ACTIVE", "live": true, "created_at": time.Date(2026, 11, 4, 1, 0, 0, 0, time.UTC), "updated_at": time.Date(2026, 11, 4, 1, 0, 0, 0, time.UTC)})
	return a, rid11CoordinateKnownBefore(a), r
}
func rid11CoordinateJSON(t *testing.T, v any) string {
	t.Helper()
	b, e := json.Marshal(v)
	require.NoError(t, e)
	return string(b)
}
func rid11CoordinateNoSecret(t *testing.T, v any) {
	t.Helper()
	s := rid11CoordinateJSON(t, v)
	for _, secret := range []string{rid11CoordinateSecret, rid11CoordinateJWT, "SENSITIVE_PEM_SENTINEL", "BEGIN PRIVATE KEY"} {
		require.NotContains(t, s, secret)
	}
}
func TestRID11Coordinate_AddedMember(t *testing.T) {
	_, k, r := rid11CoordinateFixture()
	d := rid11CoordinateDifference(k, "access_binding_target_members", nil, []rid09PrimaryRow{r})
	require.Equal(t, 1, len(d.Added))
	require.Zero(t, len(d.Removed)+len(d.Changed))
	require.True(t, d.Added[0].KeyValid)
	require.Equal(t, "svaeeeeeeee", d.Added[0].Fields["object_id"].Safe)
}
func TestRID11Coordinate_RemovedMember(t *testing.T) {
	_, k, r := rid11CoordinateFixture()
	d := rid11CoordinateDifference(k, "access_binding_target_members", []rid09PrimaryRow{r}, nil)
	require.Equal(t, 1, len(d.Removed))
	require.Zero(t, len(d.Added)+len(d.Changed))
}
func TestRID11Coordinate_ChangedSamePrimaryKey(t *testing.T) {
	_, k, r := rid11CoordinateFixture()
	n := rid11RestoreClone(r)
	n["verification_status"] = json.RawMessage(`"REJECTED"`)
	d := rid11CoordinateDifference(k, "access_binding_target_members", []rid09PrimaryRow{r}, []rid09PrimaryRow{n})
	require.Equal(t, 1, len(d.Changed))
	require.Zero(t, len(d.Added)+len(d.Removed))
	require.Equal(t, d.Changed[0].Before.KeySHA256, d.Changed[0].After.KeySHA256)
	require.NotEqual(t, d.Changed[0].Before.RowSHA256, d.Changed[0].After.RowSHA256)
}
func TestRID11Coordinate_KeySubstitutionIsRemoveAndAdd(t *testing.T) {
	_, k, r := rid11CoordinateFixture()
	n := rid11RestoreClone(r)
	n["object_id"] = json.RawMessage(`"foreign-id"`)
	d := rid11CoordinateDifference(k, "access_binding_target_members", []rid09PrimaryRow{r}, []rid09PrimaryRow{n})
	require.Equal(t, 1, len(d.Added))
	require.Equal(t, 1, len(d.Removed))
	require.Zero(t, len(d.Changed))
	require.Nil(t, d.Added[0].Fields["object_id"].Safe)
}
func TestRID11Coordinate_UnchangedMultiset(t *testing.T) {
	_, k, r := rid11CoordinateFixture()
	d := rid11CoordinateDifference(k, "access_binding_target_members", []rid09PrimaryRow{r}, []rid09PrimaryRow{rid11RestoreClone(r)})
	require.Equal(t, 1, d.UnchangedCount)
	require.Zero(t, len(d.Added)+len(d.Removed)+len(d.Changed))
}
func TestRID11Coordinate_DuplicatePrimaryKeysRetained(t *testing.T) {
	_, k, r := rid11CoordinateFixture()
	d := rid11CoordinateDifference(k, "access_binding_target_members", []rid09PrimaryRow{r, r}, []rid09PrimaryRow{r})
	require.Equal(t, 1, d.UnchangedCount)
	require.Equal(t, 1, len(d.Removed))
	require.Equal(t, 1, len(d.DuplicateBeforeKeys))
	require.Zero(t, len(d.Changed))
}
func TestRID11Coordinate_MalformedPrimaryKeyRetained(t *testing.T) {
	_, k, r := rid11CoordinateFixture()
	r["binding_id"] = json.RawMessage(`null`)
	d := rid11CoordinateDifference(k, "access_binding_target_members", nil, []rid09PrimaryRow{r})
	require.Equal(t, 1, len(d.InvalidAfter))
	require.False(t, d.InvalidAfter[0].KeyValid)
	require.Zero(t, len(d.Added))
}
func TestRID11Coordinate_NumericOutboxPrimaryKey(t *testing.T) {
	_, k, _ := rid11CoordinateFixture()
	r := rid11RestoreRow(map[string]any{"id": int64(9007199254740993), "event_type": "fga.tuple.write"})
	d := rid11CoordinateDifference(k, "fga_outbox", nil, []rid09PrimaryRow{r})
	require.Equal(t, 1, len(d.Added))
	require.Equal(t, int64(9007199254740993), d.Added[0].Fields["id"].Safe)
}
func TestRID11Coordinate_FractionalOutboxKeyInvalid(t *testing.T) {
	_, k, _ := rid11CoordinateFixture()
	r := rid09PrimaryRow{"id": json.RawMessage(`1.0`)}
	d := rid11CoordinateDifference(k, "fga_outbox", nil, []rid09PrimaryRow{r})
	require.Equal(t, 1, len(d.InvalidAfter))
}
func TestRID11Coordinate_UnknownCellSecretHashOnly(t *testing.T) {
	_, k, r := rid11CoordinateFixture()
	r["client_secret"], _ = json.Marshal(rid11CoordinateSecret)
	r["private_key_pem"], _ = json.Marshal(rid11CoordinatePEM)
	d := rid11CoordinateDifference(k, "access_binding_target_members", nil, []rid09PrimaryRow{r})
	require.Nil(t, d.Added[0].Fields["client_secret"].Safe)
	require.NotEmpty(t, d.Added[0].Fields["client_secret"].SHA256)
	rid11CoordinateNoSecret(t, d)
}
func TestRID11Coordinate_SensitivePrimaryCoordinateNeverEchoed(t *testing.T) {
	a, _, r := rid11CoordinateFixture()
	a.Raw["users"] = append(a.Raw["users"], rid11RestoreRow(map[string]any{"id": rid11CoordinateJWT}))
	k := rid11CoordinateKnownBefore(a)
	r["object_id"], _ = json.Marshal(rid11CoordinateJWT)
	d := rid11CoordinateDifference(k, "access_binding_target_members", nil, []rid09PrimaryRow{r})
	require.Nil(t, d.Added[0].Fields["object_id"].Safe)
	rid11CoordinateNoSecret(t, d)
}
func TestRID11Coordinate_UnknownPayloadSecretNeverEchoed(t *testing.T) {
	_, k, _ := rid11CoordinateFixture()
	payload := rid11RestoreRow(map[string]any{"user": "user:usraaaaaaaa", "object": "iam_service_account:svaeeeeeeee", "relation": "v_get", "client_secret": rid11CoordinateSecret, "private_key_pem": rid11CoordinatePEM})
	raw, _ := json.Marshal(payload)
	r := rid09PrimaryRow{"id": json.RawMessage(`1`), "event_type": json.RawMessage(`"fga.tuple.write"`), "payload": raw}
	d := rid11CoordinateDifference(k, "fga_outbox", nil, []rid09PrimaryRow{r})
	safe := d.Added[0].Fields["payload"].Safe.(map[string]any)
	require.Equal(t, false, safe["closedShape"])
	require.NotNil(t, safe["keys"])
	rid11CoordinateNoSecret(t, d)
}
func TestRID11Coordinate_SourceSingletonPayload(t *testing.T) {
	_, k, _ := rid11CoordinateFixture()
	v := map[string]any{"user": "user:usraaaaaaaa", "object": "iam_service_account:svaeeeeeeee", "relation": "v_get"}
	p := rid11CoordinatePayload(k, v, "fga.tuple.write").(map[string]any)
	require.Equal(t, true, p["closedShape"])
	require.Equal(t, "user:usraaaaaaaa", p["user"])
}
func TestRID11Coordinate_SourceGroupedWriteEcho(t *testing.T) {
	_, k, _ := rid11CoordinateFixture()
	v := map[string]any{"user": "user:usraaaaaaaa", "object": "iam_service_account:svaeeeeeeee", "relations": []any{"admin", "v_get"}, "relation": "admin"}
	p := rid11CoordinatePayload(k, v, "fga.tuple.write").(map[string]any)
	require.Equal(t, true, p["closedShape"])
	v["relation"] = "v_get"
	p = rid11CoordinatePayload(k, v, "fga.tuple.write").(map[string]any)
	require.Equal(t, false, p["closedShape"])
}
func TestRID11Coordinate_SourceGroupedDeleteWithoutEcho(t *testing.T) {
	_, k, _ := rid11CoordinateFixture()
	v := map[string]any{"user": "user:usraaaaaaaa", "object": "iam_service_account:svaeeeeeeee", "relations": []any{"admin", "v_get"}}
	p := rid11CoordinatePayload(k, v, "fga.tuple.delete").(map[string]any)
	require.Equal(t, true, p["closedShape"])
	v["relation"] = "admin"
	p = rid11CoordinatePayload(k, v, "fga.tuple.delete").(map[string]any)
	require.Equal(t, false, p["closedShape"])
}
func TestRID11Coordinate_UnknownAfterIdentityNotWhitelisted(t *testing.T) {
	_, k, _ := rid11CoordinateFixture()
	v := map[string]any{"user": "user:usraaaaaaaa", "object": "iam_service_account:svaforeignID", "relation": "v_get"}
	p := rid11CoordinatePayload(k, v, "fga.tuple.write").(map[string]any)
	require.Equal(t, false, p["closedShape"])
	require.NotContains(t, rid11CoordinateJSON(t, p), "svaforeignID")
}
func TestRID11Coordinate_ConditionParametersHashOnly(t *testing.T) {
	_, k, _ := rid11CoordinateFixture()
	r := rid11RestoreRow(map[string]any{"object_type": "iam_service_account", "object_id": "svaeeeeeeee", "relation": "v_get", "subject": "user:usraaaaaaaa", "condition_name": "", "condition_params": map[string]any{"token": rid11CoordinateJWT, "pem": rid11CoordinatePEM}})
	d := rid11CoordinateDifference(k, "relation_fact", nil, []rid09PrimaryRow{r})
	require.Nil(t, d.Added[0].Fields["condition_params"].Safe)
	rid11CoordinateNoSecret(t, d)
}
func TestRID11Coordinate_WholeReceiptExcludesOperationAndAuthCells(t *testing.T) {
	a, _, r := rid11CoordinateFixture()
	a.Raw["operations"] = []rid09PrimaryRow{rid11RestoreRow(map[string]any{"id": "op-private", "response_data": rid11CoordinateSecret})}
	a.Raw["access_tokens"] = []rid09PrimaryRow{rid11RestoreRow(map[string]any{"token": rid11CoordinateJWT})}
	a.Raw["access_binding_target_members"] = []rid09PrimaryRow{r}
	b := a
	x := rid11CoordinateDiagnostic(a, b)
	require.NotNil(t, x["preservedHistoryHashes"])
	rid11CoordinateNoSecret(t, x)
	require.NotContains(t, rid11CoordinateJSON(t, x), "response_data")
	require.NotContains(t, rid11CoordinateJSON(t, x), "op-private")
}
func TestRID11Coordinate_BeforeLineageIncludesUnimplicatedBindings(t *testing.T) {
	a, _, _ := rid11CoordinateFixture()
	a.Raw["access_bindings"] = append(a.Raw["access_bindings"], rid11RestoreRow(map[string]any{"id": "acbsecondOld", "resource_type": "account", "resource_id": "accbbbbbbbb"}))
	x := rid11CoordinateDiagnostic(a, a)
	lineage := x["beforeLineageAllRows"].(map[string][]rid11CoordinateRow)
	require.Equal(t, 2, len(lineage["access_bindings"]))
	require.Contains(t, rid11CoordinateJSON(t, lineage["access_bindings"]), "acbsecondOld")
}
func TestRID11Coordinate_UnknownJSONKeysAreSafeNamesOrHashes(t *testing.T) {
	_, k, _ := rid11CoordinateFixture()
	v := map[string]any{rid11CoordinateJWT: rid11CoordinateSecret}
	p := rid11CoordinatePayload(k, v, "fga.tuple.write")
	rid11CoordinateNoSecret(t, p)
	require.Contains(t, rid11CoordinateJSON(t, p), "name-sha256-")
}
func TestRID11Coordinate_TrailingJSONIsInvalid(t *testing.T) {
	v, ok := rid11CoordinateDecode(json.RawMessage(`"acbdddddddd" trailing-secret`))
	require.False(t, ok)
	require.Nil(t, v)
}

func TestRID11Coordinate_TableColumnScopePreventsFutureFieldExport(t *testing.T) {
	_, k, _ := rid11CoordinateFixture()
	r := rid11RestoreRow(map[string]any{"role_id": "rolcccccccc", "object_type": "iam.serviceAccount", "verb": "get", "live": true, "object": "user:usraaaaaaaa"})
	d := rid11CoordinateDifference(k, "role_verb", nil, []rid09PrimaryRow{r})
	require.Nil(t, d.Added[0].Fields["object"].Safe)
	require.NotEmpty(t, d.Added[0].Fields["object"].SHA256)
}
func TestRID11Coordinate_UnknownEventPayloadDoesNotExportTuples(t *testing.T) {
	_, k, _ := rid11CoordinateFixture()
	p := rid11CoordinatePayload(k, map[string]any{"user": "user:usraaaaaaaa", "object": "iam_service_account:svaeeeeeeee", "relation": "v_get"}, rid11CoordinateSecret)
	rid11CoordinateNoSecret(t, p)
	require.Equal(t, false, p.(map[string]any)["closedShape"])
}
func TestRID11Coordinate_DiagnosticFlagsCannotClaimAcceptance(t *testing.T) {
	a, _, _ := rid11CoordinateFixture()
	x := rid11CoordinateDiagnostic(a, a)
	require.Equal(t, true, x["diagnosticOnly"])
	require.Equal(t, false, x["actualNewmanExecuted"])
	require.Equal(t, false, x["wholeDoDAccepted"])
	require.Equal(t, false, x["oracleAllowanceChanged"])
}

func TestRID11Coordinate_RoleSelectorLabelSecretHashOnly(t *testing.T) {
	a, _, _ := rid11CoordinateFixture()
	rules, e := domain.EncodeRules(domain.Rules{{Module: "iam", Resources: []string{"serviceAccount"}, Verbs: []string{"get"}, MatchLabels: map[string]string{"token": rid11CoordinateSecret}}})
	require.NoError(t, e)
	a.Raw["roles"][0]["rules"] = rules
	a.Raw["roles"][0]["is_system"] = json.RawMessage(`true`)
	a.Raw["roles"][0]["owner_module"] = json.RawMessage(`"iam"`)
	x := rid11CoordinateDiagnostic(a, a)
	require.NotEmpty(t, x["beforeRolePolicyAndSelectorProofs"])
	rid11CoordinateNoSecret(t, x)
}
func TestRID11Coordinate_UnknownConditionNameNeverEchoed(t *testing.T) {
	_, k, _ := rid11CoordinateFixture()
	r := rid11RestoreRow(map[string]any{"object_type": "iam_service_account", "object_id": "svaeeeeeeee", "relation": "v_get", "subject": "user:usraaaaaaaa", "condition_name": rid11CoordinateSecret, "condition_params": map[string]string{}})
	d := rid11CoordinateDifference(k, "relation_fact", nil, []rid09PrimaryRow{r})
	require.Nil(t, d.Added[0].Fields["condition_name"].Safe)
	rid11CoordinateNoSecret(t, d)
}

func TestRID11Coordinate_EmptyTupleEndpointsRemainUnknown(t *testing.T) {
	_, k, _ := rid11CoordinateFixture()
	p := rid11CoordinatePayload(k, map[string]any{"user": "", "object": "iam_service_account:svaeeeeeeee", "relation": "v_get"}, "fga.tuple.write").(map[string]any)
	require.Equal(t, false, p["closedShape"])
	p = rid11CoordinatePayload(k, map[string]any{"user": "user:usraaaaaaaa", "object": "", "relation": "v_get"}, "fga.tuple.write").(map[string]any)
	require.Equal(t, false, p["closedShape"])
}
