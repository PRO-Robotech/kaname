// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Только добавочная материализация уже существующей выдачи в холодном census-мире.
// Координаты выводятся до чтения AFTER; время допускается лишь от проверенного producer.
var rid11BindingSchemas = map[string][]string{
	"access_binding_target_members": strings.Fields("binding_id object_type object_id verification_status created_at updated_at role_id rule_fp live"),
	"access_binding_emitted_tuples": strings.Fields("binding_id fga_user relation object source member_object_type member_object_id"),
	"fga_outbox":                    strings.Fields("id event_type payload created_at"),
	"relation_fact":                 strings.Fields("object_type object_id relation subject source_version created_at condition_name condition_params"),
}

type rid11BindingRestorePlan struct {
	Policy  rid03DeltaPolicy
	Desired map[rid03Member][]rid03Tuple
}
type rid11BindingRestoreProof struct {
	Enabled                 bool `json:"enabled"`
	Lower, Upper            time.Time
	Members                 []rid03Member                `json:"members"`
	Tuples                  []rid03EvidenceTuple         `json:"expectedTupleUnion"`
	Producers               []rid03ProducerEvidence      `json:"producers"`
	Facts                   []rid03FactEvidence          `json:"facts"`
	ExpectedMaterialization string                       `json:"expectedMaterialization"`
	DesiredMemberCount      int                          `json:"beforeDerivedDesiredMemberCount"`
	DesiredMemberSHA256     string                       `json:"beforeDerivedDesiredMemberSHA256"`
	NewRowCounts            map[string]int               `json:"actualNewRowCounts"`
	Raw                     map[string][]rid09PrimaryRow `json:"-"`
}
type rid11BindingObject struct{ Type, ID, Account string }

// Представление четырёх закрытых таблиц должно совпасть с самостоятельным
// перепись всего SQL. jsonb сортирует ключи по длине, затем по байтам; пробелы значимы.
func rid11BindingJSONB(value any) (string, bool) {
	switch v := value.(type) {
	case nil:
		return "null", true
	case bool:
		if v {
			return "true", true
		}
		return "false", true
	case json.Number:
		return string(v), true
	case string:
		var out bytes.Buffer
		enc := json.NewEncoder(&out)
		enc.SetEscapeHTML(false)
		if enc.Encode(v) != nil {
			return "", false
		}
		return strings.TrimSuffix(out.String(), "\n"), true
	case []any:
		parts := []string{}
		for _, item := range v {
			x, ok := rid11BindingJSONB(item)
			if !ok {
				return "", false
			}
			parts = append(parts, x)
		}
		return "[" + strings.Join(parts, ", ") + "]", true
	case map[string]any:
		keys := []string{}
		for k := range v {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool {
			if len(keys[i]) != len(keys[j]) {
				return len(keys[i]) < len(keys[j])
			}
			return keys[i] < keys[j]
		})
		parts := []string{}
		for _, k := range keys {
			key, ok := rid11BindingJSONB(k)
			if !ok {
				return "", false
			}
			val, ok := rid11BindingJSONB(v[k])
			if !ok {
				return "", false
			}
			parts = append(parts, key+": "+val)
		}
		return "{" + strings.Join(parts, ", ") + "}", true
	default:
		return "", false
	}
}
func rid11BindingWholeHashes(rows []rid09PrimaryRow) ([]string, bool) {
	out := []string{}
	for _, row := range rows {
		encoded, err := json.Marshal(row)
		if err != nil {
			return nil, false
		}
		value, ok := rid11CoordinateDecode(encoded)
		if !ok {
			return nil, false
		}
		text, ok := rid11BindingJSONB(value)
		if !ok {
			return nil, false
		}
		sum := sha256.Sum256([]byte(text))
		out = append(out, hex.EncodeToString(sum[:]))
	}
	sort.Strings(out)
	return out, true
}

func rid11BindingMember(r rid09PrimaryRow) rid03Member {
	return rid03Member{rid03S(r, "binding_id"), rid03S(r, "role_id"), rid03S(r, "rule_fp"), rid03S(r, "object_type"), rid03S(r, "object_id")}
}
func rid11BindingUnique(raw map[string][]rid09PrimaryRow, table string) bool {
	rows, ok := raw[table]
	if !ok {
		return false
	}
	seen := map[string]bool{}
	for _, r := range rows {
		k, valid := rid11CoordinateKey(table, r)
		if !valid || seen[k] {
			return false
		}
		seen[k] = true
	}
	return true
}
func rid11BindingIndex(raw map[string][]rid09PrimaryRow, table string) (map[string]rid09PrimaryRow, bool) {
	if !rid11BindingUnique(raw, table) {
		return nil, false
	}
	out := map[string]rid09PrimaryRow{}
	for _, r := range raw[table] {
		id := rid03S(r, "id")
		if !rid11CoordinateID.MatchString(id) {
			return nil, false
		}
		out[id] = r
	}
	return out, true
}

// Закрытый профиль: канонические IAM-строки, пустое внешнее зеркало; неподдержанный
// профиль не получает более широкого допуска. У пользователя account — из memberships.
func rid11BindingInventory(raw map[string][]rid09PrimaryRow) ([]rid11BindingObject, bool) {
	for _, table := range []string{"resource_mirror", "resource_parent_edge", "grant_delegations"} {
		r, ok := raw[table]
		if !ok || len(r) != 0 {
			return nil, false
		}
	}
	accounts, ok := rid11BindingIndex(raw, "accounts")
	if !ok || len(accounts) == 0 {
		return nil, false
	}
	projects, ok := rid11BindingIndex(raw, "projects")
	if !ok {
		return nil, false
	}
	out := []rid11BindingObject{}
	seen := map[rid11BindingObject]bool{}
	add := func(typ, id, account string) bool {
		o := rid11BindingObject{typ, id, account}
		if !rid11CoordinateID.MatchString(id) || seen[o] {
			return false
		}
		if account != "" {
			if _, ok := accounts[account]; !ok {
				return false
			}
		}
		seen[o] = true
		out = append(out, o)
		return true
	}
	for _, table := range []string{"accounts", "projects", "groups", "service_accounts", "roles", "access_bindings", "users"} {
		if !rid11BindingUnique(raw, table) {
			return nil, false
		}
		for _, r := range raw[table] {
			id := rid03S(r, "id")
			account := ""
			typ := map[string]string{"accounts": "iam.account", "projects": "iam.project", "groups": "iam.group", "service_accounts": "iam.serviceAccount", "roles": "iam.role", "access_bindings": "iam.accessBinding", "users": "iam.user"}[table]
			switch table {
			case "accounts":
				account = id
			case "projects", "groups", "service_accounts":
				var valid bool
				account, valid = rid03Cell[string](r, "account_id")
				if !valid || account == "" {
					return nil, false
				}
			case "roles":
				// Жизненный цикл целевой роли IAM не фильтрует нативную ведомость.
				// Признак live роли, выдающей права, отдельно проверяется при построении плана.
				_, valid := rid03Cell[bool](r, "live")
				if !valid {
					return nil, false
				}
				account = rid03S(r, "account_id")
				project := rid03S(r, "project_id")
				if project != "" {
					p, exists := projects[project]
					if !exists {
						return nil, false
					}
					pa := rid03S(p, "account_id")
					if account != "" && account != pa {
						return nil, false
					}
					account = pa
				}
			case "access_bindings":
				switch rid03S(r, "resource_type") {
				case "account":
					account = rid03S(r, "resource_id")
				case "project":
					p, exists := projects[rid03S(r, "resource_id")]
					if !exists {
						return nil, false
					}
					account = rid03S(p, "account_id")
				case "cluster":
				default:
					return nil, false
				}
			case "users":
				memberships, exists := raw["memberships"]
				if !exists {
					return nil, false
				}
				for _, m := range memberships {
					if rid03S(m, "user_id") == id {
						if !add(typ, id, rid03S(m, "account_id")) {
							return nil, false
						}
					}
				}
				continue
			}
			if !add(typ, id, account) {
				return nil, false
			}
		}
	}
	return out, true
}

func rid11BindingTuples(facts *catalog.Facts, policy domain.RulePolicy, sel domain.RuleSelector, subject, typ, id string) ([]rid03Tuple, bool) {
	model, ok := facts.FGAObjectType(typ)
	if !ok || !rid11CoordinateToken.MatchString(model) {
		return nil, false
	}
	verbs := facts.VerbsOfType(model)
	if len(verbs) == 0 {
		verbs = facts.CommonVerbVocabulary()
	}
	authored := []string{}
	for _, verb := range sel.Verbs {
		if _, container := facts.ContainerVerb(typ, verb); !container {
			authored = append(authored, verb)
		}
	}
	if len(authored) == 0 {
		return nil, false
	}
	grants := facts.GrantedVerbs(model, authored, verbs, policy)
	_, tier := domain.ResolveVerbsAndTier(authored, verbs)
	out := []rid03Tuple{}
	for _, v := range grants {
		out = append(out, rid03Tuple{subject, "v_" + v, model, id})
	}
	if tier != "" {
		out = append(out, rid03Tuple{subject, tier, model, id})
	}
	return out, len(out) > 0
}

func rid11BuildBindingRestore(a rid03NewmanSnapshot, facts *catalog.Facts, upper time.Time) (rid11BindingRestorePlan, bool) {
	p := rid11BindingRestorePlan{Desired: map[rid03Member][]rid03Tuple{}, Policy: rid03DeltaPolicy{Path: "/iam/v1/accessBindings", Start: a.Whole.PrimaryFinishedAt, End: upper, Members: map[rid03Member]bool{}, Ledger: map[rid03Ledger]bool{}, Tuples: map[rid03Tuple]bool{}, DirectTuples: map[rid03Tuple]bool{}}}
	if facts == nil || p.Policy.Start.IsZero() || upper.Before(p.Policy.Start) {
		return p, false
	}
	objects, ok := rid11BindingInventory(a.Raw)
	if !ok {
		return p, false
	}
	roles, ok := rid11BindingIndex(a.Raw, "roles")
	if !ok {
		return p, false
	}
	users, ok := rid11BindingIndex(a.Raw, "users")
	if !ok {
		return p, false
	}
	if len(a.Raw["access_binding_subjects"]) != len(a.Raw["access_bindings"]) || !rid11BindingUnique(a.Raw, "access_binding_subjects") {
		return p, false
	}
	if !rid11BindingUnique(a.Raw, "access_binding_target_members") {
		return p, false
	}
	oldMembers := map[rid03Member]rid09PrimaryRow{}
	for _, r := range a.Raw["access_binding_target_members"] {
		m := rid11BindingMember(r)
		if _, ok := oldMembers[m]; ok {
			return p, false
		}
		created, cok := rid03Cell[time.Time](r, "created_at")
		updated, uok := rid03Cell[time.Time](r, "updated_at")
		if !cok || !uok || created.IsZero() || updated.Before(created) || updated.After(p.Policy.Start) {
			return p, false
		}
		oldMembers[m] = r
	}
	for _, binding := range a.Raw["access_bindings"] {
		id := rid03S(binding, "id")
		roleID := rid03S(binding, "role_id")
		if rid03S(binding, "status") != "ACTIVE" || !rid03SameCell(binding, "revoked_at", nil) {
			return p, false
		}
		for _, k := range []string{"expires_at", "narrowed_at", "delegation_id"} {
			if !rid03SameCell(binding, k, nil) {
				return p, false
			}
		}
		subjects := []rid09PrimaryRow{}
		for _, s := range a.Raw["access_binding_subjects"] {
			if rid03S(s, "binding_id") == id {
				subjects = append(subjects, s)
			}
		}
		if len(subjects) != 1 || rid03S(subjects[0], "subject_type") != rid03S(binding, "subject_type") || rid03S(subjects[0], "subject_id") != rid03S(binding, "subject_id") || !rid03SameCell(subjects[0], "ordinal", 0) || rid03S(subjects[0], "resource_type") != rid03S(binding, "resource_type") || rid03S(subjects[0], "resource_id") != rid03S(binding, "resource_id") {
			return p, false
		}
		if roleID == "" {
			if !rid03SameCell(binding, "role_id", nil) || rid03S(binding, "resource_type") != "cluster" || !rid03SameCell(binding, "is_system", true) {
				return p, false
			}
			continue
		}
		role, exists := roles[roleID]
		if !exists || !rid03SameCell(role, "live", true) {
			return p, false
		}
		rules, err := domain.DecodeRules(role["rules"])
		if err != nil {
			return p, false
		}
		system, valid := rid03Cell[bool](role, "is_system")
		if !valid {
			return p, false
		}
		policy := domain.PolicyOfRole(system, rid03S(role, "owner_module"))
		scope, valid := rid03Cell[domain.Scope](binding, "scope")
		if !valid {
			return p, false
		}
		sels := facts.GrantSelectors(rules.MaterializingSelectorsInScope(scope), policy)
		for _, sel := range sels {
			iam := false
			for _, typ := range sel.ObjectTypes {
				if strings.HasPrefix(typ, "iam.") {
					iam = true
				}
			}
			// При пустом зеркале ни прямой, ни вложенный внешний selector не имеет объектов.
			if !iam {
				continue
			}
			if rid03S(binding, "resource_type") != "account" || scope != domain.ScopeAccount || !rid03SameCell(binding, "target", map[string]any{"allInScope": true}) || rid03S(binding, "target_digest") != (domain.AccessTarget{AllInScope: true}).Digest() {
				return p, false
			}
			if sel.Arm != domain.ArmAnchor || sel.Container != nil || sel.CreatedBySubject || len(sel.MatchLabels) > 0 || len(sel.ResourceNames) > 0 {
				return p, false
			}
			if rid03S(subjects[0], "subject_type") != "user" {
				return p, false
			}
			if _, exists := users[rid03S(subjects[0], "subject_id")]; !exists {
				return p, false
			}
			subject := domain.FGASubjectRef("user", rid03S(subjects[0], "subject_id"))
			if subject == "user:" {
				return p, false
			}
			account := rid03S(binding, "resource_id")
			if account == "" {
				return p, false
			}
			for _, o := range objects {
				if o.Account != account || !rid03Has(sel.ObjectTypes, o.Type) {
					continue
				}
				tuples, valid := rid11BindingTuples(facts, policy, sel, subject, o.Type, o.ID)
				if !valid {
					return p, false
				}
				m := rid03Member{id, roleID, sel.RuleFP, o.Type, o.ID}
				if _, dup := p.Desired[m]; dup {
					return p, false
				}
				p.Desired[m] = tuples
				if old, exists := oldMembers[m]; exists {
					if rid03S(old, "verification_status") != "ACTIVE" || !rid03SameCell(old, "live", true) {
						return p, false
					}
					continue
				}
				// Холодная поставка создаёт новые SA/группы; иной пропуск требует отдельного объяснения.
				if o.Type != "iam.serviceAccount" && o.Type != "iam.group" {
					return p, false
				}
				p.Policy.Members[m] = true
				for _, tuple := range tuples {
					p.Policy.Ledger[rid03Ledger{id, "member", o.Type, o.ID, tuple}] = true
					p.Policy.Tuples[tuple] = true
					if !strings.HasPrefix(tuple.Relation, "v_") {
						p.Policy.DirectTuples[tuple] = true
					}
				}
			}
			// Scope-self уже существовал до First. Его появление или изменение здесь запрещено.
			sm := rid03Member{id, roleID, "scope_self", "iam.account", account}
			old, exists := oldMembers[sm]
			if !exists || rid03S(old, "verification_status") != "ACTIVE" || !rid03SameCell(old, "live", true) {
				return p, false
			}
			scopeVerbs := facts.VerbsOfType("account")
			if len(scopeVerbs) == 0 {
				scopeVerbs = facts.AllVerbVocabulary()
			}
			authored := rules.ScopeSelfVerbs("account", scopeVerbs)
			_, tier := domain.ResolveVerbsAndTier(authored, scopeVerbs)
			scopeTuples := []rid03Tuple{}
			if len(facts.VerbsOfType("account")) > 0 {
				for _, verb := range authored {
					if domain.IsVerbOfType(verb, scopeVerbs) {
						scopeTuples = append(scopeTuples, rid03Tuple{subject, "v_" + domain.NormalizeVerb(verb), "account", account})
					}
				}
			}
			if tier != "" {
				scopeTuples = append(scopeTuples, rid03Tuple{subject, tier, "account", account})
			}
			if len(scopeTuples) == 0 {
				return p, false
			}
			p.Desired[sm] = scopeTuples
		}
	}
	// Прежний ACTIVE-состав также должен быть желаемым: иначе неизменность
	// устаревшего права не является законным результатом обычного reconcile.
	expectedOld := map[rid03Ledger]bool{}
	for member, row := range oldMembers {
		tuples, exists := p.Desired[member]
		if !exists || rid03S(row, "verification_status") != "ACTIVE" || !rid03SameCell(row, "live", true) {
			return p, false
		}
		for _, tuple := range tuples {
			expectedOld[rid03Ledger{member.Binding, "member", member.Type, member.ID, tuple}] = true
		}
	}
	actualOld := map[rid03Ledger]bool{}
	for _, r := range a.Raw["access_binding_emitted_tuples"] {
		if rid03S(r, "source") == "binding" {
			continue
		}
		if !rid03Columns(r, "binding_id fga_user relation object source member_object_type member_object_id") || rid03S(r, "source") != "member" {
			return p, false
		}
		object := strings.SplitN(rid03S(r, "object"), ":", 2)
		if len(object) != 2 {
			return p, false
		}
		key := rid03Ledger{rid03S(r, "binding_id"), "member", rid03S(r, "member_object_type"), rid03S(r, "member_object_id"), rid03Tuple{rid03S(r, "fga_user"), rid03S(r, "relation"), object[0], object[1]}}
		if actualOld[key] {
			return p, false
		}
		actualOld[key] = true
	}
	if !reflect.DeepEqual(expectedOld, actualOld) {
		return p, false
	}
	return p, true
}

// Порядок jsonb::text для строк членов: все ключи фиксированы, скаляры сохраняют
// исходные байты PostgreSQL. Не сортируем по AFTER-идентификаторам или digest.
func rid11BindingSortMembers(rows []rid09PrimaryRow) []rid09PrimaryRow {
	out := append([]rid09PrimaryRow{}, rows...)
	keys := append([]string(nil), rid11BindingSchemas["access_binding_target_members"]...)
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) < len(keys[j])
		}
		return keys[i] < keys[j]
	})
	sort.SliceStable(out, func(i, j int) bool {
		for _, k := range keys {
			a, b := string(out[i][k]), string(out[j][k])
			if a != b {
				return a < b
			}
		}
		return false
	})
	return out
}
func rid11BindingProjection(a rid03NewmanSnapshot, members []rid09PrimaryRow) (rid09NewmanProjection, bool) {
	expected := a.Projection
	if a.Projection.Materialization != rid03EvidenceHash(a.Raw["access_binding_target_members"]) {
		return expected, false
	}
	expected.Materialization = rid03EvidenceHash(rid11BindingSortMembers(members))
	expected.Bindings = []map[string]any{}
	for _, g := range a.Projection.Bindings {
		id, ok := g["id"].(string)
		if !ok || id == "" {
			return expected, false
		}
		oldTime, newTime := time.Time{}, time.Time{}
		for _, side := range []struct {
			rows   []rid09PrimaryRow
			latest *time.Time
		}{{a.Raw["access_binding_target_members"], &oldTime}, {members, &newTime}} {
			for _, r := range side.rows {
				if rid03S(r, "binding_id") != id || rid03S(r, "verification_status") != "ACTIVE" {
					continue
				}
				at, valid := rid03Cell[time.Time](r, "updated_at")
				if !valid || at.IsZero() {
					return expected, false
				}
				if at.After(*side.latest) {
					*side.latest = at
				}
			}
		}
		oldValue, ok := rid05CanonicalMaterializedAt(oldTime)
		if !ok || !reflect.DeepEqual(g["materializedAt"], oldValue) {
			return expected, false
		}
		value, ok := rid05CanonicalMaterializedAt(newTime)
		if !ok {
			return expected, false
		}
		copy := map[string]any{}
		for k, v := range g {
			copy[k] = v
		}
		copy["materializedAt"] = value
		expected.Bindings = append(expected.Bindings, copy)
	}
	return expected, true
}

// Проверка четырёх таблиц сначала полностью сохраняет старые строки, затем
// устанавливает происхождение clocks и лишь после этого допускает физические facts.
func rid11ValidateBindingRestore(a, b rid03NewmanSnapshot, p rid11BindingRestorePlan) (rid11BindingRestoreProof, bool) {
	proof := rid11BindingRestoreProof{Enabled: true, Lower: p.Policy.Start, Upper: p.Policy.End, Raw: map[string][]rid09PrimaryRow{}, Members: []rid03Member{}, Producers: []rid03ProducerEvidence{}, Facts: []rid03FactEvidence{}}
	fresh := map[string][]rid09PrimaryRow{}
	for table, keys := range rid11BindingSchemas {
		for _, s := range []rid03NewmanSnapshot{a, b} {
			if !rid11BindingUnique(s.Raw, table) {
				return proof, false
			}
			whole, ok := s.Whole.Delivery[table]
			if !ok || len(whole.Rows) != len(s.Raw[table]) {
				return proof, false
			}
			hashes, valid := rid11BindingWholeHashes(s.Raw[table])
			if !valid || !reflect.DeepEqual(hashes, whole.Rows) {
				return proof, false
			}
			cols := append([]string(nil), whole.Columns...)
			want := append([]string(nil), keys...)
			sort.Strings(cols)
			sort.Strings(want)
			if !reflect.DeepEqual(cols, want) {
				return proof, false
			}
			for _, row := range s.Raw[table] {
				if !rid11RestoreKeys(row, keys) {
					return proof, false
				}
			}
		}
		rows, ok := rid03NewEvidenceRows(a.Raw[table], b.Raw[table])
		if !ok {
			return proof, false
		}
		fresh[table] = rows
	}
	if !p.Policy.bindProducers(fresh["fga_outbox"]) {
		return proof, false
	}
	// Одинаковый первичный ключ с иными полями не может спрятаться за новым производителем.
	for _, r := range fresh["fga_outbox"] {
		_, tuples, ok := p.Policy.producer(r)
		if !ok {
			return proof, false
		}
		at, _ := rid03Cell[time.Time](r, "created_at")
		id, _ := rid03Cell[int64](r, "id")
		payload := rid09PrimaryRow{}
		if json.Unmarshal(r["payload"], &payload) != nil {
			return proof, false
		}
		ts := []rid03EvidenceTuple{}
		for _, tuple := range tuples {
			ts = append(ts, rid03EvidenceTupleOf(tuple))
		}
		proof.Producers = append(proof.Producers, rid03ProducerEvidence{ID: id, Event: "fga.tuple.write", CreatedAt: at, PayloadShape: map[bool]string{true: "grouped", false: "singleton"}[len(payload) == 4], ScalarEcho: rid03S(payload, "relation"), Tuples: ts, FullRowSHA256: rid03EvidenceHash(r)})
	}
	memberSeen := map[rid03Member]bool{}
	ledgerSeen := map[rid03Ledger]bool{}
	factsSeen := map[rid03Tuple]bool{}
	generated := append([]rid09PrimaryRow{}, a.Raw["access_binding_target_members"]...)
	for _, r := range fresh["access_binding_target_members"] {
		m := rid11BindingMember(r)
		if !p.Policy.allows("access_binding_target_members", r) || memberSeen[m] {
			return proof, false
		}
		memberSeen[m] = true
		created, ok := rid03Cell[time.Time](r, "created_at")
		updated, ok2 := rid03Cell[time.Time](r, "updated_at")
		if !ok || !ok2 || !created.Equal(updated) {
			return proof, false
		}
		var clock json.RawMessage
		for _, producer := range fresh["fga_outbox"] {
			_, tuples, valid := p.Policy.producer(producer)
			at, _ := rid03Cell[time.Time](producer, "created_at")
			if !valid || !at.Equal(created) {
				continue
			}
			for _, tuple := range tuples {
				if p.Policy.Ledger[rid03Ledger{m.Binding, "member", m.Type, m.ID, tuple}] {
					clock = producer["created_at"]
				}
			}
		}
		if len(clock) == 0 {
			return proof, false
		}
		row := rid11RestoreRow(map[string]any{"binding_id": m.Binding, "role_id": m.Role, "rule_fp": m.Rule, "object_type": m.Type, "object_id": m.ID, "verification_status": "ACTIVE", "live": true})
		row["created_at"] = append(json.RawMessage(nil), clock...)
		row["updated_at"] = append(json.RawMessage(nil), clock...)
		if !rid11RestoreRowsEqual([]rid09PrimaryRow{row}, []rid09PrimaryRow{r}) {
			return proof, false
		}
		generated = append(generated, row)
		proof.Members = append(proof.Members, m)
	}
	for _, r := range fresh["access_binding_emitted_tuples"] {
		if !p.Policy.allows("access_binding_emitted_tuples", r) {
			return proof, false
		}
		obj := strings.SplitN(rid03S(r, "object"), ":", 2)
		l := rid03Ledger{rid03S(r, "binding_id"), rid03S(r, "source"), rid03S(r, "member_object_type"), rid03S(r, "member_object_id"), rid03Tuple{rid03S(r, "fga_user"), rid03S(r, "relation"), obj[0], obj[1]}}
		if ledgerSeen[l] {
			return proof, false
		}
		ledgerSeen[l] = true
	}
	for _, r := range fresh["relation_fact"] {
		if !p.Policy.allows("relation_fact", r) {
			return proof, false
		}
		tuple := rid03Tuple{rid03S(r, "subject"), rid03S(r, "relation"), rid03S(r, "object_type"), rid03S(r, "object_id")}
		if factsSeen[tuple] {
			return proof, false
		}
		factsSeen[tuple] = true
		version, _ := rid03Cell[time.Time](r, "source_version")
		at, _ := rid03Cell[time.Time](r, "created_at")
		proof.Facts = append(proof.Facts, rid03FactEvidence{Tuple: rid03EvidenceTupleOf(tuple), SourceVersion: version, CreatedAt: at, MatchingProducerClocks: p.Policy.FactCreated[tuple], ExpectedMaxSourceVersion: p.Policy.FactVersions[tuple], ConditionName: "", ConditionParameters: map[string]string{}, FullRowSHA256: rid03EvidenceHash(r)})
	}
	if !reflect.DeepEqual(memberSeen, p.Policy.Members) || !reflect.DeepEqual(ledgerSeen, p.Policy.Ledger) {
		return proof, false
	}
	expectedFacts := map[rid03Tuple]bool{}
	for tuple := range p.Policy.DirectTuples {
		expectedFacts[tuple] = true
	}
	for _, r := range a.Raw["relation_fact"] {
		delete(expectedFacts, rid03Tuple{rid03S(r, "subject"), rid03S(r, "relation"), rid03S(r, "object_type"), rid03S(r, "object_id")})
	}
	if !reflect.DeepEqual(factsSeen, expectedFacts) {
		return proof, false
	}
	for table := range rid11BindingSchemas {
		proof.Raw[table] = append([]rid09PrimaryRow{}, b.Raw[table]...)
	}
	proof.Raw["access_binding_target_members"] = rid11BindingSortMembers(generated)
	if !rid11RestoreRowsEqual(proof.Raw["access_binding_target_members"], b.Raw["access_binding_target_members"]) {
		return proof, false
	}
	desiredHashes := []string{}
	for coordinate, tuples := range p.Desired {
		set := map[rid03Tuple]bool{}
		for _, tuple := range tuples {
			set[tuple] = true
		}
		desiredHashes = append(desiredHashes, rid03EvidenceHash([]any{coordinate, rid03OrderedEvidenceTuples(set)}))
	}
	sort.Strings(desiredHashes)
	proof.DesiredMemberCount = len(p.Desired)
	proof.DesiredMemberSHA256 = rid03EvidenceHash(desiredHashes)
	proof.NewRowCounts = map[string]int{}
	for table, rows := range fresh {
		proof.NewRowCounts[table] = len(rows)
	}
	proof.ExpectedMaterialization = rid03EvidenceHash(proof.Raw["access_binding_target_members"])
	proof.Tuples = rid03OrderedEvidenceTuples(p.Policy.Tuples)
	return proof, true
}
