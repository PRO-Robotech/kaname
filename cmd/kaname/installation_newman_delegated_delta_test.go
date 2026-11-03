// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/stretchr/testify/require"
)

type rid03Tuple struct{ Subject, Relation, Type, ID string }
type rid03Member struct{ Binding, Role, Rule, Type, ID string }
type rid03Ledger struct {
	Binding, Source, MemberType, MemberID string
	Tuple                                 rid03Tuple
}
type rid03DeltaPolicy struct {
	NewID, Path, Account, SubjectType, SubjectID, Role, Delegation, TargetType, TargetID, GDDelegate, Creator string
	Start, End                                                                                                time.Time
	Members                                                                                                   map[rid03Member]bool
	Ledger                                                                                                    map[rid03Ledger]bool
	Tuples                                                                                                    map[rid03Tuple]bool
	DirectTuples                                                                                              map[rid03Tuple]bool
	FactVersions                                                                                              map[rid03Tuple]time.Time
	FactCreated                                                                                               map[rid03Tuple][]time.Time
	Main                                                                                                      rid09PrimaryRow
}

func rid03Cell[T any](row rid09PrimaryRow, key string) (T, bool) {
	var out T
	raw, ok := row[key]
	if !ok || json.Unmarshal(raw, &out) != nil {
		return out, false
	}
	return out, true
}
func rid03S(row rid09PrimaryRow, key string) string { v, _ := rid03Cell[string](row, key); return v }
func rid03SameCell(row rid09PrimaryRow, key string, want any) bool {
	raw, ok := row[key]
	if !ok {
		return false
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return false
	}
	b, _ := json.Marshal(want)
	var e any
	_ = json.Unmarshal(b, &e)
	return reflect.DeepEqual(v, e)
}
func rid03Columns(row rid09PrimaryRow, names string) bool {
	keys := strings.Fields(names)
	if len(row) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := row[key]; !ok {
			return false
		}
	}
	return true
}
func (p rid03DeltaPolicy) bounded(row rid09PrimaryRow, key string) bool {
	at, ok := rid03Cell[time.Time](row, key)
	return ok && !at.Before(p.Start) && !at.After(p.End)
}
func rid03RoleRules(t *testing.T, s rid03NewmanSnapshot, id string) (domain.Rules, domain.RulePolicy) {
	t.Helper()
	for _, r := range s.Raw["roles"] {
		if rid03S(r, "id") == id {
			rules, err := domain.DecodeRules(r["rules"])
			require.NoError(t, err)
			system, _ := rid03Cell[bool](r, "is_system")
			return rules, domain.PolicyOfRole(system, rid03S(r, "owner_module"))
		}
	}
	t.Fatal("primary declared role missing")
	return nil, domain.TenantPolicy()
}
func rid03Selectors(t *testing.T, s rid03NewmanSnapshot, role string) []domain.RuleSelector {
	rules, policy := rid03RoleRules(t, s, role)
	return s.Facts.GrantSelectors(rules.MaterializingSelectorsInScope(domain.ScopeAccount), policy)
}
func rid03Has(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
func rid03OwnerCoordinates(t *testing.T, e *rid03NewmanExpectation, s rid03NewmanSnapshot, newID string) map[rid03Member][]rid03Tuple {
	t.Helper()
	out := map[rid03Member][]rid03Tuple{}
	for _, g := range s.Projection.Bindings {
		if g["status"] != "ACTIVE" || g["scopeType"] != "iam.account" || g["scopeId"] != e.Tenant || g["roleId"] == "" {
			continue
		}
		target := g["target"].(map[string]any)
		if _, all := target["allInScope"]; !all {
			continue
		}
		role := g["roleId"].(string)
		for _, sel := range rid03Selectors(t, s, role) {
			if sel.Container != nil || !rid03Has(sel.ObjectTypes, "iam.accessBinding") {
				continue
			}
			require.True(t, sel.Arm == domain.ArmAnchor && !sel.CreatedBySubject, "fixture owner selector unsupported")
			m := rid03Member{g["id"].(string), role, sel.RuleFP, "iam.accessBinding", newID}
			for _, subject := range g["subjects"].([]any) {
				sub := subject.(map[string]any)
				kind := map[string]string{"SUBJECT_TYPE_USER": "user", "SUBJECT_TYPE_SERVICE_ACCOUNT": "service_account", "SUBJECT_TYPE_GROUP": "group"}[sub["type"].(string)]
				require.NotEmpty(t, kind)
				out[m] = append(out[m], rid03RoleTuples(t, s, role, sel, domain.FGASubjectRef(kind, sub["id"].(string)), "iam.accessBinding", newID)...)
			}
		}
	}
	return out
}
func rid03RoleTuples(t *testing.T, s rid03NewmanSnapshot, role string, sel domain.RuleSelector, subject, typ, id string) []rid03Tuple {
	t.Helper()
	_, policy := rid03RoleRules(t, s, role)
	model, ok := s.Facts.FGAObjectType(typ)
	require.True(t, ok)
	typeVerbs := s.Facts.VerbsOfType(model)
	if len(typeVerbs) == 0 {
		typeVerbs = s.Facts.CommonVerbVocabulary()
	}
	verbs := sel.Verbs
	if strings.HasPrefix(subject, "system_class:") {
		filtered := []string{}
		for _, v := range verbs {
			if domain.IsClassReadVerb(v) {
				filtered = append(filtered, v)
			}
		}
		verbs = filtered
	}
	granted := s.Facts.GrantedVerbs(model, verbs, typeVerbs, policy)
	_, tier := domain.ResolveVerbsAndTier(verbs, typeVerbs)
	out := []rid03Tuple{}
	for _, v := range granted {
		out = append(out, rid03Tuple{subject, "v_" + v, model, id})
	}
	if tier != "" {
		out = append(out, rid03Tuple{subject, tier, model, id})
	}
	return out
}
func rid03ExactOwnerMember(t *testing.T, e *rid03NewmanExpectation, s rid03NewmanSnapshot, row rid09PrimaryRow, owner, newID string) bool {
	t.Helper()
	m := rid03Member{rid03S(row, "binding_id"), rid03S(row, "role_id"), rid03S(row, "rule_fp"), rid03S(row, "object_type"), rid03S(row, "object_id")}
	_, ok := rid03OwnerCoordinates(t, e, s, newID)[m]
	return ok && m.Binding == owner && m.Type == "iam.accessBinding" && m.ID == newID && rid03S(row, "verification_status") == "ACTIVE"
}
func rid03BuildDeltaPolicy(t *testing.T, e *rid03NewmanExpectation, a, b rid03NewmanSnapshot, newID string) rid03DeltaPolicy {
	t.Helper()
	p := rid03DeltaPolicy{NewID: newID, Path: e.Path, Account: e.Tenant, Start: a.Whole.PrimaryFinishedAt, End: b.Whole.PrimaryStartedAt, Members: map[rid03Member]bool{}, Ledger: map[rid03Ledger]bool{}, Tuples: map[rid03Tuple]bool{}}
	table := "access_bindings"
	if e.Path == "/iam/v1/grantDelegations" {
		table = "grant_delegations"
	}
	for _, row := range b.Raw[table] {
		if rid03S(row, "id") == newID {
			p.Main = row
		}
	}
	require.NotNil(t, p.Main)
	if e.Path != "/iam/v1/accessBindings" {
		p.Account = e.Request["accountId"].(string)
		p.GDDelegate = e.Request["delegate"].(map[string]any)["id"].(string)
		p.Creator = e.Creator
		p.Role = e.Request["roleIds"].([]any)[0].(string)
		return p
	}
	p.SubjectType = e.Request["subjectType"].(string)
	p.SubjectID = e.Request["subjectId"].(string)
	p.Role = e.Request["roleId"].(string)
	p.Delegation = e.InstallationGD
	subject := domain.FGASubjectRef(p.SubjectType, p.SubjectID)
	p.DirectTuples = map[rid03Tuple]bool{}
	addMember := func(m rid03Member, tuples []rid03Tuple) {
		p.Members[m] = true
		for _, tuple := range tuples {
			p.Ledger[rid03Ledger{m.Binding, "member", m.Type, m.ID, tuple}] = true
			p.Tuples[tuple] = true
			if !strings.HasPrefix(tuple.Relation, "v_") {
				p.DirectTuples[tuple] = true
			}
		}
	}
	target := e.Request["target"].(map[string]any)["resources"].(map[string]any)["resources"].([]any)[0].(map[string]any)
	targetType, targetID := target["type"].(string), target["id"].(string)
	p.TargetType, p.TargetID = targetType, targetID
	selectors := rid03Selectors(t, a, p.Role)
	for _, sel := range selectors {
		require.True(t, sel.Arm == domain.ArmAnchor && !sel.CreatedBySubject, "fixture delivered role selector unsupported")
		if sel.Container == nil {
			if rid03Has(sel.ObjectTypes, targetType) {
				m := rid03Member{newID, p.Role, sel.RuleFP, targetType, targetID}
				tuples := rid03RoleTuples(t, a, p.Role, sel, subject, targetType, targetID)
				addMember(m, tuples)

			}
			continue
		}
		if p.SubjectType == "system_class" {
			continue
		}
		if sel.Container.Type != targetType {
			continue
		}
		model, _ := a.Facts.FGAObjectType(targetType)
		for _, edge := range a.Raw["resource_parent_edge"] {
			if rid03S(edge, "parent_type") != model || rid03S(edge, "parent_id") != targetID {
				continue
			}
			childModel, childID := rid03S(edge, "object_type"), rid03S(edge, "object_id")
			for _, typ := range sel.ObjectTypes {
				fga, ok := a.Facts.FGAObjectType(typ)
				if ok && fga == childModel {
					m := rid03Member{newID, p.Role, sel.RuleFP, typ, childID}
					tuples := rid03RoleTuples(t, a, p.Role, sel, subject, typ, childID)
					addMember(m, tuples)

				}
			}
		}
	}
	// The class public_reader member is a separate exact coordinate derived from
	// the delivered nested read rules, not a free privilege on matching endpoints.
	if p.SubjectType == "system_class" {
		fps := []string{}
		children := a.Facts.PublicReadChildren(targetType)
		for _, sel := range selectors {
			if sel.Container != nil && sel.PublicReadsChildOf(targetType, children) {
				fps = append(fps, sel.RuleFP)
			}
		}
		if len(fps) > 0 {
			sort.Strings(fps)
			fp := "public_reader:" + strings.Join(fps, ",") + "@" + subject
			model, ok := a.Facts.FGAObjectType(targetType)
			require.True(t, ok)
			tuples := []rid03Tuple{{subject, "public_reader", model, targetID}}
			addMember(rid03Member{newID, p.Role, fp, targetType, targetID}, tuples)

		}
	}
	for member, tuples := range rid03OwnerCoordinates(t, e, a, newID) {
		addMember(member, tuples)
	}

	parent := rid03Tuple{"account:" + p.Account, "account", "iam_access_binding", newID}
	p.Ledger[rid03Ledger{newID, "binding", "", "", parent}] = true
	p.Tuples[parent] = true
	p.DirectTuples[parent] = true

	return p
}

// Technical intent partition and multiplicity are not business invariants.
// Each row is closed; the independently expected complete emitted union is required.
func rid03ProducerKey(subject, typ, id string, relations []string) string {
	raw, _ := json.Marshal([]any{subject, typ, id, relations})
	return string(raw)
}
func (p rid03DeltaPolicy) producer(row rid09PrimaryRow) (string, []rid03Tuple, bool) {
	id, idOK := rid03Cell[int64](row, "id")
	if !idOK || id <= 0 || !rid03Columns(row, "id event_type payload created_at") || rid03S(row, "event_type") != "fga.tuple.write" || !p.bounded(row, "created_at") {
		return "", nil, false
	}
	var payload rid09PrimaryRow
	if json.Unmarshal(row["payload"], &payload) != nil {
		return "", nil, false
	}
	subject, subjectOK := rid03Cell[string](payload, "user")
	object, objectOK := rid03Cell[string](payload, "object")
	echo, echoOK := rid03Cell[string](payload, "relation")
	obj := strings.SplitN(object, ":", 2)
	if !subjectOK || subject == "" || !objectOK || len(obj) != 2 || obj[0] == "" || obj[1] == "" || !echoOK || echo == "" {
		return "", nil, false
	}
	relations := []string{echo}
	if rid03Columns(payload, "user object relations relation") {
		var ok bool
		relations, ok = rid03Cell[[]string](payload, "relations")
		if !ok || len(relations) < 2 || relations[0] != echo {
			return "", nil, false
		}
	} else if !rid03Columns(payload, "user object relation") {
		return "", nil, false
	}
	tuples := []rid03Tuple{}
	for i, relation := range relations {
		if relation == "" || (i > 0 && relations[i-1] >= relation) {
			return "", nil, false
		}
		tuple := rid03Tuple{subject, relation, obj[0], obj[1]}
		if !p.Tuples[tuple] {
			return "", nil, false
		}
		tuples = append(tuples, tuple)
	}
	key := rid03ProducerKey(subject, obj[0], obj[1], relations)
	return key, tuples, true
}

// Bind versions only to independently validated new producer rows. No fact cell
// participates in this proof. Ordinary fold filters verbs and uses producer time.
func (p *rid03DeltaPolicy) bindProducers(rows []rid09PrimaryRow) (accepted bool) {
	defer func() {
		if !accepted {
			p.FactVersions = nil
			p.FactCreated = nil
		}
	}()
	p.FactVersions = map[rid03Tuple]time.Time{}
	p.FactCreated = map[rid03Tuple][]time.Time{}
	emittedSeen := map[rid03Tuple]bool{}
	for _, row := range rows {
		_, tuples, ok := p.producer(row)
		if !ok {
			return false
		}
		at, ok := rid03Cell[time.Time](row, "created_at")
		if !ok {
			return false
		}
		for _, tuple := range tuples {
			emittedSeen[tuple] = true
			if !p.DirectTuples[tuple] {
				continue
			}
			last, exists := p.FactVersions[tuple]
			if !exists || at.After(last) {
				p.FactVersions[tuple] = at
			}
			// A concurrent transaction with a later start can insert first.
			// Retain ALL independently validated matching producer clocks; never
			// infer first insertion from minimum transaction-start time.
			p.FactCreated[tuple] = append(p.FactCreated[tuple], at)
		}
	}
	return reflect.DeepEqual(emittedSeen, p.Tuples)
}

func (p rid03DeltaPolicy) allows(table string, r rid09PrimaryRow) bool {
	if p.Path == "/iam/v1/grantDelegations" {
		return table == "grant_delegations" && rid03Columns(r, "id account_id delegate_id active_delegate_id role_ids target_types subject_types module status delegated_by_type delegated_by_id created_at revoked_at revoked_by_type revoked_by_id") && reflect.DeepEqual(r, p.Main) && rid03S(r, "id") == p.NewID && rid03S(r, "account_id") == p.Account && rid03S(r, "delegate_id") == p.GDDelegate && rid03S(r, "active_delegate_id") == p.GDDelegate && rid03SameCell(r, "role_ids", []string{p.Role}) && rid03SameCell(r, "target_types", []string{"registry.registries"}) && rid03SameCell(r, "subject_types", []string{"service_account"}) && rid03S(r, "module") == "registry" && rid03S(r, "status") == "ACTIVE" && rid03S(r, "delegated_by_type") == "service_account" && rid03S(r, "delegated_by_id") == p.Creator && rid03SameCell(r, "revoked_at", nil) && rid03SameCell(r, "revoked_by_type", nil) && rid03SameCell(r, "revoked_by_id", nil) && p.bounded(r, "created_at")
	}
	switch table {
	case "access_bindings":
		return rid03Columns(r, "id subject_type subject_id role_id resource_type resource_id created_at status expires_at granted_by_user_id revoked_at revoked_by_user_id scope deletion_protection labels target target_digest granted_relation is_system revocation_reason narrowed_at delegation_id") && reflect.DeepEqual(r, p.Main) && rid03S(r, "id") == p.NewID && rid03S(r, "subject_type") == p.SubjectType && rid03S(r, "subject_id") == p.SubjectID && rid03S(r, "role_id") == p.Role && rid03S(r, "resource_type") == "account" && rid03S(r, "resource_id") == p.Account && rid03S(r, "delegation_id") == p.Delegation && rid03S(r, "status") == "ACTIVE" && rid03SameCell(r, "scope", 2) && rid03SameCell(r, "expires_at", nil) && rid03SameCell(r, "revoked_at", nil) && rid03SameCell(r, "revoked_by_user_id", nil) && rid03SameCell(r, "revocation_reason", nil) && rid03SameCell(r, "narrowed_at", nil) && rid03S(r, "granted_by_user_id") == "" && rid03S(r, "granted_relation") == "" && rid03SameCell(r, "is_system", false) && rid03SameCell(r, "deletion_protection", false) && rid03SameCell(r, "labels", map[string]any{}) && rid03SameCell(r, "target", map[string]any{"resources": []any{map[string]any{"type": p.TargetType, "id": p.TargetID}}}) && rid03S(r, "target_digest") == (domain.AccessTarget{Resources: []domain.ResourceRef{{Type: p.TargetType, ID: p.TargetID}}}).Digest() && p.bounded(r, "created_at")
	case "access_binding_subjects":
		return rid03Columns(r, "binding_id subject_type subject_id ordinal resource_type resource_id") && rid03S(r, "binding_id") == p.NewID && rid03S(r, "subject_type") == p.SubjectType && rid03S(r, "subject_id") == p.SubjectID && rid03SameCell(r, "ordinal", 0) && rid03S(r, "resource_type") == "account" && rid03S(r, "resource_id") == p.Account
	case "access_binding_target_members":
		m := rid03Member{rid03S(r, "binding_id"), rid03S(r, "role_id"), rid03S(r, "rule_fp"), rid03S(r, "object_type"), rid03S(r, "object_id")}
		return rid03Columns(r, "binding_id object_type object_id verification_status created_at updated_at role_id rule_fp live") && p.Members[m] && rid03S(r, "verification_status") == "ACTIVE" && rid03SameCell(r, "live", true) && p.bounded(r, "created_at") && p.bounded(r, "updated_at")
	case "access_binding_emitted_tuples":
		object := strings.SplitN(rid03S(r, "object"), ":", 2)
		if len(object) != 2 {
			return false
		}
		coord := rid03Ledger{rid03S(r, "binding_id"), rid03S(r, "source"), rid03S(r, "member_object_type"), rid03S(r, "member_object_id"), rid03Tuple{rid03S(r, "fga_user"), rid03S(r, "relation"), object[0], object[1]}}
		return rid03Columns(r, "binding_id fga_user relation object source member_object_type member_object_id") && p.Ledger[coord]
	case "relation_fact":
		tuple := rid03Tuple{rid03S(r, "subject"), rid03S(r, "relation"), rid03S(r, "object_type"), rid03S(r, "object_id")}
		version, versionOK := rid03Cell[time.Time](r, "source_version")
		created, createdOK := rid03Cell[time.Time](r, "created_at")
		expected, proved := p.FactVersions[tuple]
		clocks, firstProved := p.FactCreated[tuple]
		backedCreation := false
		for _, clock := range clocks {
			if created.Equal(clock) {
				backedCreation = true
			}
		}
		return rid03Columns(r, "object_type object_id relation subject source_version created_at condition_name condition_params") && p.DirectTuples[tuple] && proved && firstProved && versionOK && createdOK && version.Equal(expected) && backedCreation && rid03S(r, "condition_name") == "" && rid03SameCell(r, "condition_params", map[string]any{}) && p.bounded(r, "created_at")
	case "fga_outbox":
		_, _, ok := p.producer(r)
		return ok
	case "subject_change_outbox":
		return rid03Columns(r, "id subject_id op created_at event_type payload") && rid03S(r, "subject_id") == p.SubjectID && rid03S(r, "op") == "binding_upsert" && rid03S(r, "event_type") == "binding_grant" && rid03SameCell(r, "payload", map[string]any{"subject_id": p.SubjectID, "subject_type": p.SubjectType, "op": "binding_upsert", "event_type": "binding_grant"}) && p.bounded(r, "created_at")
	case "resource_reconcile_outbox":
		return rid03Columns(r, "id object_type object_id event_type created_at sent_at last_error attempt_count") && rid03S(r, "object_type") == "iam.accessBinding" && rid03S(r, "object_id") == p.NewID && rid03S(r, "event_type") == "mirror.upsert" && rid03SameCell(r, "last_error", nil) && rid03SameCell(r, "attempt_count", 0) && p.bounded(r, "created_at") && p.bounded(r, "sent_at")
	case "resource_journal":
		return rid03Columns(r, "sequence_no resource_kind resource_id project_id scope event_type payload created_at") && rid03S(r, "resource_kind") == "iam_access_binding" && rid03S(r, "resource_id") == p.NewID && rid03S(r, "project_id") == "" && rid03SameCell(r, "scope", []any{map[string]any{"type": "account", "id": p.Account}}) && (rid03S(r, "event_type") == "CREATED" || rid03S(r, "event_type") == "UPDATED") && rid03SameCell(r, "payload", map[string]any{"id": p.NewID}) && p.bounded(r, "created_at")
	}
	return false
}

// Technical fga_outbox multiplicity is intentionally absent. Existing business
// row counts remain exact; this does not relax the separate G/GD/Operation/audit
// primary or native predicates.
func rid03BusinessCountsValid(counts map[string]int) bool {
	for table, want := range map[string]int{"access_bindings": 1, "access_binding_subjects": 1, "subject_change_outbox": 1, "resource_reconcile_outbox": 1, "resource_journal": 2, "journal-CREATED": 1, "journal-UPDATED": 1} {
		if counts[table] != want {
			return false
		}
	}
	return true
}
func rid03RequireClosedDelta(t *testing.T, a, b rid03NewmanSnapshot, p rid03DeltaPolicy) {
	t.Helper()
	// Establish producer provenance before any physical fact is admitted.
	if p.Path == "/iam/v1/accessBindings" {
		old := map[string]int{}
		for _, row := range a.Raw["fga_outbox"] {
			old[rid03RawDigest(t, row)]++
		}
		fresh := []rid09PrimaryRow{}
		for _, row := range b.Raw["fga_outbox"] {
			digest := rid03RawDigest(t, row)
			if old[digest] > 0 {
				old[digest]--
				continue
			}
			fresh = append(fresh, row)
		}
		require.True(t, p.bindProducers(fresh), "FIXTURE_NOT_ACCEPTED: closed ordinary producer rows with complete independently derived tuple coverage required")
	}
	counts := map[string]int{}
	memberSeen := map[rid03Member]bool{}
	ledgerSeen := map[rid03Ledger]bool{}
	tupleSeen := map[rid03Tuple]bool{}
	for table, oldRows := range a.Raw {
		if table == "operations" {
			continue
		}
		now, exists := b.Raw[table]
		require.True(t, exists)
		remaining := map[string]int{}
		for _, r := range oldRows {
			remaining[rid03RawDigest(t, r)]++
		}
		for _, r := range now {
			hash := rid03RawDigest(t, r)
			if remaining[hash] > 0 {
				remaining[hash]--
				continue
			}
			require.True(t, p.allows(table, r), "unexpected raw delta in %s: exact coordinates/closed columns required; safe census retained", table)
			counts[table]++
			if table == "resource_journal" {
				counts["journal-"+rid03S(r, "event_type")]++
			}
			if table == "access_binding_target_members" {
				m := rid03Member{rid03S(r, "binding_id"), rid03S(r, "role_id"), rid03S(r, "rule_fp"), rid03S(r, "object_type"), rid03S(r, "object_id")}
				require.False(t, memberSeen[m])
				memberSeen[m] = true
			}
			if table == "access_binding_emitted_tuples" {
				obj := strings.SplitN(rid03S(r, "object"), ":", 2)
				l := rid03Ledger{rid03S(r, "binding_id"), rid03S(r, "source"), rid03S(r, "member_object_type"), rid03S(r, "member_object_id"), rid03Tuple{rid03S(r, "fga_user"), rid03S(r, "relation"), obj[0], obj[1]}}
				require.False(t, ledgerSeen[l])
				ledgerSeen[l] = true
			}
			if table == "relation_fact" {
				tuple := rid03Tuple{rid03S(r, "subject"), rid03S(r, "relation"), rid03S(r, "object_type"), rid03S(r, "object_id")}
				require.False(t, tupleSeen[tuple])
				tupleSeen[tuple] = true
			}
		}
		for _, n := range remaining {
			require.Zero(t, n, "no old raw row update/deletion allowed in %s", table)
		}
	}
	require.Equal(t, len(a.Raw), len(b.Raw))
	if p.Path != "/iam/v1/accessBindings" {
		require.Equal(t, 1, counts["grant_delegations"])
		return
	}
	require.True(t, rid03BusinessCountsValid(counts), "exact business row multiplicities required")
	require.Equal(t, p.Members, memberSeen)
	require.Equal(t, p.Ledger, ledgerSeen)
	// A tuple already present before ACT is a retained shared claim. Every other
	// independently derived tuple must appear exactly once as a new direct fact.
	for _, r := range a.Raw["relation_fact"] {
		delete(p.DirectTuples, rid03Tuple{rid03S(r, "subject"), rid03S(r, "relation"), rid03S(r, "object_type"), rid03S(r, "object_id")})
	}
	require.Equal(t, p.DirectTuples, tupleSeen)
	for table, want := range map[string]int{"access_bindings": 1, "access_binding_subjects": 1, "subject_change_outbox": 1, "resource_reconcile_outbox": 1, "resource_journal": 2} {
		require.Equal(t, want, counts[table], fmt.Sprintf("exact business row count %s", table))
	}
	require.Equal(t, 1, counts["journal-CREATED"])
	require.Equal(t, 1, counts["journal-UPDATED"])
	// All technical rows and their actual multiplicity remain in full snapshots.
	// No producer-call count or partition is asserted.
	t.Logf("RID03 technical FGA intents: actual new rows=%d; full raw rows/clocks retained separately from exact business counts", counts["fga_outbox"])
}
