// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
)

func rid11RestoreRoles(t *testing.T, raw map[string][]rid09PrimaryRow, facts *catalog.Facts) []map[string]any {
	t.Helper()
	out := []map[string]any{}
	withdrawn := map[domain.RoleID][]domain.WithdrawnGrant{}
	orphanRows := raw["role_grant_orphan"]
	sort.Slice(orphanRows, func(i, j int) bool {
		for _, key := range []string{"role_id", "object_type", "verb", "source", "cause"} {
			a, b := rid09PrimaryValue[string](t, orphanRows[i], key), rid09PrimaryValue[string](t, orphanRows[j], key)
			if a != b {
				return a < b
			}
		}
		return false
	})
	for _, r := range orphanRows {
		g := domain.WithdrawnGrant{ObjectType: rid09PrimaryValue[string](t, r, "object_type"), Verb: rid09PrimaryValue[string](t, r, "verb"), Reason: rid09PrimaryValue[string](t, r, "reason"), WithdrawnAt: rid09PrimaryValue[time.Time](t, r, "orphaned_at").Truncate(time.Second), AppliedBy: rid09PrimaryValue[string](t, r, "applied_by")}
		switch rid09PrimaryValue[string](t, r, "source") {
		case "role_verb":
			g.Source = domain.WithdrawnGrantSourceGrant
		case "rule_ref":
			g.Source = domain.WithdrawnGrantSourceRuleRef
		default:
			t.Fatal("unknown primary withdrawal source")
		}
		switch rid09PrimaryValue[string](t, r, "cause") {
		case "catalog_retired":
			g.Cause = domain.WithdrawnGrantCauseCatalogRetired
		case "role_retired":
			g.Cause = domain.WithdrawnGrantCauseRoleRetired
		default:
			t.Fatal("unknown primary withdrawal cause")
		}
		id := rid09PrimaryValue[domain.RoleID](t, r, "role_id")
		withdrawn[id] = append(withdrawn[id], g)
	}
	pruned := map[domain.RoleID][]domain.PrunedSelectorType{}
	// Storage may differ by rule digest while public semantics are DISTINCT on the
	// following six fields (same exact projection as the documented read contract).
	seenPrune := map[string]bool{}
	pruneRows := append([]rid09PrimaryRow(nil), raw["role_selector_prune"]...)
	sort.SliceStable(pruneRows, func(i, j int) bool {
		for _, k := range []string{"role_id", "object_type", "outcome"} {
			a, b := rid03S(pruneRows[i], k), rid03S(pruneRows[j], k)
			if a != b {
				return a < b
			}
		}
		return false
	})
	for _, row := range pruneRows {
		id := rid09PrimaryValue[string](t, row, "role_id")
		outcome := rid09PrimaryValue[string](t, row, "outcome")
		p := domain.PrunedSelectorType{ObjectType: rid09PrimaryValue[string](t, row, "object_type"), Reason: rid09PrimaryValue[string](t, row, "retired_reason"), PrunedAt: rid09PrimaryValue[time.Time](t, row, "pruned_at").Truncate(time.Second), AppliedBy: rid09PrimaryValue[string](t, row, "applied_by")}
		key := rid03EvidenceHash([]any{id, outcome, p.ObjectType, p.Reason, row["pruned_at"], p.AppliedBy})
		if seenPrune[key] {
			continue
		}
		seenPrune[key] = true
		switch outcome {
		case "shortened":
			p.Outcome = domain.SelectorPruneOutcomeShortened
		case "dropped":
			p.Outcome = domain.SelectorPruneOutcomeDropped
		default:
			t.Fatal("unknown retained primary prune outcome")
		}
		pruned[domain.RoleID(id)] = append(pruned[domain.RoleID(id)], p)
	}
	var err error
	for _, r := range raw["roles"] {
		d := domain.Role{ID: rid09PrimaryValue[domain.RoleID](t, r, "id"), ClusterID: rid09PrimaryValue[domain.ClusterID](t, r, "cluster_id"), AccountID: rid09PrimaryValue[domain.AccountID](t, r, "account_id"), ProjectID: rid09PrimaryValue[domain.ProjectID](t, r, "project_id"), Name: rid09PrimaryValue[domain.RoleName](t, r, "name"), Description: rid09PrimaryValue[domain.Description](t, r, "description"), IsSystem: rid09PrimaryValue[bool](t, r, "is_system"), OwnerModule: rid09PrimaryValue[string](t, r, "owner_module"), CreatedAt: rid09PrimaryValue[time.Time](t, r, "created_at"), UpdatedAt: rid09PrimaryValue[time.Time](t, r, "updated_at"), Labels: rid09PrimaryValue[domain.Labels](t, r, "labels")}
		d.Rules, err = domain.DecodeRules(r["rules"])
		require.NoError(t, err)
		// CreatedByUserID is deliberately not a roles column read by roleCols. Its
		// zero value matches the actual stored-to-domain reader, not an invented actor.
		declared := domain.SegmentsOf(d.ID, d.Rules)
		unresolved := []domain.RoleSegment{}
		for _, seg := range declared {
			if _, container := facts.ContainerVerb(seg.ObjectType, seg.Verb); container {
				continue
			}
			present := false
			for _, v := range raw["role_verb"] {
				if rid03S(v, "role_id") == string(d.ID) && rid03S(v, "object_type") == seg.ObjectType && (seg.Verb == "" || rid03S(v, "verb") == seg.Verb) {
					present = true
				}
			}
			if !present {
				unresolved = append(unresolved, seg)
			}
		}
		d.Integrity = domain.HealthOf(len(declared), len(unresolved))
		d.Withdrawn = withdrawn[d.ID]
		d.PrunedSelectorTypes = pruned[d.ID]
		d.TypeVerbs = facts.RolePreviewLookup()
		d.RuleStates = domain.RuleStatesOf(d.Rules, unresolved, d.Withdrawn)
		d.Lifecycle = domain.RoleLifecycle{State: domain.RoleLifecycleDeclared}
		if !rid09PrimaryValue[bool](t, r, "live") {
			d.Lifecycle.State = domain.RoleLifecycleWithdrawn
		}
		if at := rid09PrimaryValue[*time.Time](t, r, "retired_at"); at != nil {
			d.Lifecycle.RetiredAt = at.Truncate(time.Second)
		}
		d.Lifecycle.RetiredReason = rid09PrimaryValue[string](t, r, "retired_reason")
		d.Lifecycle.RetiredBy = rid09PrimaryValue[string](t, r, "retired_by")
		var pb *iamv1.Role
		require.NoError(t, dto.Transfer(dto.FromTo(d, &pb)))
		out = append(out, rid09PrimaryJSON(t, pb))
	}
	return out
}

// This oracle applies ONLY across failed census -> ordinary StartBase. Each
// public READ still uses the unchanged strict comparator. It never reads AFTER
// to choose eligible roles, privileges, selector coordinates or public fields.
// Sources: seed/role_verb_reseed.go; seed/role_rule_ref_reseed.go;
// seed/migrate_backfill.go BackfillOwnerBindings/syncAllSystemRoleSelectorsTx.
type rid11RestorePlan struct {
	Raw               map[string][]rid09PrimaryRow
	Eligible          map[string]bool
	Selectors         map[string]rid09PrimaryRow
	ExistingSelectors map[string]rid09PrimaryRow
	Facts             *catalog.Facts
}

var rid11RestoreSchemas = map[string][]string{
	"role_verb":                   {"role_id", "object_type", "verb", "live"},
	"role_rule_ref":               {"role_id", "module", "resource", "verb", "live"},
	"role_selector_verbs_pending": {"role_id", "enqueued_at"},
	"role_rule_selectors":         {"role_id", "rule_fp", "object_types", "match_labels", "created_at", "updated_at", "arm", "resource_names", "live", "container_type", "container_object_type", "container_arm", "container_resource_names", "container_match_labels", "verbs_by_type", "created_by_subject"},
}

func rid11RestoreError() error {
	return errors.New("FIXTURE_NOT_ACCEPTED: census restoration primary shape or producer contract")
}
func rid11RestoreRow(v map[string]any) rid09PrimaryRow {
	r := rid09PrimaryRow{}
	for k, x := range v {
		r[k], _ = json.Marshal(x)
	}
	return r
}
func rid11RestoreClone(r rid09PrimaryRow) rid09PrimaryRow {
	n := rid09PrimaryRow{}
	for k, v := range r {
		n[k] = append(json.RawMessage(nil), v...)
	}
	return n
}
func rid11RestoreKeys(r rid09PrimaryRow, keys []string) bool {
	if len(r) != len(keys) {
		return false
	}
	for _, k := range keys {
		if _, ok := r[k]; !ok {
			return false
		}
	}
	return true
}
func rid11RestoreRowsEqual(a, b []rid09PrimaryRow) bool {
	encode := func(rows []rid09PrimaryRow) []string {
		out := []string{}
		for _, r := range rows {
			var normalized any
			v, _ := json.Marshal(r)
			if json.Unmarshal(v, &normalized) != nil {
				return nil
			}
			v, _ = json.Marshal(normalized)
			out = append(out, string(v))
		}
		sort.Strings(out)
		return out
	}
	return reflect.DeepEqual(encode(a), encode(b))
}
func rid11RestoreGet[T any](r rid09PrimaryRow, k string) (T, error) {
	var v T
	raw, ok := r[k]
	if !ok || len(raw) == 0 || string(raw) == "null" {
		return v, rid11RestoreError()
	}
	if json.Unmarshal(raw, &v) != nil {
		return v, rid11RestoreError()
	}
	return v, nil
}
func rid11RestoreArm(a domain.Arm) string {
	switch a {
	case domain.ArmNames:
		return "names"
	case domain.ArmLabels:
		return "labels"
	default:
		return "anchor"
	}
}
func rid11RestoreStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
func rid11RestoreLabels(m map[string]string) map[string]string {
	if m == nil {
		return map[string]string{}
	}
	return m
}

// Facts are reconstructed from retained BEFORE physical rows, not the saved
// pointer or public catalog. Raw catalog rows remain strict in the comparator.
func rid11RestoreFacts(t *testing.T, raw map[string][]rid09PrimaryRow) *catalog.Facts {
	t.Helper()
	halves := catalog.Halves{}
	for _, r := range raw["catalog_module"] {
		h := &halves.Live
		if !rid09PrimaryValue[bool](t, r, "live") {
			h = &halves.Retired
		}
		h.Modules = append(h.Modules, rid09PrimaryValue[string](t, r, "module"))
	}
	for _, r := range raw["catalog_resource"] {
		d := catalog.ResourceRow{Module: rid09PrimaryValue[string](t, r, "module"), Resource: rid09PrimaryValue[string](t, r, "resource"), ObjectType: rid09PrimaryValue[string](t, r, "object_type")}
		h := &halves.Live
		if rid09PrimaryValue[bool](t, r, "live") {
			d.ParentTypes = rid09PrimaryValue[[]string](t, r, "parent_types")
			d.ParentNames = rid09PrimaryValue[[]string](t, r, "parent_names")
			d.Writes = rid09PrimaryValue[[]string](t, r, "writes")
			d.PublicReadToChildren = rid09PrimaryValue[bool](t, r, "public_read_to_children")
			d.PermanentProject = rid09PrimaryValue[bool](t, r, "permanent_project")
		} else {
			h = &halves.Retired
			d.SupersededBy = rid09PrimaryValue[string](t, r, "superseded_by")
		}
		h.Resources = append(h.Resources, d)
	}
	for _, r := range raw["catalog_verb"] {
		d := catalog.VerbRow{Module: rid09PrimaryValue[string](t, r, "module"), Resource: rid09PrimaryValue[string](t, r, "resource"), Verb: rid09PrimaryValue[string](t, r, "verb"), PerObject: rid09PrimaryValue[bool](t, r, "per_object"), ContainerParent: rid09PrimaryValue[string](t, r, "container_parent"), ContainerRelation: rid09PrimaryValue[string](t, r, "container_relation")}
		h := &halves.Live
		if !rid09PrimaryValue[bool](t, r, "live") {
			h = &halves.Retired
		}
		h.Verbs = append(h.Verbs, d)
	}
	facts, err := catalog.NewFacts(halves)
	require.True(t, err == nil, "retained catalog must form valid immutable facts")
	return facts
}
func rid11BuildRestorePlan(raw map[string][]rid09PrimaryRow, facts *catalog.Facts) (rid11RestorePlan, error) {
	p := rid11RestorePlan{Raw: map[string][]rid09PrimaryRow{}, Eligible: map[string]bool{}, Selectors: map[string]rid09PrimaryRow{}, ExistingSelectors: map[string]rid09PrimaryRow{}, Facts: facts}
	if facts == nil {
		return p, rid11RestoreError()
	}
	for table, rows := range raw {
		p.Raw[table] = []rid09PrimaryRow{}
		for _, r := range rows {
			p.Raw[table] = append(p.Raw[table], rid11RestoreClone(r))
		}
	}
	for table, keys := range rid11RestoreSchemas {
		rows, ok := raw[table]
		if !ok {
			return p, rid11RestoreError()
		}
		for _, r := range rows {
			if !rid11RestoreKeys(r, keys) {
				return p, rid11RestoreError()
			}
		}
	}
	seenRoles := map[string]bool{}
	for _, r := range raw["roles"] {
		id, e := rid11RestoreGet[string](r, "id")
		if e != nil || id == "" || seenRoles[id] {
			return p, rid11RestoreError()
		}
		seenRoles[id] = true
		live, e := rid11RestoreGet[bool](r, "live")
		if e != nil {
			return p, e
		}
		system, e := rid11RestoreGet[bool](r, "is_system")
		if e != nil {
			return p, e
		}
		rules, err := domain.DecodeRules(r["rules"])
		if err != nil {
			return p, rid11RestoreError()
		}
		if !live || !system || len(rules) == 0 {
			continue
		}
		owner, e := rid11RestoreGet[string](r, "owner_module")
		if e != nil {
			if string(r["owner_module"]) != "null" {
				return p, e
			}
			owner = ""
		}
		p.Eligible[id] = true
		policy := domain.PolicyOfRole(system, owner)
		sels := facts.GrantSelectors(rules.MaterializingSelectors(), policy)
		for _, v := range facts.RoleVerbsFromSelectors(sels, policy) {
			p.Raw["role_verb"] = append(p.Raw["role_verb"], rid11RestoreRow(map[string]any{"role_id": id, "object_type": v.ObjectType, "verb": v.Verb, "live": true}))
		}
		for _, ref := range domain.RuleRefsOf(rules) {
			var verb any
			if !ref.IsAnchor() {
				verb = ref.Verb
			}
			p.Raw["role_rule_ref"] = append(p.Raw["role_rule_ref"], rid11RestoreRow(map[string]any{"role_id": id, "module": ref.Module, "resource": ref.Resource, "verb": verb, "live": true}))
		}
		// BackfillOwnerBindings first reprojects complete selectors from unfiltered
		// MaterializingSelectors. The following reseed fills exact per-rule grants.
		for _, sel := range sels {
			if len(sel.ObjectTypes) == 0 {
				continue
			}
			key := id + "\x00" + sel.RuleFP
			if _, ok := p.Selectors[key]; ok {
				return p, rid11RestoreError()
			}
			var ct, co, ca any
			cn := []string{}
			cl := map[string]string{}
			if c := sel.Container; c != nil {
				ct = c.Type
				model, ok := facts.FGAObjectType(c.Type)
				if !ok {
					return p, rid11RestoreError()
				}
				co = model
				ca = rid11RestoreArm(c.Arm)
				cn = rid11RestoreStrings(c.ResourceNames)
				cl = rid11RestoreLabels(c.MatchLabels)
			}
			// Only object_types actually stored by the sync can be regrained; no
			// privilege or unrelated catalog key is imported from another rule.
			grants := map[string][]string{}
			for _, typ := range sel.ObjectTypes {
				if v, ok := sel.Grants[typ]; ok {
					grants[typ] = v
				}
			}
			p.Selectors[key] = rid11RestoreRow(map[string]any{"role_id": id, "rule_fp": sel.RuleFP, "object_types": sel.ObjectTypes, "match_labels": rid11RestoreLabels(sel.MatchLabels), "arm": rid11RestoreArm(sel.Arm), "resource_names": rid11RestoreStrings(sel.ResourceNames), "live": true, "container_type": ct, "container_object_type": co, "container_arm": ca, "container_resource_names": cn, "container_match_labels": cl, "verbs_by_type": grants, "created_by_subject": sel.CreatedBySubject})
		}
	}
	// Replace, never union, eligible projections. Keep full unrelated rows.
	for _, table := range []string{"role_verb", "role_rule_ref"} {
		derived := p.Raw[table][len(raw[table]):]
		p.Raw[table] = []rid09PrimaryRow{}
		for _, r := range raw[table] {
			if !p.Eligible[rid03S(r, "role_id")] {
				p.Raw[table] = append(p.Raw[table], rid11RestoreClone(r))
			}
		}
		p.Raw[table] = append(p.Raw[table], derived...)
	}
	p.Raw["role_selector_verbs_pending"] = []rid09PrimaryRow{}
	for _, r := range raw["role_selector_verbs_pending"] {
		if !p.Eligible[rid03S(r, "role_id")] {
			p.Raw["role_selector_verbs_pending"] = append(p.Raw["role_selector_verbs_pending"], rid11RestoreClone(r))
		}
	}
	seen := map[string]bool{}
	for _, r := range raw["role_rule_selectors"] {
		key := rid03S(r, "role_id") + "\x00" + rid03S(r, "rule_fp")
		if seen[key] {
			return p, rid11RestoreError()
		}
		seen[key] = true
		p.ExistingSelectors[key] = r
	}
	return p, nil
}

// The ONLY clock allowance is the independently identified common-transaction
// syncAllSystemRoleSelectorsTx UPSERT. Regrain itself grants no timestamp edits.
func rid11RestoreSelectorsValid(p rid11RestorePlan, actual []rid09PrimaryRow, lower, upper time.Time) bool {
	if lower.IsZero() || upper.Before(lower) {
		return false
	}
	seen := map[string]bool{}
	var syncClock time.Time
	for _, r := range actual {
		if !rid11RestoreKeys(r, rid11RestoreSchemas["role_rule_selectors"]) {
			return false
		}
		key := rid03S(r, "role_id") + "\x00" + rid03S(r, "rule_fp")
		if seen[key] {
			return false
		}
		seen[key] = true
		if !p.Eligible[rid03S(r, "role_id")] {
			old, ok := p.ExistingSelectors[key]
			if !ok || !rid11RestoreRowsEqual([]rid09PrimaryRow{old}, []rid09PrimaryRow{r}) {
				return false
			}
			continue
		}
		expected, ok := p.Selectors[key]
		if !ok {
			return false
		}
		at, e := rid11RestoreGet[time.Time](r, "updated_at")
		if e != nil || at.Before(lower) || at.After(upper) {
			return false
		}
		if !syncClock.IsZero() && !syncClock.Equal(at) {
			return false
		}
		syncClock = at
		created, e := rid11RestoreGet[time.Time](r, "created_at")
		if e != nil || created.IsZero() || created.After(at) {
			return false
		}
		if old, ok := p.ExistingSelectors[key]; ok {
			oldCreated, e := rid11RestoreGet[time.Time](old, "created_at")
			if e != nil || !created.Equal(oldCreated) {
				return false
			}
			oldUpdated, e := rid11RestoreGet[time.Time](old, "updated_at")
			if e != nil || oldUpdated.IsZero() || oldUpdated.After(lower) || oldCreated.After(oldUpdated) {
				return false
			}
		} else if !created.Equal(at) {
			return false
		}
		for k, v := range expected {
			if !rid11RestoreRowsEqual([]rid09PrimaryRow{{k: v}}, []rid09PrimaryRow{{k: r[k]}}) {
				return false
			}
		}
	}
	for key := range p.Selectors {
		if !seen[key] {
			return false
		}
	}
	for key, r := range p.ExistingSelectors {
		if !p.Eligible[rid03S(r, "role_id")] && !seen[key] {
			return false
		}
	}
	return true
}
func rid11RestoreRawValid(p rid11RestorePlan, a rid03NewmanSnapshot, b rid03NewmanSnapshot) bool {
	if len(p.Raw) != len(b.Raw) || !reflect.DeepEqual(a.Whole.Separation, b.Whole.Separation) || len(a.Whole.Delivery) != len(b.Whole.Delivery) {
		return false
	}
	for table, rows := range p.Raw {
		actual, ok := b.Raw[table]
		if !ok {
			return false
		}
		if table == "role_rule_selectors" {
			if !rid11RestoreSelectorsValid(p, actual, a.Whole.PrimaryFinishedAt, b.Whole.PrimaryStartedAt) {
				return false
			}
		} else if !rid11RestoreRowsEqual(rows, actual) {
			return false
		}
	}
	for table, old := range a.Whole.Delivery {
		now, ok := b.Whole.Delivery[table]
		if !ok || !reflect.DeepEqual(old.Columns, now.Columns) {
			return false
		}
		if keys, allowed := rid11RestoreSchemas[table]; allowed {
			cols := append([]string(nil), old.Columns...)
			want := append([]string(nil), keys...)
			sort.Strings(cols)
			sort.Strings(want)
			if !reflect.DeepEqual(cols, want) {
				return false
			}
		} else if !reflect.DeepEqual(old, now) {
			return false
		}
	}
	return reflect.DeepEqual(a.BusinessAudit, b.BusinessAudit)
}

// No raw operation/auth table cells escape. Diagnostics are unconditional and
// precede any oracle assertion, including schema/DTO decoding failures.
func rid11RequireCensusRestoration(t *testing.T, w *ridLifecycleWorld, a, b rid03NewmanSnapshot) {
	t.Helper()
	rid08Write(t, w.f.session.Root, "rid11-census-restoration-coordinate-diagnostic", rid11CoordinateDiagnostic(a, b))
	type delta struct {
		BeforeColumns, AfterColumns []string
		BeforeCount, AfterCount     int
		BeforeHash, AfterHash       string
		ColumnHashes                map[string][2]string
	}
	census := map[string]delta{}
	tables := map[string]bool{}
	for k := range a.Raw {
		tables[k] = true
	}
	for k := range b.Raw {
		tables[k] = true
	}
	for table := range tables {
		ar, br := a.Raw[table], b.Raw[table]
		cols := map[string]bool{}
		for _, rows := range [][]rid09PrimaryRow{ar, br} {
			for _, r := range rows {
				for c := range r {
					cols[c] = true
				}
			}
		}
		ch := map[string][2]string{}
		for col := range cols {
			hash := func(rows []rid09PrimaryRow) string {
				cells := []string{}
				for _, r := range rows {
					if v, ok := r[col]; ok {
						cells = append(cells, rid03EvidenceHash(v))
					} else {
						cells = append(cells, "MISSING")
					}
				}
				sort.Strings(cells)
				return rid03EvidenceHash(cells)
			}
			ch[col] = [2]string{hash(ar), hash(br)}
		}
		ac, bc := a.Whole.Delivery[table].Columns, b.Whole.Delivery[table].Columns
		if table == "operations" {
			ac, bc = a.Whole.Bookkeeping[table].Columns, b.Whole.Bookkeeping[table].Columns
		}
		census[table] = delta{ac, bc, len(ar), len(br), rid03EvidenceHash(ar), rid03EvidenceHash(br), ch}
	}
	rid08Write(t, w.f.session.Root, "rid11-census-restoration-all-table-diagnostics", map[string]any{"sourceDerivedOracle": true, "actualNewmanExecuted": false, "wholeDoDAccepted": false, "beforeWhole": a.Whole, "afterWhole": b.Whole, "tables": census, "beforeProjectionSHA256": rid03EvidenceHash(a.Projection), "afterProjectionSHA256": rid03EvidenceHash(b.Projection), "beforeBusinessSHA256": rid03EvidenceHash(a.BusinessAudit), "afterBusinessSHA256": rid03EvidenceHash(b.BusinessAudit)})
	facts := rid11RestoreFacts(t, a.Raw)
	p, err := rid11BuildRestorePlan(a.Raw, facts)
	require.True(t, err == nil, "closed BEFORE restoration premise")
	require.True(t, rid11RestoreRawValid(p, a, b), "exact source-derived restoration raw delta; safe all-column diagnostics retained")
	expected := a.Projection
	expected.Roles = rid11RestoreRoles(t, p.Raw, facts)
	require.True(t, reflect.DeepEqual(expected, b.Projection), "complete independently derived restoration projection")
	rid04RequireGDGUnchanged(t, a, b)
	ridRequireOwnCeilingsPreserved(t, a.Whole, b.Whole)
	require.True(t, reflect.DeepEqual(a.Whole.Bookkeeping["operations"], b.Whole.Bookkeeping["operations"]), "zero new/unchanged complete operations")
	rid08Write(t, w.f.session.Root, "rid11-census-restoration-accepted", map[string]any{"sourceDerivedOracle": true, "actualNewmanExecuted": false, "wholeDoDAccepted": false, "eligibleRoleCount": len(p.Eligible), "beforeDerivedRoleVerbSHA256": rid03EvidenceHash(p.Raw["role_verb"]), "beforeDerivedRuleRefSHA256": rid03EvidenceHash(p.Raw["role_rule_ref"]), "beforeDerivedSelectorSemanticsSHA256": rid03EvidenceHash(p.Selectors), "selectorClockLower": a.Whole.PrimaryFinishedAt, "selectorClockUpper": b.Whole.PrimaryStartedAt, "actualRawSHA256": rid03EvidenceHash(b.Raw), "expectedProjectionSHA256": rid03EvidenceHash(expected), "actualProjectionSHA256": rid03EvidenceHash(b.Projection)})
}
