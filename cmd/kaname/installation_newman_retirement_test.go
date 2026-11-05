// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
)

var rid04NewmanActors = map[string]string{
	"registry-installation-rid04-S1-BEFORE-RETIREMENT":      "O",
	"registry-installation-rid04-S1-RETIRED-DENIED-ACT":     "I",
	"registry-installation-rid04-S1-RETIRED-DENIED-VERIFY":  "O",
	"registry-installation-rid04-S1-REFUSED-APPLY-SNAPSHOT": "O",
	"registry-installation-rid04-S1-RESTORED-GRANT-ACT":     "I",
	"registry-installation-rid04-S1-RESTORED-GRANT-VERIFY":  "O",
	"registry-installation-rid04-S1-RESTORED-REAPPLY":       "O",
	"registry-installation-rid04-S2-BEFORE-RETIREMENT":      "O",
	"registry-installation-rid04-S2-RETIRED-DENIED-ACT":     "I",
	"registry-installation-rid04-S2-RETIRED-DENIED-VERIFY":  "O",
	"registry-installation-rid04-S2-REFUSED-APPLY-SNAPSHOT": "O",
	"registry-installation-rid04-S2-RESTORED-GRANT-ACT":     "I",
	"registry-installation-rid04-S2-RESTORED-GRANT-VERIFY":  "O",
	"registry-installation-rid04-S2-RESTORED-REAPPLY":       "O",
}
var rid04NewmanPhases = map[string]string{
	"registry-installation-rid04-S1-BEFORE-RETIREMENT":      "READ",
	"registry-installation-rid04-S1-RETIRED-DENIED-ACT":     "ACT",
	"registry-installation-rid04-S1-RETIRED-DENIED-VERIFY":  "VERIFY",
	"registry-installation-rid04-S1-REFUSED-APPLY-SNAPSHOT": "READ",
	"registry-installation-rid04-S1-RESTORED-GRANT-ACT":     "ACT",
	"registry-installation-rid04-S1-RESTORED-GRANT-VERIFY":  "VERIFY",
	"registry-installation-rid04-S1-RESTORED-REAPPLY":       "READ",
	"registry-installation-rid04-S2-BEFORE-RETIREMENT":      "READ",
	"registry-installation-rid04-S2-RETIRED-DENIED-ACT":     "ACT",
	"registry-installation-rid04-S2-RETIRED-DENIED-VERIFY":  "VERIFY",
	"registry-installation-rid04-S2-REFUSED-APPLY-SNAPSHOT": "READ",
	"registry-installation-rid04-S2-RESTORED-GRANT-ACT":     "ACT",
	"registry-installation-rid04-S2-RESTORED-GRANT-VERIFY":  "VERIFY",
	"registry-installation-rid04-S2-RESTORED-REAPPLY":       "READ",
}

func rid04NewmanActor(id string) (string, bool) { actor, ok := rid04NewmanActors[id]; return actor, ok }
func rid04BuildTechnicalReceipt(e *rid03NewmanExpectation, a, b rid03NewmanSnapshot, p *rid03DeltaPolicy) (rid03TechnicalReceipt, bool) {
	phase, ok := rid04NewmanPhases[e.CaseID]
	if !ok || phase != e.Phase {
		return rid03TechnicalReceipt{}, false
	}
	return ridNewmanBuildClosedTechnicalReceipt(e, a, b, p)
}

type rid04PublicContext struct {
	owner                                                    string
	body                                                     map[string]any
	bodySHA256                                               string
	oldGrant                                                 string
	beforeRetirement, beforeFailure, preRestore, beforeApply *rid03NewmanSnapshot
	refusalProof                                             bool
}
type rid04NewmanExpectation struct {
	rid03NewmanExpectation
	CreatorAuthority bool   `json:"creatorAuthority"`
	OldGrantID       string `json:"oldGrantId"`
}

func rid04PublicConsumer(t *testing.T, w *ridLifecycleWorld, owner string) *rid04PublicContext {
	t.Helper()
	require.Contains(t, []string{"retired", "apply-denied", "recovery"}, owner)
	if os.Getenv("KANAME_RID_NEWMAN") == "1" {
		return &rid04PublicContext{owner: owner}
	}
	for _, suffix := range rid04OwnedSuffixes(owner) {
		id := "registry-installation-rid04-" + rid03Mode(t, w) + "-" + suffix
		_, ok := rid04NewmanActor(id)
		require.True(t, ok)
		rid08Write(t, w.f.session.Root, "newman-"+strings.ToLower(id), map[string]any{"state": "NOT_EXECUTED", "caseId": id, "actualNewmanExecuted": false, "wholeDoDAccepted": false})
	}
	return nil
}
func rid04OwnedSuffixes(owner string) []string {
	switch owner {
	case "retired":
		return []string{"BEFORE-RETIREMENT"}
	case "apply-denied":
		return []string{"REFUSED-APPLY-SNAPSHOT"}
	case "recovery":
		return []string{"RETIRED-DENIED-ACT", "RETIRED-DENIED-VERIFY", "RESTORED-GRANT-ACT", "RESTORED-GRANT-VERIFY", "RESTORED-REAPPLY"}
	}
	return nil
}
func (p *rid04PublicContext) prepare(t *testing.T, w *ridLifecycleWorld, g *iamv1.AccessBinding) {
	if p == nil {
		return
	}
	t.Helper()
	p.oldGrant = g.Id
	if p.owner == "recovery" {
		subject := w.f.ridSA(t, w.f.tenantID, "rid04-public-grantee")
		p.body = w.bindingInput("service_account", subject, w.pull, "registry.registries", w.object)
		p.bodySHA256 = rid03EvidenceHash(p.body)
	}
	before := rid03StableNewmanSnapshot(t, w)
	rid04RequireAuthority(t, w, before, true)
	rid04RequireOldActive(t, w, before, p.oldGrant)
	require.NotEmpty(t, before.BusinessAudit, "normal durable business audit fixture required")
	p.beforeRetirement = &before
	if p.owner == "retired" {
		p.read(t, w, "BEFORE-RETIREMENT", true, before)
	}
}
func (p *rid04PublicContext) retired(t *testing.T, w *ridLifecycleWorld) {
	if p == nil {
		return
	}
	t.Helper()
	after := rid03StableNewmanSnapshot(t, w)
	require.NotNil(t, p.beforeRetirement)
	rid04RequireGDGUnchanged(t, *p.beforeRetirement, after)
	rid04RequireOldActive(t, w, after, p.oldGrant)
	rid04RequireAuthority(t, w, after, false)
	if p.owner == "recovery" {
		p.actionPair(t, w, "RETIRED-DENIED", true, false)
	}
}
func (p *rid04PublicContext) beforeRefusedApply(t *testing.T, w *ridLifecycleWorld) {
	if p == nil {
		return
	}
	before := rid03StableNewmanSnapshot(t, w)
	rid04RequireAuthority(t, w, before, false)
	p.beforeFailure = &before
	p.refusalProof = false
}
func (p *rid04PublicContext) refusalBeforeRestore(t *testing.T, w *ridLifecycleWorld) {
	if p == nil {
		return
	}
	t.Helper()
	require.NotNil(t, p.beforeFailure)
	// Жизнь слушателя не предполагается. Это ограниченное первичное интеграционное доказательство SQL,
	// а не фаза Newman или публичная квитанция.
	after := rid03PhaseSnapshot(t, w)
	ridRequireWholeDeliveryUnchanged(t, p.beforeFailure.Whole, after.Whole)
	require.Equal(t, p.beforeFailure.Projection, after.Projection)
	require.True(t, reflect.DeepEqual(p.beforeFailure.Raw, after.Raw), "failed apply full raw delivery/history/Operations zero before ANY restoration")
	require.Equal(t, p.beforeFailure.BusinessAudit, after.BusinessAudit)
	require.Equal(t, p.beforeFailure.Whole.Bookkeeping["operations"], after.Whole.Bookkeeping["operations"])
	rid04RequireAuthority(t, w, after, false)
	p.preRestore = &after
	p.refusalProof = true
	rid08Write(t, w.f.session.Root, "rid04-"+p.owner+"-"+rid03Mode(t, w)+"-refusal-before-restore", map[string]any{"integrationOnly": true, "actualNewmanExecuted": false, "fullRawZeroDeltaProved": true, "beforeWhole": p.beforeFailure.Whole, "afterWhole": after.Whole, "businessBeforeSHA256": rid03EvidenceHash(p.beforeFailure.BusinessAudit), "businessAfterSHA256": rid03EvidenceHash(after.BusinessAudit), "wholeDoDAccepted": false})
}
func (p *rid04PublicContext) afterRefusedApply(t *testing.T, w *ridLifecycleWorld) {
	if p == nil {
		return
	}
	t.Helper()
	require.True(t, rid04RefusalProofReady(p), "pre-restoration full primary proof is mandatory")
	require.NotNil(t, p.preRestore)
	after := rid03StableNewmanSnapshot(t, w)
	rid04RequireNormalBoundary(t, w, *p.preRestore, after, 0)
	rid04RequireAuthority(t, w, after, false)
	rid04RequireOldActive(t, w, after, p.oldGrant)
}
func (p *rid04PublicContext) completedApplyDenied(t *testing.T, w *ridLifecycleWorld) {
	if p == nil {
		return
	}
	require.Equal(t, "apply-denied", p.owner)
	require.True(t, p.refusalProof)
	s := rid03StableNewmanSnapshot(t, w)
	rid04RequireAuthority(t, w, s, false)
	p.read(t, w, "REFUSED-APPLY-SNAPSHOT", false, s)
}
func (p *rid04PublicContext) restoredGrant(t *testing.T, w *ridLifecycleWorld) {
	if p == nil {
		return
	}
	t.Helper()
	require.Equal(t, "recovery", p.owner)
	require.True(t, p.refusalProof)
	s := rid03StableNewmanSnapshot(t, w)
	rid04RequireAuthority(t, w, s, true)
	rid04RequireOldActive(t, w, s, p.oldGrant)
	p.actionPair(t, w, "RESTORED-GRANT", false, true)
}
func (p *rid04PublicContext) beforeReapply(t *testing.T, w *ridLifecycleWorld) {
	if p == nil {
		return
	}
	before := rid03StableNewmanSnapshot(t, w)
	rid04RequireAuthority(t, w, before, true)
	p.beforeApply = &before
}
func (p *rid04PublicContext) afterReapply(t *testing.T, w *ridLifecycleWorld) {
	if p == nil {
		return
	}
	t.Helper()
	require.NotNil(t, p.beforeApply)
	after := rid03StableNewmanSnapshot(t, w)
	rid04RequireNormalBoundary(t, w, *p.beforeApply, after, len(w.accounts))
	rid04RequireAuthority(t, w, after, true)
	rid04RequireOldActive(t, w, after, p.oldGrant)
	p.read(t, w, "RESTORED-REAPPLY", true, after)
}
func rid04RequireAuthority(t *testing.T, w *ridLifecycleWorld, s rid03NewmanSnapshot, want bool) {
	t.Helper()
	for _, who := range []struct {
		kind, id string
		count    int
	}{{"user", w.f.operator.UserID(), 1}, {"service_account", w.f.creator.ID, map[bool]int{true: 1, false: 0}[want]}} {
		grants, facts := rid04AuthorityCounts(s, who.kind, who.id)
		require.Equal(t, who.count, grants, "durable current authority")
		require.Equal(t, who.count, facts, "materialized current authority; independent O survives")
	}
}
func rid04AuthorityCounts(s rid03NewmanSnapshot, kind, id string) (int, int) {
	grants, facts := 0, 0
	for _, row := range s.Raw["cluster_admin_grants"] {
		if rid03S(row, "cluster_id") != "cluster_root" || rid03S(row, "subject_type") != kind || rid03S(row, "subject_id") != id {
			continue
		}
		if rid03SameCell(row, "granted_until", nil) {
			grants++
			continue
		}
		until, ok := rid03Cell[time.Time](row, "granted_until")
		if ok && until.After(s.Whole.PrimaryStartedAt) {
			grants++
		}
	}
	for _, row := range s.Raw["relation_fact"] {
		if rid03S(row, "object_type") == "cluster" && rid03S(row, "object_id") == "cluster_root" && rid03S(row, "relation") == "system_admin" && rid03S(row, "subject") == kind+":"+id {
			facts++
		}
	}
	return grants, facts
}
func rid04RefusalProofReady(p *rid04PublicContext) bool {
	return p != nil && p.refusalProof && p.preRestore != nil && p.beforeFailure != nil
}
func rid04GDGHistoryEqual(a, b rid03NewmanSnapshot) bool {
	if !reflect.DeepEqual(a.Projection.Delegations, b.Projection.Delegations) || !reflect.DeepEqual(a.Projection.Bindings, b.Projection.Bindings) {
		return false
	}
	selected := func(s rid03NewmanSnapshot) map[string][]rid09PrimaryRow {
		out := map[string][]rid09PrimaryRow{}
		for table, rows := range s.Raw {
			if table == "grant_delegations" || strings.HasPrefix(table, "access_binding") {
				out[table] = rows
			}
		}
		return out
	}
	return reflect.DeepEqual(selected(a), selected(b))
}
func rid04RequireGDGUnchanged(t *testing.T, a, b rid03NewmanSnapshot) {
	t.Helper()
	require.True(t, rid04GDGHistoryEqual(a, b), "full GD/G projection/raw/history survives native boundary")
	require.Equal(t, a.Projection.Delegations, b.Projection.Delegations)
	require.Equal(t, a.Projection.Bindings, b.Projection.Bindings)
	for table, rows := range a.Raw {
		if table == "grant_delegations" || strings.HasPrefix(table, "access_binding") {
			require.Equal(t, rows, b.Raw[table], "full GD/G identities/createdAt/materializedAt/axes/history preserved across native boundary")
		}
	}
}
func rid04RequireOldActive(t *testing.T, w *ridLifecycleWorld, s rid03NewmanSnapshot, oldID string) {
	t.Helper()
	old, gd := false, false
	for _, row := range s.Projection.Bindings {
		if row["id"] == oldID {
			require.Equal(t, "ACTIVE", row["status"])
			require.Equal(t, w.gd.Id, row["delegationId"])
			require.NotNil(t, row["materializedAt"])
			old = true
		}
	}
	for _, row := range s.Projection.Delegations {
		if row["id"] == w.gd.Id {
			require.Equal(t, "ACTIVE", row["status"])
			require.Equal(t, map[string]any{"type": "service_account", "id": w.f.creator.ID}, row["delegatedBy"])
			gd = true
		}
	}
	require.True(t, old && gd)
}
func rid04RequireNormalBoundary(t *testing.T, w *ridLifecycleWorld, a, b rid03NewmanSnapshot, delta int) {
	t.Helper()
	// Штатный нативный запуск может заново проецировать учёт каталога. Это отделено
	// от полной необработанной контрольной точки отказавшего запуска и строгих скобок каждой публичной фазы.
	require.Equal(t, a.Projection, b.Projection)
	rid04RequireGDGUnchanged(t, a, b)
	require.Equal(t, a.BusinessAudit, b.BusinessAudit, "idempotent apply/catalog restore emits no new AB/GD business event")
	ridRequireOwnCeilingsPreserved(t, a.Whole, b.Whole)
	old, now := rid03RowsByID(t, a.Raw["operations"]), rid03RowsByID(t, b.Raw["operations"])
	require.Equal(t, len(old)+delta, len(now), "exact normal Operation count")
	ids := []string{}
	for id, row := range old {
		require.True(t, reflect.DeepEqual(row, now[id]), "every old complete Operation remains exact; no redaction exception")
		ids = append(ids, id)
	}
	if delta > 0 {
		require.Equal(t, len(w.accounts), delta)
		ctx, cancel := context.WithTimeout(w.f.given.ctx, 30*time.Second)
		defer cancel()
		view, fixture, given := *w, *w.f, *w.f.given
		given.ctx = ctx
		fixture.given = &given
		view.f = &fixture
		rid07CheckApplyOperations(t, &view, ids, true)
		require.NoError(t, ctx.Err())
	}
}
func (p *rid04PublicContext) expectation(t *testing.T, w *ridLifecycleWorld, id string, authority bool, s rid03NewmanSnapshot) rid04NewmanExpectation {
	f := w.f
	return rid04NewmanExpectation{rid03NewmanExpectation: rid03NewmanExpectation{CaseID: id, Mode: rid03Mode(t, w), Phase: rid04NewmanPhases[id], Actor: w.issuer.ID, Operator: f.operator.UserID(), Issuer: w.issuer.ID, Creator: f.creator.ID, System: f.baseline.SystemID, Tenant: f.tenantID, InstallationGD: w.gd.Id, Path: "/iam/v1/accessBindings", Request: p.body, Snapshot: s}, CreatorAuthority: authority, OldGrantID: p.oldGrant}
}
func (p *rid04PublicContext) read(t *testing.T, w *ridLifecycleWorld, suffix string, authority bool, s rid03NewmanSnapshot) {
	id := "registry-installation-rid04-" + rid03Mode(t, w) + "-" + suffix
	e := p.expectation(t, w, id, authority, s)
	rid04RequireAuthority(t, w, s, authority)
	rid04RequireOldActive(t, w, s, p.oldGrant)
	var receipt ridNewmanReceipt
	func() {
		defer func() {
			after := rid03PhaseSnapshot(t, w)
			rid03RequireReadOnly(t, s, after)
			proof, ok := rid04BuildTechnicalReceipt(&e.rid03NewmanExpectation, s, after, nil)
			require.True(t, ok)
			require.True(t, receipt.OK)
			proof.PhaseRuntimeChecksPassed = true
			rid08Write(t, w.f.session.Root, "newman-"+strings.ToLower(id)+"-primary-technical-audit-receipt", proof)
		}()
		receipt = ridRunNewmanPhase(t, w.f, "registry-installation-rid04", id, strings.ToLower(id), map[string]any{"rid04Expected": e})
		require.True(t, receipt.OK)
	}()
}
func (p *rid04PublicContext) actionPair(t *testing.T, w *ridLifecycleWorld, scenario string, denied, authority bool) {
	t.Helper()
	// Настоящий штатный удостоверяющий материал I захватывается неизменным допуском FD5. Материал C
	// не подставляется, и токен предъявителя не переносится в VERIFY только для O.
	require.NotEmpty(t, p.bodySHA256)
	require.Equal(t, p.bodySHA256, rid03EvidenceHash(p.body), "denied and lawful twin use the exact retained request")
	token := w.issuerToken
	require.NotEmpty(t, token)
	before := rid03StableNewmanSnapshot(t, w)
	rid04RequireAuthority(t, w, before, authority)
	rid04RequireOldActive(t, w, before, p.oldGrant)
	prefix := "registry-installation-rid04-" + rid03Mode(t, w) + "-" + scenario
	e := p.expectation(t, w, prefix+"-ACT", authority, before)
	e.Scenario = scenario
	e.Denied = denied
	var after rid03NewmanSnapshot
	var receipt ridNewmanReceipt
	func() {
		defer func() {
			after = rid03StableNewmanSnapshot(t, w)
			rid03RequireActionDeltaWithReceipt(t, w, &e.rid03NewmanExpectation, before, after, rid04BuildTechnicalReceipt)
			rid04RequireOldActive(t, w, after, p.oldGrant)
			rid04RequireAuthority(t, w, after, authority)
			require.NotNil(t, e.TechnicalEvidence)
			require.True(t, receipt.OK)
			e.TechnicalEvidence.PhaseRuntimeChecksPassed = true
			rid08Write(t, w.f.session.Root, "newman-"+strings.ToLower(e.CaseID)+"-primary-technical-audit-receipt", e.TechnicalEvidence)
		}()
		receipt = ridRunNewmanPhase(t, w.f, "registry-installation-rid04", e.CaseID, strings.ToLower(e.CaseID), map[string]any{"rid04Expected": e, "jwtRIDIssuer": token})
		require.True(t, receipt.OK)
	}()
	e.CaseID = prefix + "-VERIFY"
	e.Phase = "VERIFY"
	e.Snapshot = after
	var verify ridNewmanReceipt
	func() {
		defer func() {
			end := rid03PhaseSnapshot(t, w)
			rid03RequireReadOnly(t, after, end)
			proof, ok := rid04BuildTechnicalReceipt(&e.rid03NewmanExpectation, after, end, nil)
			require.True(t, ok)
			require.True(t, verify.OK)
			proof.PhaseRuntimeChecksPassed = true
			rid08Write(t, w.f.session.Root, "newman-"+strings.ToLower(e.CaseID)+"-primary-technical-audit-receipt", proof)
		}()
		verify = ridRunNewmanPhase(t, w.f, "registry-installation-rid04", e.CaseID, strings.ToLower(e.CaseID), map[string]any{"rid04Expected": e})
		require.True(t, verify.OK)
	}()
}
