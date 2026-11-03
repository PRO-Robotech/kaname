// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/operations/operationspb"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

var rid05NewmanActors = map[string]string{
	"registry-installation-rid05-S1-KEYS-AND-REFERENCES-CLEAN":      "O",
	"registry-installation-rid05-S1-DELETED-C-SNAPSHOT":             "O",
	"registry-installation-rid05-S1-OLD-C-TOKEN-REFUSED":            "A",
	"registry-installation-rid05-S1-DELETED-C-GRANT-ACT":            "I",
	"registry-installation-rid05-S1-DELETED-C-GRANT-VERIFY":         "O",
	"registry-installation-rid05-S1-SAME-NAME-C2-SNAPSHOT":          "O",
	"registry-installation-rid05-S1-C2-NO-REVIVAL-ACT":              "I",
	"registry-installation-rid05-S1-C2-NO-REVIVAL-VERIFY":           "O",
	"registry-installation-rid05-S1-ACTIVE-DELEGATE-DELETE-ACT":     "O",
	"registry-installation-rid05-S1-ACTIVE-DELEGATE-DELETE-VERIFY":  "O",
	"registry-installation-rid05-S1-REVOKE-ONLY-DELETE-TWIN-ACT":    "O",
	"registry-installation-rid05-S1-REVOKE-ONLY-DELETE-TWIN-VERIFY": "O",
	"registry-installation-rid05-S1-EXPLICIT-C2-RECOVERY-ACT":       "I",
	"registry-installation-rid05-S1-EXPLICIT-C2-RECOVERY-VERIFY":    "O",
	"registry-installation-rid05-S1-RECOVERY-REAPPLY":               "O",
	"registry-installation-rid05-S2-KEYS-AND-REFERENCES-CLEAN":      "O",
	"registry-installation-rid05-S2-DELETED-C-SNAPSHOT":             "O",
	"registry-installation-rid05-S2-OLD-C-TOKEN-REFUSED":            "A",
	"registry-installation-rid05-S2-DELETED-C-GRANT-ACT":            "I",
	"registry-installation-rid05-S2-DELETED-C-GRANT-VERIFY":         "O",
	"registry-installation-rid05-S2-SAME-NAME-C2-SNAPSHOT":          "O",
	"registry-installation-rid05-S2-C2-NO-REVIVAL-ACT":              "I",
	"registry-installation-rid05-S2-C2-NO-REVIVAL-VERIFY":           "O",
	"registry-installation-rid05-S2-ACTIVE-DELEGATE-DELETE-ACT":     "O",
	"registry-installation-rid05-S2-ACTIVE-DELEGATE-DELETE-VERIFY":  "O",
	"registry-installation-rid05-S2-REVOKE-ONLY-DELETE-TWIN-ACT":    "O",
	"registry-installation-rid05-S2-REVOKE-ONLY-DELETE-TWIN-VERIFY": "O",
	"registry-installation-rid05-S2-EXPLICIT-C2-RECOVERY-ACT":       "I",
	"registry-installation-rid05-S2-EXPLICIT-C2-RECOVERY-VERIFY":    "O",
	"registry-installation-rid05-S2-RECOVERY-REAPPLY":               "O",
}

func rid05NewmanActor(id string) (string, bool) { v, ok := rid05NewmanActors[id]; return v, ok }
func rid05TokenCase(id string) bool {
	return id == "registry-installation-rid05-S1-OLD-C-TOKEN-REFUSED" || id == "registry-installation-rid05-S2-OLD-C-TOKEN-REFUSED"
}
func rid05Phase(id string) string {
	if strings.HasSuffix(id, "-ACT") {
		return "ACT"
	}
	if strings.HasSuffix(id, "-VERIFY") {
		return "VERIFY"
	}
	return "READ"
}
func rid05BuildTechnicalReceipt(e *rid03NewmanExpectation, a, b rid03NewmanSnapshot, p *rid03DeltaPolicy) (rid03TechnicalReceipt, bool) {
	if _, ok := rid05NewmanActor(e.CaseID); !ok || rid05Phase(e.CaseID) != e.Phase {
		return rid03TechnicalReceipt{}, false
	}
	return ridNewmanBuildClosedTechnicalReceipt(e, a, b, p)
}

type rid05Snapshot struct {
	Core         rid03NewmanSnapshot
	DeletedAudit []rid09PrimaryRow
}

func rid05Capture(t *testing.T, ctx context.Context, w *ridLifecycleWorld) (rid05Snapshot, bool) {
	t.Helper()
	out := rid05Snapshot{}
	core, stable := rid03CaptureNewmanSnapshotWithCensus(t, ctx, w.f, func(ctx context.Context, tx pgx.Tx) {
		rows, err := tx.Query(ctx, `SELECT to_jsonb(r) FROM kaname.audit_outbox r WHERE event_type='iam.service_account.deleted' ORDER BY id`)
		require.NoError(t, err)
		defer rows.Close()
		out.DeletedAudit = []rid09PrimaryRow{}
		for rows.Next() {
			var raw []byte
			require.NoError(t, rows.Scan(&raw))
			var row rid09PrimaryRow
			require.NoError(t, json.Unmarshal(raw, &row))
			require.True(t, rid03Columns(row, "id event_type tenant_account_id event_payload status attempts created_at next_attempt_at sent_at last_error"), "closed audit schema required")
			immutable := rid09PrimaryRow{}
			for _, key := range []string{"id", "event_type", "tenant_account_id", "event_payload", "created_at"} {
				immutable[key] = row[key]
			}
			out.DeletedAudit = append(out.DeletedAudit, immutable)
		}
		require.NoError(t, rows.Err())
	})
	out.Core = core
	require.NoError(t, ctx.Err())
	return out, stable
}
func rid05Equal(a, b rid05Snapshot) bool {
	return rid03SnapshotEqual(a.Core, b.Core) && reflect.DeepEqual(a.DeletedAudit, b.DeletedAudit)
}
func rid05SnapshotRead(t *testing.T, w *ridLifecycleWorld, stable bool) rid05Snapshot {
	t.Helper()
	ctx, cancel := context.WithTimeout(w.f.given.ctx, 30*time.Second)
	defer cancel()
	if !stable {
		s, ok := rid05Capture(t, ctx, w)
		require.True(t, ok, "primary moved within phase capture")
		return s
	}
	// One caller budget covers full native materialization readiness and ALL SQL.
	view, fixture, given := *w, *w.f, *w.f.given
	given.ctx = ctx
	fixture.given = &given
	view.f = &fixture
	rid03StableNewmanSnapshot(t, &view)
	var previous *rid05Snapshot
	for {
		require.NoError(t, ctx.Err())
		s, ok := rid05Capture(t, ctx, &view)
		if ok && previous != nil && rid05Equal(*previous, s) {
			require.NoError(t, ctx.Err())
			return s
		}
		previous = nil
		if ok {
			previous = &s
		}
		select {
		case <-ctx.Done():
			t.Fatal("RID05 primary not stable")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

type rid05PublicContext struct {
	beforeNativeDeletion                   *rid05Snapshot
	refusalSequence                        int
	owner, oldGrant, oldGD, c2             string
	body                                   map[string]any
	bodySHA                                string
	beforeFailure, preRestore, beforeApply *rid05Snapshot
	refusalProof                           bool
	initialGD                              map[string]map[string]any
}
type rid05Expectation struct {
	DeleteContract *rid05DeleteWireContract `json:"deleteContract,omitempty"`
	rid03NewmanExpectation
	OldCreatorID         string     `json:"oldCreatorId"`
	ReplacementCreatorID string     `json:"replacementCreatorId"`
	OldGrantID           string     `json:"oldGrantId"`
	OldDelegationID      string     `json:"oldDelegationId"`
	CreatorPresent       bool       `json:"creatorPresent"`
	OldGrantStatus       string     `json:"oldGrantStatus"`
	BlockingDelegationID string     `json:"blockingDelegationId"`
	AssertionExpiresAt   *time.Time `json:"assertionExpiresAt,omitempty"`
}

func rid05OwnedSuffixes(owner string) []string {
	switch owner {
	case "deleted":
		return []string{"KEYS-AND-REFERENCES-CLEAN", "DELETED-C-SNAPSHOT", "OLD-C-TOKEN-REFUSED", "DELETED-C-GRANT-ACT", "DELETED-C-GRANT-VERIFY"}
	case "same-name":
		return []string{"SAME-NAME-C2-SNAPSHOT"}
	case "delete-guard":
		return []string{"ACTIVE-DELEGATE-DELETE-ACT", "ACTIVE-DELEGATE-DELETE-VERIFY", "REVOKE-ONLY-DELETE-TWIN-ACT", "REVOKE-ONLY-DELETE-TWIN-VERIFY"}
	case "recovery":
		return []string{"C2-NO-REVIVAL-ACT", "C2-NO-REVIVAL-VERIFY", "EXPLICIT-C2-RECOVERY-ACT", "EXPLICIT-C2-RECOVERY-VERIFY", "RECOVERY-REAPPLY"}
	}
	return nil
}
func rid05PublicConsumer(t *testing.T, w *ridLifecycleWorld, owner string) *rid05PublicContext {
	t.Helper()
	require.NotEmpty(t, rid05OwnedSuffixes(owner))
	if os.Getenv("KANAME_RID_NEWMAN") == "1" {
		return &rid05PublicContext{owner: owner}
	}
	for _, suffix := range rid05OwnedSuffixes(owner) {
		id := "registry-installation-rid05-" + rid03Mode(t, w) + "-" + suffix
		rid08Write(t, w.f.session.Root, "newman-"+strings.ToLower(id), map[string]any{"caseId": id, "state": "NOT_EXECUTED", "actualNewmanExecuted": false, "wholeDoDAccepted": false})
	}
	return nil
}
func (p *rid05PublicContext) prepare(t *testing.T, w *ridLifecycleWorld, g *iamv1.AccessBinding, body map[string]any) {
	if p == nil {
		return
	}
	p.oldGrant = g.Id
	p.oldGD = w.gd.Id
	p.body = body
	if p.owner == "recovery" {
		subject := w.f.ridSA(t, w.f.tenantID, "rid05-public-grantee")
		p.body = w.bindingInput("service_account", subject, w.pull, "registry.registries", w.object)
	}
	p.bodySHA = rid03EvidenceHash(p.body)
	s := rid05SnapshotRead(t, w, true)
	p.initialGD = rid03ProjectionRows(t, s.Core.Projection.Delegations)
}
func (p *rid05PublicContext) expect(t *testing.T, w *ridLifecycleWorld, suffix string, s rid05Snapshot, present bool, status string) rid05Expectation {
	id := "registry-installation-rid05-" + rid03Mode(t, w) + "-" + suffix
	return rid05Expectation{rid03NewmanExpectation: rid03NewmanExpectation{CaseID: id, Mode: rid03Mode(t, w), Phase: rid05Phase(id), Actor: w.issuer.ID, Operator: w.f.operator.UserID(), Issuer: w.issuer.ID, Creator: w.f.creator.ID, System: w.f.baseline.SystemID, Tenant: w.f.tenantID, InstallationGD: w.gd.Id, Path: "/iam/v1/accessBindings", Request: p.body, Snapshot: s.Core}, OldCreatorID: w.f.creator.ID, ReplacementCreatorID: p.c2, OldGrantID: p.oldGrant, OldDelegationID: p.oldGD, CreatorPresent: present, OldGrantStatus: status}
}
func (p *rid05PublicContext) premise(t *testing.T, w *ridLifecycleWorld, s rid05Snapshot, present bool, status string) {
	t.Helper()
	found := false
	c2found := p.c2 == ""
	for _, sa := range s.Core.Projection.ServiceAccounts {
		if sa["id"] == w.f.creator.ID {
			found = true
		}
		if p.c2 != "" && sa["id"] == p.c2 {
			c2found = true
			require.True(t, p.c2 != w.f.creator.ID)
			require.Equal(t, "rid-native-standing-creator", sa["name"])
			require.Equal(t, w.f.creator.AccountID, sa["accountId"])
		}
	}
	require.True(t, c2found, "actual native C2 primary identity required")
	require.Equal(t, present, found)
	rid04RequireAuthority(t, w, s.Core, false)
	for _, row := range s.Core.Raw["group_members"] {
		require.False(t, rid03S(row, "member_type") == "service_account" && rid03S(row, "member_id") == w.f.creator.ID, "old C must have no group reference")
	}
	legacy, secondary, valid := rid05CreatorSubjectReferences(s.Core.Raw, w.f.creator.ID)
	require.True(t, valid, "mandatory primary subject-reference schema and binding links required")
	require.Zero(t, legacy, "old C must have no unrevoked legacy subject grant")
	require.Zero(t, secondary, "old C must have no unrevoked secondary subject grant")
	if p.c2 != "" {
		g, f := rid04AuthorityCounts(s.Core, "service_account", p.c2)
		want := 0
		if p.owner == "recovery" {
			want = 1
		}
		require.Equal(t, want, g)
		require.Equal(t, want, f)
	}
	for _, row := range s.Core.Raw["service_account_oauth_clients"] {
		require.False(t, rid03S(row, "sva_id") == w.f.creator.ID, "all original C keys must be gone")
	}
	old := false
	for _, g := range s.Core.Projection.Bindings {
		if g["id"] == p.oldGrant {
			old = true
			require.Equal(t, status, g["status"])
			require.Equal(t, p.oldGD, g["delegationId"])
		}
	}
	require.True(t, old)
	for _, gd := range s.Core.Projection.Delegations {
		if previous := p.initialGD[gd["id"].(string)]; previous != nil {
			require.Equal(t, status, gd["status"])
			require.Equal(t, previous["createdAt"], gd["createdAt"])
			require.Equal(t, previous["delegatedBy"], gd["delegatedBy"])
			require.Equal(t, previous["roleIds"], gd["roleIds"])
			require.Equal(t, previous["targetTypes"], gd["targetTypes"])
			require.Equal(t, previous["subjectTypes"], gd["subjectTypes"])
			require.Equal(t, previous["delegate"], gd["delegate"])
			require.Equal(t, previous["accountId"], gd["accountId"])
			require.Equal(t, map[string]any{"type": "service_account", "id": w.f.creator.ID}, gd["delegatedBy"])
		}
	}
}
func (p *rid05PublicContext) read(t *testing.T, w *ridLifecycleWorld, suffix string, present bool, status string, assertion bool) {
	s := rid05SnapshotRead(t, w, true)
	p.premise(t, w, s, present, status)
	e := p.expect(t, w, suffix, s, present, status)
	vars := map[string]any{}
	if assertion {
		proof, end := rid01FreshAssertion(t, w.f)
		e.AssertionExpiresAt = &end
		vars["rid05ClientAssertion"] = proof
		vars["rid05IssuanceOrigin"] = w.f.wire.IssuanceURL
	}
	vars["rid05Expected"] = e
	var receipt ridNewmanReceipt
	func() {
		defer func() {
			end := rid05SnapshotRead(t, w, false)
			require.True(t, rid05Equal(s, end), "full primary/read/credential/business history changed within public phase")
			proof, ok := rid05BuildTechnicalReceipt(&e.rid03NewmanExpectation, s.Core, end.Core, nil)
			require.True(t, ok)
			require.True(t, receipt.OK)
			proof.PhaseRuntimeChecksPassed = true
			rid08Write(t, w.f.session.Root, "newman-"+strings.ToLower(e.CaseID)+"-primary-proof", proof)
		}()
		receipt = ridRunNewmanPhase(t, w.f, "registry-installation-rid05", e.CaseID, strings.ToLower(e.CaseID), vars)
		require.True(t, receipt.OK)
	}()
}
func (p *rid05PublicContext) keysClean(t *testing.T, w *ridLifecycleWorld) {
	if p != nil && p.owner == "deleted" {
		p.read(t, w, "KEYS-AND-REFERENCES-CLEAN", true, "ACTIVE", false)
	}
}
func (p *rid05PublicContext) deleted(t *testing.T, w *ridLifecycleWorld) {
	if p != nil && p.owner == "deleted" {
		p.read(t, w, "DELETED-C-SNAPSHOT", false, "ACTIVE", false)
		p.read(t, w, "OLD-C-TOKEN-REFUSED", false, "ACTIVE", true)
	}
}
func (p *rid05PublicContext) deletedGrant(t *testing.T, w *ridLifecycleWorld) {
	if p != nil && p.owner == "deleted" {
		p.actionPair(t, w, "DELETED-C-GRANT", true, "ACTIVE")
	}
}
func (p *rid05PublicContext) sameName(t *testing.T, w *ridLifecycleWorld, id string) {
	if p == nil {
		return
	}
	require.NotEqual(t, w.f.creator.ID, id)
	p.c2 = id
	if p.owner == "same-name" {
		s := rid05SnapshotRead(t, w, true)
		g, f := rid04AuthorityCounts(s.Core, "service_account", id)
		require.Zero(t, g)
		require.Zero(t, f)
		p.read(t, w, "SAME-NAME-C2-SNAPSHOT", false, "ACTIVE", false)
	}
}
func (p *rid05PublicContext) noRevival(t *testing.T, w *ridLifecycleWorld, id string) {
	if p == nil {
		return
	}
	require.Equal(t, p.c2, id)
	s := rid05SnapshotRead(t, w, true)
	g, f := rid04AuthorityCounts(s.Core, "service_account", id)
	require.Equal(t, 1, g)
	require.Equal(t, 1, f)
	p.actionPair(t, w, "C2-NO-REVIVAL", true, "ACTIVE")
}
func (p *rid05PublicContext) beforeRefusedApply(t *testing.T, w *ridLifecycleWorld) {
	if p == nil {
		return
	}
	s := rid05SnapshotRead(t, w, true)
	p.beforeFailure = &s
	p.refusalSequence++
	p.refusalProof = false
}
func (p *rid05PublicContext) refusalBeforeRestore(t *testing.T, w *ridLifecycleWorld) {
	if p == nil {
		return
	}
	require.NotNil(t, p.beforeFailure)
	s := rid05SnapshotRead(t, w, false)
	ridRequireWholeDeliveryUnchanged(t, p.beforeFailure.Core.Whole, s.Core.Whole)
	require.True(t, reflect.DeepEqual(p.beforeFailure.Core.Raw, s.Core.Raw), "full raw delivery/Operations unchanged before restoration")
	require.True(t, reflect.DeepEqual(p.beforeFailure.DeletedAudit, s.DeletedAudit))
	require.True(t, reflect.DeepEqual(p.beforeFailure.Core.BusinessAudit, s.Core.BusinessAudit))
	require.Equal(t, p.beforeFailure.Core.Projection, s.Core.Projection)
	p.preRestore = &s
	p.refusalProof = true
	rid08Write(t, w.f.session.Root, fmt.Sprintf("rid05-%s-%s-refusal-before-restore-%d", p.owner, rid03Mode(t, w), p.refusalSequence), map[string]any{"integrationOnly": true, "actualNewmanExecuted": false, "rawEqual": true, "before": p.beforeFailure.Core.Whole, "after": s.Core.Whole, "wholeDoDAccepted": false})
}
func (p *rid05PublicContext) afterRefusedApply(t *testing.T, w *ridLifecycleWorld) {
	if p == nil {
		return
	}
	require.True(t, p.refusalProof && p.preRestore != nil && p.beforeFailure != nil)
	s := rid05SnapshotRead(t, w, true)
	rid04RequireNormalBoundary(t, w, p.preRestore.Core, s.Core, 0)
	require.True(t, reflect.DeepEqual(p.preRestore.DeletedAudit, s.DeletedAudit))
	p.premise(t, w, s, false, "ACTIVE")
}
func (p *rid05PublicContext) beforeReapply(t *testing.T, w *ridLifecycleWorld, c2 string) {
	if p == nil {
		return
	}
	require.Equal(t, p.c2, c2)
	s := rid05SnapshotRead(t, w, true)
	p.beforeApply = &s
}
func (p *rid05PublicContext) recoveryReady(t *testing.T, w *ridLifecycleWorld, c2 string) {
	if p == nil {
		return
	}
	require.NotNil(t, p.beforeApply)
	require.Equal(t, p.c2, c2)
	after := rid05SnapshotRead(t, w, true)
	require.Equal(t, p.beforeApply.Core.Projection, after.Core.Projection)
	rid04RequireGDGUnchanged(t, p.beforeApply.Core, after.Core)
	require.True(t, reflect.DeepEqual(p.beforeApply.Core.BusinessAudit, after.Core.BusinessAudit))
	require.True(t, reflect.DeepEqual(p.beforeApply.DeletedAudit, after.DeletedAudit))
	ridRequireOwnCeilingsPreserved(t, p.beforeApply.Core.Whole, after.Core.Whole)
	p.requireApplyOperations(t, w, *p.beforeApply, after, c2)
	p.premise(t, w, after, false, "REVOKED")
	p.read(t, w, "RECOVERY-REAPPLY", false, "REVOKED", false)
}
func (p *rid05PublicContext) requireApplyOperations(t *testing.T, w *ridLifecycleWorld, a, b rid05Snapshot, creator string) {
	old, now := rid03RowsByID(t, a.Core.Raw["operations"]), rid03RowsByID(t, b.Core.Raw["operations"])
	require.Equal(t, len(old)+len(w.accounts), len(now))
	for id, row := range old {
		require.True(t, reflect.DeepEqual(row, now[id]), "old full Operation changed")
	}
	ctx, cancel := context.WithTimeout(w.f.given.ctx, 30*time.Second)
	defer cancel()
	accounts := map[string]bool{}
	for id := range now {
		if old[id] != nil {
			continue
		}
		op, err := operations.NewRepo(w.f.given.pool, "kaname").Get(ctx, id)
		require.NoError(t, err)
		require.True(t, op.Done && op.Error == nil)
		require.True(t, op.Principal == (operations.Principal{Type: "service_account", ID: creator, DisplayName: creator}))
		var meta iamv1.CreateGrantDelegationMetadata
		require.NotNil(t, op.Metadata)
		require.NoError(t, op.Metadata.UnmarshalTo(&meta))
		require.False(t, accounts[meta.AccountId])
		accounts[meta.AccountId] = true
		var gd string
		require.NoError(t, w.f.given.pool.QueryRow(ctx, `SELECT id FROM kaname.grant_delegations WHERE account_id=$1 AND delegate_id=$2 AND status='ACTIVE' AND delegated_by_id=$3`, meta.AccountId, w.issuer.ID, creator).Scan(&gd))
		requireNativeInstallationOperation(t, ctx, w.f.given.pool, id, meta.AccountId, creator, gd)
	}
	require.NoError(t, ctx.Err())
}
func (p *rid05PublicContext) recoveredGrant(t *testing.T, w *ridLifecycleWorld, c2 string) {
	if p == nil {
		return
	}
	require.Equal(t, p.c2, c2)
	p.actionPair(t, w, "EXPLICIT-C2-RECOVERY", false, "REVOKED")
}
func (p *rid05PublicContext) actionPair(t *testing.T, w *ridLifecycleWorld, scenario string, denied bool, status string) {
	require.Equal(t, p.bodySHA, rid03EvidenceHash(p.body), "public request must remain identical")
	a := rid05SnapshotRead(t, w, true)
	p.premise(t, w, a, false, status)
	e := p.expect(t, w, scenario+"-ACT", a, false, status)
	e.Denied = denied
	e.Scenario = scenario
	var b rid05Snapshot
	var receipt ridNewmanReceipt
	func() {
		defer func() {
			b = rid05SnapshotRead(t, w, true)
			rid03RequireActionDeltaWithReceipt(t, w, &e.rid03NewmanExpectation, a.Core, b.Core, rid05BuildTechnicalReceipt)
			require.True(t, reflect.DeepEqual(a.DeletedAudit, b.DeletedAudit))
			p.premise(t, w, b, false, status)
			require.True(t, receipt.OK)
			require.NotNil(t, e.TechnicalEvidence)
			e.TechnicalEvidence.PhaseRuntimeChecksPassed = true
			rid08Write(t, w.f.session.Root, "newman-"+strings.ToLower(e.CaseID)+"-primary-proof", e.TechnicalEvidence)
		}()
		receipt = ridRunNewmanPhase(t, w.f, "registry-installation-rid05", e.CaseID, strings.ToLower(e.CaseID), map[string]any{"rid05Expected": e, "jwtRIDIssuer": w.issuerToken})
		require.True(t, receipt.OK)
	}()
	e.CaseID = strings.TrimSuffix(e.CaseID, "-ACT") + "-VERIFY"
	e.Phase = "VERIFY"
	e.Snapshot = b.Core
	var verify ridNewmanReceipt
	func() {
		defer func() {
			end := rid05SnapshotRead(t, w, false)
			require.True(t, rid05Equal(b, end), "full VERIFY primary ledger changed")
			proof, ok := rid05BuildTechnicalReceipt(&e.rid03NewmanExpectation, b.Core, end.Core, nil)
			require.True(t, ok)
			require.True(t, verify.OK)
			proof.PhaseRuntimeChecksPassed = true
			rid08Write(t, w.f.session.Root, "newman-"+strings.ToLower(e.CaseID)+"-primary-proof", proof)
		}()
		verify = ridRunNewmanPhase(t, w.f, "registry-installation-rid05", e.CaseID, strings.ToLower(e.CaseID), map[string]any{"rid05Expected": e})
		require.True(t, verify.OK)
	}()
}

// Keep the typed operation adapter local and nonsecret. The independently read
// operation, never a Node report ID/body, is the source for native assertions.
func rid05LifecycleOperation(t *testing.T, op *operations.Operation) ridLifecycleOperation {
	raw, err := json.Marshal(rid09PrimaryJSON(t, operationspb.ToProto(op)))
	require.NoError(t, err)
	var out ridLifecycleOperation
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}

// Match the production Delete WHERE NOT EXISTS predicate: only revoked_at
// removes a subject reference. Narrowing and expiry do not authorize deletion.
// Validate every coordinate first so omitted/malformed raw fields cannot turn
// the independent census into a vacuous zero. No raw rows enter error output.
func rid05CreatorSubjectReferences(raw map[string][]rid09PrimaryRow, creator string) (legacy, secondary int, valid bool) {
	bindings, haveBindings := raw["access_bindings"]
	subjects, haveSubjects := raw["access_binding_subjects"]
	if creator == "" || !haveBindings || !haveSubjects {
		return 0, 0, false
	}
	unrevoked := map[string]bool{}
	for _, row := range bindings {
		id, idOK := rid03Cell[string](row, "id")
		kind, kindOK := rid03Cell[string](row, "subject_type")
		subject, subjectOK := rid03Cell[string](row, "subject_id")
		// json null unmarshals into string's zero value, so enforce string tokens.
		if !idOK || id == "" || !kindOK || kind == "" || !subjectOK || subject == "" || strings.TrimSpace(string(row["subject_id"])) == "null" {
			return 0, 0, false
		}
		if _, duplicate := unrevoked[id]; duplicate {
			return 0, 0, false
		}
		revoked, hasRevoked := row["revoked_at"]
		if !hasRevoked {
			return 0, 0, false
		}
		active := strings.TrimSpace(string(revoked)) == "null"
		if !active {
			var at time.Time
			if json.Unmarshal(revoked, &at) != nil || strings.TrimSpace(string(revoked)) == "" {
				return 0, 0, false
			}
		}
		unrevoked[id] = active
		if active && kind == "service_account" && subject == creator {
			legacy++
		}
	}
	for _, row := range subjects {
		binding, bindingOK := rid03Cell[string](row, "binding_id")
		kind, kindOK := rid03Cell[string](row, "subject_type")
		subject, subjectOK := rid03Cell[string](row, "subject_id")
		if !bindingOK || binding == "" || !kindOK || kind == "" || !subjectOK || subject == "" || strings.TrimSpace(string(row["subject_id"])) == "null" {
			return 0, 0, false
		}
		active, exists := unrevoked[binding]
		if !exists {
			return 0, 0, false
		}
		if active && kind == "service_account" && subject == creator {
			secondary++
		}
	}
	return legacy, secondary, true
}
