// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations/operationspb"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
)

var rid06PublicActors = map[string]string{"registry-installation-rid06-S1-BEFORE-REVOKE": "O",
	"registry-installation-rid06-S1-REVOKE-ACT":               "O",
	"registry-installation-rid06-S1-AFTER-REVOKE":             "O",
	"registry-installation-rid06-S1-SEQUENTIAL-BEFORE-REVOKE": "O",
	"registry-installation-rid06-S1-SEQUENTIAL-AFTER-OVERLAP": "O",
	"registry-installation-rid06-S1-AFTER-SEQUENTIAL-REFUSAL": "O",
	"registry-installation-rid06-S1-NO-REVOKE-BEFORE":         "O",
	"registry-installation-rid06-S1-NO-REVOKE-TWIN":           "O",
	"registry-installation-rid06-S1-RECOVERY-BEFORE-REVOKE":   "O",
	"registry-installation-rid06-S1-RECOVERY-AFTER-REVOKE":    "O",
	"registry-installation-rid06-S1-EXPLICIT-CREATE-ACT":      "C",
	"registry-installation-rid06-S1-EXPLICIT-CREATE-VERIFY":   "O",
	"registry-installation-rid06-S1-RECOVERY-REAPPLY":         "O",
	"registry-installation-rid06-S1-EXPLICIT-RECOVERY-ACT":    "I",
	"registry-installation-rid06-S1-EXPLICIT-RECOVERY-VERIFY": "O",
	"registry-installation-rid06-S2-BEFORE-REVOKE":            "O",
	"registry-installation-rid06-S2-REVOKE-ACT":               "O",
	"registry-installation-rid06-S2-AFTER-REVOKE":             "O",
	"registry-installation-rid06-S2-SEQUENTIAL-BEFORE-REVOKE": "O",
	"registry-installation-rid06-S2-SEQUENTIAL-AFTER-OVERLAP": "O",
	"registry-installation-rid06-S2-AFTER-SEQUENTIAL-REFUSAL": "O",
	"registry-installation-rid06-S2-NO-REVOKE-BEFORE":         "O",
	"registry-installation-rid06-S2-NO-REVOKE-TWIN":           "O",
	"registry-installation-rid06-S2-RECOVERY-BEFORE-REVOKE":   "O",
	"registry-installation-rid06-S2-RECOVERY-AFTER-REVOKE":    "O",
	"registry-installation-rid06-S2-EXPLICIT-CREATE-ACT":      "C",
	"registry-installation-rid06-S2-EXPLICIT-CREATE-VERIFY":   "O",
	"registry-installation-rid06-S2-RECOVERY-REAPPLY":         "O",
	"registry-installation-rid06-S2-EXPLICIT-RECOVERY-ACT":    "I",
	"registry-installation-rid06-S2-EXPLICIT-RECOVERY-VERIFY": "O"}
var rid06PublicOwners = map[string][]string{"revoke": {"BEFORE-REVOKE", "REVOKE-ACT", "AFTER-REVOKE"},
	"sequential": {"SEQUENTIAL-BEFORE-REVOKE", "SEQUENTIAL-AFTER-OVERLAP", "AFTER-SEQUENTIAL-REFUSAL"},
	"twin":       {"NO-REVOKE-BEFORE", "NO-REVOKE-TWIN"},
	"recovery":   {"RECOVERY-BEFORE-REVOKE", "RECOVERY-AFTER-REVOKE", "EXPLICIT-CREATE-ACT", "EXPLICIT-CREATE-VERIFY", "RECOVERY-REAPPLY", "EXPLICIT-RECOVERY-ACT", "EXPLICIT-RECOVERY-VERIFY"}}

func rid06PublicActor(id string) (string, bool) { v, ok := rid06PublicActors[id]; return v, ok }
func rid06PublicPhase(id string) string {
	if strings.HasSuffix(id, "-ACT") {
		return "ACT"
	}
	if strings.HasSuffix(id, "-VERIFY") || strings.HasSuffix(id, "-AFTER-REVOKE") && !strings.Contains(id, "RECOVERY-") {
		return "VERIFY"
	}
	return "READ"
}
func rid06BuildTechnicalReceipt(e *rid03NewmanExpectation, a, b rid03NewmanSnapshot, p *rid03DeltaPolicy) (rid03TechnicalReceipt, bool) {
	if _, ok := rid06PublicActor(e.CaseID); !ok || e.Phase != rid06PublicPhase(e.CaseID) {
		return rid03TechnicalReceipt{}, false
	}
	return ridNewmanBuildClosedTechnicalReceipt(e, a, b, p)
}

type rid06PublicContext struct {
	owner, oldGD, oldG, pendingOp                                                          string
	before, atPending, preRevoke, postRevoke, beforeSequentialRun, preRestore, beforeApply *rid03NewmanSnapshot
	publicBody                                                                             map[string]any
	bodySHA                                                                                string
	revokeOperation                                                                        map[string]any
	refusalProof                                                                           bool
	barrierDeadline                                                                        time.Time
}
type rid06PublicExpectation struct {
	rid03NewmanExpectation
	OldGD          string     `json:"oldDelegationId"`
	OldG           string     `json:"oldGrantId"`
	OldStatus      string     `json:"oldStatus"`
	ActionDeadline *time.Time `json:"actionDeadline,omitempty"`
}

func rid06PublicConsumer(t *testing.T, w *ridLifecycleWorld, owner string) *rid06PublicContext {
	require.NotEmpty(t, rid06PublicOwners[owner])
	if os.Getenv("KANAME_RID_NEWMAN") == "1" {
		return &rid06PublicContext{owner: owner}
	}
	for _, s := range rid06PublicOwners[owner] {
		id := "registry-installation-rid06-" + rid03Mode(t, w) + "-" + s
		rid08Write(t, w.f.session.Root, "newman-"+strings.ToLower(id), map[string]any{"caseId": id, "state": "NOT_EXECUTED", "actualNewmanExecuted": false, "wholeDoDAccepted": false})
	}
	return nil
}
func rid06Primary(t *testing.T, w *ridLifecycleWorld, stable bool) rid03NewmanSnapshot {
	if stable {
		return rid05SnapshotRead(t, w, true).Core
	}
	return rid03PhaseSnapshot(t, w)
}
func (p *rid06PublicContext) expect(t *testing.T, w *ridLifecycleWorld, suffix string, s rid03NewmanSnapshot, status string) rid06PublicExpectation {
	id := "registry-installation-rid06-" + rid03Mode(t, w) + "-" + suffix
	return rid06PublicExpectation{rid03NewmanExpectation: rid03NewmanExpectation{CaseID: id, Mode: rid03Mode(t, w), Phase: rid06PublicPhase(id), Actor: w.issuer.ID, Operator: w.f.operator.UserID(), Creator: w.f.creator.ID, Issuer: w.issuer.ID, System: w.f.baseline.SystemID, Tenant: w.f.tenantID, InstallationGD: w.gd.Id, Snapshot: s}, OldGD: p.oldGD, OldG: p.oldG, OldStatus: status}
}
func (p *rid06PublicContext) state(t *testing.T, w *ridLifecycleWorld, s rid03NewmanSnapshot, status string) {
	require.NotNil(t, p.before)
	rid04RequireAuthority(t, w, s, true)
	gd := rid03ProjectionRows(t, s.Projection.Delegations)[p.oldGD]
	g := rid03ProjectionRows(t, s.Projection.Bindings)[p.oldG]
	require.NotNil(t, gd)
	require.NotNil(t, g)
	require.Equal(t, status, gd["status"])
	require.Equal(t, status, g["status"])
	require.Equal(t, p.oldGD, g["delegationId"])
	oldGD := rid03ProjectionRows(t, p.before.Projection.Delegations)[p.oldGD]
	for _, key := range []string{"id", "accountId", "module", "delegate", "delegatedBy", "createdAt", "roleIds", "targetTypes", "subjectTypes"} {
		require.Equal(t, oldGD[key], gd[key])
	}
	if status == "REVOKED" {
		require.Equal(t, "REVOCATION_REASON_DELEGATION_REVOKED", g["revocationReason"])
	}
	for _, account := range w.accounts {
		count := 0
		for _, row := range s.Projection.Delegations {
			if row["accountId"] == account && reflect.DeepEqual(row["delegate"], oldGD["delegate"]) {
				count++
				if account != w.f.tenantID {
					require.Equal(t, "ACTIVE", row["status"])
				}
			}
		}
		want := 1
		if account == w.f.tenantID && w.gd.Id != p.oldGD {
			want = 2
		}
		require.Equal(t, want, count)
	}
}
func (p *rid06PublicContext) read(t *testing.T, w *ridLifecycleWorld, suffix, status string) {
	s := rid06Primary(t, w, true)
	p.state(t, w, s, status)
	e := p.expect(t, w, suffix, s, status)
	if suffix == "AFTER-REVOKE" {
		e.Operation = p.revokeOperation
	}
	var receipt ridNewmanReceipt
	func() {
		defer func() {
			after := rid06Primary(t, w, false)
			rid03RequireReadOnly(t, s, after)
			proof, ok := rid06BuildTechnicalReceipt(&e.rid03NewmanExpectation, s, after, nil)
			require.True(t, ok)
			require.True(t, receipt.OK)
			proof.PhaseRuntimeChecksPassed = true
			rid08Write(t, w.f.session.Root, "newman-"+strings.ToLower(e.CaseID)+"-primary-technical-proof", proof)
			rid08Write(t, w.f.session.Root, "newman-"+strings.ToLower(e.CaseID)+"-primary-bracket", map[string]any{"caseId": e.CaseID, "fullPrimaryUnchanged": true, "before": s.Whole, "after": after.Whole, "wholeDoDAccepted": false})
		}()
		receipt = ridRunNewmanPhase(t, w.f, "registry-installation-rid06", e.CaseID, strings.ToLower(e.CaseID), map[string]any{"rid06Expected": e})
		require.True(t, receipt.OK)
	}()
}
func (p *rid06PublicContext) beforeOverlap(t *testing.T, w *ridLifecycleWorld, g *iamv1.AccessBinding) {
	if p == nil {
		return
	}
	p.oldGD = w.gd.Id
	p.oldG = g.Id
	if p.owner == "recovery" {
		subject := w.f.ridSA(t, w.f.tenantID, "rid06-public-recovery-grantee")
		p.publicBody = w.bindingInput("service_account", subject, w.pull, "registry.registries", w.object)
		p.bodySHA = rid03EvidenceHash(p.publicBody)
	}
	s := rid06Primary(t, w, true)
	p.before = &s
	suffix := map[string]string{"revoke": "BEFORE-REVOKE", "sequential": "SEQUENTIAL-BEFORE-REVOKE", "twin": "NO-REVOKE-BEFORE", "recovery": "RECOVERY-BEFORE-REVOKE"}[p.owner]
	p.read(t, w, suffix, "ACTIVE")
}
func (p *rid06PublicContext) pending(t *testing.T, w *ridLifecycleWorld, id string) {
	if p == nil {
		return
	}
	p.pendingOp = id
}
func (p *rid06PublicContext) afterOverlap(t *testing.T, w *ridLifecycleWorld, g *iamv1.AccessBinding, revoke bool) {
	if p == nil {
		return
	}
	s := rid06Primary(t, w, true)
	require.NotNil(t, p.before)
	rid06RequireNativeBoundary(t, w, *p.before, s, p.owner == "twin", p.revokeOperation)
	reference := p.before
	if revoke {
		require.NotNil(t, p.postRevoke)
		reference = p.postRevoke
	}
	rid06RequireNativeHistory(t, *reference, s)
	status := "REVOKED"
	if !revoke {
		status = "ACTIVE"
	}
	suffix := map[string]string{"revoke": "AFTER-REVOKE", "sequential": "SEQUENTIAL-AFTER-OVERLAP", "twin": "NO-REVOKE-TWIN", "recovery": "RECOVERY-AFTER-REVOKE"}[p.owner]
	p.read(t, w, suffix, status)
}
func (p *rid06PublicContext) beforeSequential(t *testing.T, w *ridLifecycleWorld) {
	if p == nil {
		return
	}
	s := rid06Primary(t, w, true)
	p.beforeSequentialRun = &s
	p.refusalProof = false
}
func (p *rid06PublicContext) sequentialBeforeRestore(t *testing.T, w *ridLifecycleWorld) {
	if p == nil {
		return
	}
	require.NotNil(t, p.beforeSequentialRun)
	s := rid06Primary(t, w, false)
	rid06RequireNativeBoundary(t, w, *p.beforeSequentialRun, s, false, nil)
	rid06RequireNativeHistory(t, *p.beforeSequentialRun, s)
	ridRequireWholeDeliveryUnchanged(t, p.beforeSequentialRun.Whole, s.Whole)
	require.True(t, rid06FailedDeliveryEqual(*p.beforeSequentialRun, s), "full delivery/raw/business delta before ANY restoration must be zero; only independently checked installer Operations may be new")
	p.preRestore = &s
	p.refusalProof = true
	rid08Write(t, w.f.session.Root, "rid06-"+rid03Mode(t, w)+"-sequential-pre-restore", map[string]any{"integrationOnly": true, "actualNewmanExecuted": false, "before": p.beforeSequentialRun.Whole, "after": s.Whole, "wholeDoDAccepted": false})
}
func (p *rid06PublicContext) afterSequential(t *testing.T, w *ridLifecycleWorld) {
	if p == nil {
		return
	}
	require.True(t, p.refusalProof && p.preRestore != nil && p.beforeSequentialRun != nil)
	s := rid06Primary(t, w, true)
	rid04RequireNormalBoundary(t, w, *p.preRestore, s, 0)
	p.read(t, w, "AFTER-SEQUENTIAL-REFUSAL", "REVOKED")
}
func (p *rid06PublicContext) beforeRecoveryApply(t *testing.T, w *ridLifecycleWorld) {
	if p == nil {
		return
	}
	s := rid06Primary(t, w, true)
	p.beforeApply = &s
}
func (p *rid06PublicContext) afterRecoveryApply(t *testing.T, w *ridLifecycleWorld) {
	if p == nil {
		return
	}
	require.NotNil(t, p.beforeApply)
	s := rid06Primary(t, w, true)
	rid04RequireNormalBoundary(t, w, *p.beforeApply, s, len(w.accounts))
	p.read(t, w, "RECOVERY-REAPPLY", "REVOKED")
}

// При настоящем нативном запуске учёт каталога может проецироваться заново. Каждая
// старая Operation сохраняется побайтно; все новые Operation установщика сохраняют свой
// исходный полный типизированный нативный оракул. Это отделено от скобок публичного ACT.
func rid06RequireNativeBoundary(t *testing.T, w *ridLifecycleWorld, a, b rid03NewmanSnapshot, success bool, revokeOp map[string]any) {
	old := rid03RowsByID(t, a.Raw["operations"])
	now := rid03RowsByID(t, b.Raw["operations"])
	ids := []string{}
	for id, row := range old {
		require.True(t, reflect.DeepEqual(row, now[id]), "old complete Operation changed across normal startup")
		ids = append(ids, id)
	}
	if revokeOp != nil {
		ids = append(ids, revokeOp["id"].(string))
	}
	rid07CheckApplyOperations(t, w, ids, success)
	ridRequireOwnCeilingsPreserved(t, a.Whole, b.Whole)
	if success {
		require.True(t, rid04GDGHistoryEqual(a, b))
		require.True(t, reflect.DeepEqual(a.Projection, b.Projection))
		require.True(t, reflect.DeepEqual(a.BusinessAudit, b.BusinessAudit))
	}
}
func (p *rid06PublicContext) create(t *testing.T, w *ridLifecycleWorld, token string) ridLifecycleOperation {
	e := p.actionPair(t, w, "EXPLICIT-CREATE", w.gdCreateBody(w.f.tenantID, w.issuer.ID), token, true)
	var op ridLifecycleOperation
	raw, err := json.Marshal(e.Operation)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(raw, &op))
	return op
}
func (p *rid06PublicContext) recoveredGrant(t *testing.T, w *ridLifecycleWorld) {
	if p == nil {
		return
	}
	require.Equal(t, p.bodySHA, rid03EvidenceHash(p.publicBody))
	p.actionPair(t, w, "EXPLICIT-RECOVERY", p.publicBody, w.issuerToken, false)
}
func (p *rid06PublicContext) actionPair(t *testing.T, w *ridLifecycleWorld, scenario string, body map[string]any, token string, creator bool) rid06PublicExpectation {
	a := rid06Primary(t, w, true)
	p.state(t, w, a, "REVOKED")
	e := p.expect(t, w, scenario+"-ACT", a, "REVOKED")
	e.Path = "/iam/v1/accessBindings"
	rawBody, err := json.Marshal(body)
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(rawBody, &e.Request))
	e.Scenario = scenario
	key := "jwtRIDIssuer"
	if creator {
		key = "jwtRIDCreator"
		e.Actor = w.f.creator.ID
		e.Path = "/iam/v1/grantDelegations"
	}
	var receipt ridNewmanReceipt
	var b rid03NewmanSnapshot
	func() {
		defer func() {
			b = rid06Primary(t, w, true)
			rid03RequireActionDeltaWithReceipt(t, w, &e.rid03NewmanExpectation, a, b, rid06BuildTechnicalReceipt)
			require.True(t, receipt.OK)
			require.NotNil(t, e.TechnicalEvidence)
			e.TechnicalEvidence.PhaseRuntimeChecksPassed = true
			rid08Write(t, w.f.session.Root, "newman-"+strings.ToLower(e.CaseID)+"-primary-proof", e.TechnicalEvidence)
		}()
		receipt = ridRunNewmanPhase(t, w.f, "registry-installation-rid06", e.CaseID, strings.ToLower(e.CaseID), map[string]any{"rid06Expected": e, key: token})
		require.True(t, receipt.OK)
	}()
	act := e
	e.CaseID = strings.TrimSuffix(e.CaseID, "-ACT") + "-VERIFY"
	e.Phase = "VERIFY"
	e.Snapshot = b
	var verify ridNewmanReceipt
	func() {
		defer func() {
			after := rid06Primary(t, w, false)
			rid03RequireReadOnly(t, b, after)
			proof, ok := rid06BuildTechnicalReceipt(&e.rid03NewmanExpectation, b, after, nil)
			require.True(t, ok)
			require.True(t, verify.OK)
			proof.PhaseRuntimeChecksPassed = true
			rid08Write(t, w.f.session.Root, "newman-"+strings.ToLower(e.CaseID)+"-primary-technical-proof", proof)
		}()
		verify = ridRunNewmanPhase(t, w.f, "registry-installation-rid06", e.CaseID, strings.ToLower(e.CaseID), map[string]any{"rid06Expected": e})
		require.True(t, verify.OK)
	}()
	return act
}

// Только Revoke работает внутри консервативной ранней границы spawned+20s. Весь
// допуск, оба полных снимка SQL и настоящий POST/опрос владельца делят её.
func (p *rid06PublicContext) revoke(t *testing.T, w *ridLifecycleWorld, id string, deadline time.Time) installruntime.Operation {
	ctx, cancel := context.WithDeadline(w.f.given.ctx, deadline)
	defer cancel()
	require.NoError(t, ctx.Err(), "FIXTURE_NOT_ACCEPTED: no original pause budget remains")
	view, f, given := *w, *w.f, *w.f.given
	given.ctx = ctx
	f.given = &given
	view.f = &f
	defer func() { w.f.secrets = f.secrets; w.f.operator = f.operator }()
	a := rid06Primary(t, &view, true)
	p.preRevoke = &a
	e := p.expect(t, &view, "REVOKE-ACT", a, "ACTIVE")
	e.Actor = w.f.operator.UserID()
	e.ActionDeadline = &deadline
	e.Path = "/iam/v1/grantDelegations/" + id + ":revoke"
	e.Request = map[string]any{}
	var receipt ridNewmanReceipt
	var result installruntime.Operation
	func() {
		defer func() {
			b := rid06Primary(t, &view, true)
			op, proof := rid06RequireRevokeDelta(t, &view, e, a, b)
			require.True(t, receipt.OK)
			p.postRevoke = &b
			p.revokeOperation = rid09PrimaryJSON(t, operationspb.ToProto(op))
			raw, err := json.Marshal(p.revokeOperation)
			require.NoError(t, err)
			require.NoError(t, json.Unmarshal(raw, &result))
			rid08Write(t, w.f.session.Root, "newman-"+strings.ToLower(e.CaseID)+"-primary-revoke-proof", proof)
			require.NoError(t, ctx.Err(), "FIXTURE_NOT_ACCEPTED: original pause budget exhausted")
		}()
		receipt = ridRunNewmanPhaseBudget(t, &f, "registry-installation-rid06", e.CaseID, strings.ToLower(e.CaseID), map[string]any{"rid06Expected": e}, ctx)
		require.True(t, receipt.OK)
	}()
	w.f.secrets = f.secrets
	return result
}

func rid06RequireNativeHistory(t *testing.T, a, b rid03NewmanSnapshot) {
	require.True(t, rid04GDGHistoryEqual(a, b), "full primary GD/G raw history changed across startup")
	require.True(t, reflect.DeepEqual(a.Projection, b.Projection), "full primary projection changed across startup")
	require.True(t, reflect.DeepEqual(a.BusinessAudit, b.BusinessAudit), "startup changed business audit")
	require.True(t, rid06HistoryOwnCeilingsValid(a.Whole, b.Whole), "midrun own-ceilings must preserve full semantics and unchanged or bounded diagnostic clocks")
}
func (p *rid06PublicContext) beforeRevoke(t *testing.T, w *ridLifecycleWorld, deadline time.Time) {
	if p == nil {
		return
	}
	p.barrierDeadline = deadline
	ctx, cancel := context.WithDeadline(w.f.given.ctx, deadline)
	defer cancel()
	view, f, given := *w, *w.f, *w.f.given
	given.ctx = ctx
	f.given = &given
	view.f = &f
	s := rid06Primary(t, &view, true)
	p.preRevoke = &s
}
func (p *rid06PublicContext) afterRevoke(t *testing.T, w *ridLifecycleWorld, id string) {
	if p == nil {
		return
	}
	require.NotNil(t, p.preRevoke)
	ctx, cancel := context.WithDeadline(w.f.given.ctx, p.barrierDeadline)
	defer cancel()
	view, f, given := *w, *w.f, *w.f.given
	given.ctx = ctx
	f.given = &given
	view.f = &f
	b := rid06Primary(t, &view, true)
	e := p.expect(t, &view, "REVOKE-ACT", *p.preRevoke, "ACTIVE")
	e.Actor = w.f.operator.UserID()
	op, proof := rid06RequireRevokeDelta(t, &view, e, *p.preRevoke, b)
	require.Equal(t, id, op.ID)
	p.revokeOperation = rid09PrimaryJSON(t, operationspb.ToProto(op))
	p.postRevoke = &b
	if p.owner != "revoke" {
		rid08Write(t, w.f.session.Root, "rid06-"+p.owner+"-"+rid03Mode(t, w)+"-native-revoke-proof", map[string]any{"integrationOnly": true, "actualNewmanExecuted": false, "proof": proof, "wholeDoDAccepted": false})
	}
	require.NoError(t, ctx.Err())
}

// Во время отказавшего запуска могут добавляться только нативные Operation установщика.
// Их точные типизированные количество/исход отдельно проверяет нативный
// оракул Operation; каждая другая известная или будущая необработанная таблица поставки сохраняется точно.
func rid06FailedDeliveryEqual(a, b rid03NewmanSnapshot) bool {
	if len(a.Raw) != len(b.Raw) || !reflect.DeepEqual(a.Projection, b.Projection) || !reflect.DeepEqual(a.BusinessAudit, b.BusinessAudit) {
		return false
	}
	for table, rows := range a.Raw {
		now, ok := b.Raw[table]
		if !ok {
			return false
		}
		if table != "operations" && !reflect.DeepEqual(rows, now) {
			return false
		}
	}
	return true
}
func rid06PauseDeadline(ctx context.Context, spawned time.Time) time.Time {
	deadline := spawned.Add(20 * time.Second)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		return parent
	}
	return deadline
}

// Оракул свежести остановленной базы остаётся обязательным в NativeBoundary выше.
// Эта отдельная грань истории может начаться ПОСЛЕ обновления собственного посева этого запуска
// (postRevoke). Поэтому неизменные диагностические часы допустимы. Изменённые
// часы должны подтверждаться настоящим охватывающим интервалом наблюдения PRIMARY.
func rid06HistoryOwnCeilingsValid(before, after ridWholeDeliverySnapshot) bool {
	a, b := before.OwnCeilings, after.OwnCeilings
	if before.PrimaryStartedAt.IsZero() || before.PrimaryFinishedAt.IsZero() || after.PrimaryStartedAt.IsZero() || after.PrimaryFinishedAt.IsZero() || before.PrimaryFinishedAt.Before(before.PrimaryStartedAt) || after.PrimaryFinishedAt.Before(after.PrimaryStartedAt) || after.PrimaryStartedAt.Before(before.PrimaryFinishedAt) {
		return false
	}
	if !reflect.DeepEqual(a.Raw.Columns, b.Raw.Columns) || !reflect.DeepEqual(a.Semantic, b.Semantic) || len(a.Semantic) == 0 || len(a.Raw.Rows) != len(a.Semantic) || len(b.Raw.Rows) != len(a.Semantic) || len(a.StatedAt) != len(a.Semantic) || len(b.StatedAt) != len(a.Semantic) {
		return false
	}
	columns := map[string]bool{}
	for _, column := range a.Raw.Columns {
		if column == "" || columns[column] {
			return false
		}
		columns[column] = true
	}
	for _, required := range []string{"kind", "limit_value", "stated_at"} {
		if !columns[required] {
			return false
		}
	}
	unchanged := true
	for kind, digest := range a.Semantic {
		old, oldOK := a.StatedAt[kind]
		now, nowOK := b.StatedAt[kind]
		if kind == "" || digest == "" || !oldOK || !nowOK || old.IsZero() || now.IsZero() || old.After(before.PrimaryFinishedAt) || now.After(after.PrimaryStartedAt) {
			return false
		}
		if !now.Equal(old) {
			unchanged = false
			if now.Before(before.PrimaryFinishedAt) || now.After(after.PrimaryStartedAt) {
				return false
			}
		}
	}
	// Необработанные хеши сохраняются, а не переписываются из значений AFTER. Когда
	// диагностические часы не сдвинулись, ПОЛНАЯ перепись необработанных строк также должна совпадать точно.
	return !unchanged || reflect.DeepEqual(a.Raw.Rows, b.Raw.Rows)
}
