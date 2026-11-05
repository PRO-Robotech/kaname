// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
)

type rid11PublicContext struct {
	input                 rid11Case
	credential            string
	creator               map[string]any
	beforeRun, preRestore *rid03NewmanSnapshot
	refusalProved         bool
	receipts              map[string]bool
}
type rid11NewmanExpectation struct {
	rid03NewmanExpectation
	Variant                   string         `json:"variant"`
	Stage                     string         `json:"stage"`
	CreatorAbsent             bool           `json:"creatorAbsent"`
	IssuerPresent             bool           `json:"issuerPresent"`
	Token401                  bool           `json:"token401"`
	CreatorReference          map[string]any `json:"creatorReference"`
	DeclaredIssuer            map[string]any `json:"declaredIssuer"`
	DeclaredIssuerSubjectType string         `json:"declaredIssuerSubjectType"`
	StockServiceAccountIDs    []string       `json:"stockServiceAccountIds"`
	AssertionExpiresAt        time.Time      `json:"assertionExpiresAt"`
}

func rid11OwnedStages(c rid11Case) []string {
	if !c.Twin && c.Variant == "deleted-creator" {
		return []string{"BEFORE", "KEY-REVOKED-C-LIVE", "AFTER"}
	}
	return []string{"BEFORE", "AFTER"}
}
func rid11PublicConsumer(t *testing.T, w *ridLifecycleWorld, c rid11Case) *rid11PublicContext {
	t.Helper()
	if os.Getenv("KANAME_RID_NEWMAN") == "1" {
		return &rid11PublicContext{input: c, receipts: map[string]bool{}}
	}
	for _, stage := range rid11OwnedStages(c) {
		id := rid11PublicCaseID(c, stage)
		_, ok := rid11PublicRules[id]
		require.True(t, ok)
		rid08Write(t, w.f.session.Root, "newman-"+strings.ToLower(id), map[string]any{"state": "NOT_EXECUTED", "caseId": id, "actualNewmanExecuted": false, "wholeDoDAccepted": false})
	}
	return nil
}
func rid11NamedIssuer(p rid09NewmanProjection, system, creator string, stock []string) (map[string]any, bool) {
	var found map[string]any
	for _, sa := range p.ServiceAccounts {
		if sa["accountId"] == system && sa["name"] == "rid-public-issuer" {
			if found != nil || sa["id"] == creator || sa["enabled"] != true {
				return nil, false
			}
			id, ok := sa["id"].(string)
			if !ok || id == "" {
				return nil, false
			}
			for _, s := range stock {
				if s == id {
					return nil, false
				}
			}
			found = sa
		}
	}
	return found, true
}
func rid11ServiceAccount(p rid09NewmanProjection, id string) (map[string]any, bool) {
	var found map[string]any
	for _, sa := range p.ServiceAccounts {
		if sa["id"] == id {
			if found != nil {
				return nil, false
			}
			found = sa
		}
	}
	return found, true
}
func rid11StockIDs(w *ridLifecycleWorld) []string {
	ids := []string{}
	for id := range w.f.baseline.ServiceAccounts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
func (p *rid11PublicContext) before(t *testing.T, w *ridLifecycleWorld) {
	if p == nil {
		return
	}
	s := rid03StableNewmanSnapshot(t, w)
	var ok bool
	p.creator, ok = rid11ServiceAccount(s.Projection, w.f.creator.ID)
	require.True(t, ok && p.creator != nil)
	p.read(t, w, "BEFORE", s)
}
func (p *rid11PublicContext) liveAfterRevoke(t *testing.T, w *ridLifecycleWorld) {
	if p == nil {
		return
	}
	require.True(t, !p.input.Twin && p.input.Variant == "deleted-creator")
	p.read(t, w, "KEY-REVOKED-C-LIVE", rid03StableNewmanSnapshot(t, w))
}
func (p *rid11PublicContext) beforeStartup(t *testing.T, w *ridLifecycleWorld, credential string) {
	if p == nil {
		return
	}
	p.credential = credential
	s := rid03StableNewmanSnapshot(t, w)
	p.beforeRun = &s
	p.refusalProved = false
}
func rid11RequireOldOperations(t *testing.T, a, b rid03NewmanSnapshot, delta int) []string {
	t.Helper()
	old, now := rid03RowsByID(t, a.Raw["operations"]), rid03RowsByID(t, b.Raw["operations"])
	require.Equal(t, len(old)+delta, len(now), "exact native installer Operation count")
	fresh := []string{}
	for id, row := range old {
		require.True(t, reflect.DeepEqual(row, now[id]), "old full Operation changed; no redaction exception")
	}
	for id := range now {
		if _, exists := old[id]; !exists {
			fresh = append(fresh, id)
		}
	}
	return fresh
}
func (p *rid11PublicContext) afterPositive(t *testing.T, w *ridLifecycleWorld) {
	if p == nil {
		return
	}
	require.True(t, p.input.Twin)
	require.NotNil(t, p.beforeRun)
	s := rid03StableNewmanSnapshot(t, w)
	ids := rid11RequireOldOperations(t, *p.beforeRun, s, len(w.accounts))
	issuer, ok := rid11NamedIssuer(s.Projection, w.f.baseline.SystemID, w.f.creator.ID, rid11StockIDs(w))
	require.True(t, ok && issuer != nil)
	ctx, cancel := context.WithTimeout(w.f.given.ctx, 30*time.Second)
	defer cancel()
	seen := map[string]bool{}
	pairs := map[string]string{}
	for _, id := range ids {
		op, err := operations.NewRepo(w.f.given.pool, "kaname").Get(ctx, id)
		require.NoError(t, err)
		require.True(t, op.Done && op.Error == nil && string(op.CreatedBy) == w.f.creator.ID, "actual native creator Operation identity")
		require.True(t, op.Principal == (operations.Principal{Type: "service_account", ID: w.f.creator.ID, DisplayName: w.f.creator.ID}))
		require.NotNil(t, op.Metadata)
		var meta iamv1.CreateGrantDelegationMetadata
		require.NoError(t, op.Metadata.UnmarshalTo(&meta))
		require.False(t, seen[meta.AccountId])
		seen[meta.AccountId] = true
		pairs[meta.AccountId] = meta.GrantDelegationId
		expectedAccount := false
		for _, a := range w.accounts {
			if a == meta.AccountId {
				expectedAccount = true
			}
		}
		require.True(t, expectedAccount)
		var gd map[string]any
		for _, row := range s.Projection.Delegations {
			if row["id"] == meta.GrantDelegationId {
				require.Nil(t, gd)
				gd = row
			}
		}
		require.True(t, gd != nil && gd["accountId"] == meta.AccountId)
		delegate, ok := gd["delegate"].(map[string]any)
		require.True(t, ok && delegate["id"] == issuer["id"])
		raw := rid03RowsByID(t, s.Raw["operations"])[id]
		require.Equal(t, w.f.creator.ID, rid03S(raw, "created_by"))
		requireNativeInstallationOperation(t, ctx, w.f.given.pool, id, meta.AccountId, w.f.creator.ID, meta.GrantDelegationId)
	}
	require.NoError(t, ctx.Err())
	pull := ""
	for _, role := range s.Raw["roles"] {
		if rid03S(role, "name") == "registry.puller" && rid03S(role, "owner_module") == "registry" {
			require.Empty(t, pull)
			pull = rid03S(role, "id")
		}
	}
	require.NotEmpty(t, pull)
	auditPairs := pairs
	if p.input.Active {
		auditPairs = map[string]string{}
	}
	require.True(t, rid11InstallerAuditValid(p.beforeRun.BusinessAudit, s.BusinessAudit, w.f.creator.ID, issuer["id"].(string), pull, auditPairs, p.beforeRun.Whole.PrimaryFinishedAt, s.Whole.PrimaryStartedAt), "exact normal installer GD business audit delta; no extra AB/GD event")
	// Предыдущие делегирование/выдача/история установки сохраняются побайтно. Новый
	// штатный запуск отсутствующей пары подтверждается отдельно нативными утверждениями.
	if p.input.Active {
		rid04RequireGDGUnchanged(t, *p.beforeRun, s)
	}
	rid08Write(t, w.f.session.Root, "rid11-native-success-primary", map[string]any{"integrationOnly": true, "actualNewmanExecuted": false, "beforeWhole": p.beforeRun.Whole, "afterWhole": s.Whole, "operationIds": ids, "primaryDerivedIssuer": issuer, "wholeDoDAccepted": false})
	p.read(t, w, "AFTER", s)
}
func (p *rid11PublicContext) beforeRestore(t *testing.T, w *ridLifecycleWorld, result rid11Return) {
	if p == nil {
		return
	}
	require.False(t, p.input.Twin)
	require.NotNil(t, p.beforeRun)
	require.True(t, result.ErrorPresent && result.CaptureOK && result.MessageMatches && result.Code == int32(p.input.returnCode()), "actual failed startup must be captured before any restoration")
	s := rid03PhaseSnapshot(t, w)
	rid11RequireOldOperations(t, *p.beforeRun, s, 0)
	require.True(t, reflect.DeepEqual(p.beforeRun.Raw["grant_delegations"], s.Raw["grant_delegations"]), "all GD/history before restoration exact")
	require.True(t, reflect.DeepEqual(p.beforeRun.BusinessAudit, s.BusinessAudit), "failed startup emits no AB/GD business event")
	if p.input.Variant != "census" {
		ridRequireWholeDeliveryUnchanged(t, p.beforeRun.Whole, s.Whole)
		require.True(t, reflect.DeepEqual(p.beforeRun.Raw, s.Raw), "failed prewrite startup full delivery/history/Operation zero")
		require.True(t, reflect.DeepEqual(p.beforeRun.Projection, s.Projection), "failed prewrite startup projection zero")
	} else {
		// Перепись отказывает ПОСЛЕ штатного посева/поставки каталога и независимого создания I.
		// Сохраняются исходные нативные защиты страниц/RR/сбоев и точные защиты GD/Operation.
		if p.input.Active {
			rid04RequireGDGUnchanged(t, *p.beforeRun, s)
		}
		issuer, ok := rid11NamedIssuer(s.Projection, w.f.baseline.SystemID, w.f.creator.ID, rid11StockIDs(w))
		require.True(t, ok && issuer != nil)
	}
	p.preRestore = &s
	p.refusalProved = true
	rid08Write(t, w.f.session.Root, "rid11-failed-start-before-any-restore", map[string]any{"integrationOnly": true, "actualNewmanExecuted": false, "variant": p.input.Variant, "code": result.Code, "stage": p.input.expected().Stage, "beforeWhole": p.beforeRun.Whole, "afterWhole": s.Whole, "beforeRawSHA256": rid03EvidenceHash(p.beforeRun.Raw), "afterRawSHA256": rid03EvidenceHash(s.Raw), "businessHistorySHA256": rid03EvidenceHash(s.BusinessAudit), "censusNormalDeliveryAllowed": p.input.Variant == "census", "wholeDoDAccepted": false})
}
func (p *rid11PublicContext) afterNegative(t *testing.T, w *ridLifecycleWorld) {
	if p == nil {
		return
	}
	require.True(t, p.refusalProved && p.preRestore != nil, "failed-start proof before ANY restoration mandatory")
	s := rid03StableNewmanSnapshot(t, w)
	if p.input.Variant == "census" {
		rid11RequireCensusRestoration(t, w, *p.preRestore, s)
	} else {
		rid04RequireNormalBoundary(t, w, *p.preRestore, s, 0)
	}
	p.read(t, w, "AFTER", s)
}
func (p *rid11PublicContext) complete(t *testing.T) bool {
	for _, stage := range rid11OwnedStages(p.input) {
		require.True(t, p.receipts[rid11PublicCaseID(p.input, stage)], "each owned literal public phase actually executed")
	}
	return true
}
func (p *rid11PublicContext) read(t *testing.T, w *ridLifecycleWorld, stage string, s rid03NewmanSnapshot) {
	id := rid11PublicCaseID(p.input, stage)
	rule, ok := rid11PublicRules[id]
	require.True(t, ok)
	require.False(t, p.receipts[id])
	issuer, ok := rid11NamedIssuer(s.Projection, w.f.baseline.SystemID, w.f.creator.ID, rid11StockIDs(w))
	require.True(t, ok)
	require.Equal(t, rule.IssuerPresent, issuer != nil)
	creator, ok := rid11ServiceAccount(s.Projection, w.f.creator.ID)
	require.True(t, ok)
	require.Equal(t, !rule.CreatorAbsent, creator != nil)
	if creator != nil {
		require.True(t, reflect.DeepEqual(p.creator, creator), "same complete C, no replacement or changed identity")
	}
	n := 0
	if rule.GDPresent {
		n = len(w.accounts)
	}
	require.Equal(t, n, len(s.Projection.Delegations))
	e := rid11NewmanExpectation{rid03NewmanExpectation: rid03NewmanExpectation{CaseID: id, Mode: p.input.Mode, Phase: "READ", Operator: w.f.operator.UserID(), Creator: w.f.creator.ID, System: w.f.baseline.SystemID, Tenant: w.f.tenantID, Snapshot: s}, Variant: p.input.Variant, Stage: stage, CreatorAbsent: rule.CreatorAbsent, IssuerPresent: rule.IssuerPresent, Token401: rule.Token401, CreatorReference: p.creator, DeclaredIssuer: issuer, DeclaredIssuerSubjectType: "service_account", StockServiceAccountIDs: rid11StockIDs(w)}
	vars := map[string]any{}
	var authBefore *rid11AuthnSnapshot
	var observer func() error
	if rule.Token401 {
		assertion, expiry := rid11FreshInputAssertion(t, w.f, p.credential)
		vars["rid11ClientAssertion"] = assertion
		vars["rid11IssuanceOrigin"] = w.f.wire.IssuanceURL
		e.AssertionExpiresAt = expiry
		observer = func() error {
			ctx, cancel := context.WithTimeout(w.f.given.ctx, 20*time.Second)
			defer cancel()
			a, err := rid11CaptureAuthn(ctx, w.f)
			if err == nil {
				authBefore = &a
			}
			return err
		}
	}
	vars["rid11Expected"] = e
	var receipt ridNewmanReceipt
	func() {
		defer func() {
			after := rid03PhaseSnapshot(t, w)
			rid03RequireReadOnly(t, s, after)
			proof, valid := ridNewmanBuildClosedTechnicalReceipt(&e.rid03NewmanExpectation, s, after, nil)
			require.True(t, valid)
			if rule.Token401 {
				require.NotNil(t, authBefore, "post-O/pre-authn protected baseline mandatory")
				ctx, cancel := context.WithTimeout(w.f.given.ctx, 20*time.Second)
				defer cancel()
				authAfter, err := rid11CaptureAuthn(ctx, w.f)
				require.NoError(t, err)
				require.True(t, rid11AuthnUnchanged(*authBefore, authAfter), "FIXTURE_NOT_ACCEPTED: authn action/history changed or audit transport transition invalid")
				beforeAction, beforeTransport := rid11AuditParts(authBefore.Raw["audit_outbox"])
				afterAction, afterTransport := rid11AuditParts(authAfter.Raw["audit_outbox"])
				rid08Write(t, w.f.session.Root, "newman-"+strings.ToLower(id)+"-authn-primary", map[string]any{"caseId": id, "afterOrdinaryOExchange": true, "beforeAuditImmutableSHA256": beforeAction, "afterAuditImmutableSHA256": afterAction, "beforeAuditTransportSHA256": beforeTransport, "afterAuditTransportSHA256": afterTransport, "before": authBefore, "after": authAfter, "zeroReplayAndAccessTokenDelta": true, "auditActionHistoryUnchanged": true, "auditTransportTransitionValidated": true, "wholeDoDAccepted": false})
			}
			require.True(t, receipt.OK)
			proof.PhaseRuntimeChecksPassed = true
			rid08Write(t, w.f.session.Root, "newman-"+strings.ToLower(id)+"-primary-technical-audit-receipt", proof)
			p.receipts[id] = true
		}()
		if observer != nil {
			receipt = ridRunNewmanInputObserved(t, w.f, id, strings.ToLower(id), vars, observer)
		} else {
			receipt = ridRunNewmanPhase(t, w.f, "registry-installation-rid11", id, strings.ToLower(id), vars)
		}
		require.True(t, receipt.OK)
	}()
}

// Нативная установка не является изменением Newman. Её независимые первичные
// метаданные Operation дают ID ресурсов; заявленные оси манифеста дают эту
// замкнутую нагрузку аудита. Вся старая история и перепись всего семейства AB/GD сохраняются.
func rid11InstallerAuditValid(before, after []rid09PrimaryRow, creator, issuer, role string, pairs map[string]string, start, end time.Time) bool {
	if creator == "" || issuer == "" || role == "" || start.IsZero() || end.Before(start) {
		return false
	}
	fresh, ok := rid03NewEvidenceRows(before, after)
	if !ok || len(fresh) != len(pairs) {
		return false
	}
	seen := map[string]bool{}
	for _, row := range fresh {
		if !rid03Columns(row, "id event_type tenant_account_id event_payload created_at") || !rid03AuditIDPattern.MatchString(rid03S(row, "id")) || seen[rid03S(row, "id")] {
			return false
		}
		seen[rid03S(row, "id")] = true
		account := rid03S(row, "tenant_account_id")
		gd, ok := pairs[account]
		if !ok || gd == "" {
			return false
		}
		at, valid := rid03Cell[time.Time](row, "created_at")
		if !valid || at.Before(start) || at.After(end) || rid03S(row, "event_type") != "iam.grant_delegation.created" {
			return false
		}
		payload := map[string]any{"actor": creator, "delegation_id": gd, "account_id": account, "delegate": issuer, "module": "registry", "role_ids": []string{role}, "target_types": []string{"registry.registries"}, "subject_types": []string{"service_account"}}
		if !rid03SameCell(row, "event_payload", payload) {
			return false
		}
	}
	accounts := map[string]bool{}
	for _, row := range fresh {
		account := rid03S(row, "tenant_account_id")
		if accounts[account] {
			return false
		}
		accounts[account] = true
	}
	return len(accounts) == len(pairs)
}
