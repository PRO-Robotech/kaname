// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	"github.com/golang-jwt/jwt/v5"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

type rid01OperationColumnProof struct {
	SHA256 string `json:"sha256"`
	Kind   string `json:"kind"`
	Null   bool   `json:"null"`
}

type rid01NewmanSnapshot struct {
	Projection            rid09NewmanProjection                           `json:"projection"`
	Whole                 ridWholeDeliverySnapshot                        `json:"-"`
	Operations            map[string]string                               `json:"-"`
	OperationColumnHashes map[string]map[string]rid01OperationColumnProof `json:"-"`
}
type rid01PublicContext struct {
	f                    *installationNativeWorld
	Kind                 string
	Phases               []string
	Calls                int
	Initial              rid01NewmanSnapshot
	Previous             *rid01NewmanSnapshot
	RefusalBeforeRestore *rid01NewmanSnapshot
}
type rid01PublicExpectation struct {
	CaseID             string                 `json:"caseId"`
	Phase              string                 `json:"phase"`
	Operator           string                 `json:"operatorId"`
	Creator            string                 `json:"creatorId"`
	System             string                 `json:"systemId"`
	Tenant             string                 `json:"tenantId"`
	Modules            []string               `json:"modules"`
	Issuers            map[string]string      `json:"issuers"`
	Snapshot           rid01NewmanSnapshot    `json:"snapshot"`
	Previous           *rid09NewmanProjection `json:"previousProjection"`
	AssertionExpiresAt string                 `json:"assertionExpiresAt"`
}

func rid01CaptureSnapshot(t *testing.T, ctx context.Context, f *installationNativeWorld) (rid01NewmanSnapshot, bool) {
	t.Helper()
	require.NoError(t, ctx.Err())
	p := rid09ReadNewmanProjectionContext(t, ctx, f)
	readWorld, readGiven := *f, *f.given
	readGiven.ctx = ctx
	readWorld.given = &readGiven
	whole := ridReadWholeDelivery(t, &readWorld)
	tx, err := f.given.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = tx.Rollback(closeCtx)
	}()
	var recovery bool
	require.NoError(t, tx.QueryRow(ctx, "SELECT pg_is_in_recovery()").Scan(&recovery))
	require.False(t, recovery)
	ops := map[string]string{}
	columns := map[string]map[string]rid01OperationColumnProof{}
	for _, row := range rid09PrimaryRows(t, ctx, tx, "operations") {
		id := rid09PrimaryValue[string](t, row, "id")
		require.NotContains(t, ops, id)
		ops[id] = ridWholeDigest(t, row)
		columns[id] = map[string]rid01OperationColumnProof{}
		for name, value := range row {
			// A primary cell is json.RawMessage: SQL NULL is the literal
			// bytes "null", not a nil Go wrapper. Decode only its JSON kind;
			// the digest always covers the untouched original RawMessage.
			var cell any
			decoder := json.NewDecoder(bytes.NewReader(value))
			decoder.UseNumber()
			require.NoError(t, decoder.Decode(&cell))
			kind := "null"
			switch cell.(type) {
			case nil:
			case string:
				kind = "string"
			case json.Number:
				kind = "number"
			case bool:
				kind = "boolean"
			case map[string]any:
				kind = "object"
			case []any:
				kind = "array"
			default:
				t.Fatal("unrecognized primary JSON cell kind")
			}
			columns[id][name] = rid01OperationColumnProof{SHA256: ridWholeDigest(t, value), Kind: kind, Null: cell == nil}
		}
	}
	require.NoError(t, tx.Commit(ctx))
	after := rid09ReadNewmanProjectionContext(t, ctx, f)
	require.NoError(t, ctx.Err(), "aggregate RID01 snapshot budget expired before return")
	return rid01NewmanSnapshot{Projection: p, Whole: whole, Operations: ops, OperationColumnHashes: columns}, reflect.DeepEqual(p, after)
}
func rid01StableSnapshots(a, b rid01NewmanSnapshot) bool {
	return reflect.DeepEqual(a.Projection, b.Projection) && reflect.DeepEqual(a.Whole.Delivery, b.Whole.Delivery) && reflect.DeepEqual(a.Whole.OwnCeilings, b.Whole.OwnCeilings) && reflect.DeepEqual(a.Operations, b.Operations) && reflect.DeepEqual(a.Whole.Bookkeeping["operations"], b.Whole.Bookkeeping["operations"])
}

// Only the readiness baseline is observed until stable. A single caller context
// bounds all SQL/raw/projection reads, waits and the successful return.
func rid01Baseline(t *testing.T, f *installationNativeWorld) rid01NewmanSnapshot {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.given.ctx, 30*time.Second)
	defer cancel()
	var previous *rid01NewmanSnapshot
	for {
		snapshot, composed := rid01CaptureSnapshot(t, ctx, f)
		if composed && previous != nil && rid01StableSnapshots(*previous, snapshot) {
			require.NoError(t, ctx.Err())
			return snapshot
		}
		previous = nil
		if composed {
			previous = &snapshot
		}
		select {
		case <-ctx.Done():
			t.Fatal("fixture NOT_ACCEPTED: aggregate30s RID01 baseline did not stabilize")
		case <-time.After(100 * time.Millisecond):
		}
	}
}
func rid01NewmanContext(t *testing.T, f *installationNativeWorld, kind string) *rid01PublicContext {
	t.Helper()
	phases := map[string][]string{"clean": {"CLEAN-BEFORE", "CLEAN-INSTALLED"}, "identities": {"S1-EXACT-IDENTITIES"}, "renewal": {"RENEWAL-BEFORE", "EXPIRED-ACCESS-TOKEN", "RENEWAL-AFTER"}, "key": {"VALID-KEY-TWIN", "EXPIRED-KEY-REFUSAL"}}
	require.Contains(t, phases, kind)
	if os.Getenv("KANAME_RID_NEWMAN") != "1" {
		for _, phase := range phases[kind] {
			id := "registry-installation-rid01-" + phase
			rid08Write(t, f.session.Root, "newman-"+strings.ToLower(id), map[string]any{"state": "NOT_EXECUTED", "caseId": id, "actualNewmanExecuted": false, "wholeDoDAccepted": false})
		}
		return nil
	}
	h := &rid01PublicContext{f: f, Kind: kind, Phases: phases[kind], Initial: rid01Baseline(t, f)}
	t.Cleanup(func() {
		require.Equal(t, len(h.Phases), h.Calls, "all canonical RID01 phases must execute exactly once")
	})
	return h
}
func rid01NewmanPhase(t *testing.T, h *rid01PublicContext, phase string, variables map[string]any) {
	t.Helper()
	if h == nil {
		return
	}
	require.Less(t, h.Calls, len(h.Phases))
	require.Equal(t, h.Phases[h.Calls], phase)
	h.Calls++
	f := h.f
	id := "registry-installation-rid01-" + phase
	snapshot := rid01Baseline(t, f)
	modules := []string{"ridfirst"}
	if h.Kind == "clean" {
		modules = []string{"ridfirst", "ridsecond"}
	}
	if phase == "CLEAN-BEFORE" {
		modules = []string{}
	}
	e := rid01PublicExpectation{CaseID: id, Phase: phase, Operator: string(f.given.user), Creator: f.creator.ID, System: f.baseline.SystemID, Tenant: f.tenantID, Modules: modules, Issuers: map[string]string{}, Snapshot: snapshot}
	rid01RequirePremise(t, h, &e)
	previous := h.Initial
	if h.Previous != nil {
		previous = *h.Previous
		e.Previous = &previous.Projection
	}
	installedNow := phase == "CLEAN-INSTALLED" || phase == "S1-EXACT-IDENTITIES" || phase == "RENEWAL-BEFORE" || phase == "VALID-KEY-TWIN"
	// Closed census of all eight boundary types. Full raw zero-delta belongs
	// to read-only/no-startup boundaries and the refusal BEFORE restoration.
	// Normal startup may restate seed/catalog storage while preserving the full
	// public state and exact historical GD/G rows; never call it a zero-write.
	switch phase {
	case "CLEAN-BEFORE", "EXPIRED-ACCESS-TOKEN":
		require.True(t, rid01StableSnapshots(previous, snapshot), "read-only boundary preserves all primary/raw/Operation state")
	case "CLEAN-INSTALLED", "S1-EXACT-IDENTITIES", "RENEWAL-BEFORE", "VALID-KEY-TWIN":
		// New delivered resources are checked independently by literal module
		// counts and all declared identities/seeds in rid01RequirePremise.
		ridRequireOwnCeilingsPreserved(t, previous.Whole, snapshot.Whole)
	case "RENEWAL-AFTER":
		rid01RequireReentryPreserved(t, previous, snapshot)
		ridRequireOwnCeilingsPreserved(t, previous.Whole, snapshot.Whole)
	case "EXPIRED-KEY-REFUSAL":
		require.NotNil(t, h.RefusalBeforeRestore, "successful strict refusal capture BEFORE any restore is mandatory; no post-restore fallback")
		rid01RequireReentryPreserved(t, previous, snapshot)
		// Bound the actual normal restoring startup by the independently
		// captured post-refusal primary clocks, not by a new repaired baseline.
		ridRequireOwnCeilingsPreserved(t, h.RefusalBeforeRestore.Whole, snapshot.Whole)
	default:
		t.Fatal("unclassified RID01 phase boundary")
	}
	delta := 0
	if installedNow {
		delta = len(modules)
	}
	if phase == "RENEWAL-AFTER" {
		delta = 1
	}
	rid01RequireOperations(t, f, previous, snapshot, delta)
	if variables == nil {
		variables = map[string]any{}
	}
	if phase == "EXPIRED-KEY-REFUSAL" {
		require.False(t, time.Now().Before(f.creator.ExpiresAt.Add(tokenpolicy.ClockSkew+time.Second)), "only actual expired key is admitted")
		proof, end := rid01FreshAssertion(t, f)
		variables["rid01ClientAssertion"] = proof
		variables["rid01IssuanceOrigin"] = f.wire.IssuanceURL
		e.AssertionExpiresAt = end.Format(time.RFC3339)
	}
	variables["rid01Expected"] = e
	func() {
		defer func() {
			ctx, cancel := context.WithTimeout(f.given.ctx, 30*time.Second)
			defer cancel()
			after, composed := rid01CaptureSnapshot(t, ctx, f)
			stable := composed && rid01StableSnapshots(snapshot, after)
			rid08Write(t, f.session.Root, "newman-"+strings.ToLower(id)+"-primary-bracket", map[string]any{"caseId": id, "fullPrimarySnapshotUnchangedDuringPhase": stable, "wholeDoDAccepted": false})
			require.True(t, stable, "fixture NOT_ACCEPTED: full primary/raw/materialization/Operation ledger moved during single actual Newman attempt; no retry")
		}()
		receipt := ridRunNewmanPhase(t, f, "registry-installation-rid01", id, strings.ToLower(id), variables)
		require.True(t, receipt.OK)
	}()
	current := snapshot
	h.Previous = &current
}

// Successful re-entry preserves all public fields and full raw historical
// GD/G/target/materialization identities. The complete raw snapshot remains
// captured and is strict within each actual public phase; unrelated catalog/seed
// restatement hashes are not asserted zero across an authorized startup.
func rid01RequireReentryPreserved(t *testing.T, before, after rid01NewmanSnapshot) {
	t.Helper()
	require.Equal(t, before.Projection, after.Projection, "full public identities/createdAt/axes/materializedAt/catalog/seed unchanged across normal re-entry")
	require.Equal(t, before.Whole.Separation, after.Whole.Separation)
	for table, rows := range before.Whole.Delivery {
		if table == "grant_delegations" || strings.HasPrefix(table, "access_binding") {
			require.Contains(t, after.Whole.Delivery, table)
			require.Equal(t, rows, after.Whole.Delivery[table], "full raw GD/G history, targets and materialization preserved")
		}
	}
}

func rid01RequireOperations(t *testing.T, f *installationNativeWorld, before, after rid01NewmanSnapshot, delta int) {
	t.Helper()
	// Diagnose every changed historical row BEFORE any existing assertion can
	// stop this phase. Values and credential response bodies never leave memory;
	// only per-column SHA256 and identities from the real fixture are retained.
	changed := map[string]any{}
	for id, digest := range before.Operations {
		if after.Operations[id] == digest {
			continue
		}
		kind := "other"
		switch id {
		case f.creator.CreateOperation.ID:
			kind = "standing-creator-create"
		case f.creator.GrantOperation.ID:
			kind = "standing-creator-admin-grant"
		case f.creator.KeyOperation.ID:
			kind = "standing-creator-key-issue"
		}
		fields := map[string]any{}
		for name, old := range before.OperationColumnHashes[id] {
			current, exists := after.OperationColumnHashes[id][name]
			if !exists || current != old {
				fields[name] = map[string]any{"beforePresent": true, "afterPresent": exists, "before": old, "after": current}
			}
		}
		for name, current := range after.OperationColumnHashes[id] {
			if _, exists := before.OperationColumnHashes[id][name]; !exists {
				fields[name] = map[string]any{"beforePresent": false, "afterPresent": true, "after": current}
			}
		}
		changed[id] = map[string]any{"kind": kind, "beforeRowSHA256": digest, "afterRowSHA256": after.Operations[id], "changedColumns": fields}
	}
	if len(changed) != 0 {
		rid08Write(t, f.session.Root, "rid01-operation-history-diagnostic", map[string]any{"state": "CHANGED_HISTORICAL_OPERATIONS_NOT_ACCEPTED", "changed": changed, "beforeCount": len(before.Operations), "afterCount": len(after.Operations), "expectedNewCount": delta, "wholeDoDAccepted": false})
	}
	require.Len(t, after.Operations, len(before.Operations)+delta)
	for id, row := range before.Operations {
		require.Equal(t, row, after.Operations[id], "all existing full normal Operation rows exact")
	}
	ctx, cancel := context.WithTimeout(f.given.ctx, 30*time.Second)
	defer cancel()
	for id := range after.Operations {
		if _, old := before.Operations[id]; old {
			continue
		}
		var account, resource string
		require.NoError(t, f.given.pool.QueryRow(ctx, "SELECT account_id,resource_id FROM kaname.operations WHERE id=$1", id).Scan(&account, &resource))
		require.Equal(t, f.tenantID, account)
		found := false
		for _, g := range after.Projection.Delegations {
			if g["id"] == resource {
				found = true
				require.Equal(t, f.tenantID, g["accountId"])
			}
		}
		require.True(t, found)
		requireNativeInstallationOperation(t, ctx, f.given.pool, id, account, f.creator.ID, resource)
	}
	require.NoError(t, ctx.Err())
}
func rid01RequirePremise(t *testing.T, h *rid01PublicContext, e *rid01PublicExpectation) {
	t.Helper()
	p := e.Snapshot.Projection
	f := h.f
	require.Len(t, p.Accounts, 2)
	require.Len(t, p.ServiceAccounts, 3+len(e.Modules))
	require.Len(t, p.Delegations, len(e.Modules))
	require.Len(t, f.baseline.ServiceAccounts, 2)
	tenants := 0
	for _, a := range p.Accounts {
		if a["id"] != e.System {
			tenants++
			require.Equal(t, e.Tenant, a["id"])
			require.Equal(t, e.Operator, a["ownerUserId"])
		}
	}
	require.Equal(t, 1, tenants)
	sas := map[string]bool{}
	for _, sa := range p.ServiceAccounts {
		id := sa["id"].(string)
		sas[id] = true
		require.Equal(t, e.System, sa["accountId"])
		for _, module := range e.Modules {
			if sa["name"] == "svc-"+module {
				require.NotContains(t, e.Issuers, module)
				e.Issuers[module] = id
				require.NotEqual(t, e.Creator, id)
				require.NotContains(t, f.baseline.ServiceAccounts, id)
				require.Equal(t, true, sa["enabled"])
			}
		}
	}
	require.True(t, sas[e.Creator])
	for id := range f.baseline.ServiceAccounts {
		require.True(t, sas[id])
	}
	require.NotEqual(t, e.Creator, e.Tenant)
	require.NotEqual(t, e.System, e.Tenant)
	require.Len(t, e.Issuers, len(e.Modules))
	require.Len(t, p.Roles, len(h.Initial.Projection.Roles)+len(e.Modules))
	require.Len(t, p.Groups, len(h.Initial.Projection.Groups)+len(e.Modules))
	require.Len(t, p.Bindings, len(h.Initial.Projection.Bindings)+len(e.Modules))
	beforeMembers, afterMembers := 0, 0
	for _, members := range h.Initial.Projection.Members {
		beforeMembers += len(members)
	}
	for _, members := range p.Members {
		afterMembers += len(members)
	}
	require.Equal(t, beforeMembers+len(e.Modules), afterMembers)
	stockGroups := 0
	for _, g := range p.Groups {
		if g["accountId"] == e.System && g["name"] == "module-relation-writers" {
			stockGroups++
		}
	}
	require.Equal(t, 1, stockGroups)
	for _, module := range e.Modules {
		role := ""
		for _, r := range p.Roles {
			if r["name"] == module+".reader" {
				require.Empty(t, role)
				role = r["id"].(string)
				require.Equal(t, "cluster_root", r["clusterId"])
			}
		}
		require.NotEmpty(t, role)
		catalogCount := 0
		for _, raw := range p.Catalog["modules"].([]any) {
			entry := raw.(map[string]any)
			if entry["module"] == module {
				catalogCount++
				resources := entry["resources"].([]any)
				require.Len(t, resources, 1)
				resource := resources[0].(map[string]any)
				require.Equal(t, "objects", resource["resource"])
				require.ElementsMatch(t, []any{"get", "list"}, resource["verbs"])
			}
		}
		require.Equal(t, 1, catalogCount)
		groupID := ""
		writerGroup := ""
		for _, group := range p.Groups {
			if group["name"] == module+"-readers" {
				require.Empty(t, groupID)
				require.Equal(t, e.System, group["accountId"])
				groupID = group["id"].(string)
			}
			if group["name"] == "module-relation-writers" && group["accountId"] == e.System {
				writerGroup = group["id"].(string)
			}
		}
		require.NotEmpty(t, groupID)
		require.NotEmpty(t, writerGroup)
		joins := 0
		for _, member := range p.Members[writerGroup] {
			if member["memberType"] == "service_account" && member["memberId"] == e.Issuers[module] {
				joins++
			}
		}
		require.Equal(t, 1, joins)
		bindings := 0
		for _, binding := range p.Bindings {
			if binding["roleId"] == role && binding["subjectId"] == groupID {
				bindings++
				require.Equal(t, "ACTIVE", binding["status"])
				require.Equal(t, "group", binding["subjectType"])
				require.Equal(t, "iam.cluster", binding["scopeType"])
				require.Equal(t, "cluster_root", binding["scopeId"])
				require.Equal(t, true, binding["system"])
				require.Equal(t, true, binding["deletionProtection"])
				require.Equal(t, []any{map[string]any{"type": "SUBJECT_TYPE_GROUP", "id": groupID}}, binding["subjects"])
				require.Equal(t, map[string]any{"allInScope": map[string]any{}}, binding["target"])
			}
		}
		require.Equal(t, 1, bindings)
		matches := 0
		for _, g := range p.Delegations {
			if g["module"] != module {
				continue
			}
			matches++
			require.Equal(t, e.Tenant, g["accountId"])
			require.Equal(t, map[string]any{"type": "SUBJECT_TYPE_SERVICE_ACCOUNT", "id": e.Issuers[module]}, g["delegate"])
			require.Equal(t, map[string]any{"type": "service_account", "id": e.Creator}, g["delegatedBy"])
			require.Equal(t, []any{role}, g["roleIds"])
			require.Equal(t, []any{module + ".objects"}, g["targetTypes"])
			require.Equal(t, []any{"SUBJECT_TYPE_SERVICE_ACCOUNT"}, g["subjectTypes"])
			require.Equal(t, "ACTIVE", g["status"])
			require.Nil(t, g["revokedAt"])
			require.Nil(t, g["revokedBy"])
		}
		require.Equal(t, 1, matches)
	}
}

// Normal ES256 client assertion contract, same credential/signing recipe as
// rid11PublicRefusal/StandingKeyRefusal. Sign only; actual token POST is Newman.
// Assertion lifetime stays live even though the stored standing key is expired.
func rid01FreshAssertion(t *testing.T, f *installationNativeWorld) (string, time.Time) {
	t.Helper()
	raw, err := os.ReadFile(f.creator.CredentialFile)
	require.NoError(t, err)
	var input installationCredential
	require.NoError(t, json.Unmarshal(raw, &input))
	key, err := jwt.ParseECPrivateKeyFromPEM([]byte(input.PrivateKeyPEM))
	require.NoError(t, err)
	nonce := make([]byte, 24)
	_, err = rand.Read(nonce)
	require.NoError(t, err)
	now := time.Now().UTC().Truncate(time.Second)
	end := now.Add(60 * time.Second)
	assertion := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.RegisteredClaims{Issuer: input.ClientID, Subject: input.ClientID, Audience: jwt.ClaimStrings{"https://kaname.local"}, ID: hex.EncodeToString(nonce), IssuedAt: jwt.NewNumericDate(now), ExpiresAt: jwt.NewNumericDate(end)})
	assertion.Header["typ"] = tokenpolicy.TokenTypeClientAssertion
	assertion.Header["kid"] = input.KeyID
	proof, err := assertion.SignedString(key)
	require.NoError(t, err)
	f.secrets = append(f.secrets, proof)
	return proof, end
}

// Observe the refused process's complete primary result AFTER terminal/reap and
// BEFORE normal serve can upsert any catalog or seed. Never replace the retained
// VALID-KEY-TWIN oracle with this observation or a post-restore baseline.
func rid01RequireRefusalBeforeRestore(t *testing.T, h *rid01PublicContext) {
	t.Helper()
	require.NotNil(t, h)
	require.Equal(t, "key", h.Kind)
	require.Equal(t, 1, h.Calls)
	require.NotNil(t, h.Previous)
	ctx, cancel := context.WithTimeout(h.f.given.ctx, 30*time.Second)
	defer cancel()
	refused, composed := rid01CaptureSnapshot(t, ctx, h.f)
	rid08Write(t, h.f.session.Root, "rid01-expired-key-pre-restore-primary", map[string]any{
		"state":                          "PRIMARY_CAPTURED_BEFORE_RESTORE",
		"retainedValidKeyTwinProjection": h.Previous.Projection,
		"retainedValidKeyTwinWhole":      h.Previous.Whole,
		"retainedValidKeyTwinOperations": h.Previous.Operations,
		"refusedProjection":              refused.Projection,
		"refusedWhole":                   refused.Whole,
		"refusedOperations":              refused.Operations,
		"wholeDoDAccepted":               false,
	})
	require.True(t, composed, "fixture NOT_ACCEPTED: primary moved during pre-restore refusal capture; no repair/retry")
	require.Equal(t, h.Previous.Projection, refused.Projection, "refusal must preserve full projection before any normal catalog/seed upsert")
	ridRequireWholeDeliveryUnchanged(t, h.Previous.Whole, refused.Whole)
	require.Equal(t, h.Previous.Operations, refused.Operations, "refused startup creates no Operation and preserves all full historical rows")
	require.Equal(t, h.Previous.Whole.Bookkeeping["operations"], refused.Whole.Bookkeeping["operations"], "full physical Operation ledger zero delta before restore")
	require.NoError(t, ctx.Err(), "aggregate RID01 pre-restore refusal budget expired before success return")
	proof := refused
	h.RefusalBeforeRestore = &proof
}

// All native expired-key outcome/cleanup assertions have completed. Restore the
// same delivered catalog/seed on the same DB using normal serve with NO GD stage.
// The VALID-KEY-TWIN primary snapshot remains the oracle for the refusal phase.
func rid01RestorePublicListeners(t *testing.T, f *installationNativeWorld, in installruntime.DeliveryInput) {
	t.Helper()
	var doc map[string]any
	require.NoError(t, yaml.Unmarshal(in.Manifests.First, &doc))
	seed, ok := doc["seed"].(map[string]any)
	require.True(t, ok)
	delete(seed, "grantDelegations")
	raw, err := yaml.Marshal(doc)
	require.NoError(t, err)
	in.Manifests.First = raw
	process, err := f.session.StartDelivery(f.given.ctx, in)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(f.given.ctx, 60*time.Second)
	defer cancel()
	require.NoError(t, process.AwaitReady(ctx, f.wire.ProductionReady))
	require.NoError(t, process.OwnsListeners(installruntime.DefaultNativePorts().All()...))
}
