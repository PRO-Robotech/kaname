// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/operations/operationspb"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// Зависит от зафиксированных первичных помощников проекции RID09 (63ab0c...4059). Полная
// публичная проекция и дополнительный необработанный снимок/снимок Operation владеют отдельными первичными
// транзакциями RO/RR и объединяются только после точных скобок перед допуском.
type rid10NewmanSnapshot struct {
	PullRole      string                     `json:"-"`
	Projection    rid09NewmanProjection      `json:"projection"`
	Operations    []map[string]any           `json:"operations"`
	GDRows        map[string]json.RawMessage `json:"-"`
	BindingRows   map[string]json.RawMessage `json:"-"`
	OperationRows map[string]json.RawMessage `json:"-"`
}
type rid10NewmanExpectation struct {
	CaseID          string               `json:"caseId"`
	Mode            string               `json:"mode"`
	Phase           string               `json:"phase"`
	Operator        string               `json:"operatorId"`
	Creator         string               `json:"creatorId"`
	System          string               `json:"systemId"`
	NamedSystem     string               `json:"tenantNamedSystem"`
	Issuer          string               `json:"issuerId"`
	FirstAccount    string               `json:"firstAccountId"`
	FirstGD         string               `json:"firstGDId"`
	OldG            string               `json:"oldGId"`
	FailedOperation string               `json:"failedOperationId"`
	Snapshot        rid10NewmanSnapshot  `json:"snapshot"`
	Previous        *rid10NewmanSnapshot `json:"previousSnapshot"`
}
type rid10NewmanContext struct {
	Baseline rid10NewmanSnapshot
	Partial  *rid10NewmanSnapshot
	FirstGD  string
	OldG     string
	Calls    map[string]bool
}

func rid10ReadNewmanSnapshot(t *testing.T, ctx context.Context, f *installationNativeWorld) rid10NewmanSnapshot {
	t.Helper()
	require.NoError(t, ctx.Err(), "midrun snapshot caller context expired")
	s := rid10NewmanSnapshot{Projection: rid09ReadNewmanProjectionContext(t, ctx, f), Operations: []map[string]any{}, GDRows: map[string]json.RawMessage{}, BindingRows: map[string]json.RawMessage{}, OperationRows: map[string]json.RawMessage{}}
	tx, err := f.given.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	defer func() {
		cctx, c := context.WithTimeout(context.Background(), time.Second)
		defer c()
		_ = tx.Rollback(cctx)
	}()
	var recovery bool
	require.NoError(t, tx.QueryRow(ctx, "SELECT pg_is_in_recovery()").Scan(&recovery))
	require.False(t, recovery)
	for _, entry := range []struct {
		table string
		dest  map[string]json.RawMessage
	}{{"grant_delegations", s.GDRows}, {"access_bindings", s.BindingRows}} {
		for _, r := range rid09PrimaryRows(t, ctx, tx, entry.table) {
			id := rid09PrimaryValue[string](t, r, "id")
			require.NotContains(t, entry.dest, id)
			raw, err := json.Marshal(r)
			require.NoError(t, err)
			entry.dest[id] = raw
		}
	}
	require.NoError(t, tx.QueryRow(ctx, "SELECT id FROM kaname.roles WHERE name='registry.puller' AND owner_module='registry' AND cluster_id='cluster_root' AND live").Scan(&s.PullRole))
	metadata, err := anypb.New(&iamv1.CreateGrantDelegationMetadata{})
	require.NoError(t, err)
	rows, err := tx.Query(ctx, `SELECT id,description,created_at,created_by,modified_at,done,metadata_type,metadata_data,
 error_code,error_message,error_details,response_type,response_data,principal_type,principal_id,principal_display_name,
 account_id,resource_id,to_jsonb(o) FROM kaname.operations o WHERE metadata_type=$1 ORDER BY id`, metadata.TypeUrl)
	require.NoError(t, err)
	for rows.Next() {
		op := &operations.Operation{}
		var mt string
		var md []byte
		var code *int32
		var message *string
		var details []byte
		var rt *string
		var rd []byte
		var account, resource string
		var raw []byte
		require.NoError(t, rows.Scan(&op.ID, &op.Description, &op.CreatedAt, &op.CreatedBy, &op.ModifiedAt, &op.Done, &mt, &md, &code, &message, &details, &rt, &rd, &op.Principal.Type, &op.Principal.ID, &op.Principal.DisplayName, &account, &resource, &raw))
		op.Metadata = &anypb.Any{TypeUrl: mt, Value: md}
		if code != nil {
			op.Error = &statuspb.Status{Code: *code}
			if message != nil {
				op.Error.Message = *message
			}
			if details != nil {
				var stored statuspb.Status
				require.NoError(t, proto.Unmarshal(details, &stored))
				op.Error.Details = stored.Details
			}
		}
		if rt != nil {
			require.NotNil(t, rd)
			op.Response = &anypb.Any{TypeUrl: *rt, Value: rd}
		}
		require.True(t, op.Done)
		require.Equal(t, operations.Principal{Type: "service_account", ID: f.creator.ID, DisplayName: f.creator.ID}, op.Principal)
		var meta iamv1.CreateGrantDelegationMetadata
		require.NoError(t, op.Metadata.UnmarshalTo(&meta))
		require.NotEmpty(t, meta.GrantDelegationId)
		require.Equal(t, meta.AccountId, account)
		require.Equal(t, meta.GrantDelegationId, resource)
		if op.Error != nil {
			require.EqualValues(t, 13, op.Error.Code)
			require.Equal(t, "internal error", op.Error.Message)
			require.Nil(t, op.Response)
			require.NotContains(t, s.GDRows, resource)
		} else {
			require.NotNil(t, op.Response)
			var gd iamv1.GrantDelegation
			require.NoError(t, op.Response.UnmarshalTo(&gd))
			require.Equal(t, meta.GrantDelegationId, gd.Id)
			require.Equal(t, meta.AccountId, gd.AccountId)
			require.Contains(t, s.GDRows, gd.Id)
			var expected *iamv1.GrantDelegation
			for _, g := range s.Projection.Delegations {
				if g["id"] == gd.Id {
					encoded, err := json.Marshal(g)
					require.NoError(t, err)
					expected = &iamv1.GrantDelegation{}
					require.NoError(t, protojson.Unmarshal(encoded, expected))
				}
			}
			require.NotNil(t, expected)
			require.True(t, proto.Equal(expected, &gd), "stored Operation response equals complete independent GD projection")
		}
		require.NotContains(t, s.OperationRows, op.ID)
		s.OperationRows[op.ID] = append(json.RawMessage{}, raw...)
		s.Operations = append(s.Operations, rid09PrimaryJSON(t, operationspb.ToProto(op)))
	}
	require.NoError(t, rows.Err())
	rows.Close()
	require.NoError(t, tx.Commit(ctx))
	after := rid09ReadNewmanProjectionContext(t, ctx, f)
	require.Equal(t, s.Projection, after, "fixture NOT_ACCEPTED: primary public projection moved while composing rawGD/G/Operation snapshot; no admission")
	require.NoError(t, ctx.Err(), "midrun snapshot caller context expired before return")
	return s
}

// Захватываем лишь независимую первичную базу, без дополнительной публичной фазы.
// Ждём материализации настоящего старого G каждого объекта, затем дважды наблюдаем стабильный
// полный журнал до нативного сбоя/вывода из обращения. Состояние не чинится.
func rid10NewmanBaseline(t *testing.T, x *rid10World, p *rid10Proof) *rid10NewmanContext {
	t.Helper()
	if os.Getenv("KANAME_RID_NEWMAN") != "1" {
		return nil
	}
	f := x.w.f
	ctx, cancel := context.WithTimeout(f.given.ctx, 20*time.Second)
	defer cancel()
	var previous *rid09NewmanProjection
	for {
		require.NoError(t, ctx.Err(), "aggregate midrun baseline budget expired")
		projection := rid09ReadNewmanProjectionContext(t, ctx, f)
		require.Len(t, projection.Delegations, 1)
		first := projection.Delegations[0]["id"].(string)
		old := ""
		materialized := false
		for _, binding := range projection.Bindings {
			if binding["delegationId"] == first {
				require.Empty(t, old)
				old = binding["id"].(string)
				materialized = binding["materializedAt"] != nil
				require.Equal(t, "ACTIVE", binding["status"])
			}
		}
		require.NotEmpty(t, old)
		if materialized && previous != nil && reflect.DeepEqual(*previous, projection) {
			s := rid10ReadNewmanSnapshot(t, ctx, f)
			require.Equal(t, projection, s.Projection)
			require.Len(t, s.GDRows, 1)
			require.Len(t, s.OperationRows, 1)
			require.Equal(t, p.First.Winner, first)
			require.Equal(t, p.FirstG, old)
			out := &rid10NewmanContext{Baseline: s, FirstGD: first, OldG: old, Calls: map[string]bool{}}
			require.NoError(t, ctx.Err(), "aggregate midrun baseline budget expired before success return")
			return out
		}
		previous = &projection
		select {
		case <-ctx.Done():
			t.Fatal("fixture NOT_ACCEPTED: aggregate20s midrun baseline expired/canceled before stable first-G history")
		case <-time.After(100 * time.Millisecond):
		}
	}
}

func rid10NewmanPhase(t *testing.T, x *rid10World, p *rid10Proof, history *rid10NewmanContext, phase string) {
	t.Helper()
	require.Contains(t, []string{"partial", "recovered", "twin"}, phase)
	require.Contains(t, []string{"fault", "retirement"}, p.Mode)
	caseID := "registry-installation-rid10-" + strings.ToUpper(p.Mode+"-"+phase)
	label := strings.ToLower(caseID)
	f := x.w.f
	if os.Getenv("KANAME_RID_NEWMAN") != "1" {
		rid08Write(t, f.session.Root, "newman-"+label, map[string]any{"state": "NOT_EXECUTED", "caseId": caseID, "wholeDoDAccepted": false})
		return
	}
	require.NotNil(t, history)
	require.False(t, history.Calls[phase])
	history.Calls[phase] = true
	require.Equal(t, p.Twin, phase == "twin")
	if phase == "recovered" {
		require.NotNil(t, history.Partial)
		require.True(t, history.Calls["partial"])
	}
	// Отдельно проверенное основным агентом дополнение FD5 токеном C должно аудировать ЭТОТ
	// настоящий токен предъявителя до любого следующего способного отказать дочернего шага/допуска.
	// Существующий помощник ridToken вызывает ExchangeLifecycleKey и захватывает
	// утверждение/токен в f.secrets. Адаптер не добавляет отдельный родительский /me;
	// явный C /me Newman доказывает владение субъектом этой фазы.
	// Node никогда не получает адрес выдачи или закрытый ключ C.
	creatorToken := f.ridToken(t, f.creator)
	snapshot := func() rid10NewmanSnapshot {
		snapshotCtx, snapshotCancel := context.WithTimeout(f.given.ctx, 30*time.Second)
		defer snapshotCancel()
		return rid10ReadNewmanSnapshot(t, snapshotCtx, f)
	}()
	e := rid10NewmanExpectation{CaseID: caseID, Mode: p.Mode, Phase: phase, Operator: string(f.given.user), Creator: f.creator.ID, System: f.baseline.SystemID, FirstGD: history.FirstGD, OldG: history.OldG, Snapshot: snapshot, Previous: history.Partial}
	rid10RequireNewmanPremise(t, x, p, history, &e)
	func() {
		defer func() {
			afterCtx, afterCancel := context.WithTimeout(f.given.ctx, 30*time.Second)
			defer afterCancel()
			after := rid10ReadNewmanSnapshot(t, afterCtx, f)
			stable := reflect.DeepEqual(e.Snapshot, after)
			state := "PRIMARY_STABLE"
			if !stable {
				state = "FIXTURE_NOT_ACCEPTED"
			}
			rid08Write(t, f.session.Root, "newman-"+label+"-primary-bracket", map[string]any{"state": state, "caseId": caseID, "fullPrimarySnapshotUnchangedDuringPhase": stable, "wholeDoDAccepted": false})
			require.Equal(t, e.Snapshot, after, "fixture NOT_ACCEPTED: full primary snapshot/materialization/Operation ledger moved during single Newman phase; no retry")
		}()
		receipt := ridRunNewmanPhase(t, f, "registry-installation-rid10", caseID, label, map[string]any{"rid10Expected": e, "jwtRIDCreator": creatorToken})
		require.True(t, receipt.OK)
	}()
	if phase == "partial" {
		snapshot := e.Snapshot
		history.Partial = &snapshot
	}
}
func rid10RequireNewmanPremise(t *testing.T, x *rid10World, p *rid10Proof, h *rid10NewmanContext, e *rid10NewmanExpectation) {
	t.Helper()
	f := x.w.f
	s := e.Snapshot
	projection := s.Projection
	require.Len(t, projection.Accounts, 4)
	normal := []string{}
	for _, a := range projection.Accounts {
		id := a["id"].(string)
		if id == e.System {
			require.Equal(t, "system", a["name"])
			require.Equal(t, f.baseline.SystemOwner, a["ownerUserId"])
		} else {
			require.Equal(t, e.Operator, a["ownerUserId"])
			normal = append(normal, id)
		}
		if a["name"] == "system-tenant" {
			e.NamedSystem = id
			require.NotEqual(t, e.System, id)
		}
	}
	sort.Strings(normal)
	require.Len(t, normal, 3)
	require.Equal(t, x.w.accounts, normal)
	require.NotEmpty(t, e.NamedSystem)
	require.Contains(t, normal, e.NamedSystem)
	e.FirstAccount = normal[0]
	// Stock2+C+ДВА именованных объявления жизненного цикла относятся к SYS; независимо
	// созданный получатель находится в первой штатной учётной записи, а не является шестой идентичностью SYS.
	require.Len(t, f.baseline.ServiceAccounts, 2)
	require.NotContains(t, f.baseline.ServiceAccounts, e.Creator)
	require.Len(t, projection.ServiceAccounts, 6)
	sysIDs := map[string]bool{}
	grantee := ""
	writer := ""
	for _, sa := range projection.ServiceAccounts {
		id := sa["id"].(string)
		if sa["accountId"] == e.System {
			sysIDs[id] = true
		} else {
			require.Equal(t, e.FirstAccount, sa["accountId"])
			require.Equal(t, "rid10-first-grantee", sa["name"])
			require.Empty(t, grantee)
			grantee = id
		}
		if sa["name"] == "rid-public-issuer" {
			require.Empty(t, e.Issuer)
			require.Equal(t, e.System, sa["accountId"])
			require.Equal(t, true, sa["enabled"])
			e.Issuer = id
		}
		if sa["name"] == "kacho-registry" {
			require.Empty(t, writer)
			require.Equal(t, e.System, sa["accountId"])
			require.Equal(t, true, sa["enabled"])
			writer = id
		}
	}
	require.Len(t, sysIDs, 5)
	require.True(t, sysIDs[e.Creator])
	for id := range f.baseline.ServiceAccounts {
		require.True(t, sysIDs[id])
	}
	require.NotEmpty(t, e.Issuer)
	require.NotEmpty(t, writer)
	require.NotEqual(t, writer, e.Issuer)
	require.NotEqual(t, writer, e.Creator)
	require.NotContains(t, f.baseline.ServiceAccounts, writer)
	require.NotEqual(t, e.Creator, e.Issuer)
	require.NotContains(t, f.baseline.ServiceAccounts, e.Issuer)
	require.NotEmpty(t, grantee)
	role := ""
	for _, r := range projection.Roles {
		if r["name"] == "registry.puller" {
			require.Empty(t, role)
			role = r["id"].(string)
			require.Equal(t, "cluster_root", r["clusterId"])
		}
	}
	require.NotEmpty(t, role)
	require.Equal(t, s.PullRole, role, "role resolves independently by declared name/module/live tier, never from GD")
	count := 3
	if e.Phase == "partial" {
		count = 1
	}
	require.Len(t, projection.Delegations, count)
	require.Len(t, s.GDRows, count)
	pairs := map[string]bool{}
	for _, g := range projection.Delegations {
		account := g["accountId"].(string)
		require.Contains(t, normal, account)
		require.False(t, pairs[account])
		pairs[account] = true
		require.Equal(t, "registry", g["module"])
		require.Equal(t, "ACTIVE", g["status"])
		require.Nil(t, g["revokedAt"])
		require.Nil(t, g["revokedBy"])
		require.Equal(t, []any{role}, g["roleIds"])
		require.Equal(t, []any{"registry.registries"}, g["targetTypes"])
		require.Equal(t, []any{"SUBJECT_TYPE_SERVICE_ACCOUNT"}, g["subjectTypes"])
		require.Equal(t, map[string]any{"type": "SUBJECT_TYPE_SERVICE_ACCOUNT", "id": e.Issuer}, g["delegate"])
		require.Equal(t, map[string]any{"type": "service_account", "id": e.Creator}, g["delegatedBy"])
		if g["id"] == e.FirstGD {
			require.Equal(t, e.FirstAccount, account)
		}
	}
	require.True(t, pairs[e.FirstAccount])
	require.Equal(t, h.Baseline.GDRows[e.FirstGD], s.GDRows[e.FirstGD], "full original GD row exact incl ID/createdAt and all axes")
	require.Equal(t, h.Baseline.BindingRows, s.BindingRows, "all pre-existing full binding rows/history preserved")
	var beforeOld, currentOld map[string]any
	for _, b := range h.Baseline.Projection.Bindings {
		if b["id"] == e.OldG {
			beforeOld = b
		}
	}
	for _, b := range projection.Bindings {
		if b["id"] == e.OldG {
			currentOld = b
		}
	}
	require.NotNil(t, beforeOld)
	require.NotNil(t, currentOld)
	require.Equal(t, beforeOld, currentOld, "full old G projection includes exact materializedAt, never suppressed")
	require.Equal(t, "ACTIVE", currentOld["status"])
	require.Equal(t, e.FirstGD, currentOld["delegationId"])
	require.Equal(t, role, currentOld["roleId"])
	require.Equal(t, grantee, currentOld["subjectId"])
	require.Equal(t, "iam.account", currentOld["scopeType"])
	require.Equal(t, e.FirstAccount, currentOld["scopeId"])
	require.Equal(t, []any{map[string]any{"type": "SUBJECT_TYPE_SERVICE_ACCOUNT", "id": grantee}}, currentOld["subjects"])
	require.Equal(t, map[string]any{"resources": map[string]any{"resources": []any{map[string]any{"type": "registry.registries", "id": "rid-native-registry"}}}}, currentOld["target"])
	require.NotNil(t, currentOld["materializedAt"])
	require.Nil(t, currentOld["revokedAt"])
	wantedOps := 3
	if e.Phase == "partial" {
		wantedOps = 1
		if e.Mode == "fault" {
			wantedOps = 2
		}
	}
	if e.Phase == "recovered" {
		wantedOps = 4
		if e.Mode == "fault" {
			wantedOps = 5
		}
	}
	require.Len(t, s.Operations, wantedOps)
	require.Len(t, s.OperationRows, wantedOps)
	failures := 0
	for _, op := range s.Operations {
		require.Equal(t, true, op["done"])
		require.Equal(t, "service_account", op["principalType"])
		require.Equal(t, e.Creator, op["principalId"])
		if op["error"] != nil {
			failures++
			e.FailedOperation = op["id"].(string)
			failure := op["error"].(map[string]any)
			require.Equal(t, float64(13), failure["code"])
			require.Equal(t, "internal error", failure["message"])
			require.Equal(t, normal[1], op["metadata"].(map[string]any)["accountId"])
		}
	}
	if e.Mode == "fault" && e.Phase != "twin" {
		require.Equal(t, 1, failures)
		require.NotNil(t, p.Failure)
		require.Equal(t, p.Failure.ID, e.FailedOperation)
	} else {
		require.Zero(t, failures)
		require.Empty(t, e.FailedOperation)
	}
	for id, row := range h.Baseline.OperationRows {
		require.Equal(t, row, s.OperationRows[id], "original normal successful Operation full row exact")
	}
	if e.Phase == "recovered" {
		require.NotNil(t, e.Previous)
		for id, row := range e.Previous.GDRows {
			require.Equal(t, row, s.GDRows[id])
		}
		for id, row := range e.Previous.OperationRows {
			require.Equal(t, row, s.OperationRows[id], "failed/first normal Ops survive exact")
		}
		require.Len(t, s.OperationRows, len(e.Previous.OperationRows)+3)
	}
}
