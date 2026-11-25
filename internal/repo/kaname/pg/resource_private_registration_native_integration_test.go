// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationscene"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Owner DB connection нужен только для закрытого private compiler. Это не
// public Run/readiness/ordinary LOGIN acceptance. Все business источники,
// module Gate, typed participant, final authority и DML настоящие.
func TestResourcePrivateRegisterActualEntry(t *testing.T) {
	r := writerProtocolRig(t)
	scenes := [2]registrationscene.Scene{registrationscene.Seed(t, r.ctx, r.admin), registrationscene.Seed(t, r.ctx, r.admin)}
	roster, err := moduleidentity.Parse([]string{"modules/kacho-vpc=module-writer"})
	require.NoError(t, err)
	owner := lifecycleOwner(r)
	writer, err := owner.Writer(r.ctx)
	require.NoError(t, err)
	defer policyFixtureRollback(writer)
	_, err = writer.ServiceAccountsW().Insert(r.ctx, domain.ServiceAccount{
		ID:        domain.ServiceAccountID(authzguard.ServiceAccountIDForService("vpc")),
		AccountID: domain.AccountID(r.a), Name: "kacho-vpc", Description: "private registration component",
	})
	require.NoError(t, err)
	require.NoError(t, writer.Commit(r.ctx))
	require.NoError(t, seed.ApplyRegistrationAccountWriters(r.ctx, kanamepg.NewRegistrationAccountWriterStore(r.admin), roster,
		seed.RegistrationWriterPlan{Assignments: []domain.RegistrationAccountWriter{{AssignmentID: "private-register-A", AccountID: scenes[0].Account, Module: "vpc"}}}))
	require.NoError(t, owner.ActivateAuthorityBundle(r.ctx, r.bundle))
	gate := authzguard.NewRelationWriteGate(delegationNativeDoor{r}).WithModuleRoster(roster)
	ctx := grpcsrv.WithCertIdentityIn(r.ctx, grpcsrv.NewTrustDomain("kacho.cloud"), "spiffe://kacho.cloud/ns/modules/sa/kacho-vpc", true)
	require.NoError(t, gate.AuthorizeAccount(ctx, scenes[0].Account))
	require.Error(t, gate.AuthorizeAccount(ctx, scenes[1].Account))
	// Readiness остаётся фактической: private probe его не подменяет.
	var readinessBefore bool
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT kaname.authority_resource_storage_v2('{"abi":1,"aliases":{"nlb":"loadbalancer"},"fallback":"identity"}'::jsonb)`).Scan(&readinessBefore))
	makeIntent := func(scene int, id string) kaname.ResourceDecisionIntent {
		s := scenes[scene]
		return kaname.ResourceDecisionIntent{Action: kaname.ResourceDecisionRegister,
			Tuple: outboxtypes.RelationTuple{User: "project:" + s.Project, Relation: "project", Object: "vpc_network:" + id},
			Mirror: outboxtypes.ResourceMirrorRow{ObjectType: "vpc_network", ObjectID: id, ParentProjectID: s.Project,
				ParentAccountID: s.Account, ParentChain: s.ProjectChain(), Labels: map[string]string{"private_probe": "yes"},
				SourceVersion: time.Date(2026, 11, 14, 10, 0, 0, 123456000, time.UTC)}}
	}
	// Полный снимок persistable артефактов по объекту. Проверка выполняется
	// отдельной owner сессией после возврата, то есть видит только COMMIT.
	snapshot := func(callCtx context.Context, id string) json.RawMessage {
		var raw json.RawMessage
		require.NoError(t, r.admin.QueryRow(callCtx, `SELECT jsonb_build_object(
'mirror',(SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]') FROM kaname.resource_mirror x WHERE object_type='vpc.network' AND object_id=$1),
'edges',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY depth),'[]') FROM kaname.resource_parent_edge x WHERE object_type='vpc_network' AND object_id=$1),
'facts',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY relation,subject),'[]') FROM kaname.relation_fact x WHERE object_type='vpc_network' AND object_id=$1),
'binding',(SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]') FROM kaname.object_project_binding x WHERE object_type='vpc_network' AND object_id=$1),
'receipts',(SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]') FROM kaname.producer_source_receipt x WHERE object_type='vpc_network' AND object_id=$1),
'pointers',(SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]') FROM kaname.resource_registration_pointer x WHERE object_type='vpc_network' AND object_id=$1),
'scopes',(SELECT coalesce(jsonb_agg(to_jsonb(x)),'[]') FROM kaname.resource_registration_scope x WHERE object_type='vpc_network' AND object_id=$1),
'audits',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]') FROM kaname.audit_outbox x WHERE event_payload#>>'{object,id}'=$1),
'reconcile',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]') FROM kaname.resource_reconcile_outbox x WHERE object_type='vpc.network' AND object_id=$1),
'outbox',(SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY id),'[]') FROM kaname.fga_outbox x WHERE payload->>'object'='vpc_network:'||$1))`, id).Scan(&raw))
		return raw
	}
	t.Run("first registration evidence requires owner and signed RC", func(t *testing.T) {
		const query = `SELECT kaname._authority_resource_first_registration_absence_v1(NULL,NULL,NULL,100,100)`
		var sqlErr *pgconn.PgError
		require.ErrorAs(t, r.runtime.QueryRow(ctx, query).Scan(new(json.RawMessage)), &sqlErr)
		require.Equal(t, "42501", sqlErr.Code)
		require.Contains(t, sqlErr.Message, "permission denied for function")
		require.ErrorAs(t, r.admin.QueryRow(ctx, query).Scan(new(json.RawMessage)), &sqlErr)
		require.Equal(t, "42501", sqlErr.Code)
		require.Contains(t, sqlErr.Message, "signed resource frame")
	})
	t.Run("genuine private Register commits all effects", func(t *testing.T) {
		input := makeIntent(0, "private-registration-positive")
		before := snapshot(ctx, input.Mirror.ObjectID)
		result, trace, callErr := kanamepg.ProbePrivateFirstRegistrationAbsence(ctx, kanamepg.New(r.admin, nil), r.bundle, gate, input)
		t.Logf("private trace: %+v", trace)
		{
			var sqlCause *pgconn.PgError
			if errors.As(callErr, &sqlCause) {
				t.Logf("actual SQL error: code=%s message=%s where=%s", sqlCause.Code, sqlCause.Message, sqlCause.Where)
			}
		}
		require.Equal(t, []int{2, 3, 4, 5, 6, 25, 26, 28}, trace.DirectCaptureKinds)
		require.Zero(t, trace.RootParentEdgeRows)
		require.NoError(t, callErr)
		require.Equal(t, "committed", trace.Stage)
		require.NotZero(t, trace.BackendPID)
		require.True(t, trace.RRClosed)
		require.True(t, trace.TypedRCEntered)
		require.Equal(t, 16, trace.FirstRegistrationAbsenceReads)
		require.True(t, trace.Finalized)
		require.True(t, trace.Authorized)
		require.True(t, trace.BodyExecuted)
		require.True(t, trace.Committed)
		require.True(t, result.Changed)
		require.Equal(t, "vpc.network", result.CatalogType)
		after := snapshot(ctx, input.Mirror.ObjectID)
		require.NotEqual(t, string(before), string(after))
		var state map[string][]json.RawMessage
		require.NoError(t, json.Unmarshal(after, &state))
		require.Len(t, state["mirror"], 1)
		require.NotEmpty(t, state["edges"])
		require.Len(t, state["facts"], 1)
		require.NotEmpty(t, state["scopes"])
		require.Len(t, state["audits"], 1)
		require.Len(t, state["reconcile"], 1)
		require.Len(t, state["outbox"], 1)
		var fact struct {
			Subject  string `json:"subject"`
			Relation string `json:"relation"`
		}
		require.NoError(t, json.Unmarshal(state["facts"][0], &fact))
		require.Equal(t, input.Tuple.User, fact.Subject)
		require.Equal(t, input.Tuple.Relation, fact.Relation)
	})
	t.Run("same authenticated actor without installation rolls back", func(t *testing.T) {
		input := makeIntent(1, "private-registration-denied")
		before := snapshot(ctx, input.Mirror.ObjectID)
		result, trace, callErr := kanamepg.ProbePrivateRegistration(ctx, kanamepg.New(r.admin, nil), r.bundle, gate, input)
		t.Logf("private deny trace: %+v", trace)
		{
			var sqlCause *pgconn.PgError
			if errors.As(callErr, &sqlCause) {
				t.Logf("actual SQL error: code=%s message=%s where=%s", sqlCause.Code, sqlCause.Message, sqlCause.Where)
			}
		}
		require.Equal(t, []int{2, 3, 4, 5, 6, 25, 26, 28}, trace.DirectCaptureKinds)
		require.Zero(t, trace.RootParentEdgeRows)
		require.Error(t, callErr)
		require.Equal(t, codes.PermissionDenied, status.Code(callErr))
		require.True(t, trace.RRClosed)
		require.True(t, trace.TypedRCEntered)
		require.Equal(t, kaname.ResourceDecisionResult{}, result)
		require.False(t, trace.Committed)
		require.False(t, trace.BodyExecuted)
		require.JSONEq(t, string(before), string(snapshot(ctx, input.Mirror.ObjectID)))
	})
	// Эти два сценария используют только законные installation transitions и
	// тот же реальный private compiler; публичная readiness не подменяется.
	t.Run("genuine private Unregister commits cleanup", func(t *testing.T) {
		input := makeIntent(0, "private-unregistration-positive")
		_, registered, callErr := kanamepg.ProbePrivateRegistration(ctx, kanamepg.New(r.admin, nil), r.bundle, gate, input)
		t.Logf("cleanup seed trace: %+v", registered)
		{
			var sqlCause *pgconn.PgError
			if errors.As(callErr, &sqlCause) {
				t.Logf("actual SQL error: code=%s message=%s where=%s", sqlCause.Code, sqlCause.Message, sqlCause.Where)
			}
		}
		require.NoError(t, callErr)
		require.True(t, registered.Committed)
		before := snapshot(ctx, input.Mirror.ObjectID)
		input.Action = kaname.ResourceDecisionUnregister
		result, trace, callErr := kanamepg.ProbePrivateRegistration(ctx, kanamepg.New(r.admin, nil), r.bundle, gate, input)
		t.Logf("private cleanup trace: %+v", trace)
		{
			var sqlCause *pgconn.PgError
			if errors.As(callErr, &sqlCause) {
				t.Logf("actual SQL error: code=%s message=%s where=%s", sqlCause.Code, sqlCause.Message, sqlCause.Where)
			}
		}
		require.Equal(t, []int{2, 3, 6, 25, 26, 27, 28, 35}, trace.DirectCaptureKinds)
		require.Positive(t, trace.RootParentEdgeRows)
		require.NoError(t, callErr)
		require.Equal(t, "committed", trace.Stage)
		require.True(t, trace.RRClosed)
		require.True(t, trace.TypedRCEntered)
		require.True(t, trace.Finalized)
		require.True(t, trace.Authorized)
		require.True(t, trace.BodyExecuted)
		require.True(t, trace.Committed)
		require.True(t, result.Changed)
		require.Equal(t, "vpc.network", result.CatalogType)
		after := snapshot(ctx, input.Mirror.ObjectID)
		require.NotEqual(t, string(before), string(after))
		var state map[string][]json.RawMessage
		require.NoError(t, json.Unmarshal(after, &state))
		require.Empty(t, state["mirror"])
		require.Empty(t, state["edges"])
		require.Empty(t, state["facts"])
		require.Len(t, state["audits"], 2)
		require.Len(t, state["reconcile"], 2)
		require.Len(t, state["outbox"], 2)
		var deletes int
		require.NoError(t, r.admin.QueryRow(ctx, `SELECT count(*) FROM kaname.fga_outbox WHERE event_type='fga.tuple.delete' AND payload->>'object'='vpc_network:'||$1`, input.Mirror.ObjectID).Scan(&deletes))
		require.Equal(t, 1, deletes)
	})
	t.Run("private Unregister after legal installation revoke rolls back", func(t *testing.T) {
		assignments := []domain.RegistrationAccountWriter{
			{AssignmentID: "private-register-A", AccountID: scenes[0].Account, Module: "vpc"},
			{AssignmentID: "private-register-B", AccountID: scenes[1].Account, Module: "vpc"},
		}
		require.NoError(t, seed.ApplyRegistrationAccountWriters(ctx, kanamepg.NewRegistrationAccountWriterStore(r.admin), roster,
			seed.RegistrationWriterPlan{Assignments: assignments}))
		input := makeIntent(1, "private-unregistration-denied")
		_, registered, callErr := kanamepg.ProbePrivateRegistration(ctx, kanamepg.New(r.admin, nil), r.bundle, gate, input)
		t.Logf("denied cleanup seed trace: %+v", registered)
		{
			var sqlCause *pgconn.PgError
			if errors.As(callErr, &sqlCause) {
				t.Logf("actual SQL error: code=%s message=%s where=%s", sqlCause.Code, sqlCause.Message, sqlCause.Where)
			}
		}
		require.NoError(t, callErr)
		require.True(t, registered.Committed)
		require.NoError(t, seed.ApplyRegistrationAccountWriters(ctx, kanamepg.NewRegistrationAccountWriterStore(r.admin), roster,
			seed.RegistrationWriterPlan{Assignments: assignments[:1]}))
		require.Error(t, gate.AuthorizeAccount(ctx, scenes[1].Account))
		before := snapshot(ctx, input.Mirror.ObjectID)
		input.Action = kaname.ResourceDecisionUnregister
		result, trace, callErr := kanamepg.ProbePrivateRegistration(ctx, kanamepg.New(r.admin, nil), r.bundle, gate, input)
		t.Logf("private cleanup deny trace: %+v", trace)
		{
			var sqlCause *pgconn.PgError
			if errors.As(callErr, &sqlCause) {
				t.Logf("actual SQL error: code=%s message=%s where=%s", sqlCause.Code, sqlCause.Message, sqlCause.Where)
			}
		}
		require.Equal(t, []int{2, 3, 6, 25, 26, 27, 28, 35}, trace.DirectCaptureKinds)
		require.Error(t, callErr)
		require.Equal(t, codes.PermissionDenied, status.Code(callErr))
		require.True(t, trace.RRClosed)
		require.True(t, trace.TypedRCEntered)
		require.Equal(t, kaname.ResourceDecisionResult{}, result)
		require.False(t, trace.Committed)
		require.False(t, trace.BodyExecuted)
		require.JSONEq(t, string(before), string(snapshot(ctx, input.Mirror.ObjectID)))
	})
	// Refusal audit runs after the failed registration transaction and preserves
	// the verified peer without requiring the very installation that was denied.
	t.Run("private refusal audits uninstalled peer without business writes", func(t *testing.T) {
		input := makeIntent(1, "private-refusal-positive")
		input.Action = kaname.ResourceDecisionRecordRefusal
		input.RefusalOutcome = kaname.ResourceRefusalPermissionDenied
		input.Mirror.ParentAccountID = "forged-audit-tenant"
		input.Mirror.ParentProjectID = "forged-audit-project"
		input.Mirror.ParentChain = []string{"project:forged-audit-project"}
		require.Error(t, gate.AuthorizeAccount(ctx, scenes[1].Account))
		result, trace, callErr := kanamepg.ProbePrivateRegistration(ctx, kanamepg.New(r.admin, nil), r.bundle, gate, input)
		t.Logf("private refusal trace: %+v", trace)
		{
			var sqlCause *pgconn.PgError
			if errors.As(callErr, &sqlCause) {
				t.Logf("actual SQL error: code=%s message=%s where=%s", sqlCause.Code, sqlCause.Message, sqlCause.Where)
			}
		}
		require.NoError(t, callErr)
		require.True(t, trace.RRClosed)
		require.True(t, trace.TypedRCEntered)
		require.True(t, trace.RefusalIdentityVerified)
		require.True(t, trace.Finalized)
		require.False(t, trace.Authorized, "negative audit does not confer registration authority")
		require.True(t, trace.BodyExecuted)
		require.True(t, trace.Committed)
		require.False(t, result.Changed)
		var state map[string][]json.RawMessage
		require.NoError(t, json.Unmarshal(snapshot(ctx, input.Mirror.ObjectID), &state))
		for table, rows := range state {
			if table == "audits" {
				require.Len(t, rows, 1)
				continue
			}
			require.Empty(t, rows, table)
		}
		var audit struct {
			Tenant    *string `json:"tenant_account_id"`
			EventType string  `json:"event_type"`
			Payload   struct {
				Actor   string   `json:"actor"`
				Outcome string   `json:"outcome"`
				Version string   `json:"source_version"`
				Chain   []string `json:"parent_chain"`
			} `json:"event_payload"`
		}
		require.NoError(t, json.Unmarshal(state["audits"][0], &audit))
		require.Nil(t, audit.Tenant)
		require.Equal(t, "iam.resource_registration.registered", audit.EventType)
		require.Equal(t, "service_account:"+authzguard.ServiceAccountIDForService("vpc"), audit.Payload.Actor)
		require.Equal(t, "permission_denied", audit.Payload.Outcome)
		require.Equal(t, input.Mirror.SourceVersion.UTC().Format(time.RFC3339Nano), audit.Payload.Version)
		require.Empty(t, audit.Payload.Chain)
	})
	t.Run("private refusal rejects unverified identity without audit", func(t *testing.T) {
		input := makeIntent(1, "private-refusal-unverified")
		input.Action = kaname.ResourceDecisionRecordRefusal
		input.RefusalOutcome = kaname.ResourceRefusalFailedPrecondition
		before := snapshot(ctx, input.Mirror.ObjectID)
		unverified := grpcsrv.WithCertIdentityIn(r.ctx, grpcsrv.NewTrustDomain("kacho.cloud"), "spiffe://kacho.cloud/ns/modules/sa/kacho-vpc", false)
		_, trace, callErr := kanamepg.ProbePrivateRegistration(unverified, kanamepg.New(r.admin, nil), r.bundle, gate, input)
		require.Error(t, callErr)
		require.False(t, trace.RefusalIdentityVerified)
		require.False(t, trace.TypedRCEntered)
		require.False(t, trace.BodyExecuted)
		require.False(t, trace.Committed)
		require.JSONEq(t, string(before), string(snapshot(ctx, input.Mirror.ObjectID)))
	})
	var readinessAfter bool
	require.NoError(t, r.admin.QueryRow(ctx, `SELECT kaname.authority_resource_storage_v2('{"abi":1,"aliases":{"nlb":"loadbalancer"},"fallback":"identity"}'::jsonb)`).Scan(&readinessAfter))
	require.Equal(t, readinessBefore, readinessAfter)
}
