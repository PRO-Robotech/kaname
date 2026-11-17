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

// Настоящий production constructor и Run на отдельном ordinary LOGIN.
// TestMain использует только pgtest.Goose(migrations.FS), без private SQL preload.
func TestResourcePublicEntryCutoverActualCases(t *testing.T) {
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
		AccountID: domain.AccountID(r.a), Name: "kacho-vpc", Description: "Проверка публичной регистрации",
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
	// Readiness должна быть открыта только настоящей полной Goose сборкой.
	var readinessBefore bool
	require.NoError(t, r.runtime.QueryRow(ctx, `SELECT kaname.authority_resource_storage_v2('{"abi":1,"aliases":{"nlb":"loadbalancer"},"fallback":"identity"}'::jsonb)`).Scan(&readinessBefore))
	require.True(t, readinessBefore)
	var effective, session string
	require.NoError(t, r.runtime.QueryRow(ctx, `SELECT current_user,session_user`).Scan(&effective, &session))
	require.Equal(t, r.role, effective)
	require.Equal(t, r.role, session)
	runner, err := kanamepg.NewResourceDecisionRunner(ctx, r.repo, r.bundle, gate)
	require.NoError(t, err)
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
	t.Run("Register сохраняет все эффекты", func(t *testing.T) {
		input := makeIntent(0, "private-registration-positive")
		before := snapshot(ctx, input.Mirror.ObjectID)
		result, callErr := runner.RunResourceDecision(ctx, input)
		resourcePublicEntryCause(t, callErr)
		require.NoError(t, callErr)
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
	t.Run("Register без установки откатывает изменения", func(t *testing.T) {
		input := makeIntent(1, "private-registration-denied")
		before := snapshot(ctx, input.Mirror.ObjectID)
		result, callErr := runner.RunResourceDecision(ctx, input)
		require.Error(t, callErr)
		require.Equal(t, codes.PermissionDenied, status.Code(callErr))
		require.Equal(t, kaname.ResourceDecisionResult{}, result)
		require.JSONEq(t, string(before), string(snapshot(ctx, input.Mirror.ObjectID)))
	})
	// Cleanup использует тот же публичный runner после законного installer transition.
	t.Run("Unregister фиксирует очистку", func(t *testing.T) {
		input := makeIntent(0, "private-unregistration-positive")
		_, callErr := runner.RunResourceDecision(ctx, input)
		resourcePublicEntryCause(t, callErr)
		require.NoError(t, callErr)
		before := snapshot(ctx, input.Mirror.ObjectID)
		input.Action = kaname.ResourceDecisionUnregister
		result, callErr := runner.RunResourceDecision(ctx, input)
		resourcePublicEntryCause(t, callErr)
		require.NoError(t, callErr)
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
	t.Run("Unregister после законного отзыва установки откатывается", func(t *testing.T) {
		assignments := []domain.RegistrationAccountWriter{
			{AssignmentID: "private-register-A", AccountID: scenes[0].Account, Module: "vpc"},
			{AssignmentID: "private-register-B", AccountID: scenes[1].Account, Module: "vpc"},
		}
		require.NoError(t, seed.ApplyRegistrationAccountWriters(ctx, kanamepg.NewRegistrationAccountWriterStore(r.admin), roster,
			seed.RegistrationWriterPlan{Assignments: assignments}))
		input := makeIntent(1, "private-unregistration-denied")
		_, callErr := runner.RunResourceDecision(ctx, input)
		resourcePublicEntryCause(t, callErr)
		require.NoError(t, callErr)
		require.NoError(t, seed.ApplyRegistrationAccountWriters(ctx, kanamepg.NewRegistrationAccountWriterStore(r.admin), roster,
			seed.RegistrationWriterPlan{Assignments: assignments[:1]}))
		require.Error(t, gate.AuthorizeAccount(ctx, scenes[1].Account))
		before := snapshot(ctx, input.Mirror.ObjectID)
		input.Action = kaname.ResourceDecisionUnregister
		result, callErr := runner.RunResourceDecision(ctx, input)
		require.Error(t, callErr)
		require.Equal(t, codes.PermissionDenied, status.Code(callErr))
		require.Equal(t, kaname.ResourceDecisionResult{}, result)
		require.JSONEq(t, string(before), string(snapshot(ctx, input.Mirror.ObjectID)))
	})
	// Отказный аудит сохраняет проверенного отправителя после отказа регистрации,
	// не требуя отсутствующей установки.
	t.Run("Refusal пишет только аудит проверенного неустановленного модуля", func(t *testing.T) {
		input := makeIntent(1, "private-refusal-positive")
		input.Action = kaname.ResourceDecisionRecordRefusal
		input.RefusalOutcome = kaname.ResourceRefusalPermissionDenied
		input.Mirror.ParentAccountID = "forged-audit-tenant"
		input.Mirror.ParentProjectID = "forged-audit-project"
		input.Mirror.ParentChain = []string{"project:forged-audit-project"}
		require.Error(t, gate.AuthorizeAccount(ctx, scenes[1].Account))
		result, callErr := runner.RunResourceDecision(ctx, input)
		resourcePublicEntryCause(t, callErr)
		require.NoError(t, callErr)
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
	t.Run("Refusal без проверенной идентичности не пишет аудит", func(t *testing.T) {
		input := makeIntent(1, "private-refusal-unverified")
		input.Action = kaname.ResourceDecisionRecordRefusal
		input.RefusalOutcome = kaname.ResourceRefusalFailedPrecondition
		before := snapshot(ctx, input.Mirror.ObjectID)
		unverified := grpcsrv.WithCertIdentityIn(r.ctx, grpcsrv.NewTrustDomain("kacho.cloud"), "spiffe://kacho.cloud/ns/modules/sa/kacho-vpc", false)
		result, callErr := runner.RunResourceDecision(unverified, input)
		resourcePublicEntryCause(t, callErr)
		require.NoError(t, callErr)
		require.Equal(t, kaname.ResourceDecisionResult{}, result)
		require.JSONEq(t, string(before), string(snapshot(ctx, input.Mirror.ObjectID)))
	})
	var readinessAfter bool
	require.NoError(t, r.runtime.QueryRow(ctx, `SELECT kaname.authority_resource_storage_v2('{"abi":1,"aliases":{"nlb":"loadbalancer"},"fallback":"identity"}'::jsonb)`).Scan(&readinessAfter))
	require.Equal(t, readinessBefore, readinessAfter)
}

func resourcePublicEntryCause(t *testing.T, err error) {
	t.Helper()
	var cause *pgconn.PgError
	if errors.As(err, &cause) {
		t.Logf("Публичный вход SQLSTATE=%s сообщение=%s контекст=%s", cause.Code, cause.Message, cause.Where)
	}
}
