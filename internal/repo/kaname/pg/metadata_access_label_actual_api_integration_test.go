// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	accountapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/account"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// Штатный Account.Update: готовность установленной миграции, runtime writer,
// apply source, audit, reconcile event и commit. Нет test-only SQL exports.
func TestMetadataAccessLabelsActualAccountUpdateRetainsAndDirties(t *testing.T) {
	r, owner := writerProtocolRigBeforePreparation(t)
	team := seedAccessDefinition(t, r, "account", r.a, "team", "before", "after")
	keep := seedAccessDefinition(t, r, "account", r.a, "keep", "yes", "no")
	// Значение легально; отказ ниже доказывает отсутствие apply, не registry miss.
	seedAccessDefinition(t, r, "account", r.a, "no_apply", "blocked")
	actor := bindingPublicOwner(t, r)
	seedMetadataActualApplySource(t, r, actor, team.id, keep.id)
	require.NoError(t, owner.PrepareAuthorityBundle(r.ctx, r.bundle))
	cfg := r.runtime.Config()
	cfg.ConnConfig.Tracer = metadataActualQueryTrace{test: t}
	traced, err := pgxpool.NewWithConfig(r.ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(traced.Close)
	r.runtime, r.repo = traced, kanamepg.New(traced, nil)
	var recipient string
	var losing, surviving domain.AccessBindingID
	w := metadataFixtureModeWithRig(t, false, "prepared", r, func(r protocolRig) {
		recipient, losing, surviving = seedMetadataRetentionTwoHolders(t, r)
	})
	ports, err := w.factory.WithInstalledAccessLabels(r.ctx)
	require.NoError(t, err)
	_, protected := ports.(kaname.AccountAccessLabelsWriterFactory)
	require.True(t, protected, "migration 140000 must enable the actual protected writer")
	update := accountapp.NewUpdateAccountUseCase(w.full, w.ops).
		WithRelationStore(w.door, nil).WithAccountMetadataWriter(ports)
	// Результат читаем через отдельный LOGIN с правами на чтение.
	reader := metadataActualReadbackLogin(t, r)
	bindings := []string{string(losing), string(surviving)}
	var holders []string
	require.NoError(t, reader.QueryRow(r.ctx, `SELECT array_agg(DISTINCT binding_id ORDER BY binding_id)
 FROM kaname.access_binding_emitted_tuples WHERE binding_id=ANY($1::text[])
 AND member_object_type='iam.account' AND member_object_id=$2
 AND fga_user=$3 AND relation='viewer' AND object='account:'||$2`,
		bindings, r.a, "user:"+recipient).Scan(&holders))
	require.ElementsMatch(t, bindings, holders, "two real holders emit the exact same OLD fact")
	var original, oldFact json.RawMessage
	require.NoError(t, reader.QueryRow(r.ctx, `SELECT to_jsonb(a) FROM kaname.accounts a WHERE id=$1`, r.a).Scan(&original))
	require.NoError(t, reader.QueryRow(r.ctx, `SELECT to_jsonb(f) FROM kaname.relation_fact f
 WHERE object_type='account' AND object_id=$1 AND relation='viewer' AND subject=$2`, r.a, "user:"+recipient).Scan(&oldFact))
	var auditsBefore, journalsBefore int
	require.NoError(t, reader.QueryRow(r.ctx, `SELECT
 (SELECT count(*) FROM kaname.audit_outbox WHERE event_payload->>'resource_id'=$1 AND event_type='iam.account.updated'),
 (SELECT count(*) FROM kaname.resource_journal WHERE resource_kind='account' AND resource_id=$1 AND event_type='UPDATED')`, r.a).
		Scan(&auditsBefore, &journalsBefore))
	description := domain.Description("protected metadata exact committed description")
	run := func(labels domain.Labels, withDescription bool, want codes.Code) {
		t.Helper()
		input := accountapp.UpdateAccountInput{ID: w.account.ID, AccessLabels: labels, UpdateMask: []string{"access_labels"}}
		if withDescription {
			input.Description = &description
			input.UpdateMask = append(input.UpdateMask, "description")
		}
		op, err := update.Execute(declarerCtx(r.ctx, actor), input)
		require.NoError(t, err)
		result := awaitOperation(t, r.ctx, w.ops, op.ID)
		if want == codes.OK {
			require.Nil(t, result.Error)
		} else {
			require.NotNil(t, result.Error)
			require.Equal(t, int32(want), result.Error.Code, result.Error.Message)
		}
	}
	checkCommitted := func(labels domain.Labels, writes int) {
		t.Helper()
		patch, err := json.Marshal(map[string]any{"access_labels": labels, "description": description})
		require.NoError(t, err)
		var exact bool
		var audits, journals int
		require.NoError(t, reader.QueryRow(r.ctx, `SELECT to_jsonb(a)=($2::jsonb||$3::jsonb),
 (SELECT count(*) FROM kaname.audit_outbox WHERE event_payload->>'resource_id'=$1 AND event_type='iam.account.updated'),
 (SELECT count(*) FROM kaname.resource_journal WHERE resource_kind='account' AND resource_id=$1 AND event_type='UPDATED')
 FROM kaname.accounts a WHERE a.id=$1`, r.a, original, patch).Scan(&exact, &audits, &journals))
		require.True(t, exact, "the committed row is exactly OLD plus the approved fields")
		require.Equal(t, auditsBefore+writes, audits)
		require.Equal(t, journalsBefore+writes, journals)
		var sameFact bool
		require.NoError(t, reader.QueryRow(r.ctx, `SELECT to_jsonb(f)=$3::jsonb FROM kaname.relation_fact f
 WHERE object_type='account' AND object_id=$1 AND relation='viewer' AND subject=$2`, r.a, "user:"+recipient, oldFact).Scan(&sameFact))
		require.True(t, sameFact, "freshness fencing does not delete the OLD physical fact")
	}

	run(domain.Labels{"team": "after", "keep": "yes"}, true, codes.OK)
	checkCommitted(domain.Labels{"team": "after", "keep": "yes"}, 1)
	var pending int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.authority_access_label_dirty_fact
 WHERE root_type='iam.account' AND root_id=$1 AND object_type='account' AND object_id=$1
 AND relation='viewer' AND subject=$2`, r.a, "user:"+recipient).Scan(&pending))
	require.Zero(t, pending, "NEW certificate from the second holder retains the shared fact")
	var fresh bool
	require.NoError(t, reader.QueryRow(r.ctx, `SELECT kaname.authority_access_label_fact_fresh_v1('account',$1,'viewer',$2)`, r.a, "user:"+recipient).Scan(&fresh))
	require.True(t, fresh, "another LOGIN can use the retained fact")

	run(domain.Labels{"team": "after", "keep": "no"}, false, codes.OK)
	checkCommitted(domain.Labels{"team": "after", "keep": "no"}, 2)
	var generation string
	var newLabels json.RawMessage
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT generation::text,new_labels
 FROM kaname.authority_access_label_dirty_root WHERE root_type='iam.account' AND root_id=$1`, r.a).
		Scan(&generation, &newLabels))
	require.NotEmpty(t, generation)
	require.JSONEq(t, `{"team":"after","keep":"no"}`, string(newLabels))
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.authority_access_label_dirty_fact
 WHERE root_type='iam.account' AND root_id=$1 AND generation=$3::uuid AND object_type='account' AND object_id=$1
 AND relation='viewer' AND subject=$2`, r.a, "user:"+recipient, generation).Scan(&pending))
	require.Equal(t, 1, pending, "both NEW selectors miss; OLD fact is pending under the committed generation")
	require.NoError(t, reader.QueryRow(r.ctx, `SELECT kaname.authority_access_label_fact_fresh_v1('account',$1,'viewer',$2)`, r.a, "user:"+recipient).Scan(&fresh))
	require.False(t, fresh, "another LOGIN sees the committed revocation fence before reconciliation")
	var auditPayloads []json.RawMessage
	rows, err := reader.Query(r.ctx, `SELECT event_payload FROM kaname.audit_outbox
 WHERE event_type='iam.account.updated' AND event_payload->>'resource_id'=$1 AND event_payload->>'actor'=$2`, r.a, actor)
	require.NoError(t, err)
	for rows.Next() {
		var payload json.RawMessage
		require.NoError(t, rows.Scan(&payload))
		auditPayloads = append(auditPayloads, payload)
	}
	require.NoError(t, rows.Err())
	rows.Close()
	require.Len(t, auditPayloads, 2)
	var fields [][]string
	for _, raw := range auditPayloads {
		var payload struct {
			Changed []string `json:"changed_fields"`
		}
		require.NoError(t, json.Unmarshal(raw, &payload))
		fields = append(fields, payload.Changed)
	}
	require.ElementsMatch(t, [][]string{{"description", "access_labels"}, {"access_labels"}}, fields)

	beforeDenied := metadataActualDurableSnapshot(t, r)
	run(domain.Labels{"team": "after", "keep": "no", "no_apply": "blocked"}, false, codes.PermissionDenied)
	require.JSONEq(t, beforeDenied, metadataActualDurableSnapshot(t, r),
		"even the account owner cannot apply a declared key without its exact apply source")
}

// Источник полномочия устанавливается до подготовки bundle.
func seedMetadataActualApplySource(t *testing.T, r protocolRig, actor string, definitions ...string) {
	t.Helper()
	seedMetadataActualApplySourceInScope(t, r, actor, domain.ScopeAnchor{Type: "account", ID: r.a}, definitions...)
}

func seedMetadataActualApplySourceInScope(t *testing.T, r protocolRig, actor string, scope domain.ScopeAnchor, definitions ...string) {
	t.Helper()
	subject := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(actor)}
	source := domain.Role{ID: domain.RoleID(ids.NewID(domain.PrefixRole)),
		Name: "metadata_actual_apply", Rules: domain.Rules{accessRoleApply(definitions...)}}
	switch scope.Type {
	case "account":
		source.AccountID = domain.AccountID(scope.ID)
	case "project":
		source.ProjectID = domain.ProjectID(scope.ID)
	default:
		t.Fatalf("unsupported metadata apply fixture scope %q", scope.Type)
	}
	ordinary, caps, err := domain.SplitGrantCapabilityRules(source.Rules)
	require.NoError(t, err)
	source.Permissions, err = domain.CompileRules(ordinary)
	require.NoError(t, err)
	projection, err := r.bundle.Projection(source)
	require.NoError(t, err)
	seed, err := lifecycleOwner(r).Writer(r.ctx)
	require.NoError(t, err)
	defer func() { _ = seed.Rollback(context.WithoutCancel(r.ctx)) }()
	_, err = seed.RolesW().Insert(r.ctx, source)
	require.NoError(t, err)
	require.NoError(t, seed.RolesW().ReplaceRuleSelectors(r.ctx, source.ID, projection.Selectors))
	require.NoError(t, seed.RolesW().ReplaceRoleVerbs(r.ctx, source.ID, projection.Verbs))
	binding, err := bindingset.Insert(r.ctx, seed.AccessBindingsW(), domain.AccessBinding{
		ID: domain.AccessBindingID(ids.NewID("acb")), SubjectType: subject.Type, SubjectID: subject.ID, Subjects: []domain.Subject{subject},
		RoleID: source.ID, ResourceType: domain.ResourceType(scope.Type), ResourceID: scope.ID, Scope: domain.DeriveFromResourceType(scope.Type),
		Status: domain.AccessBindingStatusActive, Target: domain.AccessTarget{AllInScope: true},
	})
	require.NoError(t, err)
	require.NoError(t, seed.Commit(r.ctx))
	privateSeed, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, privateSeed)
	_, err = privateSeed.Exec(r.ctx, `UPDATE kaname.access_bindings SET grant_capability_version=1 WHERE id=$1`, binding.ID)
	require.NoError(t, err)
	_, err = privateSeed.Exec(r.ctx, `ALTER TABLE kaname.authority_role_access_label_rule DISABLE TRIGGER authority_role_access_label_rule_closed`)
	require.NoError(t, err)
	for _, cap := range caps {
		_, err = privateSeed.Exec(r.ctx, accessRoleProjectionInsert, source.ID, cap.RuleFP, string(cap.DefinitionID))
		require.NoError(t, err)
	}
	_, err = privateSeed.Exec(r.ctx, `ALTER TABLE kaname.authority_role_access_label_rule ENABLE TRIGGER authority_role_access_label_rule_closed`)
	require.NoError(t, err)
	require.NoError(t, privateSeed.Commit(r.ctx))
}

func metadataActualReadbackLogin(t *testing.T, r protocolRig) *pgxpool.Pool {
	t.Helper()
	name := "metadata_reader_" + strings.ReplaceAll(ids.NewID("rol"), "-", "_")
	quoted := pgx.Identifier{name}.Sanitize()
	password := ids.NewID("pwd")
	_, err := r.admin.Exec(r.ctx, "CREATE ROLE "+quoted+" LOGIN PASSWORD '"+strings.ReplaceAll(password, "'", "''")+"' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT")
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = r.admin.Exec(ctx, "DROP OWNED BY "+quoted)
		_, _ = r.admin.Exec(ctx, "DROP ROLE "+quoted)
	})
	_, err = r.admin.Exec(r.ctx, `GRANT USAGE ON SCHEMA kaname TO `+quoted+`;
 GRANT SELECT ON kaname.accounts,kaname.projects,kaname.service_accounts,kaname.audit_outbox,kaname.resource_journal,
 kaname.access_binding_emitted_tuples,kaname.relation_fact TO `+quoted)
	require.NoError(t, err)
	cfg := r.admin.Config()
	cfg.ConnConfig.User, cfg.ConnConfig.Password = name, password
	cfg.AfterConnect = nil
	pool, err := pgxpool.NewWithConfig(r.ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	var effective, session string
	require.NoError(t, pool.QueryRow(r.ctx, `SELECT current_user,session_user`).Scan(&effective, &session))
	require.Equal(t, name, effective)
	require.Equal(t, name, session)
	require.NotEqual(t, r.role, session)
	return pool
}

func metadataActualDurableSnapshot(t *testing.T, r protocolRig) string {
	t.Helper()
	var value string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_object(
 'root',(SELECT jsonb_build_array(xmin::text,ctid::text,to_jsonb(a)) FROM kaname.accounts a WHERE id=$1),
 'generation',(SELECT to_jsonb(d) FROM kaname.authority_access_label_dirty_root d WHERE root_type='iam.account' AND root_id=$1),
 'facts',(SELECT coalesce(jsonb_agg(to_jsonb(d) ORDER BY object_type,object_id,relation,subject),'[]') FROM kaname.authority_access_label_dirty_fact d WHERE root_type='iam.account' AND root_id=$1),
 'audit',(SELECT count(*) FROM kaname.audit_outbox WHERE event_type='iam.account.updated' AND event_payload->>'resource_id'=$1),
 'journal',(SELECT count(*) FROM kaname.resource_journal WHERE resource_kind='account' AND resource_id=$1 AND event_type='UPDATED'))::text`, r.a).Scan(&value))
	return value
}

// Выполняем те же SQL-команды и сохраняем причину отказа только в журнале теста.
// Клиент по-прежнему получает штатный санитизированный статус операции.
type metadataActualQueryTrace struct{ test *testing.T }
type metadataActualQueryKey struct{}

func (metadataActualQueryTrace) TraceQueryStart(ctx context.Context, _ *pgx.Conn, query pgx.TraceQueryStartData) context.Context {
	return context.WithValue(ctx, metadataActualQueryKey{}, query.SQL)
}

func (trace metadataActualQueryTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, result pgx.TraceQueryEndData) {
	var pgErr *pgconn.PgError
	if errors.As(result.Err, &pgErr) {
		query, _ := ctx.Value(metadataActualQueryKey{}).(string)
		trace.test.Logf("PostgreSQL %s %s, функция %s, запрос %.200s", pgErr.Code, pgErr.Message, pgErr.Where, query)
	}
}
