// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	accountapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/account"
	projectapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/project"
	saapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/service_account"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

type metadataWorld struct {
	r               protocolRig
	full            *kanamepg.Repository
	factory         *kanamepg.MetadataMutationWriters
	actor, outsider string
	account         domain.Account
	project         domain.Project
	sa              domain.ServiceAccount
	binding         domain.AccessBindingID
	door            clients.RelationStore
	ops             operations.Repo
}

func metadataFixture(t *testing.T, expiring bool) metadataWorld {
	t.Helper()
	r := writerProtocolRig(t)
	actor := seedMemberUser(t, r.ctx, r.admin, r.a, "metadata-editor")
	outsider := seedMemberUser(t, r.ctx, r.admin, r.b, "metadata-outsider")
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=ANY($1::text[])`, []string{actor, outsider, bindingPublicOwner(t, r)})
	require.NoError(t, err)
	// Как в Project.Create, строка и структурные связи проекта фиксируются
	// одной транзакцией. seedProject вставляет только строку; resource_scope_edge
	// читает родительские связи из зафиксированных вместе с ней relation facts.
	seed, err := lifecycleOwner(r).Writer(r.ctx)
	require.NoError(t, err)
	defer func() { _ = seed.Rollback(context.WithoutCancel(r.ctx)) }()
	project, err := seed.ProjectsW().Insert(r.ctx, domain.Project{
		ID: domain.ProjectID(ids.NewID(domain.PrefixProject)), AccountID: domain.AccountID(r.a),
		Name: "metadata-project", Description: "integration test metadata-project", Labels: domain.Labels{},
	})
	require.NoError(t, err)
	var structural []service.RelationTuple
	for _, fact := range project.StructuralFacts() {
		structural = append(structural, service.RelationTuple{User: fact.User, Relation: fact.Relation, Object: fact.Object})
	}
	require.NoError(t, seed.EmitFGARelationWrite(r.ctx, structural))
	require.NoError(t, seed.Commit(r.ctx))
	var parents []string
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT COALESCE(array_agg(parent_type||':'||parent_id ORDER BY parent_type,parent_id),'{}'::text[]) FROM kaname.resource_scope_edge WHERE object_type='project' AND object_id=$1`, string(project.ID)).Scan(&parents))
	require.ElementsMatch(t, []string{"account:" + r.a, "cluster:" + domain.ClusterSingletonID}, parents, "Дано: родительские связи проекта зафиксированы как в Project.Create")
	sa := seedSA(t, r.ctx, lifecycleOwner(r), domain.AccountID(r.a), "metadata-service-account")
	binding := groupLifecycleBinding(t, r, r.a, actor, "metadata_editor_role", domain.Rule{Module: "iam", Resources: []string{"account", "project", "serviceAccount"}, Verbs: []string{"update"}})
	source := rolePolicyCatalog(t, r)
	engine := reconcile.New(kanamepg.NewReconcileAdapter(r.admin, source), slog.Default(), source)
	require.NoError(t, engine.ReconcileBinding(r.ctx, binding))
	var granted []string
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT COALESCE(array_agg(DISTINCT object ORDER BY object),'{}'::text[]) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND fga_user=$2 AND relation='v_update'`, string(binding), "user:"+actor).Scan(&granted))
	require.ElementsMatch(t, []string{"account:" + r.a, "project:" + string(project.ID), "iam_service_account:" + string(sa.ID)}, granted, "Дано: для всех трёх объектов материализована точная привязка только на update")
	if expiring {
		_, err = r.admin.Exec(r.ctx, `UPDATE kaname.access_bindings SET expires_at=clock_timestamp()+interval '5 seconds' WHERE id=$1`, string(binding))
		require.NoError(t, err)
	}
	rd, err := r.repo.Reader(r.ctx)
	require.NoError(t, err)
	account, err := rd.Accounts().Get(r.ctx, domain.AccountID(r.a))
	require.NoError(t, err)
	require.NoError(t, rd.Rollback(r.ctx))
	full, _ := fullContractActivate(t, r)
	factory, err := kanamepg.NewMetadataMutationWriters(r.ctx, full, r.bundle)
	require.NoError(t, err)
	plans, err := authzmodel.New(r.bundle.ModelSource())
	require.NoError(t, err)
	door := authzcascade.WrapAdmitted(relverdict.NewPreparedAsker(r.runtime, plans), personmarks.New(r.runtime))
	return metadataWorld{r, full, factory, actor, outsider, account, project, sa, binding, door, operations.NewRepo(r.runtime, "kaname")}
}
func (w metadataWorld) subject(id string) domain.Subject {
	return domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(id)}
}
func (w metadataWorld) open(ctx context.Context, kind, name string, mask []string, actor string) (kaname.SemanticAuthorityWriter, error) {
	switch kind {
	case "account":
		a := w.account
		if name != "" {
			a.Name = domain.AccountName(name)
		}
		return w.factory.AccountMetadataWriter(ctx, a, mask, w.subject(actor))
	case "project":
		a := w.project
		if name != "" {
			a.Name = domain.ProjectName(name)
		}
		return w.factory.ProjectMetadataWriter(ctx, a, mask, w.subject(actor))
	default:
		a := w.sa
		if name != "" {
			a.Name = domain.SvcAccountName(name)
		}
		return w.factory.ServiceAccountMetadataWriter(ctx, a, mask, w.subject(actor))
	}
}
func metadataSnapshot(t *testing.T, w metadataWorld) string {
	t.Helper()
	var state string
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT jsonb_build_array(
 (SELECT to_jsonb(a) FROM kaname.accounts a WHERE id=$1),
 (SELECT to_jsonb(p) FROM kaname.projects p WHERE id=$2),
 (SELECT to_jsonb(s) FROM kaname.service_accounts s WHERE id=$3),
 (SELECT count(*) FROM kaname.audit_outbox),(SELECT count(*) FROM kaname.resource_journal),
 (SELECT count(*) FROM kaname.resource_reconcile_outbox))::text`, w.r.a, string(w.project.ID), string(w.sa.ID)).Scan(&state))
	return state
}
func TestFullMetadataActualThreeUseCasesAndDeniedNoEffects(t *testing.T) {
	w := metadataFixture(t, false)
	ctx := declarerCtx(w.r.ctx, w.actor)
	a := accountapp.NewUpdateAccountUseCase(w.full, w.ops).WithRelationStore(w.door, nil).WithAccountMetadataWriter(w.factory)
	p := projectapp.NewUpdateProjectUseCase(w.full, w.ops).WithRelationStore(w.door, nil).WithProjectMetadataWriter(w.factory)
	s := saapp.NewUpdateServiceAccountUseCase(w.full, w.ops).WithServiceAccountMetadataWriter(w.factory)
	description := domain.Description("full metadata committed")
	before := metadataSnapshot(t, w)
	ao, err := a.Execute(ctx, accountapp.UpdateAccountInput{ID: w.account.ID, Description: &description, UpdateMask: []string{"description"}})
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, w.r.ctx, w.ops, ao.ID).Error)
	po, err := p.Execute(ctx, projectapp.UpdateProjectInput{ID: w.project.ID, Description: &description, UpdateMask: []string{"description"}})
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, w.r.ctx, w.ops, po.ID).Error)
	so, err := s.Execute(ctx, saapp.UpdateServiceAccountInput{ID: w.sa.ID, Description: &description, UpdateMask: []string{"description"}})
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, w.r.ctx, w.ops, so.ID).Error)
	require.NotEqual(t, before, metadataSnapshot(t, w))
	var matching, audits int
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT (SELECT count(*) FROM kaname.accounts WHERE id=$1 AND description=$4)+(SELECT count(*) FROM kaname.projects WHERE id=$2 AND description=$4)+(SELECT count(*) FROM kaname.service_accounts WHERE id=$3 AND description=$4)`, w.r.a, string(w.project.ID), string(w.sa.ID), string(description)).Scan(&matching))
	require.Equal(t, 3, matching)
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE event_payload->>'actor'=$1 AND event_payload->>'resource_id'=ANY($2::text[])`, w.actor, []string{w.r.a, string(w.project.ID), string(w.sa.ID)}).Scan(&audits))
	require.Equal(t, 3, audits, "all committed metadata bodies must keep actor and audit in their TX")
	// Exercise actual successful rename + labels branches through the same UCs.
	// The immutable owner/parent/enabled fields are absent from these patches.
	an := domain.AccountName("metadata-renamed-account")
	pn := domain.ProjectName("metadata-renamed-project")
	sn := domain.SvcAccountName("metadata-renamed-sa")
	labels := domain.Labels{"metadata-test": "updated"}
	ao, err = a.Execute(ctx, accountapp.UpdateAccountInput{ID: w.account.ID, Name: &an, Labels: labels, UpdateMask: []string{"name", "labels"}})
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, w.r.ctx, w.ops, ao.ID).Error)
	po, err = p.Execute(ctx, projectapp.UpdateProjectInput{ID: w.project.ID, Name: &pn, Labels: labels, UpdateMask: []string{"name", "labels"}})
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, w.r.ctx, w.ops, po.ID).Error)
	so, err = s.Execute(ctx, saapp.UpdateServiceAccountInput{ID: w.sa.ID, Name: &sn, Labels: labels, UpdateMask: []string{"name", "labels"}})
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, w.r.ctx, w.ops, so.ID).Error)
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT (SELECT count(*) FROM kaname.accounts WHERE id=$1 AND name=$4 AND labels->>'metadata-test'='updated')+(SELECT count(*) FROM kaname.projects WHERE id=$2 AND name=$5 AND labels->>'metadata-test'='updated')+(SELECT count(*) FROM kaname.service_accounts WHERE id=$3 AND name=$6 AND labels->>'metadata-test'='updated')`, w.r.a, string(w.project.ID), string(w.sa.ID), string(an), string(pn), string(sn)).Scan(&matching))
	require.Equal(t, 3, matching)
	unchanged := metadataSnapshot(t, w)
	for _, kind := range []string{"account", "project", "service_account"} {
		denied, err := w.open(w.r.ctx, kind, "", []string{"description"}, w.outsider)
		if denied != nil {
			_ = denied.Rollback(w.r.ctx)
		}
		require.ErrorIs(t, err, iamerr.ErrPermissionDenied)
		require.Nil(t, denied)
		require.Equal(t, unchanged, metadataSnapshot(t, w))
	}
	for _, kind := range []string{"account", "project", "service_account"} {
		raw, err := w.full.Writer(w.r.ctx)
		require.NoError(t, err)
		switch kind {
		case "account":
			_, err = raw.AccountsW().Update(w.r.ctx, w.account, []string{"description"})
		case "project":
			_, err = raw.ProjectsW().Update(w.r.ctx, w.project, []string{"description"})
		default:
			_, err = raw.ServiceAccountsW().Update(w.r.ctx, w.sa, []string{"description"})
		}
		require.Error(t, err)
		_ = raw.Rollback(w.r.ctx)
	}
	require.Equal(t, unchanged, metadataSnapshot(t, w), "raw Writer must remain unsigned even on tagged repository")
	// Explicit nil configuration must never fall back to the raw writer.
	nilUC := saapp.NewUpdateServiceAccountUseCase(w.full, w.ops).WithServiceAccountMetadataWriter(nil)
	failed, err := nilUC.Execute(ctx, saapp.UpdateServiceAccountInput{ID: w.sa.ID, Description: &description, UpdateMask: []string{"description"}})
	require.NoError(t, err)
	require.NotNil(t, awaitOperation(t, w.r.ctx, w.ops, failed.ID).Error)
	require.Equal(t, unchanged, metadataSnapshot(t, w))
}

func TestFullMetadataDescriptionAndLabelsKeepLocalNonCoarseLocks(t *testing.T) {
	w := metadataFixture(t, false)
	for _, kind := range []string{"account", "project", "service_account"} {
		for _, field := range []string{"description", "labels"} {
			opened, err := w.open(w.r.ctx, kind, "unused-name-outside-mask", []string{field}, w.actor)
			require.NoError(t, err)
			require.Equal(t, kaname.AuthorityFenceAccounts, opened.AuthorityFence().Mode())
			var coarse int
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.usename=$1 AND l.locktype='relation' AND l.relation IN ('kaname.accounts'::regclass,'kaname.projects'::regclass,'kaname.service_accounts'::regclass) AND l.mode='ShareRowExclusiveLock' AND l.granted`, w.r.role).Scan(&coarse))
			require.Zero(t, coarse, "ordinary metadata must not serialize whole-table DML")
			require.NoError(t, opened.Rollback(w.r.ctx))
		}
	}
}

// A real fixed-generation typed ordinary writer in a different account holds
// physical DML locks. No disabled guards, owner bypass, free GUC or fake allow.
func metadataForeignBlocker(t *testing.T, w metadataWorld, kind, name string) pgx.Tx {
	t.Helper()
	tx, err := w.r.runtime.Begin(w.r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	id := w.r.bundle.Identity()
	_, err = tx.Exec(w.r.ctx, `SELECT kaname.authority_protocol_enter_typed_v3('accounts',ARRAY[$1],jsonb_build_array(jsonb_build_object('kind','account','id',$1)),'resource',$2,$3,$4,'participant')`, w.r.b, id.ModelID, id.CatalogID, id.ProjectorVersion)
	require.NoError(t, err)
	switch kind {
	case "account":
		// Account.name is globally unique. A new root INSERT would hold GLOBAL;
		// a foreign existing-account rename exercises the post-entry table seam.
		_, err = tx.Exec(w.r.ctx, `UPDATE kaname.accounts SET name=$1 WHERE id=$2`, name, w.r.b)
	case "project":
		_, err = tx.Exec(w.r.ctx, `INSERT INTO kaname.projects(id,account_id,name) VALUES($1,$2,$3)`, ids.NewID(domain.PrefixProject), w.r.b, name)
	default:
		_, err = tx.Exec(w.r.ctx, `INSERT INTO kaname.service_accounts(id,account_id,name) VALUES($1,$2,$3)`, ids.NewID(domain.PrefixServiceAccount), w.r.b, name)
	}
	require.NoError(t, err)
	return tx
}

// Глобально уникальное имя account сохраняет ожидание чужого аккаунта на SRE.
// Локальные unique keys project/SA проверяются ниже на account fence.
func TestFullMetadataRenameWaitExpiresBeforeOldAuthorityDecision(t *testing.T) {
	for _, kind := range []string{"account"} {
		t.Run(kind, func(t *testing.T) {
			w := metadataFixture(t, true)
			positive, err := w.open(w.r.ctx, kind, "", []string{"description"}, w.actor)
			require.NoError(t, err)
			require.NoError(t, positive.Rollback(w.r.ctx))
			before := metadataSnapshot(t, w)
			name := "metadata-collision-" + ids.NewID("nam")
			blocker := metadataForeignBlocker(t, w, kind, name)
			done := lifecycleAsync(t, w.r.ctx, func(ctx context.Context) error {
				opened, e := w.open(ctx, kind, name, []string{"name"}, w.actor)
				if opened != nil {
					_ = opened.Rollback(ctx)
				}
				return e
			})
			receiptWaitForBlocker(t, w.r.ctx, w.r.admin, int(blocker.Conn().PgConn().PID()))
			// Confirm this is the approved physical table seam, not an account fence wait.
			var pending bool
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='relation' AND relation=to_regclass($1) AND mode='ShareRowExclusiveLock' AND NOT granted)`, "kaname."+map[string]string{"account": "accounts", "project": "projects", "service_account": "service_accounts"}[kind]).Scan(&pending))
			require.True(t, pending)
			require.Eventually(t, func() bool {
				var expired bool
				e := w.r.admin.QueryRow(w.r.ctx, `SELECT expires_at<clock_timestamp() FROM kaname.access_bindings WHERE id=$1`, string(w.binding)).Scan(&expired)
				return e == nil && expired
			}, 10*time.Second, 10*time.Millisecond)
			require.NoError(t, blocker.Rollback(w.r.ctx))
			require.ErrorIs(t, lifecycleResult(t, w.r.ctx, done), iamerr.ErrPermissionDenied, "authority expired while rename waited; OLD native gate must deny")
			require.Equal(t, before, metadataSnapshot(t, w))
		})
	}
}

func TestFullMetadataQueuedEntryRechecksOwnerContractGeneration(t *testing.T) {
	w := metadataFixture(t, false)
	before := metadataSnapshot(t, w)
	owner, err := w.r.admin.Begin(w.r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, owner)
	_, err = owner.Exec(w.r.ctx, `SELECT kaname.authority_protocol_drain()`)
	require.NoError(t, err)
	done := lifecycleAsync(t, w.r.ctx, func(ctx context.Context) error {
		opened, e := w.open(ctx, "project", "", []string{"description"}, w.actor)
		if opened != nil {
			_ = opened.Rollback(ctx)
		}
		return e
	})
	receiptWaitForBlocker(t, w.r.ctx, w.r.admin, int(owner.Conn().PgConn().PID()))
	// Adversarial privileged state transition under the real owner barrier.
	// Production lifecycle intentionally does not offer generation downgrade.
	_, err = owner.Exec(w.r.ctx, `UPDATE kaname.authority_writer_contract SET required_contract=1 WHERE singleton`)
	require.NoError(t, err)
	require.NoError(t, owner.Commit(w.r.ctx))
	err = lifecycleResult(t, w.r.ctx, done)
	var protocolErr *pgconn.PgError
	require.ErrorAs(t, err, &protocolErr)
	require.Equal(t, "P1036", protocolErr.Code)
	require.Equal(t, before, metadataSnapshot(t, w))
}

func TestFullMetadataBodyRollbackKeepsAllEffectsAtomic(t *testing.T) {
	w := metadataFixture(t, false)
	before := metadataSnapshot(t, w)
	changed := w.project
	changed.Description = "rolled back metadata"
	// Замороженная программа соответствует реальному телу, включая NEW description.
	opened, err := w.factory.ProjectMetadataWriter(w.r.ctx, changed, []string{"description"}, w.subject(w.actor))
	require.NoError(t, err)
	_, err = opened.ProjectsW().Update(w.r.ctx, changed, []string{"description"})
	require.NoError(t, err)
	require.NoError(t, opened.EmitReconcileEvent(w.r.ctx, "mirror.upsert", "iam.project", string(changed.ID)))
	require.NoError(t, opened.Rollback(w.r.ctx))
	require.Equal(t, before, metadataSnapshot(t, w), "row, journal and reconcile must roll back together")
}

// Same-unique-key INSERT cannot overlap the account fence. This tests that
// earlier wait separately from the foreign-account table-lock wait above.
func TestFullMetadataSameKeyUncommittedInsertExpiresBeforeRename(t *testing.T) {
	for _, kind := range []string{"account", "project", "service_account"} {
		t.Run(kind, func(t *testing.T) {
			w := metadataFixture(t, true)
			before := metadataSnapshot(t, w)
			positive, err := w.open(w.r.ctx, kind, "", []string{"description"}, w.actor)
			require.NoError(t, err)
			require.NoError(t, positive.Rollback(w.r.ctx))
			blocker, err := w.r.runtime.Begin(w.r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, blocker)
			identity := w.r.bundle.Identity()
			mode := "accounts"
			accounts := []string{w.r.a}
			if kind == "account" {
				mode = "global"
				accounts = []string{}
			}
			_, err = blocker.Exec(w.r.ctx, `SELECT kaname.authority_protocol_enter_typed_v3($1,$2::text[],jsonb_build_array(jsonb_build_object('kind','account','id',$6::text)),'resource',$3,$4,$5,'participant')`, mode, accounts, identity.ModelID, identity.CatalogID, identity.ProjectorVersion, w.r.a)
			require.NoError(t, err)
			name := "metadata-collision-" + ids.NewID("nam")
			switch kind {
			case "account":
				_, err = blocker.Exec(w.r.ctx, `INSERT INTO kaname.accounts(id,owner_user_id,name) VALUES($1,$2,$3)`, ids.NewID(domain.PrefixAccount), string(w.account.OwnerUserID), name)
			case "project":
				_, err = blocker.Exec(w.r.ctx, `INSERT INTO kaname.projects(id,account_id,name) VALUES($1,$2,$3)`, ids.NewID(domain.PrefixProject), w.r.a, name)
			default:
				_, err = blocker.Exec(w.r.ctx, `INSERT INTO kaname.service_accounts(id,account_id,name) VALUES($1,$2,$3)`, ids.NewID(domain.PrefixServiceAccount), w.r.a, name)
			}
			require.NoError(t, err)
			done := lifecycleAsync(t, w.r.ctx, func(ctx context.Context) error {
				opened, e := w.open(ctx, kind, name, []string{"name"}, w.actor)
				if opened != nil {
					_ = opened.Rollback(ctx)
				}
				return e
			})
			pid := receiptWaitForBlocker(t, w.r.ctx, w.r.admin, int(blocker.Conn().PgConn().PID()))
			if kind != "account" {
				var accountWait, coarseWait bool
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT
 EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='advisory' AND classid=1262569281::oid AND objid=(hashtext($2)::bigint & 4294967295)::oid AND objsubid=2 AND mode='ExclusiveLock' AND NOT granted),
 EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='relation' AND mode='ShareRowExclusiveLock')`, pid, w.r.a).Scan(&accountWait, &coarseWait))
				require.True(t, accountWait, "невидимый INSERT того же unique key ждём на account fence до final clock")
				require.False(t, coarseWait, "локальный rename не должен запрашивать SRE")
			}
			require.Eventually(t, func() bool {
				var expired bool
				e := w.r.admin.QueryRow(w.r.ctx, `SELECT expires_at<clock_timestamp() FROM kaname.access_bindings WHERE id=$1`, string(w.binding)).Scan(&expired)
				return e == nil && expired
			}, 10*time.Second, 10*time.Millisecond)
			require.NoError(t, blocker.Rollback(w.r.ctx))
			require.ErrorIs(t, lifecycleResult(t, w.r.ctx, done), iamerr.ErrPermissionDenied)
			require.Equal(t, before, metadataSnapshot(t, w))
		})
	}
}

// Чужой незавершённый INSERT занимает то же имя в другом аккаунте и держит
// RowExclusive. Оба настоящих metadata body должны зафиксироваться ДО его
// завершения: описание и rename не сериализуют всю таблицу project/SA.
func TestFullMetadataLocalRenameAndDescriptionCommitBesideForeignInsert(t *testing.T) {
	for _, kind := range []string{"project", "service_account"} {
		for _, field := range []string{"description", "name"} {
			t.Run(kind+"/"+field, func(t *testing.T) {
				w := metadataFixture(t, false)
				name := "parallel-collision-" + ids.NewID("nam")
				foreign := metadataForeignBlocker(t, w, kind, name)
				ctx, cancel := context.WithTimeout(w.r.ctx, 5*time.Second)
				defer cancel()
				done := lifecycleAsync(t, ctx, func(ctx context.Context) error {
					// Фабрика и body получают одни resolved значения, как публичный UC.
					project := w.project
					project.Name = domain.ProjectName(name)
					project.Description = "metadata parallel committed"
					sa := w.sa
					sa.Name = domain.SvcAccountName(name)
					sa.Description = "metadata parallel committed"
					var opened kaname.SemanticAuthorityWriter
					var err error
					if kind == "project" {
						opened, err = w.factory.ProjectMetadataWriter(ctx, project, []string{field}, w.subject(w.actor))
					} else {
						opened, err = w.factory.ServiceAccountMetadataWriter(ctx, sa, []string{field}, w.subject(w.actor))
					}
					if err != nil {
						return err
					}
					defer func() { _ = opened.Rollback(context.WithoutCancel(ctx)) }()
					if kind == "project" {
						changed := w.project
						changed.Name = domain.ProjectName(name)
						changed.Description = "metadata parallel committed"
						_, err = opened.ProjectsW().Update(ctx, changed, []string{field})
					} else {
						changed := w.sa
						changed.Name = domain.SvcAccountName(name)
						changed.Description = "metadata parallel committed"
						_, err = opened.ServiceAccountsW().Update(ctx, changed, []string{field})
					}
					if err != nil {
						return err
					}
					return opened.Commit(ctx)
				})
				// Никакого освобождения blocker до получения успешного commit.
				require.NoError(t, lifecycleResult(t, ctx, done))
				var foreignHeld, coarse bool
				table := map[string]string{"project": "projects", "service_account": "service_accounts"}[kind]
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT
 EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND locktype='relation' AND relation=to_regclass($2) AND mode='RowExclusiveLock' AND granted),
 EXISTS(SELECT 1 FROM pg_locks l JOIN pg_stat_activity a ON a.pid=l.pid WHERE a.usename=$3 AND l.locktype='relation' AND l.relation=to_regclass($2) AND l.mode='ShareRowExclusiveLock')`, int(foreign.Conn().PgConn().PID()), "kaname."+table, w.r.role).Scan(&foreignHeld, &coarse))
				require.True(t, foreignHeld, "чужой writer ещё удерживает RowExclusive после местного commit")
				require.False(t, coarse)
				var gotName, gotDescription string
				if kind == "project" {
					require.NoError(t, w.r.runtime.QueryRow(w.r.ctx, `SELECT name,description FROM kaname.projects WHERE id=$1`, string(w.project.ID)).Scan(&gotName, &gotDescription))
				} else {
					require.NoError(t, w.r.runtime.QueryRow(w.r.ctx, `SELECT name,description FROM kaname.service_accounts WHERE id=$1`, string(w.sa.ID)).Scan(&gotName, &gotDescription))
				}
				if field == "name" {
					require.Equal(t, name, gotName)
				} else {
					require.Equal(t, "metadata parallel committed", gotDescription)
				}
				require.NoError(t, foreign.Rollback(w.r.ctx))
			})
		}
	}
}
