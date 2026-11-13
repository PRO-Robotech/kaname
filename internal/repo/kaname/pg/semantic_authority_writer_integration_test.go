// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func semanticBundleDB(t *testing.T, ctx context.Context, pool *pgxpool.Pool) *granteffect.Bundle {
	t.Helper()
	halves, err := kanamepg.NewCatalogRepo(pool).ReadCatalogHalves(ctx)
	require.NoError(t, err)
	b, err := granteffect.NewBundle(ctx, authzmodel.DSL, halves, granteffect.ProjectorVersion)
	require.NoError(t, err)
	return b
}

// Только синтетическая предпосылка пробы сравнения. Это НЕ product activation:
// миграция оставляет uninitialized, coordinator/backstop здесь не реализованы.
func semanticFixtureIdentity(t *testing.T, ctx context.Context, pool *pgxpool.Pool, b *granteffect.Bundle) {
	t.Helper()
	id := b.Identity()
	_, err := pool.Exec(ctx, `INSERT INTO kaname.authority_semantic_identity(singleton,phase,protocol_version,model_id,catalog_id,projector_version)
 VALUES(true,'active',1,$1,$2,$3) ON CONFLICT(singleton) DO UPDATE SET phase=EXCLUDED.phase,protocol_version=EXCLUDED.protocol_version,model_id=EXCLUDED.model_id,catalog_id=EXCLUDED.catalog_id,projector_version=EXCLUDED.projector_version`, id.ModelID, id.CatalogID, id.ProjectorVersion)
	require.NoError(t, err)
}
func semanticStart(t *testing.T, ctx context.Context, repo *kanamepg.Repository, plan kaname.AuthorityFencePlan, b *granteffect.Bundle) *authorityPending {
	t.Helper()
	waitCtx, cancel := context.WithCancel(ctx)
	p := &authorityPending{result: make(chan authorityOpenResult, 1), cancel: cancel}
	go func() {
		w, err := repo.SemanticAuthorityWriter(waitCtx, plan, b)
		p.result <- authorityOpenResult{w, err}
	}()
	t.Cleanup(func() {
		cancel()
		if p.taken {
			return
		}
		select {
		case result := <-p.result:
			if result.w != nil {
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				_ = result.w.Rollback(cleanup)
			}
		case <-time.After(6 * time.Second):
			t.Error("semantic writer не завершился после отмены")
		}
	})
	return p
}
func semanticIdentityLock(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (pgx.Tx, string) {
	t.Helper()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	})
	var singleton bool
	require.NoError(t, tx.QueryRow(ctx, `SELECT singleton FROM kaname.authority_semantic_identity FOR UPDATE`).Scan(&singleton))
	var xid string
	require.NoError(t, tx.QueryRow(ctx, `SELECT pg_current_xact_id()::text`).Scan(&xid))
	return tx, xid
}
func semanticWaitIdentity(t *testing.T, ctx context.Context, pool *pgxpool.Pool, xid string) {
	t.Helper()
	require.Eventually(t, func() bool {
		var waiting bool
		err := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='transactionid' AND transactionid::text=$1 AND NOT granted)`, xid).Scan(&waiting)
		return err == nil && waiting
	}, 5*time.Second, 10*time.Millisecond, "writer должен ждать именно TX владельца строки identity")
}

func TestSemanticAuthorityWriterRejectsInvalidBundleBeforeTransaction(t *testing.T) {
	repo := kanamepg.New(nil, nil)
	for _, b := range []*granteffect.Bundle{nil, {}} {
		w, err := repo.SemanticAuthorityWriter(context.Background(), authorityAccounts("acc-one"), b)
		require.ErrorIs(t, err, granteffect.ErrInvalidBundle)
		require.Nil(t, w)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	w, err := repo.SemanticAuthorityWriter(ctx, authorityAccounts("acc-one"), nil)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, w)
}

func TestSemanticAuthorityWriterDefaultsAndAllIdentityAxesDeny(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует PostgreSQL")
	}
	ctx, pool, repo := authorityTestDB(t)
	b := semanticBundleDB(t, ctx, pool)
	deny := func(t *testing.T) {
		t.Helper()
		w, err := repo.SemanticAuthorityWriter(ctx, authorityAccounts("acc-one"), b)
		require.ErrorIs(t, err, kaname.ErrSemanticIdentityUnavailable)
		require.Nil(t, w)
		authorityWaitReleased(t, pool)
	}
	deny(t)
	for _, tc := range []struct{ name, sql string }{
		{"transition", `UPDATE kaname.authority_semantic_identity SET phase='transition'`},
		{"protocol", `UPDATE kaname.authority_semantic_identity SET protocol_version=2`},
		{"model", `UPDATE kaname.authority_semantic_identity SET model_id=repeat('a',64)`},
		{"catalog", `UPDATE kaname.authority_semantic_identity SET catalog_id=repeat('b',64)`},
		{"projector", `UPDATE kaname.authority_semantic_identity SET projector_version='granteffect/v3'`},
		{"missing", `DELETE FROM kaname.authority_semantic_identity`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			semanticFixtureIdentity(t, ctx, pool, b)
			_, err := pool.Exec(ctx, tc.sql)
			require.NoError(t, err)
			deny(t)
		})
	}
	semanticFixtureIdentity(t, ctx, pool, b)
	for _, sql := range []string{
		`UPDATE kaname.authority_semantic_identity SET model_id=NULL`,
		`UPDATE kaname.authority_semantic_identity SET catalog_id=NULL`,
		`UPDATE kaname.authority_semantic_identity SET projector_version=''`,
		`INSERT INTO kaname.authority_semantic_identity(singleton) VALUES(false)`,
	} {
		_, err := pool.Exec(ctx, sql)
		require.Error(t, err, "schema должна отвергнуть неполную active identity")
	}
	w, err := repo.SemanticAuthorityWriter(ctx, authorityAccounts("acc-one"), b)
	require.NoError(t, err)
	require.Same(t, b, w.SemanticBundle())
	require.NotNil(t, w.SemanticRelationChecker())
	require.NoError(t, w.Rollback(ctx))
	authorityWaitReleased(t, pool)
}

func TestSemanticAuthorityWriterReadsIdentityAfterFenceWait(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует PostgreSQL")
	}
	ctx, pool, repo := authorityTestDB(t)
	b := semanticBundleDB(t, ctx, pool)
	semanticFixtureIdentity(t, ctx, pool, b)
	holder := authorityOpen(t, ctx, repo, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal})
	pending := semanticStart(t, ctx, repo, authorityAccounts("acc-one"), b)
	authorityWaitLock(t, ctx, pool)
	_, err := pool.Exec(ctx, `UPDATE kaname.authority_semantic_identity SET phase='transition'`)
	require.NoError(t, err)
	require.NoError(t, holder.Commit(ctx))
	result := pending.take(t)
	require.ErrorIs(t, result.err, kaname.ErrSemanticIdentityUnavailable)
	require.Nil(t, result.w)
	authorityWaitReleased(t, pool)
}

func TestSemanticAuthorityWriterIdentityWaitCancellationReleasesTransaction(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует PostgreSQL")
	}
	ctx, pool, repo := authorityTestDB(t)
	b := semanticBundleDB(t, ctx, pool)
	semanticFixtureIdentity(t, ctx, pool, b)
	holder, xid := semanticIdentityLock(t, ctx, pool)
	pending := semanticStart(t, ctx, repo, authorityAccounts("acc-one"), b)
	semanticWaitIdentity(t, ctx, pool, xid)
	pending.cancel()
	result := pending.take(t)
	require.Error(t, result.err)
	require.Nil(t, result.w)
	require.NoError(t, holder.Rollback(ctx))
	authorityWaitReleased(t, pool)
	next, err := repo.SemanticAuthorityWriter(ctx, authorityAccounts("acc-one"), b)
	require.NoError(t, err)
	require.NoError(t, next.Rollback(ctx))
	authorityWaitReleased(t, pool)
}

func TestSemanticAuthorityWriterPostIdentityWaitExpiryUsesOneTime(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует PostgreSQL")
	}
	ctx, pool, repo := authorityTestDB(t)
	uid := mustSeedUser(t, ctx, pool, "semantic-expiry")
	account := seedAccount(t, ctx, repo, "semantic-expiry-account", uid)
	// Служебный субъект не получает owner/admin от seed пользователя. Оба Allow
	// ниже обязаны прийти от носителя, срок которого затем пересечёт ожидание.
	_, err := pool.Exec(ctx, `INSERT INTO kaname.service_accounts(id,account_id,name) VALUES ('sva-semantic',$1,'semantic')`, account.ID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO kaname.roles(id,account_id,name,permissions,rules) VALUES ('rol-semantic',$1,'semantic','[]','[{"module":"iam","resources":["account"],"verbs":["get"]},{"module":"iam","resources":["accessBinding"],"verbs":["create"]}]')`, account.ID)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO kaname.role_verb(role_id,object_type,verb) VALUES ('rol-semantic','iam.account','get')`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO kaname.role_rule_selectors(role_id,rule_fp,arm,object_types,match_labels,verbs_by_type) VALUES ('rol-semantic','ordinary','anchor',ARRAY['iam.account'],'{}','{"iam.account":["get"]}')`)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO kaname.role_create_binding_rule(role_id,rule_fp) VALUES ('rol-semantic',$1)`, strings.Repeat("a", 64))
	require.NoError(t, err)
	// Отложенный access_bindings_carry_a_subject проверяет набор при COMMIT:
	// carrier и точная пара субъекта должны появиться в одной транзакции.
	fixtureTx, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		_ = fixtureTx.Rollback(cleanup)
	})
	_, err = fixtureTx.Exec(ctx, `INSERT INTO kaname.access_bindings(id,subject_type,subject_id,role_id,resource_type,resource_id,status,created_at,grant_capability_version) VALUES ('acb-semantic','service_account','sva-semantic','rol-semantic','account',$1,'ACTIVE','2000-01-01',1)`, account.ID)
	require.NoError(t, err)
	_, err = fixtureTx.Exec(ctx, `INSERT INTO kaname.access_binding_subjects(binding_id,subject_type,subject_id) VALUES ('acb-semantic','service_account','sva-semantic')`)
	require.NoError(t, err)
	require.NoError(t, fixtureTx.Commit(ctx))
	ref, err := grantcapability.Encode(grantcapability.Coordinate{Kind: domain.GrantCapabilityCreateBinding, Anchor: domain.ScopeAnchor{Type: "account", ID: string(account.ID)}})
	require.NoError(t, err)
	b := semanticBundleDB(t, ctx, pool)
	semanticFixtureIdentity(t, ctx, pool, b)
	plan := authorityAccounts(string(account.ID))
	check := func(w kaname.SemanticAuthorityWriter, want bool) {
		t.Helper()
		for _, q := range [][2]string{{"v_get", "account:" + string(account.ID)}, {ref.Relation, ref.ObjectType + ":" + ref.ObjectID}} {
			allowed, err := w.SemanticRelationChecker().Check(ctx, "service_account:sva-semantic", q[0], q[1])
			require.NoError(t, err)
			require.Equal(t, want, allowed, q[0])
		}
	}
	before, err := repo.SemanticAuthorityWriter(ctx, plan, b)
	require.NoError(t, err)
	check(before, true)
	require.NoError(t, before.Rollback(ctx))
	holder, xid := semanticIdentityLock(t, ctx, pool)
	pending := semanticStart(t, ctx, repo, plan, b)
	semanticWaitIdentity(t, ctx, pool, xid)
	var expiredAt time.Time
	require.NoError(t, holder.QueryRow(ctx, `UPDATE kaname.access_bindings SET expires_at=clock_timestamp() WHERE id='acb-semantic' RETURNING expires_at`).Scan(&expiredAt))
	require.NoError(t, holder.Commit(ctx))
	result := pending.take(t)
	require.NoError(t, result.err)
	w, ok := result.w.(kaname.SemanticAuthorityWriter)
	require.True(t, ok)
	require.True(t, w.AuthorityFence().DecisionAt().After(expiredAt), "время BEGIN и время до row wait уже устарели")
	check(w, false)
	require.NoError(t, w.Rollback(ctx))
	allowed, err := w.SemanticRelationChecker().Check(ctx, "service_account:sva-semantic", "v_get", "account:"+string(account.ID))
	require.Error(t, err)
	require.False(t, allowed, "закрытый writer не должен читать через pool")
	authorityWaitReleased(t, pool)
}

func TestSemanticIdentityDownRejectsConcurrentActivation(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует PostgreSQL")
	}
	ctx, pool, _ := authorityTestDB(t)
	raw, err := os.ReadFile("../../../migrations/20261113100000_authority_semantic_identity_starts_uninitialized.sql")
	require.NoError(t, err)
	parts := strings.SplitN(string(raw), "-- +goose Down", 2)
	require.Len(t, parts, 2)
	downSQL := parts[1]
	// Сначала положительный контроль настоящего Down на исходной схеме.
	down, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = down.Exec(ctx, downSQL)
	require.NoError(t, err)
	require.NoError(t, down.Rollback(ctx))
	b := semanticBundleDB(t, ctx, pool)
	activation, err := pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = activation.Rollback(cleanup)
	})
	id := b.Identity()
	_, err = activation.Exec(ctx, `UPDATE kaname.authority_semantic_identity SET phase='active',protocol_version=1,model_id=$1,catalog_id=$2,projector_version=$3`, id.ModelID, id.CatalogID, id.ProjectorVersion)
	require.NoError(t, err)
	down, err = pool.Begin(ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = down.Rollback(cleanup)
	})
	var pid int32
	require.NoError(t, down.QueryRow(ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	waitCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	result := make(chan error, 1)
	taken := false
	go func() { _, e := down.Exec(waitCtx, downSQL); result <- e }()
	// Даже при провале assertion снимаем ожидающий запрос до rollback его TX.
	defer func() {
		cancel()
		if taken {
			return
		}
		select {
		case <-result:
		case <-time.After(6 * time.Second):
			t.Error("Down не завершился после отмены")
		}
	}()
	require.Eventually(t, func() bool {
		var blocked bool
		e := pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE pid=$1 AND relation='kaname.authority_semantic_identity'::regclass AND mode='AccessExclusiveLock' AND NOT granted)`, pid).Scan(&blocked)
		return e == nil && blocked
	}, 5*time.Second, 10*time.Millisecond, "Down должен ждать реальный ACCESS EXCLUSIVE до проверки")
	require.NoError(t, activation.Commit(ctx))
	select {
	case e := <-result:
		taken = true
		require.ErrorContains(t, e, "semantic identity has left the uninitialized state")
	case <-time.After(6 * time.Second):
		t.Fatal("Down не дождался завершения activation fixture")
	}
	require.NoError(t, down.Rollback(ctx))
	var phase string
	require.NoError(t, pool.QueryRow(ctx, `SELECT phase FROM kaname.authority_semantic_identity`).Scan(&phase))
	require.Equal(t, "active", phase, "guard не должен удалить принятую identity")
	authorityWaitReleased(t, pool)
}
