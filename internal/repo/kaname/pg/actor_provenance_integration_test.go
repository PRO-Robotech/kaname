// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/grantsource"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationscene"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestProducerSourcesActualRegistrationPublicationVersionlessAndTypedActor(t *testing.T) {
	uc, pool := publicReadRig(t)
	ctx := context.Background()
	// kaname#1034: свежий каталог не разрешает owner без объявления модуля.
	// Применяем настоящий стендовый манифест, затем вызываем actual Register.
	var writes []string
	require.NoError(t, pool.QueryRow(ctx, `SELECT writes FROM kaname.catalog_resource WHERE dotted='registry.registries'`).Scan(&writes))
	require.NotContains(t, writes, "owner:user")
	body, err := os.ReadFile("../../../../tests/authz-fixtures/registry-own-stand-fixture.yaml")
	require.NoError(t, err)
	declaration, err := manifest.Load(body)
	require.NoError(t, err)
	_, err = applierOver(t, pool).Apply(ctx, declaration)
	require.NoError(t, err)
	require.NoError(t, pool.QueryRow(ctx, `SELECT writes FROM kaname.catalog_resource WHERE dotted='registry.registries'`).Scan(&writes))
	require.Contains(t, writes, "owner:user")
	scene := registrationscene.Seed(t, ctx, pool)
	var uid string
	require.NoError(t, pool.QueryRow(ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, scene.Account).Scan(&uid))
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}
	base := time.Now().Add(-time.Hour).UTC().Truncate(time.Microsecond)
	for i, id := range []string{"provenance-finite", "provenance-zero"} {
		request := &iamv1.RegisterResourceRequest{SubjectId: "user:" + uid, Relation: "owner", Object: "registry_registry:" + id, ParentProjectId: scene.Project, ParentAccountId: scene.Account, ParentChain: scene.ProjectChain()}
		if i == 0 {
			request.SourceVersion = timestamppb.New(base)
		}
		// kaname#1034: owner опирается на сохранённый project pointer.
		// Безверсионный pointer не опережает ни finite, ни versionless owner.
		require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{
			SubjectId: "project:" + scene.Project, Relation: "project", Object: request.Object,
			ParentProjectId: scene.Project, ParentAccountId: scene.Account, ParentChain: scene.ProjectChain(),
		}))
		require.NoError(t, uc.Register(ctx, request))
	}
	id := "provenance-public/team/app"
	registerPublicReadTarget(t, uc, pool, id)
	publish(t, uc, id, time.Time{})
	repo := kanamepg.New(pool, nil)
	bundle := semanticBundleDB(t, ctx, pool)
	semanticFixtureIdentity(t, ctx, pool, bundle)
	// Все typed principals объявлены до RR, включая заведомо отсутствующих.
	// Отсутствие не выдаёт authority: защищённое чтение проверяет реальные rows.
	saActor := domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: actor.ID}
	standalone := seedSA(t, ctx, repo, domain.AccountID(scene.Account), "provenance-only-sa")
	deletedUser := mustSeedUser(t, ctx, pool, "provenance-deleted")
	_, err = pool.Exec(ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, deletedUser)
	require.NoError(t, err)
	deletedActor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(deletedUser)}
	reads := []kaname.SemanticReadIntent{}
	for _, subject := range []domain.Subject{actor, saActor,
		{Type: domain.SubjectTypeUser, ID: "usr-provenance-absent"},
		{Type: domain.SubjectTypeServiceAccount, ID: "sva-provenance-absent"},
		{Type: domain.SubjectTypeUser, ID: domain.SubjectID(standalone.ID)}, deletedActor} {
		reads = append(reads, kaname.SemanticReadIntent{Actor: subject, Native: []kaname.SemanticNativeQuestion{{Relation: publicReadRelation, Object: publicReadObject(id)}}})
	}
	w, err := repo.PlannedSemanticPopulationWriter(ctx, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}, bundle, reads)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = w.Rollback(cleanup)
	})
	reader := w.(kaname.SemanticSourceReader)
	reopen := func() {
		w, err = repo.PlannedSemanticPopulationWriter(ctx, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}, bundle, reads)
		require.NoError(t, err)
		reader = w.(kaname.SemanticSourceReader)
	}

	read := func(actor domain.Subject) []kaname.ProducerSource {
		out := []kaname.ProducerSource{}
		token := ""
		pages := 0
		for {
			page, next, e := reader.ProducerSources(ctx, kaname.CanonicalSourceFilter{Actor: actor, After: token, Limit: 1})
			require.NoError(t, e)
			require.GreaterOrEqual(t, page.Cost.Rows, len(page.Sources))
			out = append(out, page.Sources...)
			pages++
			require.Less(t, pages, 20)
			if next == "" {
				break
			}
			token = next
		}
		require.Greater(t, pages, 1)
		return out
	}
	sources := read(actor)
	require.Len(t, sources, 3)
	for _, s := range sources {
		require.Empty(t, s.Issue)
		require.Equal(t, bundle.Identity(), s.Identity)
	}
	finite, zero, publication := false, false, false
	for _, s := range sources {
		switch s.Receipt.ObjectID {
		case "provenance-finite":
			finite = true
			require.False(t, s.Versionless)
		case "provenance-zero":
			zero = true
			require.True(t, s.Versionless)
		case id:
			publication = true
			require.Equal(t, domain.Subject{Type: domain.SubjectTypeSystemClass, ID: domain.ClassAnonymous}, s.Receipt.Subject)
			require.True(t, s.Versionless)
		}
	}
	require.True(t, finite && zero && publication)
	var stamped int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.producer_source_receipt WHERE model_identity IS NOT NULL OR catalog_identity IS NOT NULL OR projector_version IS NOT NULL`).Scan(&stamped))
	require.Zero(t, stamped)
	// Поддельно опережающая mirror квитанция не даёт эффекта. Это отрицательная
	// порча metadata, не положительный обход actual producer.
	require.NoError(t, w.Rollback(ctx))
	_, err = pool.Exec(ctx, `UPDATE kaname.producer_source_receipt SET source_version=$1 WHERE object_id='provenance-finite'`, base.Add(time.Hour))
	require.NoError(t, err)
	reopen()
	for _, s := range read(actor) {
		if s.Receipt.ObjectID == "provenance-finite" {
			require.Equal(t, "producer_version", s.Issue)
		}
	}
	require.NoError(t, w.Rollback(ctx))
	_, err = pool.Exec(ctx, `UPDATE kaname.producer_source_receipt SET source_version=$1 WHERE object_id='provenance-finite'`, base)
	require.NoError(t, err)
	// Новый mirror watermark без замены projection сохраняет прежнего owner.
	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{SubjectId: "project:" + scene.Project, Relation: "project", Object: "registry_registry:provenance-finite", ParentProjectId: scene.Project, ParentAccountId: scene.Account, ParentChain: scene.ProjectChain(), SourceVersion: timestamppb.New(base.Add(time.Minute))}))
	reopen()
	for _, s := range read(actor) {
		if s.Receipt.ObjectID == "provenance-finite" {
			require.Empty(t, s.Issue)
			require.True(t, s.Receipt.SourceVersion.Equal(base))
		}
	}
	// kaname#1034: ID другой категории не доказывает существование actor.
	absent := func(subject domain.Subject) {
		t.Helper()
		_, e := reader.AdmitSourceActor(ctx, subject)
		require.ErrorIs(t, e, kaname.ErrSourceUnconfirmed)
		page, token, e := reader.ProducerSources(ctx, kaname.CanonicalSourceFilter{Actor: subject, Limit: 1})
		require.ErrorIs(t, e, kaname.ErrSourceUnconfirmed)
		require.Equal(t, kaname.ProducerSourcePage{}, page)
		require.Empty(t, token)
		out, e := grantsource.CollectSemanticActor(ctx, w, subject)
		require.ErrorIs(t, e, kaname.ErrSourceUnconfirmed)
		require.Equal(t, grantsource.ActorEffects{}, out)
		allowed, e := w.SemanticRelationChecker().Check(ctx, string(subject.Type)+":"+string(subject.ID), publicReadRelation, publicReadObject(id))
		require.NoError(t, e)
		require.False(t, allowed)
	}
	absent(saActor)
	absent(domain.Subject{Type: domain.SubjectTypeUser, ID: "usr-provenance-absent"})
	absent(domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: "sva-provenance-absent"})
	// Положительная коллизия теперь содержит ОБЕ реальные строки, а не phantom SA.
	_, err = w.ServiceAccountsW().Insert(ctx, domain.ServiceAccount{ID: domain.ServiceAccountID(actor.ID), AccountID: domain.AccountID(scene.Account), Name: "provenance-collision", CreatedBy: actor})
	require.NoError(t, err)
	_, err = reader.AdmitSourceActor(ctx, saActor)
	require.NoError(t, err)
	sameID := read(saActor)
	require.Len(t, sameID, 1)
	require.Equal(t, domain.PublicationReceipt, sameID[0].Receipt.Kind)
	require.Empty(t, sameID[0].Issue)
	for _, subject := range []domain.Subject{actor, saActor} {
		allowed, e := w.SemanticRelationChecker().Check(ctx, string(subject.Type)+":"+string(subject.ID), publicReadRelation, publicReadObject(id))
		require.NoError(t, e)
		require.True(t, allowed)
	}
	// Удалённая учётка перестаёт наследовать anonymous в следующем снимке.
	require.NoError(t, w.ServiceAccountsW().Delete(ctx, domain.ServiceAccountID(actor.ID)))
	absent(saActor)
	absent(domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(standalone.ID)})
	_, err = reader.AdmitSourceActor(ctx, deletedActor)
	require.NoError(t, err)
	require.NoError(t, w.Rollback(ctx))
	remove, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer remove.Rollback(context.Background())
	// Сначала собственный account, затем человек: действующий FK удаления.
	_, err = remove.Exec(ctx, `DELETE FROM kaname.accounts WHERE owner_user_id=$1`, deletedUser)
	require.NoError(t, err)
	_, err = remove.Exec(ctx, `DELETE FROM kaname.users WHERE id=$1`, deletedUser)
	require.NoError(t, err)
	require.NoError(t, remove.Commit(ctx))
	reopen()
	absent(deletedActor)
	got, err := grantsource.CollectSemanticActor(ctx, w, actor)
	require.NoError(t, err)
	require.Len(t, got.Producers, 3)
	require.False(t, got.Component.Complete())
	require.NoError(t, w.Rollback(ctx))
	// Применившийся withdrawal и его старый replay не оживляют publication.
	withdraw(t, uc, id, base.Add(time.Hour))
	publish(t, uc, id, time.Time{})
	next, err := repo.PlannedSemanticPopulationWriter(ctx, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}, bundle, reads)
	require.NoError(t, err)
	defer next.Rollback(ctx)
	page, _, err := next.(kaname.SemanticSourceReader).ProducerSources(ctx, kaname.CanonicalSourceFilter{Actor: actor, Limit: 256})
	require.NoError(t, err)
	for _, s := range page.Sources {
		require.NotEqual(t, domain.PublicationReceipt, s.Receipt.Kind)
	}
	// Новая защищённая попытка читает изменённую отметку человека.
	require.NoError(t, next.Rollback(ctx))
	_, err = pool.Exec(ctx, `UPDATE kaname.users SET email_verified_at=NULL WHERE id=$1`, uid)
	require.NoError(t, err)
	next, err = repo.PlannedSemanticPopulationWriter(ctx, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}, bundle, reads)
	require.NoError(t, err)
	defer next.Rollback(ctx)
	none, err := grantsource.CollectSemanticActor(ctx, next, actor)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	require.Equal(t, grantsource.ActorEffects{}, none)
}

func TestRoleProjectionCheckpointSameWriterRollbackAndRelevantCatalog(t *testing.T) {
	ctx, pool, repo := authorityTestDB(t)
	uid, account := kac127SeedUserAndAccount(t, ctx, pool, "provrole")
	bundle := semanticBundleDB(t, ctx, pool)
	semanticFixtureIdentity(t, ctx, pool, bundle)
	role := domain.Role{ID: domain.RoleID(ids.NewID(domain.PrefixRole)), AccountID: domain.AccountID(account), Name: "provenance_role", Rules: domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}}}, CreatedByUserID: domain.UserID(uid)}
	readIntent := kaname.SemanticReadIntent{Actor: domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}, Roles: []domain.RoleID{role.ID}}
	w, err := repo.PlannedSemanticAuthorityWriter(ctx, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}, bundle, readIntent)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = w.Rollback(cleanup)
	})
	role.Permissions, err = domain.CompileRules(role.Rules)
	require.NoError(t, err)
	_, err = w.RolesW().Insert(ctx, role)
	require.NoError(t, err)
	projection, err := bundle.Projection(role)
	require.NoError(t, err)
	require.NoError(t, w.RolesW().ReplaceRoleVerbs(ctx, role.ID, projection.Verbs))
	require.NoError(t, w.RolesW().ReplaceRuleSelectors(ctx, role.ID, projection.Selectors))
	reader := w.(kaname.SemanticSourceReader)
	checkpoint, cost, err := reader.RoleProjectionCheckpoint(ctx, role.ID)
	require.NoError(t, err)
	require.Equal(t, projection.Checkpoint, checkpoint)
	require.Positive(t, cost.Rows)
	var count int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.roles WHERE id=$1`, role.ID).Scan(&count))
	require.Zero(t, count)
	// Защищённый SOURCE reader завершён до внешнего catalog writer. Следующая
	// попытка заново создаёт ту же незакоммиченную роль через настоящие adapters.
	require.NoError(t, w.Rollback(ctx))
	reopenRole := func() {
		w, err = repo.PlannedSemanticAuthorityWriter(ctx, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}, bundle, readIntent)
		require.NoError(t, err)
		_, err = w.RolesW().Insert(ctx, role)
		require.NoError(t, err)
		require.NoError(t, w.RolesW().ReplaceRoleVerbs(ctx, role.ID, projection.Verbs))
		require.NoError(t, w.RolesW().ReplaceRuleSelectors(ctx, role.ID, projection.Selectors))
		reader = w.(kaname.SemanticSourceReader)
	}
	_, err = pool.Exec(ctx, `INSERT INTO kaname.catalog_module(module) VALUES('provenanceforeign')`)
	require.NoError(t, err)
	reopenRole()
	unchanged, _, err := reader.RoleProjectionCheckpoint(ctx, role.ID)
	require.NoError(t, err)
	require.Equal(t, checkpoint, unchanged)
	// Настоящая проекция на writer перестаёт совпадать с authored Rules.
	require.NoError(t, w.RolesW().ReplaceRoleVerbs(ctx, role.ID, nil))
	_, _, err = reader.RoleProjectionCheckpoint(ctx, role.ID)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	require.NoError(t, w.RolesW().ReplaceRoleVerbs(ctx, role.ID, projection.Verbs))
	// Между защищёнными попытками изменён relevant catalog. Active identity
	// специально прежняя: одного совпадения её строки недостаточно.
	require.NoError(t, w.Rollback(ctx))
	_, err = pool.Exec(ctx, `INSERT INTO kaname.catalog_verb(module,resource,verb,per_object) VALUES('iam','account','provenanceprobe',true)`)
	require.NoError(t, err)
	reopenRole()
	_, _, err = reader.RoleProjectionCheckpoint(ctx, role.ID)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	require.NoError(t, w.Rollback(ctx))
	authorityWaitReleased(t, pool)
	next, err := repo.PlannedSemanticAuthorityWriter(ctx, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}, bundle, readIntent)
	require.NoError(t, err)
	defer next.Rollback(ctx)
	_, _, err = next.(kaname.SemanticSourceReader).RoleProjectionCheckpoint(ctx, role.ID)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
}

// Барьер SQL-компонента стоит перед вторым запросом через настоящий pgx.
// Здесь нет authority entry: первый SELECT завершён, writer коммитится до второго.
type projectionSnapshotBarrier struct {
	armed   atomic.Bool
	reached chan struct{}
	resume  chan struct{}
	once    sync.Once
}

func (b *projectionSnapshotBarrier) release() { b.once.Do(func() { close(b.resume) }) }
func (b *projectionSnapshotBarrier) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, "WITH module_rows AS") && strings.Contains(data.SQL, "selector_rows AS") && b.armed.CompareAndSwap(true, false) {
		close(b.reached)
		select {
		case <-b.resume:
		case <-ctx.Done():
		}
	}
	return ctx
}
func (*projectionSnapshotBarrier) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}

func TestRoleProjectionCheckpointSQLComponentConcurrentAuthoredMismatchChargesSnapshot(t *testing.T) {
	for _, large := range []bool{false, true} {
		name := "mismatch"
		if large {
			name = "mismatch-over-limit"
		}
		t.Run(name, func(t *testing.T) {
			rig := writerProtocolRig(t)
			parent, pool, repo := rig.ctx, rig.admin, kanamepg.New(rig.admin, nil)
			ctx, cancel := context.WithTimeout(parent, 15*time.Second)
			defer cancel()
			uid, account := kac127SeedUserAndAccount(t, ctx, pool, "provcost")
			bundle := semanticBundleDB(t, ctx, pool)
			semanticFixtureIdentity(t, ctx, pool, bundle)
			role := domain.Role{ID: domain.RoleID(ids.NewID(domain.PrefixRole)), AccountID: domain.AccountID(account), Name: "provenance_cost", Rules: domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}}}, CreatedByUserID: domain.UserID(uid)}
			var err error
			role.Permissions, err = domain.CompileRules(role.Rules)
			require.NoError(t, err)
			projection, err := bundle.Projection(role)
			require.NoError(t, err)
			seed, err := repo.Writer(ctx)
			require.NoError(t, err)
			defer seed.Rollback(context.Background())
			_, err = seed.RolesW().Insert(ctx, role)
			require.NoError(t, err)
			require.NoError(t, seed.RolesW().ReplaceRuleSelectors(ctx, role.ID, projection.Selectors))
			require.NoError(t, seed.RolesW().ReplaceRoleVerbs(ctx, role.ID, projection.Verbs))
			require.NoError(t, seed.Commit(ctx))
			barrier := &projectionSnapshotBarrier{reached: make(chan struct{}), resume: make(chan struct{})}
			config := rig.runtime.Config()
			config.ConnConfig.Tracer = barrier
			traced, err := pgxpool.NewWithConfig(ctx, config)
			require.NoError(t, err)
			defer traced.Close()
			var effective, session string
			require.NoError(t, traced.QueryRow(ctx, `SELECT current_user,session_user`).Scan(&effective, &session))
			require.Equal(t, rig.role, effective)
			require.Equal(t, rig.role, session)
			w, err := kanamepg.OpenUnprotectedProjectionComponentProbe(ctx, kanamepg.New(traced, nil), bundle)
			require.NoError(t, err)
			defer func() {
				cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
				defer stop()
				_ = w.Rollback(cleanup)
			}()
			reader := w
			positive, baselineCost, err := reader.RoleProjectionCheckpoint(ctx, role.ID)
			require.NoError(t, err)
			require.Equal(t, projection.Checkpoint, positive)
			require.Greater(t, baselineCost.Rows, 2)
			require.LessOrEqual(t, baselineCost.Rows, 4096)
			require.Equal(t, 2, baselineCost.Reads)
			if large {
				// SQL-компонент работает без GLOBAL: snapshot обязан списать
				// превышение бюджета раньше проверки concurrent authored mismatch.
				_, err = pool.Exec(ctx, `INSERT INTO kaname.catalog_verb(module,resource,verb,per_object) SELECT 'iam','account','provenancecost'||n,true FROM generate_series(1,4097) n`)
				require.NoError(t, err)
			}
			type answer struct {
				checkpoint granteffect.ProjectionCheckpoint
				cost       kaname.SourceReadCost
				err        error
			}
			result := make(chan answer, 1)
			finished := make(chan struct{})
			barrier.armed.Store(true)
			go func() {
				defer close(finished)
				checkpoint, cost, e := reader.RoleProjectionCheckpoint(ctx, role.ID)
				result <- answer{checkpoint, cost, e}
			}()
			defer func() {
				cancel()
				barrier.release()
				<-finished
			}()
			select {
			case <-barrier.reached:
			case <-ctx.Done():
				t.Fatal("snapshot не достиг pgx барьера: ", ctx.Err())
			}
			// Настоящий legacy writer в SQL component probe без protected SOURCE plan.
			role.Rules[0].Verbs = []string{"list"}
			role.Permissions, err = domain.CompileRules(role.Rules)
			require.NoError(t, err)
			changed, err := bundle.Projection(role)
			require.NoError(t, err)
			require.NotEqual(t, positive.AuthoredID, changed.Checkpoint.AuthoredID)
			legacy, err := repo.Writer(ctx)
			require.NoError(t, err)
			defer legacy.Rollback(context.Background())
			_, err = legacy.RolesW().Update(ctx, role, []string{"rules"})
			require.NoError(t, err)
			require.NoError(t, legacy.Commit(ctx))
			barrier.release()
			select {
			case got := <-result:
				require.Equal(t, granteffect.ProjectionCheckpoint{}, got.checkpoint)
				require.Equal(t, 2, got.cost.Reads)
				if large {
					require.ErrorIs(t, got.err, kaname.ErrSourceReadLimit)
					require.Greater(t, got.cost.Rows, 4096)
				} else {
					require.ErrorIs(t, got.err, kaname.ErrSourceUnconfirmed)
					require.Equal(t, baselineCost.Rows, got.cost.Rows, "mismatch не отменяет уже прочитанный snapshot")
				}
			case <-ctx.Done():
				t.Fatal("snapshot не завершился: ", ctx.Err())
			}
		})
	}
}

// Трассировка наблюдает реальные BEGIN/ROLLBACK и задерживает первый RC entry
// до получения GLOBAL. Изменение после этой границы под GLOBAL запрещено.
type provenanceCompareTraceKey struct{}
type provenanceCompareBoundary struct {
	reached     chan struct{}
	resume      chan struct{}
	releaseOnce sync.Once
	pauseOnce   sync.Once
	rr          atomic.Int32
	rrClosed    atomic.Int32
	rc          atomic.Int32
	entries     atomic.Int32
	rrPID       atomic.Uint32
	rcPID       atomic.Uint32
	phase       string
}

func (b *provenanceCompareBoundary) release() { b.releaseOnce.Do(func() { close(b.resume) }) }
func (b *provenanceCompareBoundary) TraceQueryStart(ctx context.Context, conn *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	if strings.Contains(data.SQL, "FROM kaname.authority_compare_full_v2(") {
		b.entries.Add(1)
		b.rcPID.Store(conn.PgConn().PID())
		b.pauseOnce.Do(func() {
			close(b.reached)
			select {
			case <-b.resume:
			case <-ctx.Done():
			}
		})
	}
	if strings.HasPrefix(data.SQL, "begin") && strings.Contains(data.SQL, "repeatable read") {
		b.rrPID.Store(conn.PgConn().PID())
	}
	return context.WithValue(ctx, provenanceCompareTraceKey{}, data.SQL)
}
func (b *provenanceCompareBoundary) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	if data.Err != nil {
		return
	}
	sql, _ := ctx.Value(provenanceCompareTraceKey{}).(string)
	switch {
	case strings.HasPrefix(sql, "begin") && strings.Contains(sql, "repeatable read"):
		b.phase = "rr"
		b.rr.Add(1)
	case strings.HasPrefix(sql, "begin") && strings.Contains(sql, "read committed"):
		b.phase = "rc"
		b.rc.Add(1)
	case sql == "rollback":
		if b.phase == "rr" {
			b.rrClosed.Add(1)
		}
		b.phase = ""
	}
}

func TestRoleProjectionCheckpointPlannedCompareRestagesBeforeGlobal(t *testing.T) {
	for _, change := range []string{"unchanged", "authored", "relevant-catalog"} {
		t.Run(change, func(t *testing.T) {
			r, owner := writerProtocolRigBeforePreparation(t)
			ctx, cancel := context.WithTimeout(r.ctx, 15*time.Second)
			defer cancel()
			uid, account := kac127SeedUserAndAccount(t, ctx, r.admin, "provstage")
			role := domain.Role{ID: domain.RoleID(ids.NewID(domain.PrefixRole)), AccountID: domain.AccountID(account), Name: "provenance_stage", Rules: domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}}}, CreatedByUserID: domain.UserID(uid)}
			var err error
			role.Permissions, err = domain.CompileRules(role.Rules)
			require.NoError(t, err)
			projection, err := r.bundle.Projection(role)
			require.NoError(t, err)
			seed, err := kanamepg.New(r.admin, nil).Writer(ctx)
			require.NoError(t, err)
			defer seed.Rollback(context.Background())
			_, err = seed.RolesW().Insert(ctx, role)
			require.NoError(t, err)
			require.NoError(t, seed.RolesW().ReplaceRuleSelectors(ctx, role.ID, projection.Selectors))
			require.NoError(t, seed.RolesW().ReplaceRoleVerbs(ctx, role.ID, projection.Verbs))
			require.NoError(t, seed.Commit(ctx))
			// Полный посев предшествует handoff. Compare-only SQL допускает
			// active identity, а Prepare является только Stage, не активацией.
			require.NoError(t, owner.PrepareAuthorityBundle(ctx, r.bundle))
			require.NoError(t, owner.ActivateAuthorityBundle(ctx, r.bundle))
			var phase, enforcement string
			var identityVersion, protocolVersion int
			installed := r.bundle.Identity()
			require.NoError(t, r.admin.QueryRow(ctx, `SELECT a.phase,a.protocol_version,p.protocol_version,p.enforcement,
                a.model_id,a.catalog_id,a.projector_version
                FROM kaname.authority_semantic_identity a CROSS JOIN kaname.authority_writer_protocol p
                WHERE a.singleton AND p.singleton`).Scan(&phase, &identityVersion, &protocolVersion, &enforcement,
				&installed.ModelID, &installed.CatalogID, &installed.ProjectorVersion))
			require.Equal(t, "active", phase)
			require.Equal(t, 1, identityVersion)
			require.Equal(t, 1, protocolVersion)
			require.Equal(t, "strict", enforcement)
			require.Equal(t, r.bundle.Identity(), installed)
			want := projection.Checkpoint
			actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}
			intent := kaname.SemanticReadIntent{Actor: actor, Roles: []domain.RoleID{role.ID}}
			barrier := &provenanceCompareBoundary{reached: make(chan struct{}), resume: make(chan struct{})}
			cfg := r.runtime.Config()
			cfg.MaxConns, cfg.MinConns = 1, 0
			cfg.ConnConfig.Tracer = barrier
			pool, err := pgxpool.NewWithConfig(ctx, cfg)
			require.NoError(t, err)
			defer pool.Close()
			type result struct {
				writer kaname.SemanticAuthorityWriter
				err    error
			}
			done := make(chan result, 1)
			finished := make(chan struct{})
			go func() {
				defer close(finished)
				w, e := kanamepg.New(pool, nil).PlannedSemanticAuthorityWriter(ctx, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}, r.bundle, intent)
				done <- result{w, e}
			}()
			// Даже fatal assertion освобождает паузу, TX и единственный lease.
			var opened kaname.SemanticAuthorityWriter
			defer func() {
				cancel()
				barrier.release()
				<-finished
				if opened == nil {
					select {
					case out := <-done:
						opened = out.writer
					default:
					}
				}
				if opened != nil {
					cleanup, stop := context.WithTimeout(context.Background(), 5*time.Second)
					defer stop()
					_ = opened.Rollback(cleanup)
				}
			}()
			select {
			case <-barrier.reached:
			case <-ctx.Done():
				t.Fatal("нет границы RR→RC: ", ctx.Err())
			}
			require.Equal(t, int32(1), barrier.rr.Load())
			require.Equal(t, int32(1), barrier.rrClosed.Load(), "RR завершён до entry")
			require.Equal(t, int32(1), barrier.rc.Load())
			require.Equal(t, barrier.rrPID.Load(), barrier.rcPID.Load(), "RR и RC используют один backend")
			require.Equal(t, int32(1), pool.Stat().AcquiredConns())
			switch change {
			case "authored":
				role.Rules[0].Verbs = []string{"list"}
				role.Permissions, err = domain.CompileRules(role.Rules)
				require.NoError(t, err)
				changed, e := r.bundle.Projection(role)
				require.NoError(t, e)
				want = changed.Checkpoint
				require.NotEqual(t, projection.Checkpoint.AuthoredID, want.AuthoredID)
				// После активации изменение SOURCE входит существующим typed installation port.
				writer, e := owner.InstallationAuthorityWriter(ctx, kaname.AuthorityRole)
				require.NoError(t, e)
				defer writer.Rollback(context.Background())
				_, e = writer.RolesW().Update(ctx, role, []string{"rules"})
				require.NoError(t, e)
				require.NoError(t, writer.RolesW().ReplaceRuleSelectors(ctx, role.ID, changed.Selectors))
				require.NoError(t, writer.RolesW().ReplaceRoleVerbs(ctx, role.ID, changed.Verbs))
				require.NoError(t, writer.Commit(ctx))
			case "relevant-catalog":
				// Тот же relevant verb коммитится настоящим catalog installation writer.
				// Commit закрывает прежнюю identity; старый bundle не реактивируем.
				err = kanamepg.NewCatalogWriteRepo(r.admin).RunInWriteTx(ctx, func(ctx context.Context, writer modulecatalog.CatalogWriter) error {
					changed, e := writer.UpsertVerb(ctx, catalog.VerbRow{Module: "iam", Resource: "account", Verb: "provenancestage", PerObject: true})
					require.NoError(t, e)
					require.True(t, changed)
					return e
				})
				require.NoError(t, err)
			}
			barrier.release()
			select {
			case out := <-done:
				opened = out.writer
				if change == "relevant-catalog" {
					// Active Given исключает отказ из-за исходного prepared state:
					// здесь старую identity закрыл именно новый catalog commit.
					require.ErrorIs(t, out.err, kaname.ErrSemanticIdentityUnavailable)
					require.Nil(t, opened)
					require.Equal(t, int32(1), barrier.rr.Load())
					require.Equal(t, int32(1), barrier.rrClosed.Load())
					require.Equal(t, int32(1), barrier.rc.Load())
					require.Equal(t, int32(1), barrier.entries.Load())
					require.Equal(t, barrier.rrPID.Load(), barrier.rcPID.Load())
					require.Zero(t, pool.Stat().AcquiredConns())
					return
				}
				require.NoError(t, out.err)
				require.NotNil(t, opened)
			case <-ctx.Done():
				t.Fatal("planned compare не завершился: ", ctx.Err())
			}
			attempts := int32(2)
			if change == "unchanged" {
				attempts = 1
			}
			require.Equal(t, attempts, barrier.rr.Load(), "изменённый stage должен быть перечитан целиком")
			require.Equal(t, attempts, barrier.rrClosed.Load())
			require.Equal(t, attempts, barrier.rc.Load())
			require.Equal(t, attempts, barrier.entries.Load())
			require.Equal(t, barrier.rrPID.Load(), barrier.rcPID.Load())
			checkpoint, cost, err := opened.(kaname.SemanticSourceReader).RoleProjectionCheckpoint(ctx, role.ID)
			require.Equal(t, 2, cost.Reads)
			require.Positive(t, cost.Rows)
			require.NoError(t, err)
			require.Equal(t, want, checkpoint)
			// Role checkpoint не превращает незаявленный native вопрос в allow.
			allowed, err := opened.SemanticRelationChecker().Check(ctx, "user:"+uid, "admin", "account:"+account)
			require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
			require.False(t, allowed)
			require.NoError(t, opened.Rollback(ctx))
			require.Zero(t, pool.Stat().AcquiredConns())
		})
	}
}
