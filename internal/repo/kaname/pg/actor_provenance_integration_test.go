// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/grantsource"
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
		require.NoError(t, uc.Register(ctx, request))
	}
	id := "provenance-public/team/app"
	registerPublicReadTarget(t, uc, pool, id)
	publish(t, uc, id, time.Time{})
	repo := kanamepg.New(pool, nil)
	bundle := semanticBundleDB(t, ctx, pool)
	semanticFixtureIdentity(t, ctx, pool, bundle)
	w, err := repo.SemanticAuthorityWriter(ctx, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}, bundle)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = w.Rollback(cleanup)
	})
	reader := w.(kaname.SemanticSourceReader)
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
	_, err = pool.Exec(ctx, `UPDATE kaname.producer_source_receipt SET source_version=$1 WHERE object_id='provenance-finite'`, base.Add(time.Hour))
	require.NoError(t, err)
	for _, s := range read(actor) {
		if s.Receipt.ObjectID == "provenance-finite" {
			require.Equal(t, "producer_version", s.Issue)
		}
	}
	_, err = pool.Exec(ctx, `UPDATE kaname.producer_source_receipt SET source_version=$1 WHERE object_id='provenance-finite'`, base)
	require.NoError(t, err)
	// Новый mirror watermark без замены projection сохраняет прежнего owner.
	require.NoError(t, uc.Register(ctx, &iamv1.RegisterResourceRequest{SubjectId: "project:" + scene.Project, Relation: "project", Object: "registry_registry:provenance-finite", ParentProjectId: scene.Project, ParentAccountId: scene.Account, ParentChain: scene.ProjectChain(), SourceVersion: timestamppb.New(base.Add(time.Minute))}))
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
	saActor := domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: actor.ID}
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
	standalone := seedSA(t, ctx, repo, domain.AccountID(scene.Account), "provenance-only-sa")
	absent(domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(standalone.ID)})
	deletedUser := mustSeedUser(t, ctx, pool, "provenance-deleted")
	_, err = pool.Exec(ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, deletedUser)
	require.NoError(t, err)
	deletedActor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(deletedUser)}
	_, err = reader.AdmitSourceActor(ctx, deletedActor)
	require.NoError(t, err)
	remove, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer remove.Rollback(context.Background())
	// Сначала собственный account, затем человек: действующий FK удаления.
	_, err = remove.Exec(ctx, `DELETE FROM kaname.accounts WHERE owner_user_id=$1`, deletedUser)
	require.NoError(t, err)
	_, err = remove.Exec(ctx, `DELETE FROM kaname.users WHERE id=$1`, deletedUser)
	require.NoError(t, err)
	require.NoError(t, remove.Commit(ctx))
	absent(deletedActor)
	got, err := grantsource.CollectSemanticActor(ctx, w, actor)
	require.NoError(t, err)
	require.Len(t, got.Producers, 3)
	require.False(t, got.Component.Complete())
	require.NoError(t, w.Rollback(ctx))
	// Применившийся withdrawal и его старый replay не оживляют publication.
	withdraw(t, uc, id, base.Add(time.Hour))
	publish(t, uc, id, time.Time{})
	next, err := repo.SemanticAuthorityWriter(ctx, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}, bundle)
	require.NoError(t, err)
	defer next.Rollback(ctx)
	page, _, err := next.(kaname.SemanticSourceReader).ProducerSources(ctx, kaname.CanonicalSourceFilter{Actor: actor, Limit: 256})
	require.NoError(t, err)
	for _, s := range page.Sources {
		require.NotEqual(t, domain.PublicationReceipt, s.Receipt.Kind)
	}
	// Текущая отметка человека, а не успешность предыдущего вопроса.
	_, err = pool.Exec(ctx, `UPDATE kaname.users SET email_verified_at=NULL WHERE id=$1`, uid)
	require.NoError(t, err)
	none, err := grantsource.CollectSemanticActor(ctx, next, actor)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	require.Equal(t, grantsource.ActorEffects{}, none)
}

func TestRoleProjectionCheckpointSameWriterRollbackAndRelevantCatalog(t *testing.T) {
	ctx, pool, repo := authorityTestDB(t)
	uid, account := kac127SeedUserAndAccount(t, ctx, pool, "provrole")
	bundle := semanticBundleDB(t, ctx, pool)
	semanticFixtureIdentity(t, ctx, pool, bundle)
	w, err := repo.SemanticAuthorityWriter(ctx, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}, bundle)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = w.Rollback(cleanup)
	})
	role := domain.Role{ID: domain.RoleID(ids.NewID(domain.PrefixRole)), AccountID: domain.AccountID(account), Name: "provenance_role", Rules: domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}}}, CreatedByUserID: domain.UserID(uid)}
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
	_, err = pool.Exec(ctx, `INSERT INTO kaname.catalog_module(module) VALUES('provenanceforeign')`)
	require.NoError(t, err)
	unchanged, _, err := reader.RoleProjectionCheckpoint(ctx, role.ID)
	require.NoError(t, err)
	require.Equal(t, checkpoint, unchanged)
	// Настоящая проекция на writer перестаёт совпадать с authored Rules.
	require.NoError(t, w.RolesW().ReplaceRoleVerbs(ctx, role.ID, nil))
	_, _, err = reader.RoleProjectionCheckpoint(ctx, role.ID)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	require.NoError(t, w.RolesW().ReplaceRoleVerbs(ctx, role.ID, projection.Verbs))
	// Relevant catalog изменён старым writer вне нового fence. Active identity
	// специально осталась прежней: одного совпадения её строки недостаточно.
	_, err = pool.Exec(ctx, `INSERT INTO kaname.catalog_verb(module,resource,verb,per_object) VALUES('iam','account','provenanceprobe',true)`)
	require.NoError(t, err)
	_, _, err = reader.RoleProjectionCheckpoint(ctx, role.ID)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	require.NoError(t, w.Rollback(ctx))
	authorityWaitReleased(t, pool)
	next, err := repo.SemanticAuthorityWriter(ctx, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}, bundle)
	require.NoError(t, err)
	defer next.Rollback(ctx)
	_, _, err = next.(kaname.SemanticSourceReader).RoleProjectionCheckpoint(ctx, role.ID)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
}

// Барьер стоит в настоящем pgx entrypoint второго SQL, а не в production hook.
// Preliminary SELECT уже завершён; concurrent writer коммитится до snapshot.
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

func TestRoleProjectionCheckpointConcurrentAuthoredMismatchChargesSnapshot(t *testing.T) {
	for _, large := range []bool{false, true} {
		name := "mismatch"
		if large {
			name = "mismatch-over-limit"
		}
		t.Run(name, func(t *testing.T) {
			parent, pool, repo := authorityTestDB(t)
			ctx, cancel := context.WithCancel(parent)
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
			config := pool.Config()
			config.ConnConfig.Tracer = barrier
			traced, err := pgxpool.NewWithConfig(ctx, config)
			require.NoError(t, err)
			defer traced.Close()
			w, err := kanamepg.New(traced, nil).SemanticAuthorityWriter(ctx, kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}, bundle)
			require.NoError(t, err)
			defer w.Rollback(context.Background())
			reader := w.(kaname.SemanticSourceReader)
			positive, baselineCost, err := reader.RoleProjectionCheckpoint(ctx, role.ID)
			require.NoError(t, err)
			require.Equal(t, projection.Checkpoint, positive)
			require.Greater(t, baselineCost.Rows, 2)
			if large {
				// Старый catalog writer обходит новый fence: snapshot уже прочёл
				// больше локального лимита даже при concurrent authored mismatch.
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
			// Настоящий legacy writer, разрешённый нынешней compare-only границей.
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
