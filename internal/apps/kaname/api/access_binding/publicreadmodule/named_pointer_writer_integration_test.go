// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicreadmodule_test

import (
	"context"
	"errors"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/jackc/pgx/v5"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationwriterfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

func namedRequest(w *p2, id string) *iamv1.RegisterResourceRequest {
	return &iamv1.RegisterResourceRequest{SubjectId: pmBoxType + ":" + pmB1, Relation: "box", Object: pmItemType + ":" + id,
		ParentProjectId: w.prjA, ParentAccountId: w.accA, ParentChain: []string{pmBoxType + ":" + pmB1, "project:" + w.prjA, "account:" + w.accA}}
}

func namedSnapshot(t *testing.T, w *p2) string {
	t.Helper()
	var snapshot string
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.resource_mirror x),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.resource_parent_edge x),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.resource_registration_pointer x),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.resource_registration_scope x),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.relation_fact x),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.fga_outbox x),
 (SELECT jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text) FROM kaname.resource_reconcile_outbox x))::text`).Scan(&snapshot))
	return snapshot
}

type namedAuthority struct {
	module   string
	denied   string
	accounts []string
}

func (a *namedAuthority) Authorize(context.Context) (string, error) { return a.module, nil }
func (a *namedAuthority) AuthorizeCatalogModule(context.Context) (string, error) {
	return a.module, nil
}
func (a *namedAuthority) AuthorizeAccount(_ context.Context, id string) error {
	a.accounts = append(a.accounts, id)
	if id == a.denied {
		return errors.New("account authority refused")
	}
	return nil
}

func TestNamedPointer_ExactCatalogAndAuthorityBeforeWrites(t *testing.T) {
	for _, name := range []string{"valid", "unknown-relation", "wrong-subject-type", "unknown-container", "foreign-module", "missing-account-authority", "direct-account", "root-object", "iam-object", "wrong-project-claim"} {
		t.Run(name, func(t *testing.T) {
			w := newP2(t)
			req := namedRequest(w, "named-admission")
			authority := &namedAuthority{module: "probemod"}
			w.reg.WithRegistrationAuthority(authority)
			switch name {
			case "unknown-relation":
				req.Relation = "other_box"
			case "wrong-subject-type":
				req.SubjectId = "project:" + w.prjA
			case "unknown-container":
				req.SubjectId = pmBoxType + ":missing"
			case "foreign-module":
				authority.module = "registry"
			case "missing-account-authority":
				authority.denied = w.accA
			case "direct-account":
				req.SubjectId = "account:" + w.accA
			case "root-object":
				req.Object = "cluster:cluster_root"
			case "iam-object":
				req.Object = "iam_role:role"
			case "wrong-project-claim":
				req.ParentProjectId = "other-project"
			}
			before := namedSnapshot(t, w)
			err := w.reg.Register(w.ctx, req)
			if name == "valid" {
				require.NoError(t, err)
				require.Equal(t, []string{w.accA}, authority.accounts)
				var claims int
				require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.resource_registration_pointer WHERE module='probemod' AND object_type=$1 AND object_id='named-admission' AND relation='box' AND subject=$2 AND active`, pmItemType, req.SubjectId).Scan(&claims))
				require.Equal(t, 1, claims)
			} else {
				require.Error(t, err)
				require.Equal(t, before, namedSnapshot(t, w), "отказ не оставляет зеркало, claim, факт или журнал")
			}
		})
	}
}

// Политика сужается настоящей доставкой следующей редакции манифеста.
func namedShrink(t *testing.T, w *p2, retire bool) {
	t.Helper()
	doc, err := publicreadfixture.Read(publicreadfixture.ProbemodFile)
	require.NoError(t, err)
	doc, err = publicreadfixture.WithRevision(doc, 2)
	require.NoError(t, err)
	if retire {
		text := string(doc)
		at := strings.Index(text, "  - name: items")
		require.Positive(t, at)
		doc = []byte(strings.ReplaceAll(text[:at], "    publicReadToChildren: true\n", ""))
	} else {
		doc = []byte(strings.Replace(string(doc), "{name: box, type: probemod_box}", "{name: holder, type: probemod_box}", 1))
	}
	m, err := manifest.Load(doc)
	require.NoError(t, err)
	_, err = modulecatalog.NewApplier(kanamepg.NewCatalogWriteRepo(w.pool)).ApplyAll(w.ctx, []*manifest.Manifest{m})
	require.NoError(t, err)
}

func namedCount(t *testing.T, w *p2, id string) int {
	t.Helper()
	var n int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.relation_fact WHERE object_type=$1 AND object_id=$2 AND relation='box'`, pmItemType, id).Scan(&n))
	return n
}

func TestNamedPointer_ShrinkAndRetirementCleanupAndDescendants(t *testing.T) {
	for _, retire := range []bool{false, true} {
		for _, descendants := range []bool{false, true} {
			t.Run(map[bool]string{false: "shrink", true: "retire"}[retire]+"/"+map[bool]string{false: "direct", true: "descendants"}[descendants], func(t *testing.T) {
				w := newP2(t)
				require.Equal(t, 1, namedCount(t, w, pmI1))
				namedShrink(t, w, retire)
				if descendants {
					require.NoError(t, w.reg.Unregister(w.ctx, &iamv1.UnregisterResourceRequest{SubjectId: "project:" + w.prjA, Relation: "project", Object: pmBoxType + ":" + pmB1}))
					require.Zero(t, namedCount(t, w, pmI1))
					require.Equal(t, 1, namedCount(t, w, pmI3), "чужая ветвь остаётся")
				} else {
					request := &iamv1.UnregisterResourceRequest{SubjectId: pmBoxType + ":" + pmB1, Relation: "box", Object: pmItemType + ":" + pmI1}
					require.NoError(t, w.reg.Unregister(w.ctx, request))
					require.NoError(t, w.reg.Unregister(w.ctx, request), "повтор не требует нынешней policy")
					require.Zero(t, namedCount(t, w, pmI1))
				}
			})
		}
	}
}

func TestNamedPointer_MissingProvenanceCannotUseCurrentPolicy(t *testing.T) {
	w := newP2(t)
	for _, request := range []*iamv1.UnregisterResourceRequest{
		{SubjectId: pmBoxType + ":" + pmB2, Relation: "box", Object: pmItemType + ":" + pmI1},
		{SubjectId: pmBoxType + ":" + pmB1, Relation: "other_box", Object: pmItemType + ":" + pmI1},
	} {
		before := namedSnapshot(t, w)
		require.Error(t, w.reg.Unregister(w.ctx, request))
		require.Equal(t, before, namedSnapshot(t, w))
	}
	// Совпадение живой policy и независимого факта без записи registrar не является владением.
	tx, err := w.pool.Begin(w.ctx)
	require.NoError(t, err)
	require.NoError(t, kanamepg.NewFGAOutboxEmitter().EmitOrderedWriteTx(w.ctx, tx, []service.RelationTuple{{User: pmBoxType + ":" + pmB2, Relation: "box", Object: pmItemType + ":" + pmI1}}, time.Now()))
	require.NoError(t, tx.Commit(w.ctx))
	before := namedSnapshot(t, w)
	require.Error(t, w.reg.Unregister(w.ctx, &iamv1.UnregisterResourceRequest{SubjectId: pmBoxType + ":" + pmB2, Relation: "box", Object: pmItemType + ":" + pmI1}))
	require.Equal(t, before, namedSnapshot(t, w))
}

func TestNamedPointer_VersionFenceAndReregistration(t *testing.T) {
	w := newP2(t)
	req := namedRequest(w, "versioned-named")
	v := time.Now().Add(-time.Hour)
	req.SourceVersion = timestamppb.New(v)
	require.NoError(t, w.reg.Register(w.ctx, req))
	withdrawal := &iamv1.UnregisterResourceRequest{SubjectId: req.SubjectId, Relation: req.Relation, Object: req.Object, SourceVersion: timestamppb.New(v.Add(time.Minute))}
	require.NoError(t, w.reg.Unregister(w.ctx, withdrawal))
	for _, delta := range []time.Duration{0, time.Minute} {
		req.SourceVersion = timestamppb.New(v.Add(delta))
		before := namedSnapshot(t, w)
		require.Error(t, w.reg.Register(w.ctx, req))
		require.Equal(t, before, namedSnapshot(t, w))
	}
	req.SourceVersion = timestamppb.New(v.Add(2 * time.Minute))
	require.NoError(t, w.reg.Register(w.ctx, req))
	require.NoError(t, w.reg.Unregister(w.ctx, withdrawal), "старое надгробие не снимает новую регистрацию")
	require.Equal(t, 1, namedCount(t, w, "versioned-named"))
	w.reg.WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "registry"})
	require.Error(t, w.reg.Unregister(w.ctx, withdrawal))
}

// Держатель выдачи независим от регистрации: его жизненный цикл создан обычным
// писателем выдач, а точный ledger tuple задан как предпосылка теста свёртки.
func namedIndependentHolder(t *testing.T, w *p2, tuple service.RelationTuple) domain.AccessBindingID {
	t.Helper()
	id := w.grantAnonOnB1(w.role("named_independent", rulesBoxOnly()))
	_, err := w.pool.Exec(w.ctx, `INSERT INTO kaname.access_binding_emitted_tuples(binding_id,fga_user,relation,object,source) VALUES($1,$2,$3,$4,'binding')`, id, tuple.User, tuple.Relation, tuple.Object)
	require.NoError(t, err)
	return id
}

func namedBindingWithdraw(ctx context.Context, tx pgx.Tx, id domain.AccessBindingID, tuple service.RelationTuple) error {
	if _, err := tx.Exec(ctx, `DELETE FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND fga_user=$2 AND relation=$3 AND object=$4`, id, tuple.User, tuple.Relation, tuple.Object); err != nil {
		return err
	}
	return kanamepg.NewFGAOutboxEmitter().EmitDeleteTx(ctx, tx, []service.RelationTuple{tuple})
}

func TestNamedPointer_IndependentHoldersBothWithdrawalOrders(t *testing.T) {
	for _, ownerFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "binding-first", true: "registration-first"}[ownerFirst], func(t *testing.T) {
			w := newP2(t)
			req := namedRequest(w, "independently-held")
			v := time.Now().Add(-time.Hour)
			req.SourceVersion = timestamppb.New(v)
			require.NoError(t, w.reg.Register(w.ctx, req))
			tuple := service.RelationTuple{User: req.SubjectId, Relation: req.Relation, Object: req.Object}
			id := namedIndependentHolder(t, w, tuple)
			// Метка AB новее версии владельца: последний holder всё равно обязан уйти.
			tx, err := w.pool.Begin(w.ctx)
			require.NoError(t, err)
			require.NoError(t, kanamepg.NewFGAOutboxEmitter().EmitWriteTx(w.ctx, tx, []service.RelationTuple{tuple}))
			require.NoError(t, tx.Commit(w.ctx))
			withdrawOwner := func() {
				require.NoError(t, w.reg.Unregister(w.ctx, &iamv1.UnregisterResourceRequest{SubjectId: req.SubjectId, Relation: req.Relation, Object: req.Object, SourceVersion: timestamppb.New(v.Add(time.Minute))}))
			}
			withdrawBinding := func() {
				tx, err := w.pool.Begin(w.ctx)
				require.NoError(t, err)
				defer func() { _ = tx.Rollback(w.ctx) }()
				require.NoError(t, namedBindingWithdraw(w.ctx, tx, id, tuple))
				require.NoError(t, tx.Commit(w.ctx))
			}
			if ownerFirst {
				withdrawOwner()
			} else {
				withdrawBinding()
			}
			require.Equal(t, 1, namedCount(t, w, "independently-held"), "первое снятие не отнимает чужой факт")
			if ownerFirst {
				withdrawBinding()
			} else {
				withdrawOwner()
			}
			require.Zero(t, namedCount(t, w, "independently-held"), "последний holder снимает факт, несмотря на разные шкалы AB/owner")
		})
	}
}

func TestNamedPointer_ClaimAndJournalUseCallerRollback(t *testing.T) {
	w := newP2(t)
	store := kanamepg.NewRegistrationScopeReader()
	emitter := kanamepg.NewFGAOutboxEmitter()
	tuple := service.RelationTuple{User: pmBoxType + ":" + pmB1, Relation: "box", Object: pmItemType + ":rollback-claim"}
	before := namedSnapshot(t, w)
	tx, err := w.pool.Begin(w.ctx)
	require.NoError(t, err)
	applied, err := store.SaveRegistrationPointerTx(w.ctx, tx, "probemod", tuple, time.Now())
	require.NoError(t, err)
	require.True(t, applied)
	require.NoError(t, emitter.EmitOrderedWriteTx(w.ctx, tx, []service.RelationTuple{tuple}, time.Now()))
	_, err = tx.Exec(w.ctx, `SELECT 1/0`)
	require.Error(t, err, "сбой следующего оператора откатывает claim и journal вместе")
	require.NoError(t, tx.Rollback(w.ctx))
	require.Equal(t, before, namedSnapshot(t, w))
	tuple.Object = pmItemType + ":" + pmI1
	before = namedSnapshot(t, w)
	tx, err = w.pool.Begin(w.ctx)
	require.NoError(t, err)
	require.NoError(t, store.RetireRegistrationPointersTx(w.ctx, tx, "probemod", tuple.Object, time.Now()))
	require.NoError(t, emitter.EmitOrderedDeleteTx(w.ctx, tx, []service.RelationTuple{tuple}, time.Now()))
	require.NoError(t, tx.Rollback(w.ctx))
	require.Equal(t, before, namedSnapshot(t, w), "rollback снятия восстанавливает holder и факт")
}

// Порядок очереди доказан pg_stat_activity, а не задержкой по часам.
func namedWaitForFactWaiters(t *testing.T, w *p2, want int) {
	t.Helper()
	require.Eventually(t, func() bool {
		var n int
		err := w.pool.QueryRow(w.ctx, `SELECT count(*) FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock'`).Scan(&n)
		return err == nil && n >= want
	}, 10*time.Second, 10*time.Millisecond)
}

func TestNamedPointer_ConcurrentGrantAndWithdrawalFreshHolderSnapshot(t *testing.T) {
	for _, registrarGrant := range []bool{false, true} {
		for _, grantFirst := range []bool{false, true} {
			t.Run(map[bool]string{false: "binding-grant", true: "registration-grant"}[registrarGrant]+"/"+map[bool]string{false: "withdraw-first", true: "grant-first"}[grantFirst], func(t *testing.T) {
				w := newP2(t)
				tuple := service.RelationTuple{User: pmBoxType + ":" + pmB1, Relation: "box", Object: pmItemType + ":" + pmI1}
				id := namedIndependentHolder(t, w, tuple)
				ctx, cancel := context.WithTimeout(w.ctx, 30*time.Second)
				defer cancel()
				store := kanamepg.NewRegistrationScopeReader()
				emitter := kanamepg.NewFGAOutboxEmitter()
				// Начальный holder противоположен вновь выдаваемому, факт уже существует.
				if registrarGrant {
					tx, err := w.pool.Begin(ctx)
					require.NoError(t, err)
					require.NoError(t, store.RetireRegistrationPointersTx(ctx, tx, "probemod", tuple.Object, time.Time{}))
					require.NoError(t, tx.Commit(ctx))
				} else {
					_, err := w.pool.Exec(ctx, `DELETE FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND relation='box'`, id)
					require.NoError(t, err)
				}
				holder, err := w.pool.Begin(ctx)
				require.NoError(t, err)
				defer func() { _ = holder.Rollback(context.Background()) }()
				var locked string
				require.NoError(t, holder.QueryRow(ctx, `SELECT subject FROM kaname.relation_fact WHERE object_type=$1 AND object_id=$2 AND relation='box' FOR UPDATE`, pmItemType, pmI1).Scan(&locked))
				run := func(grant bool) <-chan error {
					done := make(chan error, 1)
					go func() {
						tx, err := w.pool.Begin(ctx)
						if err != nil {
							done <- err
							return
						}
						defer func() { _ = tx.Rollback(context.Background()) }()
						if grant {
							if registrarGrant {
								_, err = store.SaveRegistrationPointerTx(ctx, tx, "probemod", tuple, time.Time{})
							} else {
								_, err = tx.Exec(ctx, `INSERT INTO kaname.access_binding_emitted_tuples(binding_id,fga_user,relation,object,source) VALUES($1,$2,$3,$4,'binding')`, id, tuple.User, tuple.Relation, tuple.Object)
							}
							if err == nil {
								err = emitter.EmitWriteTx(ctx, tx, []service.RelationTuple{tuple})
							}
						} else if registrarGrant {
							err = namedBindingWithdraw(ctx, tx, id, tuple)
						} else {
							err = store.RetireRegistrationPointersTx(ctx, tx, "probemod", tuple.Object, time.Time{})
							if err == nil {
								err = emitter.EmitOrderedDeleteTx(ctx, tx, []service.RelationTuple{tuple}, time.Now())
							}
						}
						if err == nil {
							err = tx.Commit(ctx)
						}
						done <- err
					}()
					return done
				}
				first := run(grantFirst)
				namedWaitForFactWaiters(t, w, 1)
				second := run(!grantFirst)
				namedWaitForFactWaiters(t, w, 2)
				require.NoError(t, holder.Commit(ctx))
				require.NoError(t, <-first)
				require.NoError(t, <-second)
				require.Equal(t, 1, namedCount(t, w, pmI1), "после обоих порядков остаётся законный новый holder")
			})
		}
	}
}

func TestNamedPointer_ConcurrentLastHolderAndRollbackOrders(t *testing.T) {
	for _, ownerFirst := range []bool{false, true} {
		for _, rollbackFirst := range []bool{false, true} {
			t.Run(map[bool]string{false: "binding-first", true: "registration-first"}[ownerFirst]+"/"+map[bool]string{false: "commit", true: "rollback-first"}[rollbackFirst], func(t *testing.T) {
				w := newP2(t)
				tuple := service.RelationTuple{User: pmBoxType + ":" + pmB1, Relation: "box", Object: pmItemType + ":" + pmI1}
				id := namedIndependentHolder(t, w, tuple)
				ctx, cancel := context.WithTimeout(w.ctx, 30*time.Second)
				defer cancel()
				holder, err := w.pool.Begin(ctx)
				require.NoError(t, err)
				defer func() { _ = holder.Rollback(context.Background()) }()
				var locked string
				require.NoError(t, holder.QueryRow(ctx, `SELECT subject FROM kaname.relation_fact WHERE object_type=$1 AND object_id=$2 AND relation='box' FOR UPDATE`, pmItemType, pmI1).Scan(&locked))
				run := func(owner, rollback bool) <-chan error {
					done := make(chan error, 1)
					go func() {
						tx, err := w.pool.Begin(ctx)
						if err != nil {
							done <- err
							return
						}
						defer func() { _ = tx.Rollback(context.Background()) }()
						if owner {
							err = kanamepg.NewRegistrationScopeReader().RetireRegistrationPointersTx(ctx, tx, "probemod", tuple.Object, time.Time{})
							if err == nil {
								err = kanamepg.NewFGAOutboxEmitter().EmitOrderedDeleteTx(ctx, tx, []service.RelationTuple{tuple}, time.Now())
							}
						} else {
							err = namedBindingWithdraw(ctx, tx, id, tuple)
						}
						if err == nil {
							if rollback {
								err = tx.Rollback(ctx)
							} else {
								err = tx.Commit(ctx)
							}
						}
						done <- err
					}()
					return done
				}
				first := run(ownerFirst, rollbackFirst)
				namedWaitForFactWaiters(t, w, 1)
				second := run(!ownerFirst, false)
				namedWaitForFactWaiters(t, w, 2)
				require.NoError(t, holder.Commit(ctx))
				require.NoError(t, <-first)
				require.NoError(t, <-second)
				if rollbackFirst {
					require.Equal(t, 1, namedCount(t, w, pmI1), "откат первого сохраняет его независимое владение")
				} else {
					require.Zero(t, namedCount(t, w, pmI1), "два коммита снимают последнего holder")
				}
			})
		}
	}
}

func TestNamedPointer_ReversedTupleSetsKeepFactLockOrder(t *testing.T) {
	w := newP2(t)
	a := service.RelationTuple{User: pmBoxType + ":" + pmB1, Relation: "box", Object: pmItemType + ":" + pmI1}
	b := service.RelationTuple{User: pmBoxType + ":" + pmB2, Relation: "box", Object: pmItemType + ":" + pmI3}
	ctx, cancel := context.WithTimeout(w.ctx, 30*time.Second)
	defer cancel()
	holder, err := w.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = holder.Rollback(context.Background()) }()
	var locked string
	require.NoError(t, holder.QueryRow(ctx, `SELECT subject FROM kaname.relation_fact WHERE object_type=$1 AND object_id=$2 AND relation='box' FOR UPDATE`, pmItemType, pmI3).Scan(&locked))
	run := func(tuples []service.RelationTuple) <-chan error {
		done := make(chan error, 1)
		go func() {
			tx, err := w.pool.Begin(ctx)
			if err != nil {
				done <- err
				return
			}
			defer func() { _ = tx.Rollback(context.Background()) }()
			err = kanamepg.NewFGAOutboxEmitter().EmitDeleteTx(ctx, tx, tuples)
			if err == nil {
				err = tx.Commit(ctx)
			}
			done <- err
		}()
		return done
	}
	first := run([]service.RelationTuple{b, a})
	namedWaitForFactWaiters(t, w, 1)
	second := run([]service.RelationTuple{a, b})
	namedWaitForFactWaiters(t, w, 2)
	require.NoError(t, holder.Commit(ctx))
	require.NoError(t, <-first)
	require.NoError(t, <-second)
	require.Equal(t, 1, namedCount(t, w, pmI1))
	require.Equal(t, 1, namedCount(t, w, pmI3))
	tx, err := w.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(context.Background()) }()
	store := kanamepg.NewRegistrationScopeReader()
	require.NoError(t, store.RetireRegistrationPointersTx(ctx, tx, "probemod", a.Object, time.Time{}))
	require.NoError(t, store.RetireRegistrationPointersTx(ctx, tx, "probemod", b.Object, time.Time{}))
	require.NoError(t, kanamepg.NewFGAOutboxEmitter().EmitOrderedDeleteTx(ctx, tx, []service.RelationTuple{b, a}, time.Now()))
	require.NoError(t, tx.Commit(ctx))
	require.Zero(t, namedCount(t, w, pmI1))
	require.Zero(t, namedCount(t, w, pmI3))
}

// Сбой следующего journal шага должен откатить весь настоящий use-case, включая
// уже изменённые зеркало и claims. Триггер существует только в БД этой фикстуры.
func namedJournalFailure(t *testing.T, w *p2, event, object string) func() {
	t.Helper()
	_, err := w.pool.Exec(w.ctx, `CREATE FUNCTION kaname.named_pointer_test_journal_failure() RETURNS trigger LANGUAGE plpgsql AS $$
 BEGIN
  IF NEW.event_type=TG_ARGV[0] AND NEW.payload->>'object'=TG_ARGV[1] THEN
   RAISE EXCEPTION 'NP_TEST_AFTER_CLAIM';
  END IF;
  RETURN NEW;
 END $$`)
	require.NoError(t, err)
	literal := func(v string) string { return "'" + strings.ReplaceAll(v, "'", "''") + "'" }
	_, err = w.pool.Exec(w.ctx, `CREATE TRIGGER named_pointer_test_journal_failure BEFORE INSERT ON kaname.fga_outbox FOR EACH ROW EXECUTE FUNCTION kaname.named_pointer_test_journal_failure(`+literal(event)+`,`+literal(object)+`)`)
	require.NoError(t, err)
	disarm := func() {
		_, err := w.pool.Exec(w.ctx, `DROP TRIGGER IF EXISTS named_pointer_test_journal_failure ON kaname.fga_outbox; DROP FUNCTION IF EXISTS kaname.named_pointer_test_journal_failure()`)
		require.NoError(t, err)
	}
	t.Cleanup(disarm)
	return disarm
}

func namedClaimState(t *testing.T, w *p2, object string, watermark time.Time, active, versionless bool) {
	t.Helper()
	typ, id, _ := strings.Cut(object, ":")
	var gotActive, gotVersionless, sameVersion bool
	expected := "-infinity"
	if !watermark.IsZero() {
		expected = watermark.Format(time.RFC3339Nano)
	}
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT active,versionless,source_version=$4::text::timestamptz FROM kaname.resource_registration_pointer WHERE module='probemod' AND object_type=$1 AND object_id=$2 AND relation='box' AND subject=$3`, typ, id, pmBoxType+":"+pmB1, expected).Scan(&gotActive, &gotVersionless, &sameVersion))
	require.Equal(t, active, gotActive)
	require.Equal(t, versionless, gotVersionless)
	require.True(t, sameVersion, "история не понижается и не получает чужую метку")
}

func TestNamedPointer_DescendantFenceUsesChildLineage(t *testing.T) {
	for _, childFinite := range []bool{false, true} {
		for _, parentNewer := range []bool{false, true} {
			t.Run(map[bool]string{false: "legacy-child", true: "ordered-child"}[childFinite]+"/"+map[bool]string{false: "parent-before-child", true: "parent-after-next-child"}[parentNewer], func(t *testing.T) {
				w := newP2(t)
				child := namedRequest(w, pmI1)
				c := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
				if childFinite {
					child.SourceVersion = timestamppb.New(c)
				}
				require.NoError(t, w.reg.Register(w.ctx, child))
				p := c.Add(-time.Minute)
				if parentNewer {
					p = c.Add(10 * time.Minute)
				}
				removal := &iamv1.UnregisterResourceRequest{SubjectId: "project:" + w.prjA, Relation: "project", Object: pmBoxType + ":" + pmB1, SourceVersion: timestamppb.New(p)}
				// Отказ после child retire откатывает parent/child mirrors, edges, claim,
				// факт и уже записанные предыдущие строки journal.
				before := namedSnapshot(t, w)
				disarm := namedJournalFailure(t, w, "fga.tuple.delete", child.Object)
				err := w.reg.Unregister(w.ctx, removal)
				require.ErrorContains(t, err, "NP_TEST_AFTER_CLAIM")
				require.Equal(t, before, namedSnapshot(t, w))
				disarm()
				require.NoError(t, w.reg.Unregister(w.ctx, removal))
				var ownFence time.Time
				if childFinite {
					ownFence = c
				}
				namedClaimState(t, w, child.Object, ownFence, false, !childFinite)
				require.Zero(t, namedCount(t, w, pmI1))
				require.Equal(t, 1, namedCount(t, w, pmI3))
				var mirror, edges, ownJournal int
				require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.resource_mirror WHERE object_type='probemod.items' AND object_id=$1`, pmI1).Scan(&mirror))
				require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.resource_parent_edge WHERE object_type=$1 AND object_id=$2`, pmItemType, pmI1).Scan(&edges))
				require.Zero(t, mirror)
				require.Zero(t, edges)
				if childFinite {
					require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.fga_outbox WHERE event_type='fga.tuple.delete' AND payload->>'object'=$1 AND payload->>'user'=$2 AND payload->>'relation'='box' AND (payload->>'source_version')::timestamptz=$3`, child.Object, child.SubjectId, c).Scan(&ownJournal))
				} else {
					require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.fga_outbox WHERE event_type='fga.tuple.delete' AND payload->>'object'=$1 AND payload->>'user'=$2 AND payload->>'relation'='box' AND NOT (payload ? 'source_version')`, child.Object, child.SubjectId).Scan(&ownJournal))
				}
				require.Positive(t, ownJournal, "named journal тоже использует child C, не parent P")
				require.NoError(t, w.reg.Register(w.ctx, &iamv1.RegisterResourceRequest{SubjectId: "project:" + w.prjA, Relation: "project", Object: pmBoxType + ":" + pmB1, ParentProjectId: w.prjA, ParentAccountId: w.accA, ParentChain: []string{"project:" + w.prjA, "account:" + w.accA}, SourceVersion: timestamppb.New(p.Add(time.Minute))}))
				if childFinite {
					for _, delta := range []time.Duration{-time.Second, 0} {
						child.SourceVersion = timestamppb.New(c.Add(delta))
						before := namedSnapshot(t, w)
						require.Error(t, w.reg.Register(w.ctx, child))
						require.Equal(t, before, namedSnapshot(t, w), "old/equal child не воскрешает снятую регистрацию")
					}
				}
				child.SourceVersion = timestamppb.New(c.Add(time.Second))
				require.NoError(t, w.reg.Register(w.ctx, child), "C < C+delta < P не мешает собственной новой версии")
				namedClaimState(t, w, child.Object, c.Add(time.Second), true, false)
				require.Equal(t, 1, namedCount(t, w, pmI1))
			})
		}
	}
}

func TestNamedPointer_VersionlessPreservesOrderedHistory(t *testing.T) {
	for _, initialFinite := range []bool{false, true} {
		for _, inactive := range []bool{false, true} {
			for _, finiteRemoval := range []bool{false, true} {
				name := map[bool]string{false: "initial-zero", true: "initial-finite"}[initialFinite] + "/" + map[bool]string{false: "active", true: "inactive"}[inactive] + "/" + map[bool]string{false: "zero-removal", true: "finite-removal"}[finiteRemoval]
				t.Run(name, func(t *testing.T) {
					w := newP2(t)
					req := namedRequest(w, "versionless-mode")
					v := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
					var fence time.Time
					if initialFinite {
						req.SourceVersion = timestamppb.New(v)
						fence = v
					}
					require.NoError(t, w.reg.Register(w.ctx, req))
					if inactive {
						removal := &iamv1.UnregisterResourceRequest{SubjectId: req.SubjectId, Relation: req.Relation, Object: req.Object}
						if finiteRemoval {
							removal.SourceVersion = timestamppb.New(v.Add(time.Minute))
							fence = v.Add(time.Minute)
						}
						require.NoError(t, w.reg.Unregister(w.ctx, removal))
						require.Zero(t, namedCount(t, w, "versionless-mode"))
					}
					req.SourceVersion = nil
					require.NoError(t, w.reg.Register(w.ctx, req), "versionless intent не сравнивается как -infinity с finite history")
					namedClaimState(t, w, req.Object, fence, true, true)
					require.Equal(t, 1, namedCount(t, w, "versionless-mode"))
					var mirrors int
					require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.resource_mirror WHERE object_type='probemod.items' AND object_id='versionless-mode'`).Scan(&mirrors))
					require.Equal(t, 1, mirrors)
					if !fence.IsZero() {
						for _, delta := range []time.Duration{-time.Second, 0} {
							req.SourceVersion = timestamppb.New(fence.Add(delta))
							before := namedSnapshot(t, w)
							// У существующей finite mirror старый intent может быть штатным no-op;
							// ни при одном исходе он не понижает history и не меняет legacy mode.
							_ = w.reg.Register(w.ctx, req)
							require.Equal(t, before, namedSnapshot(t, w))
						}
					}
					next := v.Add(2 * time.Minute)
					req.SourceVersion = timestamppb.New(next)
					require.NoError(t, w.reg.Register(w.ctx, req))
					namedClaimState(t, w, req.Object, next, true, false)
					require.NoError(t, w.reg.Unregister(w.ctx, &iamv1.UnregisterResourceRequest{SubjectId: req.SubjectId, Relation: req.Relation, Object: req.Object, SourceVersion: timestamppb.New(v)}))
					namedClaimState(t, w, req.Object, next, true, false)
					require.Equal(t, 1, namedCount(t, w, "versionless-mode"), "stale ordered tombstone не снимает новую ordered регистрацию")
				})
			}
		}
	}
}

func TestNamedPointer_VersionlessFiniteHistoryRollback(t *testing.T) {
	w := newP2(t)
	req := namedRequest(w, "versionless-rollback")
	v := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
	req.SourceVersion = timestamppb.New(v)
	require.NoError(t, w.reg.Register(w.ctx, req))
	require.NoError(t, w.reg.Unregister(w.ctx, &iamv1.UnregisterResourceRequest{SubjectId: req.SubjectId, Relation: req.Relation, Object: req.Object, SourceVersion: timestamppb.New(v.Add(time.Minute))}))
	before := namedSnapshot(t, w)
	disarm := namedJournalFailure(t, w, "fga.tuple.write", req.Object)
	req.SourceVersion = nil
	require.ErrorContains(t, w.reg.Register(w.ctx, req), "NP_TEST_AFTER_CLAIM")
	require.Equal(t, before, namedSnapshot(t, w), "claim mode, mirror и факт откатываются вместе")
	namedClaimState(t, w, req.Object, v.Add(time.Minute), false, false)
	disarm()
	require.NoError(t, w.reg.Register(w.ctx, req))
	namedClaimState(t, w, req.Object, v.Add(time.Minute), true, true)
	require.Equal(t, 1, namedCount(t, w, "versionless-rollback"))
}
