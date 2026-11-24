// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicreadmodule_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

func r4Snapshot(t *testing.T, w *p2) string {
	t.Helper()
	var receipts string
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT coalesce(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]'::jsonb)::text FROM kaname.resource_registration_retirement x`).Scan(&receipts))
	return namedSnapshot(t, w) + "\n" + receipts
}
func r4Receipt(t *testing.T, w *p2, tuple service.RelationTuple) (int, time.Time) {
	t.Helper()
	typ, id, _ := strings.Cut(tuple.Object, ":")
	var n int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.resource_registration_retirement WHERE object_type=$1 AND object_id=$2 AND relation=$3 AND subject=$4`, typ, id, tuple.Relation, tuple.User).Scan(&n))
	var cutoff time.Time
	if n > 0 {
		require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT delete_through FROM kaname.resource_registration_retirement WHERE object_type=$1 AND object_id=$2 AND relation=$3 AND subject=$4`, typ, id, tuple.Relation, tuple.User).Scan(&cutoff))
	}
	return n, cutoff
}
func r4Release(t *testing.T, w *p2, holder domain.AccessBindingID, tuples []service.RelationTuple) {
	t.Helper()
	tx, err := w.pool.Begin(w.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(context.Background()) }()
	for _, tuple := range tuples {
		_, err = tx.Exec(w.ctx, `DELETE FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND object=$2 AND relation=$3 AND fga_user=$4`, holder, tuple.Object, tuple.Relation, tuple.User)
		require.NoError(t, err)
	}
	require.NoError(t, kanamepg.NewFGAOutboxEmitter().EmitDeleteTx(w.ctx, tx, tuples))
	require.NoError(t, tx.Commit(w.ctx))
}
func r4Holder(t *testing.T, w *p2, tuples []service.RelationTuple) domain.AccessBindingID {
	t.Helper()
	holder := namedIndependentHolder(t, w, tuples[0])
	for _, tuple := range tuples[1:] {
		_, err := w.pool.Exec(w.ctx, `INSERT INTO kaname.access_binding_emitted_tuples(binding_id,fga_user,relation,object,source) VALUES($1,$2,$3,$4,'binding')`, holder, tuple.User, tuple.Relation, tuple.Object)
		require.NoError(t, err)
	}
	return holder
}
func r4Owner(w *p2, parent *iamv1.RegisterResourceRequest, tuple service.RelationTuple, v time.Time) *iamv1.RegisterResourceRequest {
	r := &iamv1.RegisterResourceRequest{SubjectId: tuple.User, Relation: tuple.Relation, Object: tuple.Object, ParentProjectId: w.prjA, ParentAccountId: w.accA, ParentChain: []string{parent.Object, "project:" + w.prjA, "account:" + w.accA}}
	if !v.IsZero() {
		r.SourceVersion = timestamppb.New(v)
	}
	return r
}
func r4World(t *testing.T, future, opposite bool) (*p2, *iamv1.RegisterResourceRequest, []service.RelationTuple, time.Time, time.Time) {
	t.Helper()
	w, parent, tuples, c, _ := r3MixedWorld(t, opposite)
	f := c.Add(10 * time.Second)
	if future {
		f = time.Now().UTC().Truncate(time.Microsecond).Add(24 * time.Hour)
	}
	require.NoError(t, w.reg.Register(w.ctx, r4Owner(w, parent, tuples[1], f)))
	return w, parent, tuples, f, f.Add(time.Minute)
}

func TestNamedRetirement_FutureAndPastBothLastHolderOrders(t *testing.T) {
	for _, future := range []bool{false, true} {
		for _, parentFirst := range []bool{false, true} {
			t.Run(fmt.Sprintf("future=%t/parentFirst=%t", future, parentFirst), func(t *testing.T) {
				w, parent, tuples, f, p := r4World(t, future, false)
				holder := r4Holder(t, w, tuples)
				if parentFirst {
					require.NoError(t, w.reg.Unregister(w.ctx, r3Removal(parent, p)))
					for _, tuple := range tuples {
						require.Equal(t, 1, r3FactCount(t, w, tuple))
					}
					n, cutoff := r4Receipt(t, w, tuples[1])
					require.Equal(t, 1, n)
					require.True(t, p.Equal(cutoff))
					r4Release(t, w, holder, tuples)
				} else {
					r4Release(t, w, holder, tuples)
					require.Equal(t, 1, r3FactCount(t, w, tuples[0]), "действующий exact named holder остаётся")
					if future {
						require.Equal(t, 1, r3FactCount(t, w, tuples[1]), "прежняя future legacy comparison сохранена")
					}
					require.NoError(t, w.reg.Unregister(w.ctx, r3Removal(parent, p)))
				}
				for _, tuple := range tuples {
					require.Zero(t, r3FactCount(t, w, tuple))
				}
				typ, id, _ := strings.Cut(tuples[0].Object, ":")
				var own, inactive bool
				require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT source_version=$1,NOT active FROM kaname.resource_registration_pointer WHERE object_type=$2 AND object_id=$3`, f, typ, id).Scan(&own, &inactive))
				require.True(t, own, "own child F не превращается в parent P")
				require.True(t, inactive)
			})
		}
	}
}

func TestNamedRetirement_ActualOwnerWritesInvalidateExactReceipt(t *testing.T) {
	for _, mode := range []string{"new-finite", "lower-finite", "zero", "stale-no-emit"} {
		t.Run(mode, func(t *testing.T) {
			w, parent, tuples, f, p := r4World(t, true, false)
			holder := r4Holder(t, w, tuples)
			require.NoError(t, w.reg.Unregister(w.ctx, r3Removal(parent, p)))
			n, _ := r4Receipt(t, w, tuples[1])
			require.Equal(t, 1, n)
			require.NoError(t, w.reg.Register(w.ctx, parent))
			childVersion := f.Add(time.Second)
			if mode == "new-finite" {
				childVersion = p.Add(time.Second)
			}
			child := &iamv1.RegisterResourceRequest{SubjectId: tuples[0].User, Relation: "box", Object: tuples[0].Object, ParentProjectId: w.prjA, ParentAccountId: w.accA, ParentChain: []string{parent.Object, "project:" + w.prjA, "account:" + w.accA}, SourceVersion: timestamppb.New(childVersion)}
			require.NoError(t, w.reg.Register(w.ctx, child))
			// Named write не является legacy owner write и не сбрасывает чужую квитанцию.
			n, _ = r4Receipt(t, w, tuples[1])
			require.Equal(t, 1, n)
			ownerVersion := childVersion.Add(time.Second)
			if mode == "zero" {
				ownerVersion = time.Time{}
			}
			if mode == "stale-no-emit" {
				ownerVersion = f
			}
			before := r4Snapshot(t, w)
			require.NoError(t, w.reg.Register(w.ctx, r4Owner(w, parent, tuples[1], ownerVersion)))
			n, _ = r4Receipt(t, w, tuples[1])
			if mode == "stale-no-emit" {
				require.Equal(t, 1, n)
				require.Equal(t, before, r4Snapshot(t, w))
				return
			}
			require.Zero(t, n)
			r4Release(t, w, holder, tuples)
			require.Equal(t, 1, r3FactCount(t, w, tuples[1]), "старое retirement не снимает новую регистрацию")
			next := childVersion.Add(time.Minute)
			require.NoError(t, w.reg.Unregister(w.ctx, r3Removal(parent, next)))
			for _, tuple := range tuples {
				require.Zero(t, r3FactCount(t, w, tuple))
			}
		})
	}
}

func TestNamedRetirement_ExactCutoffAndIdentity(t *testing.T) {
	for _, mutation := range []string{"exact", "subject", "relation", "object", "stale-cutoff"} {
		t.Run(mutation, func(t *testing.T) {
			w, parent, tuples, f, p := r4World(t, true, false)
			holder := r4Holder(t, w, tuples)
			if mutation == "stale-cutoff" {
				// Настоящее stale root owner снятие не удаляет mirror F и не получает F
				// из стоящего факта: его квитанция ограничена только входным finite P<F.
				cutoff := f.Add(-time.Second)
				require.NoError(t, w.reg.Unregister(w.ctx, &iamv1.UnregisterResourceRequest{SubjectId: tuples[1].User, Relation: "owner", Object: tuples[1].Object, SourceVersion: timestamppb.New(cutoff)}))
				n, got := r4Receipt(t, w, tuples[1])
				require.Equal(t, 1, n)
				require.True(t, got.Equal(cutoff))
			} else {
				require.NoError(t, w.reg.Unregister(w.ctx, r3Removal(parent, p)))
				if mutation != "exact" {
					// Только отрицательная adapter фикстура меняет ключ уже созданной proof;
					// ни продукт, ни накат не получают права восстанавливать её из фактов.
					typ, id, _ := strings.Cut(tuples[1].Object, ":")
					subject, relation, object := tuples[1].User, "owner", id
					switch mutation {
					case "subject":
						subject = "service_account:other"
					case "relation":
						relation = "parent"
					case "object":
						object = "other-object"
					}
					_, err := w.pool.Exec(w.ctx, `UPDATE kaname.resource_registration_retirement SET subject=$1,relation=$2,object_id=$3 WHERE object_type=$4 AND object_id=$5 AND relation='owner' AND subject=$6`, subject, relation, object, typ, id, tuples[1].User)
					require.NoError(t, err)
				}
			}
			r4Release(t, w, holder, tuples)
			want := 1
			if mutation == "exact" {
				want = 0
			}
			require.Equal(t, want, r3FactCount(t, w, tuples[1]))
		})
	}
}

func TestNamedRetirement_QueuedABWritesDoNotEraseProof(t *testing.T) {
	for _, commit := range []bool{false, true} {
		for _, opposite := range []bool{false, true} {
			for _, reverse := range []bool{false, true} {
				t.Run(fmt.Sprintf("commit=%t/opposite=%t/reverse=%t", commit, opposite, reverse), func(t *testing.T) {
					w, parent, tuples, _, p := r4World(t, true, opposite)
					ctx, cancel := context.WithTimeout(w.ctx, 30*time.Second)
					defer cancel()
					holder := r4Holder(t, w, tuples)
					_, err := w.pool.Exec(ctx, `DELETE FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND object=$2`, holder, tuples[0].Object)
					require.NoError(t, err)
					tx, err := w.pool.Begin(ctx)
					require.NoError(t, err)
					defer func() { _ = tx.Rollback(context.Background()) }()
					for _, tuple := range tuples {
						_, err = tx.Exec(ctx, `INSERT INTO kaname.access_binding_emitted_tuples(binding_id,fga_user,relation,object,source) VALUES($1,$2,$3,$4,'binding')`, holder, tuple.User, tuple.Relation, tuple.Object)
						require.NoError(t, err)
					}
					input := append([]service.RelationTuple(nil), tuples...)
					if reverse {
						input[0], input[1] = input[1], input[0]
					}
					require.NoError(t, kanamepg.NewFGAOutboxEmitter().EmitWriteTx(ctx, tx, input))
					done := make(chan error, 1)
					go func() { done <- w.reg.Unregister(ctx, r3Removal(parent, p)) }()
					namedWaitForFactWaiters(t, w, 1)
					if commit {
						require.NoError(t, tx.Commit(ctx))
					} else {
						require.NoError(t, tx.Rollback(ctx))
					}
					require.NoError(t, <-done)
					n, _ := r4Receipt(t, w, tuples[1])
					require.Equal(t, 1, n)
					for _, tuple := range tuples {
						want := 0
						if commit {
							want = 1
						}
						require.Equal(t, want, r3FactCount(t, w, tuple))
					}
					if commit {
						r4Release(t, w, holder, input)
						for _, tuple := range tuples {
							require.Zero(t, r3FactCount(t, w, tuple))
						}
					}
				})
			}
		}
	}
}

func TestNamedRetirement_ConcurrentABLastAndCombinedWithdrawal(t *testing.T) {
	for _, parentFirst := range []bool{false, true} {
		for _, commit := range []bool{false, true} {
			for _, opposite := range []bool{false, true} {
				for _, reverse := range []bool{false, true} {
					t.Run(fmt.Sprintf("parentFirst=%t/commit=%t/opposite=%t/reverse=%t", parentFirst, commit, opposite, reverse), func(t *testing.T) {
						w, parent, tuples, _, p := r4World(t, true, opposite)
						ctx, cancel := context.WithTimeout(w.ctx, 30*time.Second)
						defer cancel()
						holder := r4Holder(t, w, tuples)
						last := tuples[0]
						if tuples[1].User > last.User {
							last = tuples[1]
						}
						typ, id, _ := strings.Cut(last.Object, ":")
						gate, err := w.pool.Begin(ctx)
						require.NoError(t, err)
						defer func() { _ = gate.Rollback(context.Background()) }()
						var subject string
						require.NoError(t, gate.QueryRow(ctx, `SELECT subject FROM kaname.relation_fact WHERE object_type=$1 AND object_id=$2 AND relation=$3 AND subject=$4 FOR UPDATE`, typ, id, last.Relation, last.User).Scan(&subject))
						input := append([]service.RelationTuple(nil), tuples...)
						if reverse {
							input[0], input[1] = input[1], input[0]
						}
						start := func(parentAction bool) <-chan error {
							done := make(chan error, 1)
							go func() {
								if parentAction {
									done <- w.reg.Unregister(ctx, r3Removal(parent, p))
									return
								}
								tx, err := w.pool.Begin(ctx)
								if err == nil {
									defer func() { _ = tx.Rollback(context.Background()) }()
									for _, tuple := range input {
										_, err = tx.Exec(ctx, `DELETE FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND object=$2 AND relation=$3 AND fga_user=$4`, holder, tuple.Object, tuple.Relation, tuple.User)
										if err != nil {
											break
										}
									}
									if err == nil {
										err = kanamepg.NewFGAOutboxEmitter().EmitDeleteTx(ctx, tx, input)
									}
									if err == nil && commit {
										err = tx.Commit(ctx)
									}
								}
								done <- err
							}()
							return done
						}
						a := start(parentFirst)
						namedWaitForFactWaiters(t, w, 1)
						b := start(!parentFirst)
						namedWaitForFactWaiters(t, w, 2)
						require.NoError(t, gate.Commit(ctx))
						require.NoError(t, <-a)
						require.NoError(t, <-b)
						for _, tuple := range tuples {
							want := 1
							if commit {
								want = 0
							}
							require.Equal(t, want, r3FactCount(t, w, tuple))
						}
						if !commit {
							r4Release(t, w, holder, input)
							for _, tuple := range tuples {
								require.Zero(t, r3FactCount(t, w, tuple))
							}
						}
					})
				}
			}
		}
	}
}

func TestNamedRetirement_ZeroStructuralActionBoundsSnapshot(t *testing.T) {
	for _, root := range []bool{false, true} {
		for _, repeat := range []bool{false, true} {
			t.Run(fmt.Sprintf("root=%t/repeat=%t", root, repeat), func(t *testing.T) {
				w, parent, tuples, f, _ := r4World(t, true, false)
				holder := r4Holder(t, w, tuples)
				// Реальный zero emit сохраняет aggregate F, но не создаёт новую версию часов.
				require.NoError(t, w.reg.Register(w.ctx, r4Owner(w, parent, tuples[1], time.Time{})))
				req := r3Removal(parent, time.Time{})
				if root {
					req = &iamv1.UnregisterResourceRequest{SubjectId: tuples[0].User, Relation: "box", Object: tuples[0].Object}
				}
				require.NoError(t, w.reg.Unregister(w.ctx, req))
				n, cutoff := r4Receipt(t, w, tuples[1])
				require.Equal(t, 1, n)
				require.True(t, f.Equal(cutoff))
				if repeat {
					_, err := w.pool.Exec(w.ctx, `DELETE FROM kaname.resource_registration_retirement`)
					require.NoError(t, err)
					require.NoError(t, w.reg.Unregister(w.ctx, req))
					n, _ = r4Receipt(t, w, tuples[1])
					require.Zero(t, n, "повтор без mirror не восстанавливает неизвестную историю из факта")
				}
				r4Release(t, w, holder, tuples)
				want := 0
				if repeat {
					want = 1
				}
				require.Equal(t, want, r3FactCount(t, w, tuples[1]))
			})
		}
	}
}

func TestNamedRetirement_JournalFailureRollsBackCreationAndInvalidation(t *testing.T) {
	for _, invalidate := range []bool{false, true} {
		t.Run(fmt.Sprintf("invalidate=%t", invalidate), func(t *testing.T) {
			w, parent, tuples, f, p := r4World(t, true, false)
			holder := r4Holder(t, w, tuples)
			if !invalidate {
				before := r4Snapshot(t, w)
				disarm := namedJournalFailure(t, w, "fga.tuple.delete", tuples[1].Object)
				require.ErrorContains(t, w.reg.Unregister(w.ctx, r3Removal(parent, p)), "NP_TEST_AFTER_CLAIM")
				require.Equal(t, before, r4Snapshot(t, w))
				disarm()
				require.NoError(t, w.reg.Unregister(w.ctx, r3Removal(parent, p)))
				r4Release(t, w, holder, tuples)
				require.Zero(t, r3FactCount(t, w, tuples[1]))
				return
			}
			require.NoError(t, w.reg.Unregister(w.ctx, r3Removal(parent, p)))
			require.NoError(t, w.reg.Register(w.ctx, parent))
			child := &iamv1.RegisterResourceRequest{SubjectId: tuples[0].User, Relation: "box", Object: tuples[0].Object, ParentProjectId: w.prjA, ParentAccountId: w.accA, ParentChain: []string{parent.Object, "project:" + w.prjA, "account:" + w.accA}, SourceVersion: timestamppb.New(f.Add(time.Second))}
			require.NoError(t, w.reg.Register(w.ctx, child))
			before := r4Snapshot(t, w)
			disarm := namedJournalFailure(t, w, "fga.tuple.write", tuples[1].Object)
			require.ErrorContains(t, w.reg.Register(w.ctx, r4Owner(w, parent, tuples[1], time.Time{})), "NP_TEST_AFTER_CLAIM")
			require.Equal(t, before, r4Snapshot(t, w))
			disarm()
			require.NoError(t, w.reg.Register(w.ctx, r4Owner(w, parent, tuples[1], time.Time{})))
			n, _ := r4Receipt(t, w, tuples[1])
			require.Zero(t, n)
		})
	}
}

func TestNamedRetirement_LegacyOnlyAndABNeverCreateProof(t *testing.T) {
	w := newP2(t)
	tuple := service.RelationTuple{User: "user:" + w.usrA, Relation: "owner", Object: "probemod_item:legacy-only"}
	ctx := w.ctx
	tx, err := w.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(context.Background()) }()
	emitter := kanamepg.NewFGAOutboxEmitter()
	future := time.Now().UTC().Add(24 * time.Hour)
	require.NoError(t, emitter.EmitOrderedWriteTx(ctx, tx, []service.RelationTuple{tuple}, future))
	require.NoError(t, emitter.EmitWriteTx(ctx, tx, []service.RelationTuple{tuple}))
	require.NoError(t, emitter.EmitDeleteTx(ctx, tx, []service.RelationTuple{tuple}))
	require.NoError(t, emitter.EmitOrderedDeleteTx(ctx, tx, []service.RelationTuple{tuple}, future.Add(-time.Second)))
	require.NoError(t, tx.Commit(ctx))
	n, _ := r4Receipt(t, w, tuple)
	require.Zero(t, n)
	require.Equal(t, 1, r3FactCount(t, w, tuple), "без receipt прежнее version comparison не расширяется")
}
