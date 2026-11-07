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

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationwriterfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

func r3Removal(req *iamv1.RegisterResourceRequest, version time.Time) *iamv1.UnregisterResourceRequest {
	out := &iamv1.UnregisterResourceRequest{SubjectId: req.SubjectId, Relation: req.Relation, Object: req.Object}
	if !version.IsZero() {
		out.SourceVersion = timestamppb.New(version)
	}
	return out
}

// Проверяем весь use-case: отказ должен предшествовать любому изменению mirror,
// edges, claims, facts и journal, а не только отказать последнему DELETE факта.
func TestNamedPointer_ZeroActivationRejectsRetainedFiniteTombstones(t *testing.T) {
	for _, inactive := range []bool{false, true} {
		for _, delta := range []string{"old", "equal", "new", "zero"} {
			for _, held := range []bool{false, true} {
				t.Run(fmt.Sprintf("inactive=%t/%s/held=%t", inactive, delta, held), func(t *testing.T) {
					w := newP2(t)
					req := namedRequest(w, "zero-fence-r3")
					c := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
					fence := c.Add(time.Minute)
					req.SourceVersion = timestamppb.New(c)
					require.NoError(t, w.reg.Register(w.ctx, req))
					if inactive {
						require.NoError(t, w.reg.Unregister(w.ctx, r3Removal(req, fence)))
					} else {
						req.SourceVersion = timestamppb.New(fence)
						require.NoError(t, w.reg.Register(w.ctx, req))
					}
					req.SourceVersion = nil
					require.NoError(t, w.reg.Register(w.ctx, req))
					namedClaimState(t, w, req.Object, fence, true, true)
					tuple := service.RelationTuple{User: req.SubjectId, Relation: req.Relation, Object: req.Object}
					var release func()
					if held {
						id := namedIndependentHolder(t, w, tuple)
						release = func() {
							tx, err := w.pool.Begin(w.ctx)
							require.NoError(t, err)
							defer func() { _ = tx.Rollback(context.Background()) }()
							require.NoError(t, namedBindingWithdraw(w.ctx, tx, id, tuple))
							require.NoError(t, tx.Commit(w.ctx))
						}
					}
					v := fence
					switch delta {
					case "old":
						v = fence.Add(-time.Second)
					case "new":
						v = fence.Add(time.Second)
					case "zero":
						v = time.Time{}
					}
					before := namedSnapshot(t, w)
					err := w.reg.Unregister(w.ctx, r3Removal(req, v))
					if delta == "old" || delta == "equal" {
						require.Error(t, err)
						require.Equal(t, before, namedSnapshot(t, w))
						return
					}
					require.NoError(t, err)
					wantFence := fence
					if delta == "new" {
						wantFence = v
					}
					namedClaimState(t, w, req.Object, wantFence, false, true)
					if held {
						require.Equal(t, 1, namedCount(t, w, "zero-fence-r3"))
						release()
					}
					require.Zero(t, namedCount(t, w, "zero-fence-r3"))
					var mirror, edges int
					require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.resource_mirror WHERE object_id='zero-fence-r3'`).Scan(&mirror))
					require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.resource_parent_edge WHERE object_id='zero-fence-r3'`).Scan(&edges))
					require.Zero(t, mirror)
					require.Zero(t, edges)
				})
			}
		}
	}
}

func TestNamedPointer_ZeroActivationWithdrawalRollbackAndStructuralCascade(t *testing.T) {
	for _, inactive := range []bool{false, true} {
		t.Run(fmt.Sprintf("rollback/inactive=%t", inactive), func(t *testing.T) {
			w := newP2(t)
			req := namedRequest(w, "rollback-zero-r3")
			c := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
			fence := c.Add(time.Minute)
			req.SourceVersion = timestamppb.New(c)
			require.NoError(t, w.reg.Register(w.ctx, req))
			if inactive {
				require.NoError(t, w.reg.Unregister(w.ctx, r3Removal(req, fence)))
			} else {
				req.SourceVersion = timestamppb.New(fence)
				require.NoError(t, w.reg.Register(w.ctx, req))
			}
			req.SourceVersion = nil
			require.NoError(t, w.reg.Register(w.ctx, req))
			before := namedSnapshot(t, w)
			disarm := namedJournalFailure(t, w, "fga.tuple.delete", req.Object)
			require.ErrorContains(t, w.reg.Unregister(w.ctx, r3Removal(req, fence.Add(time.Second))), "NP_TEST_AFTER_CLAIM")
			require.Equal(t, before, namedSnapshot(t, w))
			disarm()
			require.NoError(t, w.reg.Unregister(w.ctx, r3Removal(req, fence.Add(time.Second))))
			require.Zero(t, namedCount(t, w, "rollback-zero-r3"))
		})
	}
	for _, parentNewer := range []bool{false, true} {
		t.Run(fmt.Sprintf("cascade/parentNewer=%t", parentNewer), func(t *testing.T) {
			w := newP2(t)
			req := namedRequest(w, pmI1)
			c := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
			fence := c.Add(time.Minute)
			req.SourceVersion = timestamppb.New(c)
			require.NoError(t, w.reg.Register(w.ctx, req))
			require.NoError(t, w.reg.Unregister(w.ctx, r3Removal(req, fence)))
			req.SourceVersion = nil
			require.NoError(t, w.reg.Register(w.ctx, req))
			p := c.Add(-time.Minute)
			if parentNewer {
				p = fence.Add(time.Hour)
			}
			require.NoError(t, w.reg.Unregister(w.ctx, &iamv1.UnregisterResourceRequest{SubjectId: "project:" + w.prjA, Relation: "project", Object: pmBoxType + ":" + pmB1, SourceVersion: timestamppb.New(p)}))
			namedClaimState(t, w, req.Object, fence, false, true)
			require.Zero(t, namedCount(t, w, pmI1))
			var unversioned int
			require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.fga_outbox WHERE event_type='fga.tuple.delete' AND payload->>'object'=$1 AND payload->>'relation'='box' AND NOT(payload ? 'source_version')`, req.Object).Scan(&unversioned))
			require.Positive(t, unversioned)
		})
	}
}

func r3WaitWriterWaiters(t *testing.T, w *p2, want int) {
	t.Helper()
	require.Eventually(t, func() bool {
		var n int
		err := w.pool.QueryRow(w.ctx, `SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND database=(SELECT oid FROM pg_database WHERE datname=current_database()) AND NOT granted`).Scan(&n)
		return err == nil && n >= want
	}, 10*time.Second, 10*time.Millisecond)
}

func TestNamedPointer_QueuedZeroActivationAndFiniteWithdrawal(t *testing.T) {
	for _, zeroFirst := range []bool{false, true} {
		for _, rollback := range []bool{false, true} {
			for _, equal := range []bool{false, true} {
				t.Run(fmt.Sprintf("zeroFirst=%t/rollback=%t/equal=%t", zeroFirst, rollback, equal), func(t *testing.T) {
					w := newP2(t)
					ctx, cancel := context.WithTimeout(w.ctx, 30*time.Second)
					defer cancel()
					req := namedRequest(w, "queued-zero-r3")
					c := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
					fence := c.Add(time.Minute)
					req.SourceVersion = timestamppb.New(c)
					require.NoError(t, w.reg.Register(ctx, req))
					require.NoError(t, w.reg.Unregister(ctx, r3Removal(req, fence)))
					req.SourceVersion = nil
					if rollback {
						namedJournalFailure(t, w, "fga.tuple.write", req.Object)
					}
					gate, err := w.pool.Begin(ctx)
					require.NoError(t, err)
					defer func() { _ = gate.Rollback(context.Background()) }()
					_, err = gate.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('kaname.resource_registration_writers',0))`)
					require.NoError(t, err)
					start := func(zero bool) <-chan error {
						done := make(chan error, 1)
						go func() {
							if zero {
								done <- w.reg.Register(ctx, req)
							} else {
								v := fence
								if !equal {
									v = v.Add(-time.Second)
								}
								done <- w.reg.Unregister(ctx, r3Removal(req, v))
							}
						}()
						return done
					}
					first := start(zeroFirst)
					r3WaitWriterWaiters(t, w, 1)
					second := start(!zeroFirst)
					r3WaitWriterWaiters(t, w, 2)
					require.NoError(t, gate.Commit(ctx))
					a, b := <-first, <-second
					zeroErr, withdrawErr := a, b
					if !zeroFirst {
						zeroErr, withdrawErr = b, a
					}
					if rollback {
						require.ErrorContains(t, zeroErr, "NP_TEST_AFTER_CLAIM")
						require.NoError(t, withdrawErr)
						namedClaimState(t, w, req.Object, fence, false, false)
						require.Zero(t, namedCount(t, w, "queued-zero-r3"))
					} else {
						require.NoError(t, zeroErr)
						if zeroFirst {
							require.Error(t, withdrawErr)
						} else {
							require.NoError(t, withdrawErr)
						}
						namedClaimState(t, w, req.Object, fence, true, true)
						require.Equal(t, 1, namedCount(t, w, "queued-zero-r3"))
					}
				})
			}
		}
	}
}

// Политика мира расширяется настоящей доставкой каталога, не прямой записью
// relation_fact. Второй тип даёт обратный лексический порядок named/user.
func r3MixedWorld(t *testing.T, opposite bool) (*p2, *iamv1.RegisterResourceRequest, []service.RelationTuple, time.Time, time.Time) {
	t.Helper()
	w := newP2(t)
	doc, err := publicreadfixture.Read(publicreadfixture.ProbemodFile)
	require.NoError(t, err)
	const owner = "    relations:\n      - name: owner\n        definition: '[user, service_account]'\n        position: beforeTiers\n    writes:\n      - relation: owner\n        subjects: [user, service_account]\n"
	doc = []byte(strings.Replace(string(doc), "    objectType: probemod_item\n", "    objectType: probemod_item\n"+owner, 1))
	boxType, itemType := pmBoxType, pmItemType
	if opposite {
		boxType, itemType = "zz_box", "zz_item"
		doc = append(doc, []byte("\n  - name: zboxes\n    objectType: zz_box\n    parents: [project]\n    producer: derived\n    verbs: [get, list, create, update, delete]\n  - name: zitems\n    objectType: zz_item\n"+owner+"    parents:\n      - {name: box, type: zz_box}\n    producer: derived\n    verbs: [get, list, update, delete]\n")...)
	}
	doc, err = publicreadfixture.WithRevision(doc, 2)
	require.NoError(t, err)
	m, err := manifest.Load(doc)
	require.NoError(t, err)
	_, err = modulecatalog.NewApplier(kanamepg.NewCatalogWriteRepo(w.pool)).ApplyAll(w.ctx, []*manifest.Manifest{m})
	require.NoError(t, err)
	c := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Hour)
	p := c.Add(time.Minute)
	parent := &iamv1.RegisterResourceRequest{SubjectId: "project:" + w.prjA, Relation: "project", Object: boxType + ":mixed-box", ParentProjectId: w.prjA, ParentAccountId: w.accA, ParentChain: []string{"project:" + w.prjA, "account:" + w.accA}}
	require.NoError(t, w.reg.Register(w.ctx, parent))
	child := &iamv1.RegisterResourceRequest{SubjectId: parent.Object, Relation: "box", Object: itemType + ":mixed-item", ParentProjectId: w.prjA, ParentAccountId: w.accA, ParentChain: []string{parent.Object, "project:" + w.prjA, "account:" + w.accA}, SourceVersion: timestamppb.New(c)}
	require.NoError(t, w.reg.Register(w.ctx, child))
	ownerReq := &iamv1.RegisterResourceRequest{SubjectId: "user:" + w.usrA, Relation: "owner", Object: child.Object, ParentProjectId: w.prjA, ParentAccountId: w.accA, ParentChain: child.ParentChain}
	require.NoError(t, w.reg.Register(w.ctx, ownerReq))
	tuples := []service.RelationTuple{{User: child.SubjectId, Relation: "box", Object: child.Object}, {User: ownerReq.SubjectId, Relation: "owner", Object: child.Object}}
	return w, parent, tuples, c, p
}

func r3FactCount(t *testing.T, w *p2, tuple service.RelationTuple) int {
	t.Helper()
	typ, id, _ := strings.Cut(tuple.Object, ":")
	var n int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.relation_fact WHERE object_type=$1 AND object_id=$2 AND relation=$3 AND subject=$4`, typ, id, tuple.Relation, tuple.User).Scan(&n))
	return n
}

func TestNamedPointer_MixedWithdrawalUsesOneGlobalFactOrder(t *testing.T) {
	for _, opposite := range []bool{false, true} {
		for _, parentFirst := range []bool{false, true} {
			for _, reverse := range []bool{false, true} {
				for _, rollback := range []bool{false, true} {
					t.Run(fmt.Sprintf("opposite=%t/parentFirst=%t/reverse=%t/rollback=%t", opposite, parentFirst, reverse, rollback), func(t *testing.T) {
						w, parent, tuples, c, p := r3MixedWorld(t, opposite)
						ctx, cancel := context.WithTimeout(w.ctx, 30*time.Second)
						defer cancel()
						holder := namedIndependentHolder(t, w, tuples[0])
						_, err := w.pool.Exec(ctx, `INSERT INTO kaname.access_binding_emitted_tuples(binding_id,fga_user,relation,object,source) VALUES($1,$2,$3,$4,'binding')`, holder, tuples[1].User, tuples[1].Relation, tuples[1].Object)
						require.NoError(t, err)
						before := namedSnapshot(t, w)
						if rollback {
							namedJournalFailure(t, w, "fga.tuple.delete", parent.Object)
						}
						last := tuples[0]
						if tuples[1].User > last.User {
							last = tuples[1]
						}
						typ, id, _ := strings.Cut(last.Object, ":")
						gate, err := w.pool.Begin(ctx)
						require.NoError(t, err)
						defer func() { _ = gate.Rollback(context.Background()) }()
						var locked string
						require.NoError(t, gate.QueryRow(ctx, `SELECT subject FROM kaname.relation_fact WHERE object_type=$1 AND object_id=$2 AND relation=$3 AND subject=$4 FOR UPDATE`, typ, id, last.Relation, last.User).Scan(&locked))
						independent := append([]service.RelationTuple(nil), tuples...)
						if reverse {
							independent[0], independent[1] = independent[1], independent[0]
						}
						start := func(isParent bool) <-chan error {
							done := make(chan error, 1)
							go func() {
								if isParent {
									done <- w.reg.Unregister(ctx, r3Removal(parent, p))
									return
								}
								tx, err := w.pool.Begin(ctx)
								if err == nil {
									defer func() { _ = tx.Rollback(context.Background()) }()
									err = kanamepg.NewFGAOutboxEmitter().EmitDeleteTx(ctx, tx, independent)
									if err == nil && !rollback {
										err = tx.Commit(ctx)
									}
								}
								done <- err
							}()
							return done
						}
						first := start(parentFirst)
						// При отказе родителя journal fault происходит до child fact locks: такой
						// rollback проверяем отдельно, без выдуманного ожидания на закрытом пути.
						if rollback && parentFirst {
							require.ErrorContains(t, <-first, "NP_TEST_AFTER_CLAIM")
							second := start(false)
							namedWaitForFactWaiters(t, w, 1)
							require.NoError(t, gate.Commit(ctx))
							require.NoError(t, <-second)
						} else {
							namedWaitForFactWaiters(t, w, 1)
							second := start(!parentFirst)
							if !rollback {
								namedWaitForFactWaiters(t, w, 2)
							}
							require.NoError(t, gate.Commit(ctx))
							a, b := <-first, <-second
							if rollback {
								require.NoError(t, a)
								require.ErrorContains(t, b, "NP_TEST_AFTER_CLAIM")
							} else {
								require.NoError(t, a)
								require.NoError(t, b)
							}
						}
						if rollback {
							require.Equal(t, before, namedSnapshot(t, w))
							return
						}
						for _, tuple := range tuples {
							require.Equal(t, 1, r3FactCount(t, w, tuple), "независимый ACTIVE holder сохраняет named и legacy строки")
						}
						var sameFence, inactive bool
						childType, childID, _ := strings.Cut(tuples[0].Object, ":")
						require.NoError(t, w.pool.QueryRow(ctx, `SELECT source_version=$1,NOT active FROM kaname.resource_registration_pointer WHERE object_type=$2 AND object_id=$3`, c, childType, childID).Scan(&sameFence, &inactive))
						require.True(t, sameFence)
						require.True(t, inactive)
						for i, tuple := range tuples {
							v := c
							if i == 1 {
								v = p
							}
							var n int
							require.NoError(t, w.pool.QueryRow(ctx, `SELECT count(*) FROM kaname.fga_outbox WHERE event_type='fga.tuple.delete' AND payload->>'object'=$1 AND payload->>'relation'=$2 AND payload->>'user'=$3 AND (payload->>'source_version')::timestamptz=$4 AND payload->'protect_holders'='true'::jsonb`, tuple.Object, tuple.Relation, tuple.User, v).Scan(&n))
							require.Positive(t, n)
						}
						tx, err := w.pool.Begin(ctx)
						require.NoError(t, err)
						defer func() { _ = tx.Rollback(context.Background()) }()
						for _, tuple := range tuples {
							_, err = tx.Exec(ctx, `DELETE FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND fga_user=$2 AND relation=$3 AND object=$4`, holder, tuple.User, tuple.Relation, tuple.Object)
							require.NoError(t, err)
						}
						require.NoError(t, kanamepg.NewFGAOutboxEmitter().EmitDeleteTx(ctx, tx, independent))
						require.NoError(t, tx.Commit(ctx))
						for _, tuple := range tuples {
							require.Zero(t, r3FactCount(t, w, tuple), "последний держатель действительно удаляет факт")
						}
					})
				}
			}
		}
	}
}

// Обёртка намеренно предоставляет только старую capability, делегируя её
// настоящему PG. Она не должна получить молчаливый fallback на два emit.
type r3LegacyOnlyEmitter struct{ pg *kanamepg.FGAOutboxEmitter }

func (e r3LegacyOnlyEmitter) EmitOrderedWriteTx(ctx context.Context, tx service.Tx, t []service.RelationTuple, v time.Time) error {
	return e.pg.EmitOrderedWriteTx(ctx, tx, t, v)
}
func (e r3LegacyOnlyEmitter) EmitOrderedDeleteTx(ctx context.Context, tx service.Tx, t []service.RelationTuple, v time.Time) error {
	return e.pg.EmitOrderedDeleteTx(ctx, tx, t, v)
}

func TestNamedPointer_MissingCombinedDeleteCapabilityRollsBack(t *testing.T) {
	w, parent, tuples, _, p := r3MixedWorld(t, false)
	before := namedSnapshot(t, w)
	uc := internaliam.NewRegisterResourceUseCase(r3LegacyOnlyEmitter{kanamepg.NewFGAOutboxEmitter()}, kanamepg.NewResourceMirrorEmitter(), kanamepg.NewPoolTxBeginner(w.pool), kanamepg.NewCatalogTypeReader(), kanamepg.NewPublicReadPublisher(), accessbindingapp.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), catalog.Fixed{F: w.facts}), kanamepg.NewRegistrationAudit(), kanamepg.NewRegistrationScopeReader()).WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "probemod"}).WithObjectReconciler(w.rec, nil)
	require.Error(t, uc.Unregister(w.ctx, r3Removal(parent, p)))
	require.Equal(t, before, namedSnapshot(t, w))
	require.NoError(t, w.reg.Unregister(w.ctx, r3Removal(parent, p)))
	for _, tuple := range tuples {
		require.Zero(t, r3FactCount(t, w, tuple))
	}
}

func TestNamedPointer_MixedWithdrawalSeesQueuedIndependentHolder(t *testing.T) {
	for _, commit := range []bool{false, true} {
		for _, opposite := range []bool{false, true} {
			t.Run(fmt.Sprintf("commit=%t/opposite=%t", commit, opposite), func(t *testing.T) {
				w, parent, tuples, _, p := r3MixedWorld(t, opposite)
				ctx, cancel := context.WithTimeout(w.ctx, 30*time.Second)
				defer cancel()
				holder := namedIndependentHolder(t, w, tuples[0])
				_, err := w.pool.Exec(ctx, `DELETE FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND object=$2`, holder, tuples[0].Object)
				require.NoError(t, err)
				grant, err := w.pool.Begin(ctx)
				require.NoError(t, err)
				defer func() { _ = grant.Rollback(context.Background()) }()
				for _, tuple := range tuples {
					_, err = grant.Exec(ctx, `INSERT INTO kaname.access_binding_emitted_tuples(binding_id,fga_user,relation,object,source) VALUES($1,$2,$3,$4,'binding')`, holder, tuple.User, tuple.Relation, tuple.Object)
					require.NoError(t, err)
				}
				require.NoError(t, kanamepg.NewFGAOutboxEmitter().EmitWriteTx(ctx, grant, tuples))
				done := make(chan error, 1)
				go func() { done <- w.reg.Unregister(ctx, r3Removal(parent, p)) }()
				namedWaitForFactWaiters(t, w, 1)
				if commit {
					require.NoError(t, grant.Commit(ctx))
				} else {
					require.NoError(t, grant.Rollback(ctx))
				}
				require.NoError(t, <-done)
				for _, tuple := range tuples {
					want := 0
					if commit {
						want = 1
					}
					require.Equal(t, want, r3FactCount(t, w, tuple), "holder перечитывается отдельным снимком после fact lock")
				}
				if commit {
					tx, err := w.pool.Begin(ctx)
					require.NoError(t, err)
					defer func() { _ = tx.Rollback(context.Background()) }()
					_, err = tx.Exec(ctx, `DELETE FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND object=$2`, holder, tuples[0].Object)
					require.NoError(t, err)
					require.NoError(t, kanamepg.NewFGAOutboxEmitter().EmitDeleteTx(ctx, tx, tuples))
					require.NoError(t, tx.Commit(ctx))
					for _, tuple := range tuples {
						require.Zero(t, r3FactCount(t, w, tuple))
					}
				}
			})
		}
	}
}
