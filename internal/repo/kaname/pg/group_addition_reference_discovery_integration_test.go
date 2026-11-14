// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/grantpolicy"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/multitracer"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Отсутствие получателя не должно прерывать подготовку полномочий ошибкой
// owner lookup. После настоящего D3 прежняя проверка ссылки одинаково
// отвергает отсутствующую и чужую учётку; своя учётка служит законным близнецом.
func TestGroupAdditionOptionalReferenceMissingMatchesForeignAfterAuthority(t *testing.T) {
	r := writerProtocolRig(t)
	g, uid, local := membershipFixture(t, r)
	foreign := seedSAID(t, r.ctx, r.admin, r.b, "optional-reference-foreign")
	missing := ids.NewID(domain.PrefixServiceAccount)
	writers, err := kanamepg.NewGrantPolicyWriters(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}
	var refusal string
	for _, tc := range []struct {
		name, id string
		allowed  bool
	}{{"foreign", foreign, false}, {"missing", missing, false}, {"local", local, true}} {
		t.Run(tc.name, func(t *testing.T) {
			member := domain.GroupMember{GroupID: g.ID, MemberType: domain.SubjectTypeServiceAccount, MemberID: domain.SubjectID(tc.id)}
			w, err := writers.GroupAdditionAuthorityWriter(r.ctx, member, actor)
			require.NoError(t, err, "подготовка не подменяет позднюю проверку ссылки")
			roleFinalCleanup(t, w)
			if tc.name == "missing" {
				require.Equal(t, kaname.AuthorityFenceGlobal, w.AuthorityFence().Mode())
			}
			require.NoError(t, grantpolicy.RequireGroupAddition(r.ctx, w, actor, member))
			err = w.GroupsW().RequireMemberOfGroupAccount(r.ctx, member)
			if tc.allowed {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, iamerr.ErrReferenceMissing)
				if refusal == "" {
					refusal = err.Error()
				} else {
					require.Equal(t, refusal, err.Error())
				}
			}
			require.NoError(t, w.Rollback(r.ctx))
			membershipCounts(t, r, string(g.ID), "service_account:"+tc.id, 0)
		})
	}
	canceled, cancel := context.WithCancel(r.ctx)
	cancel()
	w, err := writers.GroupAdditionAuthorityWriter(canceled, domain.GroupMember{GroupID: g.ID, MemberType: domain.SubjectTypeServiceAccount, MemberID: domain.SubjectID(missing)}, actor)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, w)
}

// Tracer наблюдает настоящие запросы штатного pool. Мутация выполняется только
// ПОСЛЕ rollback первого RR: GLOBAL identity entry не ждёт удерживаемую RR gate.
// SQL/аргументы/DSN не выводятся; reader и writer не подменяются.
type optionalReferenceConcurrencyTrace struct {
	serviceAccountID   string
	snapshots          atomic.Int32
	presence           atomic.Int32
	protected          atomic.Int32
	pid                atomic.Uint32
	afterFirstSnapshot func(context.Context) error
	mutationErr        error
	inserted           bool
}
type optionalReferenceConcurrencyTraceKey struct{}

func (tr *optionalReferenceConcurrencyTrace) TraceQueryStart(ctx context.Context, conn *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	tr.pid.Store(conn.PgConn().PID())
	kind := ""
	switch {
	case d.SQL == `SELECT kaname.authority_policy_epoch_read($1::text[])`:
		kind = "snapshot"
	case d.SQL == `SELECT EXISTS(SELECT 1 FROM kaname.service_accounts WHERE id=$1)`:
		if len(d.Args) == 1 {
			if id, ok := d.Args[0].(string); ok && id == tr.serviceAccountID {
				kind = "presence"
			}
		}
	case strings.HasPrefix(d.SQL, `SELECT kaname.authority_policy_epoch_lock_for_write(`):
		kind = "protected"
	case strings.EqualFold(strings.TrimSpace(d.SQL), "rollback"):
		kind = "rollback"
	}
	return context.WithValue(ctx, optionalReferenceConcurrencyTraceKey{}, kind)
}
func (tr *optionalReferenceConcurrencyTrace) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryEndData) {
	if d.Err != nil {
		return
	}
	kind, _ := ctx.Value(optionalReferenceConcurrencyTraceKey{}).(string)
	switch kind {
	case "snapshot":
		tr.snapshots.Add(1)
	case "presence":
		tr.presence.Add(1)
	case "protected":
		tr.protected.Add(1)
	case "rollback":
		if tr.snapshots.Load() == 1 && !tr.inserted && tr.afterFirstSnapshot != nil {
			tr.inserted = true
			tr.mutationErr = tr.afterFirstSnapshot(ctx)
		}
	}
}

func TestGroupAdditionOptionalReferenceNativeConcurrency(t *testing.T) {
	for _, order := range []string{"insert_between_rr_and_rc", "insert_waits_for_global_release"} {
		t.Run(order, func(t *testing.T) {
			r := writerProtocolRig(t)
			g, uid, _ := membershipFixture(t, r)
			said := ids.NewID(domain.PrefixServiceAccount)
			member := domain.GroupMember{GroupID: g.ID, MemberType: domain.SubjectTypeServiceAccount, MemberID: domain.SubjectID(said)}
			actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(uid)}
			require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
			ctx, cancel := context.WithTimeout(r.ctx, 10*time.Second)
			defer cancel()
			intent := kaname.AuthorityWriteIntent{Kind: kaname.AuthorityIdentity, Bundle: r.bundle, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}, Owners: []kaname.AuthorityOwnerRef{{Kind: "account", ID: r.a}}}
			const insert = `INSERT INTO kaname.service_accounts(id,account_id,name) VALUES($1,$2,'optional-reference-concurrent')`
			trace := &optionalReferenceConcurrencyTrace{serviceAccountID: said}
			if order == "insert_between_rr_and_rc" {
				trace.afterFirstSnapshot = func(attempt context.Context) error {
					var exists bool
					if err := r.runtime.QueryRow(attempt, `SELECT EXISTS(SELECT 1 FROM kaname.service_accounts WHERE id=$1)`, said).Scan(&exists); err != nil {
						return err
					}
					if exists {
						return errors.New("учётка существовала до конкурентной вставки")
					}
					tx, err := r.runtime.Begin(attempt)
					if err != nil {
						return err
					}
					if err = policyFixtureApply(attempt, tx, intent, insert, said, r.a); err != nil {
						return err
					}
					if err = r.runtime.QueryRow(attempt, `SELECT EXISTS(SELECT 1 FROM kaname.service_accounts WHERE id=$1)`, said).Scan(&exists); err != nil {
						return err
					}
					if !exists {
						return errors.New("конкурентная вставка не сохранила учётку")
					}
					return nil
				}
			}
			cfg := r.runtime.Config()
			cfg.MaxConns, cfg.MinConns = 1, 0
			if cfg.ConnConfig.Tracer == nil {
				cfg.ConnConfig.Tracer = trace
			} else {
				cfg.ConnConfig.Tracer = multitracer.New(cfg.ConnConfig.Tracer, trace)
			}
			pool, err := pgxpool.NewWithConfig(ctx, cfg)
			require.NoError(t, err)
			defer pool.Close()
			writers, err := kanamepg.NewGrantPolicyWriters(ctx, kanamepg.New(pool, nil), r.bundle)
			require.NoError(t, err)
			writer, err := writers.GroupAdditionAuthorityWriter(ctx, member, actor)
			defer policyFixtureRollback(writer)
			require.NoError(t, trace.mutationErr)
			require.NoError(t, err)
			require.EqualValues(t, 1, pool.Stat().AcquiredConns())
			if order == "insert_between_rr_and_rc" {
				// Зафиксированная после RR вставка требует новой попытки discovery.
				// Её может обнаружить точный witness или более полный population token.
				require.True(t, trace.inserted)
				require.EqualValues(t, 2, trace.snapshots.Load())
				t.Logf("повторная подготовка: snapshots=%d protected=%d presence=%d", trace.snapshots.Load(), trace.protected.Load(), trace.presence.Load())
				require.NoError(t, grantpolicy.RequireGroupAddition(ctx, writer, actor, member))
				require.NoError(t, writer.GroupsW().RequireMemberOfGroupAccount(ctx, member))
				require.NoError(t, writer.Rollback(ctx))
			} else {
				require.Equal(t, kaname.AuthorityFenceGlobal, writer.AuthorityFence().Mode())
				require.EqualValues(t, 1, trace.snapshots.Load())
				require.EqualValues(t, 2, trace.presence.Load())
				require.NoError(t, grantpolicy.RequireGroupAddition(ctx, writer, actor, member))
				require.ErrorIs(t, writer.GroupsW().RequireMemberOfGroupAccount(ctx, member), iamerr.ErrReferenceMissing)
				holderPID := trace.pid.Load()
				require.NotZero(t, holderPID)
				// Strict signed INSERT сначала ждёт coordinator. Это не отдельное
				// доказательство root-only wait и не обход attestation для owner.
				done, pid, stop := policyFixtureMutation(t, r, intent, insert, said, r.a)
				defer stop()
				policyFixtureWaitLock(t, r, pid, "advisory")
				var blockedByConsumer bool
				require.NoError(t, r.admin.QueryRow(ctx, `SELECT $2::integer=ANY(pg_blocking_pids($1::integer))`, pid, holderPID).Scan(&blockedByConsumer))
				require.True(t, blockedByConsumer)
				stop()
				require.ErrorIs(t, <-done, context.Canceled)
				var count int
				require.NoError(t, r.admin.QueryRow(ctx, `SELECT count(*) FROM kaname.service_accounts WHERE id=$1`, said).Scan(&count))
				require.Zero(t, count)
				// Второй реальный INSERT обязан завершиться лишь после release.
				done, pid, stop = policyFixtureMutation(t, r, intent, insert, said, r.a)
				defer stop()
				policyFixtureWaitLock(t, r, pid, "advisory")
				require.NoError(t, r.admin.QueryRow(ctx, `SELECT $2::integer=ANY(pg_blocking_pids($1::integer))`, pid, holderPID).Scan(&blockedByConsumer))
				require.True(t, blockedByConsumer)
				select {
				case err := <-done:
					t.Fatalf("INSERT завершился до consumer rollback: %v", err)
				default:
				}
				require.NoError(t, writer.Rollback(ctx))
				require.NoError(t, <-done)
				stop() // cancel/join до окончательных assertions.
			}
			require.EqualValues(t, 0, pool.Stat().AcquiredConns())
			var account string
			require.NoError(t, r.admin.QueryRow(ctx, `SELECT account_id FROM kaname.service_accounts WHERE id=$1`, said).Scan(&account))
			require.Equal(t, r.a, account)
			membershipCounts(t, r, string(g.ID), "service_account:"+said, 0)
		})
	}
}
