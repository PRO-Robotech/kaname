// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	clusterapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/cluster"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/authzsnapshot"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestCatalogPublicationRechecksOperatorAfterAuthorityWait(t *testing.T) {
	for _, revokeCommitted := range []bool{false, true} {
		t.Run(fmt.Sprintf("revoke-committed=%t", revokeCommitted), func(t *testing.T) {
			f := newClusterParticipantFixture(t, false)
			r := f.r
			// У исходного администратора временная выдача. Публикующему
			// выдаём постоянную, а keeper остаётся вторым постоянным администратором.
			op, err := f.grant.Execute(f.ctx(), iamv1.ClusterGrantSubjectType_USER, f.target)
			require.NoError(t, err)
			require.True(t, op.GetDone())
			require.Nil(t, op.GetError())
			f.native(t, f.target, true)
			fullContractActivate(t, r)
			owner := lifecycleOwner(r)
			active, err := owner.BootstrapCatalogPublication(r.ctx, r.bundle, nil)
			require.NoError(t, err)
			reader := kanamepg.NewCatalogRepo(r.runtime)
			snapshot, err := reader.LoadActivePublication(r.ctx)
			require.NoError(t, err)
			pinned, err := authzsnapshot.WithContext(declarerCtx(r.ctx, f.target), &snapshot)
			require.NoError(t, err)
			contract, err := kanamepg.NewPublishedFullWriterContract(pinned, r.repo, active)
			require.NoError(t, err)
			writer, err := kanamepg.NewCatalogWriteRepo(r.runtime).WithFullWriterContract(contract)
			require.NoError(t, err)
			full, err := r.repo.WithFullWriterContract(contract)
			require.NoError(t, err)
			participant, err := kanamepg.NewClusterAdminParticipant(r.ctx, full, active.Bundle)
			require.NoError(t, err)
			clusterapp.NewHandler(nil, f.grant, f.revoke, nil).WithAdminTxBeginner(participant)

			document := []byte(`apiVersion: iam/v1
module: erp
revision: 1
resources:
  - name: contract
    objectType: erp_contract
    parents: [project]
    producer: authored
    verbs: [get]
`)
			plan, err := modulecatalog.PlanCatalogPublication(pinned, writer, "erp", document, 8192)
			require.NoError(t, err, "оператор публикации допущен до отзыва полномочий")
			// Сравниваем строки целиком. Операция и аудит отзыва проверяются отдельно.
			publicationState := func() []string {
				t.Helper()
				var rows []string
				for _, relation := range []string{"catalog_module", "catalog_resource", "catalog_verb", "module_part_revision", "publication_model_revision", "authority_publication_activation"} {
					var value string
					require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT COALESCE(jsonb_agg(to_jsonb(x) ORDER BY to_jsonb(x)::text),'[]'::jsonb)::text FROM kaname.`+relation+` x`).Scan(&value))
					rows = append(rows, value)
				}
				return rows
			}
			before := publicationState()
			appliedBefore := auditRowsOfType(t, r.ctx, r.admin, modulecatalog.AppliedEventType)
			revokeAuditBefore := f.auditCount(t, f.target)
			ctx, cancel := context.WithTimeout(pinned, 15*time.Second)
			defer cancel()
			release := make(chan struct{})
			gate := &publicationRevokeAuditGate{
				real: kanamepg.NewAuditOutboxEmitter(r.runtime), ready: make(chan int, 1),
				release: release, rollback: !revokeCommitted,
			}
			f.revoke.WithAuditEmitter(gate)
			revoked := lifecycleAsync(t, ctx, func(ctx context.Context) error {
				_, err := f.revoke.Execute(declarerCtx(ctx, f.keeper), iamv1.ClusterGrantSubjectType_USER, f.target)
				return err
			})
			var blocker int
			select {
			case blocker = <-gate.ready:
			case err := <-revoked:
				t.Fatalf("отзыв завершился до записи аудита: %v", err)
			case <-ctx.Done():
				t.Fatal("отзыв не дошёл до записи аудита до истечения срока")
			}
			observed := &publicationCallbackObserver{CatalogPublicationTxRunner: writer}
			var result modulecatalog.PublishedModel
			published := lifecycleAsync(t, ctx, func(ctx context.Context) error {
				var err error
				result, err = modulecatalog.ApplyCatalogPublication(ctx, observed, "erp", document, 8192, plan.StateToken)
				return err
			})
			waiter := receiptWaitForBlocker(t, ctx, r.admin, blocker)
			var globalWait bool
			require.NoError(t, r.admin.QueryRow(ctx, `
				SELECT EXISTS (
					SELECT 1 FROM pg_stat_activity
					WHERE pid = $1 AND $2 = ANY(pg_blocking_pids(pid))
					AND wait_event_type = 'Lock' AND wait_event = 'advisory'
					AND query = 'SELECT kaname.authority_installation_enter_v3($1,$2,$3,$4)'
				)`, waiter, blocker).Scan(&globalWait))
			require.True(t, globalWait, "публикация ждёт транзакцию отзыва на входе под ограду полномочий")
			require.Zero(t, observed.calls.Load())
			close(release)
			revokeErr := lifecycleResult(t, ctx, revoked)
			publishErr := lifecycleResult(t, ctx, published)
			if revokeCommitted {
				require.NoError(t, revokeErr)
				f.native(t, f.target, false)
				require.Equal(t, revokeAuditBefore+1, f.auditCount(t, f.target))
				require.ErrorIs(t, publishErr, modulecatalog.ErrPublicationOperatorDenied)
				require.Zero(t, observed.calls.Load(), "отказ по полномочиям происходит до тела публикации")
				require.Equal(t, modulecatalog.PublishedModel{}, result)
				require.Equal(t, before, publicationState())
				require.Equal(t, appliedBefore, auditRowsOfType(t, r.ctx, r.admin, modulecatalog.AppliedEventType))
				stillActive, err := reader.LoadActivePublication(r.ctx)
				require.NoError(t, err)
				require.Equal(t, snapshot.Revision, stillActive.Revision)
				require.Equal(t, snapshot.Digest, stillActive.Digest)
				require.Equal(t, snapshot.CatalogID, stillActive.CatalogID)
			} else {
				require.Equal(t, codes.Internal, status.Code(revokeErr), "в контрольном случае отзыв откатывается после вставки аудита")
				f.native(t, f.target, true)
				require.Equal(t, revokeAuditBefore, f.auditCount(t, f.target))
				require.NoError(t, publishErr)
				require.Equal(t, int32(1), observed.calls.Load())
				require.Equal(t, plan.Model, result)
				require.NotEqual(t, before, publicationState())
				require.Equal(t, appliedBefore+1, auditRowsOfType(t, r.ctx, r.admin, modulecatalog.AppliedEventType))
				// Фиксация манифеста записывает новую редакцию. Читатели
				// получают её только после штатной активации модели.
				_, err := reader.LoadActivePublication(r.ctx)
				require.ErrorIs(t, err, authzsnapshot.ErrUnconfirmed)
				pending, err := owner.LoadPublicationAuthorityBundle(r.ctx)
				require.NoError(t, err)
				require.Equal(t, snapshot.Revision+1, pending.Revision)
				require.Equal(t, result.Revision, pending.Revision)
				advanced, err := owner.AdvanceNextCatalogPublication(r.ctx, pending)
				require.NoError(t, err)
				require.True(t, advanced)
				nowActive, err := reader.LoadActivePublication(r.ctx)
				require.NoError(t, err)
				require.Equal(t, result.Revision, nowActive.Revision)
				require.Equal(t, result.Digest, nowActive.Digest)
				require.Equal(t, result.CatalogID, nowActive.CatalogID)
			}
			authorityWaitReleased(t, r.runtime)
		})
	}
}

func TestCatalogPublicationRechecksExpiryAfterCatalogWait(t *testing.T) {
	for _, expiresDuringWait := range []bool{false, true} {
		t.Run(fmt.Sprintf("expires-during-wait=%t", expiresDuringWait), func(t *testing.T) {
			f := newClusterParticipantFixture(t, false)
			r := f.r
			ttl := "1 hour"
			if expiresDuringWait {
				ttl = "10 seconds"
			}
			var deadline time.Time
			require.NoError(t, r.admin.QueryRow(r.ctx, `UPDATE kaname.cluster_admin_grants
 SET granted_until=clock_timestamp()+$2::interval
 WHERE subject_type='user' AND subject_id=$1 RETURNING granted_until`, f.actor, ttl).Scan(&deadline))
			fullContractActivate(t, r)
			owner := lifecycleOwner(r)
			active, err := owner.BootstrapCatalogPublication(r.ctx, r.bundle, nil)
			require.NoError(t, err)
			snapshot, err := kanamepg.NewCatalogRepo(r.runtime).LoadActivePublication(r.ctx)
			require.NoError(t, err)
			pinned, err := authzsnapshot.WithContext(f.ctx(), &snapshot)
			require.NoError(t, err)
			contract, err := kanamepg.NewPublishedFullWriterContract(pinned, r.repo, active)
			require.NoError(t, err)
			writer, err := kanamepg.NewCatalogWriteRepo(r.runtime).WithFullWriterContract(contract)
			require.NoError(t, err)

			ctx, cancel := context.WithTimeout(pinned, 25*time.Second)
			defer cancel()
			blocker, err := r.admin.Begin(ctx)
			require.NoError(t, err)
			defer policyFixtureRollback(blocker)
			_, err = blocker.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, kanamepg.CatalogLockKey)
			require.NoError(t, err)
			var calls atomic.Int32
			done := lifecycleAsync(t, ctx, func(ctx context.Context) error {
				return writer.RunInCatalogPublicationTx(ctx, func(context.Context, modulecatalog.CatalogPublicationWriter) error {
					calls.Add(1)
					return nil
				})
			})
			blockerPID := int(blocker.Conn().PgConn().PID())
			waiter := receiptWaitForBlocker(t, ctx, r.admin, blockerPID)
			var waiting, stillValid bool
			require.NoError(t, r.admin.QueryRow(ctx, `SELECT
 EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND $2=ANY(pg_blocking_pids(pid))
  AND query='SELECT pg_advisory_xact_lock(hashtext($1))'), clock_timestamp() < $3`,
				waiter, blockerPID, deadline).Scan(&waiting, &stillValid))
			require.True(t, waiting, "штатный writer должен ждать замок каталога")
			require.True(t, stillValid, "выдача ещё действует во время ожидания")
			require.Zero(t, calls.Load())
			if expiresDuringWait {
				require.EventuallyWithT(t, func(timer *assert.CollectT) {
					var expired bool
					if assert.NoError(timer, r.admin.QueryRow(ctx, `SELECT clock_timestamp() >= $1`, deadline).Scan(&expired)) {
						assert.True(timer, expired)
					}
				}, 15*time.Second, 50*time.Millisecond)
				f.native(t, f.actor, true) // Физический факт остался, отсечку обеспечивает срок выдачи.
			}
			require.NoError(t, blocker.Rollback(ctx))
			err = lifecycleResult(t, ctx, done)
			if expiresDuringWait {
				require.ErrorIs(t, err, modulecatalog.ErrPublicationOperatorDenied)
				require.Zero(t, calls.Load())
			} else {
				require.NoError(t, err)
				require.Equal(t, int32(1), calls.Load())
			}
			authorityWaitReleased(t, r.runtime)
		})
	}
}

// Приостанавливает транзакцию после отзыва, пересчёта связи и вставки аудита.
// Канал передаёт PID транзакции, а ожидание подтверждает PostgreSQL.
type publicationRevokeAuditGate struct {
	real     *kanamepg.AuditOutboxEmitter
	ready    chan int
	release  <-chan struct{}
	rollback bool
}

func (g *publicationRevokeAuditGate) EmitTx(ctx context.Context, tx service.Tx, event service.AuditEvent) error {
	if err := g.real.EmitTx(ctx, tx, event); err != nil {
		return err
	}
	pg, ok := tx.(pgx.Tx)
	if !ok {
		return errors.New("для проверки аудита отзыва нужна транзакция PostgreSQL")
	}
	select {
	case g.ready <- int(pg.Conn().PgConn().PID()):
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-g.release:
		if g.rollback {
			return errors.New("контрольный откат отзыва после вставки аудита")
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

type publicationCallbackObserver struct {
	modulecatalog.CatalogPublicationTxRunner
	calls atomic.Int32
}

func (r *publicationCallbackObserver) RunInCatalogPublicationTx(ctx context.Context, fn func(context.Context, modulecatalog.CatalogPublicationWriter) error) error {
	return r.CatalogPublicationTxRunner.RunInCatalogPublicationTx(ctx, func(ctx context.Context, writer modulecatalog.CatalogPublicationWriter) error {
		r.calls.Add(1)
		return fn(ctx, writer)
	})
}
