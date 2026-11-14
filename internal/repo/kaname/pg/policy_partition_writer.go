// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Один pool slot: readonly RR -> rollback -> новый RC на той же connection.
// Внешний API writer владеет lease до Commit/Rollback, включая ошибки Commit.
type policyLeaseTx struct {
	pgx.Tx
	conn *pgxpool.Conn
	once sync.Once
}

func (t *policyLeaseTx) Commit(ctx context.Context) error {
	defer t.once.Do(t.conn.Release)
	return t.Tx.Commit(ctx)
}
func (t *policyLeaseTx) Rollback(ctx context.Context) error {
	defer t.once.Do(t.conn.Release)
	return t.Tx.Rollback(ctx)
}
func policyRollback(ctx context.Context, tx pgx.Tx) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	err := tx.Rollback(cleanup)
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}
func policyRetry(err error) bool {
	var pgerr *pgconn.PgError
	return errors.Is(err, kaname.ErrAuthorityClassificationChanged) || (errors.As(err, &pgerr) && (pgerr.Code == "40001" || pgerr.Code == "40P01" || pgerr.Code == "P1034"))
}

func (p *GrantPolicyWriters) openPolicyWriter(ctx context.Context, in policyWriteRequest) (kaname.SemanticAuthorityWriter, error) {
	if p == nil || p.repo == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	conn, err := p.repo.master.Acquire(ctx)
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if !transferred {
			conn.Release()
		}
	}()
	for attempt := 0; attempt < authorityEntryAttempts; attempt++ {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		snapshot, e := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		if e != nil {
			return nil, e
		}
		plan, e := p.discoverPolicyPlan(ctx, snapshot, in)
		if cleanup := policyRollback(ctx, snapshot); cleanup != nil {
			return nil, errors.Join(e, cleanup)
		}
		if e != nil {
			if policyRetry(e) {
				continue
			}
			return nil, e
		}
		intent := plan.intent(p.bundle)
		if e = validateAuthorityIntent(intent); e != nil {
			return nil, e
		}
		owners, e := json.Marshal(intent.Owners)
		if e != nil {
			return nil, e
		}
		tx, e := conn.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if e != nil {
			return nil, e
		}
		// Не вызываем internal rediscover(owner-only): потерялся бы полный actor
		// footprint. Любое изменение возвращает целую новую RR/RC попытку.
		w, e := p.repo.enterAuthority(ctx, tx, intent, owners, intent.Plan.Mode, intent.Plan.Accounts, false, "decision")
		if e == nil {
			e = p.protectPolicyPlan(ctx, w, plan)
		}
		if e != nil {
			if cleanup := policyRollback(ctx, tx); cleanup != nil {
				return nil, errors.Join(e, cleanup)
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if policyRetry(e) {
				continue
			}
			return nil, e
		}
		w.tx = &policyLeaseTx{Tx: tx, conn: conn}
		transferred = true
		return newSemanticAuthorityWriter(w, p.bundle), nil
	}
	return nil, kaname.ErrAuthorityClassificationChanged
}
