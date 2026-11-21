// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"fmt"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// historicalPreEpochReconcileRunner доступен только тестовой сборке пакета.
// Он сохраняет старую оболочку транзакции, но использует настоящий reconcileStore.
// Современные порты staged/object намеренно не продвигаются через embedding.
type historicalPreEpochReconcileRunner struct {
	pool *pgxpool.Pool
	cat  catalog.Source
}

// Точное тело взято из последнего Up перед границей: миграция20261113190000.
// Проверяется тело prosrc, включая переводы строк между AS $$ и $$;.
const historicalPreEpochSchemaSQL = `SELECT
 (SELECT max(version_id) FROM public.goose_db_version WHERE is_applied)=20261113210000
 AND a.phase='uninitialized' AND p.enforcement='compatibility'
 AND to_regclass('kaname.authority_binding_epoch') IS NULL
 AND to_regclass('kaname.authority_writer_contract') IS NULL
 AND to_regclass('kaname.authority_producer_population_latch') IS NULL
 AND NOT EXISTS(SELECT 1 FROM pg_catalog.pg_proc modern
  JOIN pg_catalog.pg_namespace n ON n.oid=modern.pronamespace
  WHERE n.nspname='kaname' AND (modern.proname LIKE 'authority_binding_epoch%'
   OR modern.proname LIKE '%prelock_admit_v3'
   OR modern.proname IN ('authority_protocol_enter_full_v3',
    'authority_full_contract_validate_v3','_authority_consumer_enter_contract_v3')))
 AND md5(f.prosrc)='a892eb4c89fbe597085252dddcefea22'
 FROM kaname.authority_semantic_identity a CROSS JOIN kaname.authority_writer_protocol p
 JOIN pg_catalog.pg_proc f ON f.oid=to_regprocedure('kaname.authority_protocol_attestation()')
 WHERE a.singleton AND p.singleton`

// NewHistoricalPreEpochReconcileRunner создаёт только исторический тестовый runner.
// Неподходящая схема или strict дают ошибку; production-путь не имеет обхода.
func NewHistoricalPreEpochReconcileRunner(ctx context.Context, pool *pgxpool.Pool, cat catalog.Source) (reconcile.TxRunner, error) {
	if err := requireHistoricalPreEpochSchema(pool.QueryRow(ctx, historicalPreEpochSchemaSQL)); err != nil {
		return nil, err
	}
	return &historicalPreEpochReconcileRunner{pool: pool, cat: cat}, nil
}

func requireHistoricalPreEpochSchema(row pgx.Row) error {
	var exact bool
	if err := row.Scan(&exact); err != nil {
		return fmt.Errorf("исторический reconciler: проверка схемы: %w", err)
	}
	if !exact {
		return fmt.Errorf("исторический reconciler требует точную compatibility-схему20261113210000 до binding epochs")
	}
	return nil
}

// WithTx повторяет прежнюю оболочку Begin/callback/Commit с откатом при ошибке
// или панике, в том числе при отменённом контексте. Каталожный факт берётся один
// раз на транзакцию. Повторная проверка закрывает миграцию после конструктора.
func (a *historicalPreEpochReconcileRunner) WithTx(ctx context.Context, fn func(context.Context, reconcile.ReconcileStore) error) error {
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("исторический reconciler: begin: %w", err)
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer stop()
		_ = tx.Rollback(cleanup)
	}()
	if err := requireHistoricalPreEpochSchema(tx.QueryRow(ctx, historicalPreEpochSchemaSQL)); err != nil {
		return err
	}
	store := &reconcileStore{tx: tx, cat: a.cat.Facts()}
	if err := fn(ctx, store); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("исторический reconciler: commit: %w", err)
	}
	return nil
}
