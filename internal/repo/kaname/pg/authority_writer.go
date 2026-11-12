// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

// Отдельные двухцелочисленные пространства cluster/account не пересекаются
// друг с другом и с прежними bigint advisory keys (у PostgreSQL иной objsubid).
// Значения фиксированы для совместимости будущих участников протокола.
const (
	authorityClusterNamespace int32 = 0x4b414743
	authorityAccountNamespace int32 = 0x4b414741
	authorityClusterKey       int32 = 0
)

type authorityFence struct {
	mode       kaname.AuthorityFenceMode
	accounts   []domain.AccountID
	decisionAt time.Time
}

func (f authorityFence) Mode() kaname.AuthorityFenceMode { return f.mode }
func (f authorityFence) Accounts() []domain.AccountID    { return slices.Clone(f.accounts) }
func (f authorityFence) DecisionAt() time.Time           { return f.decisionAt }

type authorityWriteTx struct {
	*writeTx
	fence authorityFence
}

func (w *authorityWriteTx) AuthorityFence() kaname.AuthorityFence { return w.fence }

// AuthorityWriter начинает только явно выбранный протокол барьеров. Никаких
// повторов под удерживаемыми замками, повышения режима или выдачи attestation.
// Получение времени после барьеров ещё не доказывает согласованность семантики:
// wiring всех писателей, bundle и DB backstop поставляются отдельно до cutover.
func (r *Repository) AuthorityWriter(ctx context.Context, plan kaname.AuthorityFencePlan) (_ kaname.AuthorityWriter, err error) {
	accounts, err := canonicalAuthorityAccounts(plan)
	if err != nil {
		return nil, err
	}
	tx, err := r.master.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	transferred := false
	defer func() {
		if transferred {
			return
		}
		// Отмена запроса не отменяет обязанность освободить транзакцию и pool slot.
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		defer cancel()
		if rollbackErr := tx.Rollback(cleanup); rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
			err = errors.Join(err, fmt.Errorf("authority writer rollback: %w", rollbackErr))
		}
	}()
	clusterSQL := `SELECT pg_advisory_xact_lock_shared($1::int, $2::int)`
	if plan.Mode == kaname.AuthorityFenceGlobal {
		clusterSQL = `SELECT pg_advisory_xact_lock($1::int, $2::int)`
	}
	if _, err = tx.Exec(ctx, clusterSQL, authorityClusterNamespace, authorityClusterKey); err != nil {
		return nil, fmt.Errorf("authority cluster fence: %w", err)
	}
	if plan.Mode == kaname.AuthorityFenceAccounts {
		ids := make([]string, len(accounts))
		for i, id := range accounts {
			ids[i] = string(id)
		}
		// Порядок именно физических signed int32 ключей PostgreSQL. DISTINCT
		// схлопывает коллизии только для locks, не логический набор snapshot.
		var keys []int32
		rows, queryErr := tx.Query(ctx, `SELECT DISTINCT hashtext(id) AS key FROM unnest($1::text[]) AS account_ids(id) ORDER BY key`, ids)
		if queryErr != nil {
			return nil, fmt.Errorf("authority account keys: %w", queryErr)
		}
		keys, err = pgx.CollectRows(rows, pgx.RowTo[int32])
		if err != nil {
			return nil, fmt.Errorf("authority account keys: %w", err)
		}
		for _, key := range keys {
			if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1::int, $2::int)`, authorityAccountNamespace, key); err != nil {
				return nil, fmt.Errorf("authority account fence: %w", err)
			}
		}
	}
	var decisionAt time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&decisionAt); err != nil {
		return nil, fmt.Errorf("authority decision time: %w", err)
	}
	transferred = true
	return &authorityWriteTx{
		writeTx: &writeTx{readTx: readTx{tx: tx}},
		fence:   authorityFence{mode: plan.Mode, accounts: accounts, decisionAt: decisionAt.UTC()},
	}, nil
}

func canonicalAuthorityAccounts(plan kaname.AuthorityFencePlan) ([]domain.AccountID, error) {
	invalid := func() ([]domain.AccountID, error) { return nil, kaname.ErrInvalidAuthorityFencePlan }
	switch plan.Mode {
	case kaname.AuthorityFenceGlobal:
		if len(plan.Accounts) != 0 {
			return invalid()
		}
		return nil, nil
	case kaname.AuthorityFenceAccounts:
		if len(plan.Accounts) == 0 || len(plan.Accounts) > kaname.MaxAuthorityFenceAccounts {
			return invalid()
		}
	default:
		return invalid()
	}
	accounts := slices.Clone(plan.Accounts)
	for _, id := range accounts {
		if id == "" || strings.TrimSpace(string(id)) != string(id) || strings.ContainsRune(string(id), '\x00') {
			return invalid()
		}
	}
	slices.Sort(accounts)
	return slices.Compact(accounts), nil
}

var _ kaname.AuthorityWriterFactory = (*Repository)(nil)
var _ kaname.AuthorityWriter = (*authorityWriteTx)(nil)
