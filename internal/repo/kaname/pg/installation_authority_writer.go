// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"time"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/authorityprotocol"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// InstallationAuthorityWriter входит в протокол до передачи тела писателя.
func (r *Repository) InstallationAuthorityWriter(ctx context.Context, kind kaname.AuthorityOperation) (kaname.Writer, error) {
	if r == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if r.fullContract != nil {
		ctx = r.fullContract.Context(ctx)
	}
	tx, err := authorityprotocol.OpenParticipant(ctx, r.master, kind)
	if err != nil {
		return nil, err
	}
	return &installationWriteTx{writeTx: &writeTx{readTx: readTx{tx: tx}}}, nil
}

type installationWriteTx struct{ *writeTx }

// Отмена тела не отменяет ограниченное освобождение единственного соединения.
func (w *installationWriteTx) Rollback(ctx context.Context) error {
	return rollbackInstallation(ctx, w.tx)
}

func rollbackInstallation(ctx context.Context, tx pgx.Tx) error {
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	err := tx.Rollback(cleanup)
	if errors.Is(err, pgx.ErrTxClosed) {
		return nil
	}
	return err
}

// Вся мутация остаётся одной попыткой; неопределённый Commit не повторяет тело.
func runInstallationTx(ctx context.Context, pool *pgxpool.Pool, kind kaname.AuthorityOperation, fn func(pgx.Tx) error) (err error) {
	tx, err := authorityprotocol.OpenParticipant(ctx, pool, kind)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, rollbackInstallation(ctx, tx)) }()
	if err = fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

var _ kaname.InstallationAuthorityWriterFactory = (*Repository)(nil)
