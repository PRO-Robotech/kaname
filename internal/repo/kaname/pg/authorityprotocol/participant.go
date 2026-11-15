// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authorityprotocol

import (
	"context"
	"errors"
	"time"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OpenParticipant открывает GLOBAL mutation TX до любых business locks.
// Фаза и identity берутся сервером: этот порт не строит bundle и не выдаёт
// semantic/native proof. Вызвавший владеет успешной TX и завершает её сам.
func OpenParticipant(ctx context.Context, pool *pgxpool.Pool, kind kaname.AuthorityOperation) (pgx.Tx, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if pool == nil {
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	if profile, present := contractFromContext(ctx); present {
		if !profile.UsesPool(pool) {
			return nil, kaname.ErrInvalidAuthorityFencePlan
		}
		return openParticipantProfile(ctx, pool.BeginTx, kind, profile)
	}
	return openParticipant(ctx, pool.BeginTx, kind)
}

func openParticipant(ctx context.Context, begin func(context.Context, pgx.TxOptions) (pgx.Tx, error), kind kaname.AuthorityOperation) (pgx.Tx, error) {
	return openParticipantProfile(ctx, begin, kind, nil)
}
func openParticipantProfile(ctx context.Context, begin func(context.Context, pgx.TxOptions) (pgx.Tx, error), kind kaname.AuthorityOperation, profile *FullContract) (pgx.Tx, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Только actual installation/maintenance families. Resource имеет свой
	// закрытый runner; grant decision не получает этот обход source planning.
	switch kind {
	case kaname.AuthorityCatalog, kaname.AuthorityRole, kaname.AuthorityBinding,
		kaname.AuthorityIdentity, kaname.AuthorityCluster:
	default:
		return nil, kaname.ErrInvalidAuthorityFencePlan
	}
	tx, err := begin(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
	if err != nil {
		return nil, err
	}
	var abi int
	wantABI := 2
	if profile == nil {
		err = tx.QueryRow(ctx, `SELECT kaname.authority_installation_enter_v2($1)`, string(kind)).Scan(&abi)
	} else {
		wantABI = 3
		err = tx.QueryRow(ctx, `SELECT kaname.authority_installation_enter_v3($1,$2,$3,$4)`, string(kind), profile.model, profile.catalog, profile.projector).Scan(&abi)
	}
	if err == nil && abi != wantABI {
		err = kaname.ErrSemanticIdentityUnavailable
	}
	if err == nil {
		err = ctx.Err()
	}
	if err == nil {
		return tx, nil
	}
	cleanup, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	rollbackErr := tx.Rollback(cleanup)
	cancel()
	if rollbackErr != nil && !errors.Is(rollbackErr, pgx.ErrTxClosed) {
		err = errors.Join(err, rollbackErr)
	}
	return nil, err
}
