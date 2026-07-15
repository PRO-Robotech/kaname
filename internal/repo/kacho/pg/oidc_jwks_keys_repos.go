// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// oidc_jwks_keys_repos.go — oidc_jwks_keys repository (atomic CTE rotation).
//
// This file holds only the OIDC JWKS key repo, actively used by
// jwks_rotation_service.
package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// ───────────────────────────────────────────────────────────────────────────
// OIDCJwksKey repo (CTE atomic rotation; partial UNIQUE WHERE current=true per alg)
// ───────────────────────────────────────────────────────────────────────────

type OIDCJwksKeyRepo struct {
	pool *pgxpool.Pool
}

func NewOIDCJwksKeyRepo(pool *pgxpool.Pool) *OIDCJwksKeyRepo {
	return &OIDCJwksKeyRepo{pool: pool}
}

const jwkCols = `kid, alg, current, rotated_at, expires_at, public_key_pem,
                 private_key_pem_encrypted, created_at`

func (r *OIDCJwksKeyRepo) Get(ctx context.Context, kid string) (domain.OIDCJwksKey, error) {
	row := r.pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM oidc_jwks_keys WHERE kid = $1`, jwkCols), kid)
	out, err := scanJwksKey(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.OIDCJwksKey{}, iamerr.Wrapf(iamerr.ErrNotFound, "JwksKey %s not found", kid)
	}
	if err != nil {
		return domain.OIDCJwksKey{}, mapErr(err, "", kid)
	}
	return out, nil
}

// GetCurrent — текущий ключ для alg (current=true).
func (r *OIDCJwksKeyRepo) GetCurrent(ctx context.Context, alg domain.JWKSAlg) (domain.OIDCJwksKey, error) {
	row := r.pool.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM oidc_jwks_keys WHERE alg = $1 AND current = true`, jwkCols),
		string(alg))
	out, err := scanJwksKey(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.OIDCJwksKey{}, iamerr.Wrapf(iamerr.ErrNotFound, "no current JwksKey for alg %s", alg)
	}
	if err != nil {
		return domain.OIDCJwksKey{}, mapErr(err, "", string(alg))
	}
	return out, nil
}

// ListCurrent — все текущие (current=true) ключи, по одному на alg. Read-only;
// используется InternalIAMService.GetJWKSStatus (admin observability). НЕ
// возвращает private_key (он внутри jwkCols, но scanJwksKey не сериализует его
// наружу публично — caller (handler) маппит только публичные поля).
func (r *OIDCJwksKeyRepo) ListCurrent(ctx context.Context) ([]domain.OIDCJwksKey, error) {
	rows, err := r.pool.Query(ctx,
		fmt.Sprintf(`SELECT %s FROM oidc_jwks_keys WHERE current = true ORDER BY alg`, jwkCols))
	if err != nil {
		return nil, mapErr(err, "JwksKey.ListCurrent", "")
	}
	defer rows.Close()
	var out []domain.OIDCJwksKey
	for rows.Next() {
		k, serr := scanJwksKey(rows)
		if serr != nil {
			return nil, mapErr(serr, "JwksKey.ListCurrent.scan", "")
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// InsertBootstrap — первая row для alg (предполагает пустой index для этого alg).
// SQLSTATE 23505 если current=true уже существует для alg.
func (r *OIDCJwksKeyRepo) InsertBootstrap(ctx context.Context, txh service.Tx, k domain.OIDCJwksKey) (domain.OIDCJwksKey, error) {
	tx := txAsPgx(txh)
	const q = `
		INSERT INTO oidc_jwks_keys (kid, alg, current, rotated_at, expires_at,
		                             public_key_pem, private_key_pem_encrypted, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, COALESCE($8, now()))
		RETURNING ` + jwkCols
	var rotated any
	if k.RotatedAt != nil {
		rotated = *k.RotatedAt
	}
	row := tx.QueryRow(ctx, q,
		k.KID, string(k.Alg), k.Current, rotated, k.ExpiresAt,
		k.PublicKeyPEM, k.PrivateKeyPEMEncrypted, nullableTime(k.CreatedAt),
	)
	out, err := scanJwksKey(row)
	if err != nil {
		return domain.OIDCJwksKey{}, mapErr(err, "", k.KID)
	}
	return out, nil
}

// Rotate — atomic CTE swap. Single statement `WITH old AS (UPDATE …
// current=false), guard AS (SELECT 1 FROM old HAVING count(*)=1) INSERT …
// current=true SELECT … FROM guard`. Constraint validation at statement end —
// partial UNIQUE invariant satisfied.
//
// Guard semantics: если для данного `alg` нет текущего ключа (empty initial
// state), CTE `old` пуст → `guard` пуст → INSERT-SELECT не возвращает rows →
// RETURNING пуст → pgx.ErrNoRows → ErrFailedPrecondition с явным сообщением
// «use InsertBootstrap instead».
//
// Без guard CTE'а INSERT VALUES(...) проигнорировал бы пустой `old` и молча
// сработал как InsertBootstrap, что нарушает контракт Rotate (см. docstring).
//
// Concurrency: сериализуем concurrent Rotate(alg=X) per-alg через
// `pg_advisory_xact_lock(hashtext('jwks_rotate_' || alg))`. Lock живет до
// commit/rollback TX, автоматически освобождается на конец TX.
//
// Гарантия: data-integrity invariant `count(*) WHERE alg=X AND current=true ≤ 1`
// (партиальный UNIQUE INDEX `oidc_jwks_keys_current_unique`). Concurrent
// rotations НЕ нарушают этот инвариант — сериализуются в очередь, каждая
// демотирует current-row, вставляет новую current=true row. End-state — ровно
// одна current row на alg.
//
// Сериализация дает cascading-rotation — каждая TX в очереди demote'ит то,
// что committed предшественник, и inserts свою. CAS-style "only first wins"
// можно добавить через extension API (caller передает expected from_kid).
func (r *OIDCJwksKeyRepo) Rotate(ctx context.Context, txh service.Tx, newKey domain.OIDCJwksKey) (domain.OIDCJwksKey, error) {
	tx := txAsPgx(txh)
	if newKey.RotatedAt != nil {
		return domain.OIDCJwksKey{},
			iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument: new key must have rotated_at IS NULL")
	}
	if !newKey.Current {
		return domain.OIDCJwksKey{},
			iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument: new key must have current=true")
	}

	// Per-alg advisory_xact_lock — сериализует concurrent Rotate(alg=X) до
	// commit/rollback. Защищает invariant партиального UNIQUE INDEX
	// `(alg) WHERE current=true`: каждая ротация атомарно demote+insert, без
	// race-window между двумя TX, где обе видят current=true row и обе пробуют
	// INSERT current=true.
	if _, err := tx.Exec(ctx,
		`SELECT pg_advisory_xact_lock(hashtext($1))`,
		"jwks_rotate_"+string(newKey.Alg),
	); err != nil {
		return domain.OIDCJwksKey{}, mapErr(err, "JwksKey.Rotate.lock", newKey.KID)
	}

	const q = `
		WITH old AS (
		    UPDATE oidc_jwks_keys
		       SET current = false, rotated_at = now()
		     WHERE alg = $2 AND current = true
		    RETURNING kid
		),
		guard AS (
		    SELECT 1 AS ok FROM old HAVING count(*) = 1
		)
		INSERT INTO oidc_jwks_keys (kid, alg, current, rotated_at, expires_at,
		                             public_key_pem, private_key_pem_encrypted, created_at)
		SELECT $1, $2, true, NULL, $3, $4, $5, COALESCE($6, now())
		  FROM guard
		RETURNING ` + jwkCols
	// Args: 1=kid, 2=alg, 3=expires_at, 4=public, 5=private, 6=created_at.
	row := tx.QueryRow(ctx, q,
		newKey.KID, string(newKey.Alg), newKey.ExpiresAt,
		newKey.PublicKeyPEM, newKey.PrivateKeyPEMEncrypted, nullableTime(newKey.CreatedAt),
	)
	out, err := scanJwksKey(row)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return domain.OIDCJwksKey{}, iamerr.Wrapf(iamerr.ErrFailedPrecondition,
				"no current jwks key for alg %s; use InsertBootstrap instead", newKey.Alg)
		}
		return domain.OIDCJwksKey{}, mapErr(err, "JwksKey.Rotate", newKey.KID)
	}
	return out, nil
}

func scanJwksKey(row pgx.Row) (domain.OIDCJwksKey, error) {
	var (
		k         domain.OIDCJwksKey
		rotatedAt sql.NullTime
	)
	if err := row.Scan(
		&k.KID, (*string)(&k.Alg), &k.Current, &rotatedAt, &k.ExpiresAt,
		&k.PublicKeyPEM, &k.PrivateKeyPEMEncrypted, &k.CreatedAt,
	); err != nil {
		return domain.OIDCJwksKey{}, err
	}
	if rotatedAt.Valid {
		t := rotatedAt.Time
		k.RotatedAt = &t
	}
	return k, nil
}
