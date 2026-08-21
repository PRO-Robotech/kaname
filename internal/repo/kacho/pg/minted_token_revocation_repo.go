// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// MintedTokenRevocationRepo — хранилище отзывов токенов, отчеканенных
// платформой (задача #897).
//
// Одна строка на субъекта: «всё, выпущенное раньше этого момента,
// недействительно». Отзыв действует вперёд — выпущенное после снова
// действительно, поэтому отзыв снимает выданное, а не блокирует принципала
// навсегда.
type MintedTokenRevocationRepo struct {
	pool *pgxpool.Pool
}

// NewMintedTokenRevocationRepo — построитель.
func NewMintedTokenRevocationRepo(pool *pgxpool.Pool) *MintedTokenRevocationRepo {
	return &MintedTokenRevocationRepo{pool: pool}
}

// RevokedBefore возвращает момент, раньше которого токены субъекта
// недействительны.
//
// Отсутствие записи — ЗАКОННЫЙ ответ «отзыва нет», а не ошибка: пустое обязано
// означать пусто, и вызывающий, получивший ошибку там, где отзыва просто нет,
// закрылся бы на каждом запросе.
func (r *MintedTokenRevocationRepo) RevokedBefore(ctx context.Context, subject string) (time.Time, bool, error) {
	const q = `SELECT revoke_before FROM kacho_iam.minted_token_revocations WHERE subject = $1`
	var at time.Time
	err := r.pool.QueryRow(ctx, q, subject).Scan(&at)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, wrapPgErr(err, "TokenRevocation", subject)
	}
	return at, true, nil
}

// Revoke объявляет недействительными все токены субъекта, выпущенные раньше
// названного момента.
//
// Идемпотентна и МОНОТОННА: повторный отзыв не может отодвинуть границу назад,
// иначе повтор запроса вернул бы к жизни уже отозванное. Это выражено самим
// оператором, а не проверкой-перед-записью: под конкуренцией «прочитать,
// сравнить, записать» дало бы откат границы.
func (r *MintedTokenRevocationRepo) Revoke(ctx context.Context, subject string, before time.Time, reason, decidedBy string) error {
	if strings.TrimSpace(subject) == "" {
		return fmt.Errorf("%w: revocation must name its subject", iamerr.ErrInvalidArg)
	}
	if strings.TrimSpace(decidedBy) == "" {
		return fmt.Errorf("%w: revocation must name who decided it", iamerr.ErrInvalidArg)
	}
	const q = `INSERT INTO kacho_iam.minted_token_revocations (subject, revoke_before, reason, revoked_by)
		VALUES ($1,$2,$3,$4)
		ON CONFLICT (subject) DO UPDATE
		   SET revoke_before = GREATEST(kacho_iam.minted_token_revocations.revoke_before, EXCLUDED.revoke_before),
		       reason        = EXCLUDED.reason,
		       revoked_by    = EXCLUDED.revoked_by,
		       updated_at    = now()`
	if _, err := r.pool.Exec(ctx, q, subject, before, reason, decidedBy); err != nil {
		return wrapPgErr(err, "TokenRevocation", subject)
	}
	return nil
}
