// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
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

// SweepStaleCutoffs убирает отсечки, ставшие БЕССМЫСЛЕННЫМИ, — партией и по
// часам БАЗЫ.
//
// # Предикат бессмысленности — доказательство, а не оценка
//
// Строка отвергает токен, отчеканенный РАНЬШЕ `revoke_before`. Токен живёт не
// дольше `MaxTokenTTL` и принимается с допуском `ClockSkew`. Значит после
// `revoke_before + MaxTokenTTL + ClockSkew` строка не может изменить ни одного
// исхода: всякий токен, который она отвергла бы, к этому моменту уже отвергнут
// собственным сроком.
//
// Момент бессмысленности и порог снятия — РАЗНЫЕ величины: порог больше на
// слагаемое запаса (`RemovalSlack`), потому что читатель отсечки судит в Go
// (`handler/tokenintrospecthttp`, сравнение отметки выпуска токена), а уборка —
// часами базы, и без запаса снятие приходилось бы ровно на границу, где
// источники могут разойтись. Слагаемое приходит входом и вычисляется реестром
// `apps/kacho/retention` из `pkg/tokenpolicy`.
//
// # Горизонт в БУДУЩЕМ предикату не мешает — by construction
//
// Строка с `revoke_before` в будущем условию `revoke_before < now() − порог` не
// удовлетворяет ни при каком значении слагаемых: правая часть меньше `now()`,
// левая больше. Никакого допущения о том, кто и что пишет, для этого не нужно —
// и довод потому переживает появление писателя, называющего будущее.
//
// # Почему уборка, а не объявление «рост приемлем»
//
// Хотелось принять обратное: отсечка появляется при отзыве, отзыв — действие
// оператора, строк не больше числа принципалов. Замер посылку опроверг. Строку
// пишут ТРИГГЕРЫ применённой миграции `898002`, и один из них ключует её
// идентификатором СНЯТОЙ строки клиента: каждый отозванный ключ даёт НОВЫЙ
// субъект, потому что идентификатор клиента неизменяем (ban #15). Слияние по
// первичному ключу здесь есть и не помогает — его нет МЕЖДУ РАЗНЫМИ ключами.
// Темп ротации выбирает арендатор.
//
// Свидетельство «этому субъекту отзывали» уборка не уносит: путь отзыва пишет
// `iam.session.revoked` в `audit_outbox` той же транзакцией. Оперативная таблица
// отсечек — не журнал, и её укорачивание истории не теряет.
//
// Обход идёт по индексу `minted_token_revocations_revoke_before_idx` (миграция
// `20260827112530`): без него уборка шла бы полным перебором.
func (r *MintedTokenRevocationRepo) SweepStaleCutoffs(ctx context.Context, grace time.Duration, batch int) (int64, bool, error) {
	const q = `
DELETE FROM kacho_iam.minted_token_revocations
 WHERE ctid IN (
     SELECT ctid FROM kacho_iam.minted_token_revocations
      WHERE revoke_before < now() - make_interval(secs => $1)
      ORDER BY revoke_before
      LIMIT $2
      FOR UPDATE SKIP LOCKED
 )`
	tag, err := r.pool.Exec(ctx, q, grace.Seconds(), batch)
	if err != nil {
		return 0, false, wrapPgErr(err, "TokenRevocation", "")
	}
	n := tag.RowsAffected()
	return n, n == int64(batch), nil
}
