// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// oauth_ceremony_access_token.go — запись ВЫПУСКА токена доступа собственной
// церемонии: идентификатор выпуска → семейство (задача PRO-Robotech/kaname#319,
// решение К10 вариант А; миграция
// `20260923231545_access_token_belongs_to_its_family.sql`).
//
// # ЗАЧЕМ ЭТА ЗАПИСЬ
//
// Токен доступа сверяют по подписи, и поверхность, принимающая его, строки
// гранта не читает. Отзыв семейства доезжает до неё только так: поверхность
// спрашивает о выпуске по его идентификатору, а запись выпуска отвечает,
// жива ли его семья.
//
// # ЧТО ДЕРЖИТ БАЗА, А НЕ ЭТОТ ФАЙЛ
//
//   - единственность идентификатора — первичный ключ;
//   - выпуск только в ЖИВОЕ семейство и доезд отзыва до записи — ключ
//     `(family_id, family_live) → token_families (id, live)` с каскадом правки;
//   - «семейство снято» не превращается в «выпуск ничей» — действие ключа на
//     удаление `SET NULL (family_live)`.
//
// Поэтому ни писатель, ни читатель здесь не проверяют семейство ПЕРЕД
// записью: условие и запись исполняет сам движок под замком ключа (ban #10).

import (
	"context"
	stderrors "errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/corelib/db/pgfault"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// issuanceFamilyFK — ограничение, которым база отвергает выпуск в
// неизвестное либо отозванное семейство.
const issuanceFamilyFK = "access_tokens_family_fk"

// recordIssuanceSQL — заведение записи выпуска. Живости семейства оператор
// НЕ пишет: её берёт умолчание, и ключ сверяет его с живым семейством.
const recordIssuanceSQL = `
INSERT INTO kaname.access_tokens (jti, family_id, issued_at, expires_at)
VALUES ($1, $2, $3, $4)`

// familyRevokedOfIssuanceSQL — ЕДИНСТВЕННЫЙ оператор, читающий решение «отозвано
// ли семейство выпуска». Второго написания в дереве нет и быть не должно: его
// держит гейт `internal/check`
// `TestFamilyVerdictHasOneReaderAndEverySurfaceAsksTheRule`.
//
// `IS NOT TRUE`, а не `= false` и не `NOT family_live`: пустая живость — снятое
// семейство — обязана давать «отозван». Сравнение на ложь дало бы на ней
// «не отозван», отрицание — пустое значение, то есть снятие семейства стало бы
// допуском его токенов.
const familyRevokedOfIssuanceSQL = `SELECT family_live IS NOT TRUE FROM kaname.access_tokens WHERE jti = $1`

// sweepExpiredIssuancesSQL — уборка записей, чей токен уже не примет ни одна
// поверхность. Партией и по часам БАЗЫ, как у соседних уборщиков.
const sweepExpiredIssuancesSQL = `
DELETE FROM kaname.access_tokens
 WHERE ctid IN (
     SELECT ctid FROM kaname.access_tokens
      WHERE expires_at < now() - make_interval(secs => $1)
      ORDER BY expires_at
      LIMIT $2
      FOR UPDATE SKIP LOCKED
 )`

// RecordAccessToken записывает выпуск токена доступа в его семейство.
//
// Зовёт его выпуск токена доступа церемонии — ПОСЛЕ подписи и ДО того, как
// токен уедет клиенту: токен, чья запись не легла, отзывом семейства не
// снимается, поэтому отказ записи обязан ронять выдачу.
//
// Семейства нет либо оно отозвано — `domain.ErrAccessTokenFamilyNotLive`: это
// решает ключ базы, а не проверка перед вставкой.
func (r *OAuthCeremonyRepo) RecordAccessToken(ctx context.Context, jti, familyID string, issuedAt, expiresAt time.Time) error {
	if jti == "" {
		return fmt.Errorf("Illegal argument access_token.jti: required")
	}
	if familyID == "" {
		return fmt.Errorf("Illegal argument access_token.family_id: required")
	}
	if issuedAt.IsZero() || expiresAt.IsZero() {
		return fmt.Errorf("Illegal argument access_token: issued_at and expires_at are required")
	}
	if !expiresAt.After(issuedAt) {
		return fmt.Errorf("Illegal argument access_token.expires_at: must be after issued_at")
	}
	if _, err := r.pool.Exec(ctx, recordIssuanceSQL, jti, familyID, issuedAt, expiresAt); err != nil {
		if f := pgfault.Classify(err); f.Class == pgfault.ForeignKey && f.Constraint == issuanceFamilyFK {
			return fmt.Errorf("%w: family %s", domain.ErrAccessTokenFamilyNotLive, familyID)
		}
		return wrapPgErr(err, "AccessToken", familyID)
	}
	return nil
}

// SweepExpiredAccessTokens снимает записи выпуска, чей срок вышел раньше, чем
// `now() − grace` часами базы. Возвращает число снятых и признак «партия ушла
// полной».
//
// Порог — функция предиката читателя: каждая поверхность отвергает истёкший
// токен по его сроку с допуском `ClockSkew`, и после порога строка ни одного
// исхода не меняет. Величину слагаемых задаёт реестр уборки
// (`apps/kaname/retention`), не этот файл.
func (r *OAuthCeremonyRepo) SweepExpiredAccessTokens(ctx context.Context, grace time.Duration, batch int) (int64, bool, error) {
	if batch <= 0 {
		return 0, false, fmt.Errorf("Illegal argument access_token sweep batch: must be positive")
	}
	tag, err := r.pool.Exec(ctx, sweepExpiredIssuancesSQL, grace.Seconds(), batch)
	if err != nil {
		return 0, false, wrapPgErr(err, "AccessToken", "")
	}
	n := tag.RowsAffected()
	return n, n == int64(batch), nil
}

// familyRevokedOf — ответ записи выпуска: отозвано ли семейство выпуска с этим
// идентификатором.
//
// Записи нет — выпуск семейству не принадлежит, и это ЗАКОННЫЙ ответ «нет», а не
// ошибка: токены вне церемонии (выдача по утверждению клиента и прочие) записи
// выпуска не имеют и судятся отсечками по ключам. Ошибка хранилища — третий
// исход, вызывающий закрывается сам.
func familyRevokedOf(ctx context.Context, q rowQuerier, jti string) (bool, error) {
	var revoked bool
	err := q.QueryRow(ctx, familyRevokedOfIssuanceSQL, jti).Scan(&revoked)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, wrapPgErr(err, "AccessToken", "")
	}
	return revoked, nil
}

// FamilyRevoked — ответ о семействе выпуска для авторитета отзыва и читателя
// предъявленного (порт `tokenrevocation.Reader`). Оператор — ТОТ ЖЕ, что у
// `IsRevoked` службы отзыва: решение одно.
func (r *MintedTokenRevocationRepo) FamilyRevoked(ctx context.Context, jti string) (bool, error) {
	return familyRevokedOf(ctx, r.pool, jti)
}

// FamilyRevoked — ответ о семействе выпуска для `IsRevoked` службы отзыва.
// Оператор — ТОТ ЖЕ, что у поверхностей предъявления.
func (s *SessionRevocationsAdapter) FamilyRevoked(ctx context.Context, jti string) (bool, error) {
	return familyRevokedOf(ctx, s.pool, jti)
}
