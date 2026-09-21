// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// user_token_revocations_repo.go — pool-scoped repo for the per-user
// "revoke-all-before" cutoff (migration 0012). Backs admin ForceLogout +
// Revoke(revoke_all_user_tokens); the refresh-hook reads RevokedBefore to deny
// a token whose session auth_time is at-or-before the cutoff.
package pg

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// UserTokenRevocationRepo — pool-scoped (autocommit-style single-statement
// writes; no CQRS Writer-TX overhead — these are stateless hook / internal-RPC
// side-effects, same pattern as SessionRevocationsAdapter).
type UserTokenRevocationRepo struct {
	pool *pgxpool.Pool
}

// NewUserTokenRevocationRepo — constructor.
func NewUserTokenRevocationRepo(pool *pgxpool.Pool) *UserTokenRevocationRepo {
	return &UserTokenRevocationRepo{pool: pool}
}

// subjectCutoffRowSQL — ОДНА операция записи отсечки на всё дерево (Ф3 §4.1
// п.17, замок Ф1-63/67). Момент монотонен (`GREATEST`); причина и актор
// принадлежат записи, ЧЕЙ МОМЕНТ СТОИТ: они переписываются только вместе с
// принятым моментом, на равных стоит последняя запись. Отброшенный момент не
// переносит на стоящую запись ничего — ни причины, ни актора, ни `updated_at`.
//
// Прежняя редакция переписывала причину и актора БЕЗУСЛОВНО (`= EXCLUDED.`),
// и это был отрицательный контроль замка, а не форма: выход с моментом ниже
// стоящей отсечки администратора подменял бы её причину своей.
// ССЫЛАТЬСЯ НА НЕЁ ВПРЯМУЮ НЕЛЬЗЯ, и это несущее ограничение: записей отсечки
// ДВЕ, и они обязаны ложиться ВМЕСТЕ. Единственный её читатель —
// `upsertSubjectCutoff` ниже; писатель, позвавший оператор мимо него, положил
// бы одну запись из двух — ровно ту форму дефекта, ради которой дверь и
// заведена (kaname#313).
const subjectCutoffRowSQL = `
	INSERT INTO user_token_revocations (user_id, revoke_before, reason, revoked_by_user_id, updated_at)
	VALUES ($1, $2, $3, NULLIF($4, ''), now())
	ON CONFLICT (user_id) DO UPDATE
	    SET revoke_before      = GREATEST(user_token_revocations.revoke_before, EXCLUDED.revoke_before),
	        reason             = CASE WHEN EXCLUDED.revoke_before >= user_token_revocations.revoke_before
	                                  THEN EXCLUDED.reason ELSE user_token_revocations.reason END,
	        revoked_by_user_id = CASE WHEN EXCLUDED.revoke_before >= user_token_revocations.revoke_before
	                                  THEN EXCLUDED.revoked_by_user_id ELSE user_token_revocations.revoked_by_user_id END,
	        updated_at         = CASE WHEN EXCLUDED.revoke_before >= user_token_revocations.revoke_before
	                                  THEN now() ELSE user_token_revocations.updated_at END`

// UpsertRevokeAll — idempotent, monotonic upsert of a user-level cutoff.
//
// ban #10: the "cutoff never moves backwards" invariant is enforced on the DB
// via GREATEST inside a single-statement INSERT … ON CONFLICT … DO UPDATE. The
// PK (user_id) row-lock serializes concurrent writers; GREATEST makes the merge
// commutative so the converged cutoff is the maximum submitted revoke_before
// regardless of arrival order (no software read-modify-write / TOCTOU).
func (r *UserTokenRevocationRepo) UpsertRevokeAll(ctx context.Context, u domain.UserTokenRevocation, revokedBy domain.UserID) error {
	return upsertSubjectCutoff(ctx, r.pool, u, revokedBy)
}

// upsertSubjectCutoff — ЕДИНСТВЕННАЯ ДВЕРЬ к отсечке субъекта: кладёт ОБЕ
// записи (задача kaname#313).
//
// # ПОЧЕМУ ДВЕРЬ, А НЕ ПРАВИЛО «НЕ ЗАБЫВАЙ ВТОРУЮ»
//
// Записей отсечки две, и судят по ним РАЗНЫЕ читатели: первую — хуки выдачи
// (сравнивают с моментом аутентификации сессии), вторую — авторитет отзыва на
// ПУТИ ЗАПРОСА (сравнивает с отметкой выпуска предъявленного носителя). Путь
// снятия доступа, дошедший до одной и не дошедший до второй, есть контроль,
// исполненный наполовину и выглядящий исполненным целиком.
//
// Пока писатели звали ОПЕРАТОР, состояние «одна запись без другой» было
// ПРЕДСТАВИМО — и оно представилось: пять писателей, у одного обе записи, у
// четырёх одна. Теперь оператор виден только отсюда, а снаружи есть ровно одна
// дверь, и она кладёт обе. Состояние, которого нельзя выразить, не нужно
// сторожить.
//
// # ЧТО ЭТО НЕ ДЕЛАЕТ — НАЗВАНО
//
// Непредставимым это состояние сделано В ПРЕДЕЛАХ ПАКЕТА. Писатель на голом
// SQL мимо этих функций по-прежнему может положить одну запись; закрыть и это
// умеет только схема — триггер на первой записи, зеркалящий во вторую. Он
// сильнее и он не заведён здесь: миграция — предмет другой полосы. Пока его
// нет, дверь держит гейт дерева `TestSubjectCutoffWritersWriteBothRecords`.
//
// # РЕШИВШИЙ НАЗЫВАЕТСЯ ВСЕГДА
//
// Вторая запись не принимает пустого решившего — ограничение схемы требует
// непустого, и это верно: отсечка без принявшего неоспорима. Актор здесь
// законно бывает пуст (выход самого человека), поэтому пустой замещается ИМЕНЕМ
// МЕХАНИЗМА, выведенным из причины отсечки, — не пустой строкой и не подставным
// человеком. Тем же приёмом называют себя схемные писатели второй записи.
func upsertSubjectCutoff(ctx context.Context, ex cutoffExecutor,
	u domain.UserTokenRevocation, revokedBy domain.UserID,
) error {
	decidedBy := string(revokedBy)
	if decidedBy == "" {
		decidedBy = mechanismDecider(u.Reason)
	}
	// ПРОВЕРКИ ВХОДА ОБЕИХ ЗАПИСЕЙ — ДО ПЕРВОГО ОПЕРАТОРА. Проверка, стоящая
	// после исполнения первой записи, отвергает вход тогда, когда половина уже
	// записана: вызывающий получает отказ, а состояние изменено.
	if err := validateMintedCutoffInput(string(u.UserID), decidedBy); err != nil {
		return err
	}
	// ОДНОЙ ТРАНЗАКЦИЕЙ — И НА ПУЛЕ ТОЖЕ. На пуле два оператора суть два
	// автокоммита, и между ними существует наблюдаемое состояние «одна запись
	// без другой» — ровно то, ради чего дверь заведена. Транзакция вызывающего
	// уже открыта и своей не заводит: вложенной ей быть нельзя, а разорвать
	// чужую атомарность тем более.
	if beginner, ok := ex.(cutoffTxBeginner); ok {
		tx, err := beginner.Begin(ctx)
		if err != nil {
			return mapErr(err, "", string(u.UserID))
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if werr := writeBothCutoffs(ctx, tx, u, revokedBy, decidedBy); werr != nil {
			return werr
		}
		if cerr := tx.Commit(ctx); cerr != nil {
			return mapErr(cerr, "", string(u.UserID))
		}
		return nil
	}
	return writeBothCutoffs(ctx, ex, u, revokedBy, decidedBy)
}

// writeBothCutoffs — сами две записи, одна за другой, на ОДНОМ исполнителе.
func writeBothCutoffs(ctx context.Context, ex cutoffExecutor,
	u domain.UserTokenRevocation, revokedBy domain.UserID, decidedBy string,
) error {
	if _, err := ex.Exec(ctx, subjectCutoffRowSQL,
		string(u.UserID), u.RevokeBefore, u.Reason, string(revokedBy),
	); err != nil {
		return mapErr(err, "", string(u.UserID))
	}
	return upsertMintedCutoff(ctx, ex, string(u.UserID), u.RevokeBefore, u.Reason, decidedBy)
}

// mechanismDecider — имя механизма, принявшего отсечку, когда человека за ней
// нет. Выводится из причины, а не выписывается перечнем: перечень разошёлся бы
// со словарём причин молча.
func mechanismDecider(reason string) string {
	if reason == "" {
		return "kaname:subject-cutoff"
	}
	return "kaname:" + reason
}

// UpsertRevokeAllTx — tx-scoped variant of UpsertRevokeAll. Runs the identical
// monotonic-cutoff upsert on the caller-supplied tx so the cutoff can commit
// atomically with an audit_outbox row (запрет #10). Same DB-side
// GREATEST invariant; the row-lock on the PK still serializes concurrent writers.
func (r *UserTokenRevocationRepo) UpsertRevokeAllTx(ctx context.Context, tx pgx.Tx, u domain.UserTokenRevocation, revokedBy domain.UserID) error {
	return upsertSubjectCutoff(ctx, tx, u, revokedBy)
}

// RevokedBefore — the active per-user cutoff. Returns (cutoff, true, nil) when a
// marker exists, (zero, false, nil) when none. An error is surfaced so the
// caller can fail-closed (the refresh-hook MUST deny on a lookup error).
func (r *UserTokenRevocationRepo) RevokedBefore(ctx context.Context, userID string) (time.Time, bool, error) {
	const q = `SELECT revoke_before FROM user_token_revocations WHERE user_id = $1`
	var before time.Time
	err := r.pool.QueryRow(ctx, q, userID).Scan(&before)
	if errors.Is(err, pgx.ErrNoRows) {
		return time.Time{}, false, nil
	}
	if err != nil {
		return time.Time{}, false, mapErr(err, "", userID)
	}
	return before, true, nil
}
