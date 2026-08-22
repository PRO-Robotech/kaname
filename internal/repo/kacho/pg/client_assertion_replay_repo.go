// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// ClientAssertionReplayRepo — хранилище однократности предъявленных утверждений
// клиента (задача #898, приёмка F2 §6).
//
// # Область гарантии — ФЛОТ, а не процесс
//
// Хранилище в памяти пода корректно ровно до второй реплики: повтор, попавший в
// соседнюю, чужой записи не находит и проходит. Со второй репликой такое
// хранилище даёт защиту, КОТОРОЙ НЕТ, и при этом выглядит исправным — ни одна
// одноэкземплярная проба его от общего не отличает. Поэтому запись лежит там,
// где её видят все реплики.
type ClientAssertionReplayRepo struct {
	pool *pgxpool.Pool
}

// NewClientAssertionReplayRepo — построитель.
func NewClientAssertionReplayRepo(pool *pgxpool.Pool) *ClientAssertionReplayRepo {
	return &ClientAssertionReplayRepo{pool: pool}
}

// Redeem погашает пару «клиент + идентификатор однократности».
//
// # Один оператор — это инвариант, а не аккуратность
//
// «Не предъявлялось ли уже» и «погасить» здесь НЕДЕЛИМЫ: их делает неделимыми
// первичный ключ таблицы. Пара «SELECT, потом INSERT» была бы ровно тем
// check-then-act, который запрещает ban #10: два одновременных предъявления
// одного утверждения промахнулись бы ОБА мимо чужой ещё не записанной строки и
// прошли бы ОБА. Окна между чтением и записью при последовательном прогоне не
// существует, поэтому такая реализация проходит все последовательные пробы —
// и остаётся сломанной ровно там, где однократность и нужна.
//
// Возврат `domain.ErrAssertionReplayed` означает ПОВТОР. Всякий иной отказ —
// недоступность хранилища, и вызывающий обязан закрыться (§6.5): отложенное
// погашение есть та же пара «проверить и записать», разнесённая на
// неопределённый срок.
func (r *ClientAssertionReplayRepo) Redeem(ctx context.Context, clientID, assertionID string, expiresAt time.Time) error {
	if clientID == "" {
		return fmt.Errorf("client assertion replay: redemption must name its client")
	}
	if err := domain.ValidateAssertionID(assertionID); err != nil {
		return err
	}
	// ОДИН вызов к базе. Гейт TestAssertionAdmissionIsASingleDatabaseCall
	// стережёт это число: второй вызов здесь — возвращённая пара
	// «посмотреть — записать», и вернуть её тихо нельзя.
	const q = `INSERT INTO kacho_iam.client_assertion_replay (client_id, assertion_id, expires_at)
		VALUES ($1,$2,$3)
		ON CONFLICT (client_id, assertion_id) DO NOTHING`
	tag, err := r.pool.Exec(ctx, q, clientID, assertionID, expiresAt)
	if err != nil {
		return wrapPgErr(err, "ClientAssertionReplay", clientID)
	}
	if tag.RowsAffected() == 0 {
		// Конфликт по первичному ключу: строка уже есть, значит это повтор.
		return fmt.Errorf("%w: client %s", domain.ErrAssertionReplayed, clientID)
	}
	return nil
}

// Reap убирает строки утверждений, истёкших к названному моменту.
//
// Часы приходят ВХОДОМ, а не берутся из окружения: без этого проба сборщика
// вынуждена была бы спать, а спящая проба меряет планировщик.
//
// # Почему сборщик обязан существовать
//
// Строка живёт до истечения утверждения — не дольше и не короче. Короче нельзя:
// снятая раньше строка делает повтор законным. Дольше нельзя: у утверждения,
// предъявленного один раз, нет никого, кто пришёл бы его убрать, и хранилище
// росло бы без границы, а темп роста выбирал бы предъявитель.
//
// Два вызова к базе здесь ЗАКОННЫ и это не исключение из правила допуска:
// сборщик не решает, принять ли предъявление, поэтому неделимости от него не
// требуется. Он — законный близнец гейта на число вызовов.
func (r *ClientAssertionReplayRepo) Reap(ctx context.Context, now time.Time) (int64, error) {
	const q = `DELETE FROM kacho_iam.client_assertion_replay WHERE expires_at <= $1`
	tag, err := r.pool.Exec(ctx, q, now)
	if err != nil {
		return 0, wrapPgErr(err, "ClientAssertionReplay", "")
	}
	return tag.RowsAffected(), nil
}

// Len — число строк погашения.
//
// Читается пробой сборщика: она утверждает ЧИСЛО СТРОК, а не то, что сборщик
// вызвался. «Вызвался» зелено и на сборщике, не удалившем ничего, и на
// сборщике, опустошившем таблицу целиком, — то есть на реализации, делающей
// повтор законным.
func (r *ClientAssertionReplayRepo) Len(ctx context.Context) (int64, error) {
	const q = `SELECT count(*) FROM kacho_iam.client_assertion_replay`
	var n int64
	if err := r.pool.QueryRow(ctx, q).Scan(&n); err != nil {
		return 0, wrapPgErr(err, "ClientAssertionReplay", "")
	}
	return n, nil
}
