// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// authz_revision.go — производитель токена версии прав службы доступа (приёмка
// NTF-3, Р30 «Производитель токена»; сценарий NTF3-179).
//
// Токен — ПОЛНЫЙ снимок транзакций базы (`pg_current_snapshot()`), а не его
// нижняя граница (`xmin`). Ограда вопроса об аудитории спрашивает о версии
// строки права «видна ли транзакция `authz_rev` в снимке `R_E`»; нижняя граница
// ответила бы «да» транзакции, шедшей в момент снятия токена и закоммиченной
// позже, если её номер ниже границы чужой долгой транзакции, — и право,
// выданное после события, открыло бы его адресату.
//
// Снимок берётся на соединении пула ВНЕ транзакции: каждый вызов — свой
// оператор, свой снимок на момент оператора. Внутри открытой транзакции
// REPEATABLE READ он вернул бы снимок её начала, то есть старше вызова.

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AuthzRevisionReader — снимок транзакций базы службы доступа на момент вызова.
type AuthzRevisionReader struct {
	pool *pgxpool.Pool
}

// NewAuthzRevisionReader — конструктор.
func NewAuthzRevisionReader(pool *pgxpool.Pool) *AuthzRevisionReader {
	return &AuthzRevisionReader{pool: pool}
}

// Current — текстовая форма `pg_snapshot` (`xmin:xmax:xip,…`). Отказ базы
// классифицируется единым переводчиком хранилища: текст драйвера наружу не
// выходит.
func (r *AuthzRevisionReader) Current(ctx context.Context) (string, error) {
	var tok string
	if err := r.pool.QueryRow(ctx, `SELECT pg_current_snapshot()::text`).Scan(&tok); err != nil {
		return "", mapErr(err, "AuthzRevision.Current", "")
	}
	return tok, nil
}
