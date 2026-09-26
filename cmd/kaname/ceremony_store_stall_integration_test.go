// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// ceremony_store_stall_integration_test.go — отказ хранилища церемонии на
// кончившемся сроке вызова порта — временная недоступность (503), а не отказ
// сервера (500), как у прочих путей хранилища службы (kaname#383; задача
// PRO-Robotech/kaname#423, столкновение в сборке 425).
package main

import (
	"context"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/handler/clienttokenhttp"
)

// Хранилище не отвечает дольше срока вызова порта (таблицу клиентов держит
// чужой замок): отказ — временная недоступность, 503 temporarily_unavailable, а
// не 500. Близнец — замок снят: тот же обмен свежего кода выдаёт.
func TestLINEA1Pool_StoreStalledPastThePortDeadlineIsTemporarilyUnavailable(t *testing.T) {
	w := newCeremonyWorld(t, "POOL-STALL", "1")
	w.requireGrant(grantAuthorizationCode)
	w.requireAuthorizeEndpoint()
	pub := w.seedPublicClient("ceremony-public", []string{lineA1R})
	stalled := w.issueCode(pub, lineA1R)
	fresh := w.issueCode(pub, lineA1R)

	conn, err := pgx.ConnectConfig(w.ctx, w.pool.Config().ConnConfig.Copy())
	if err != nil {
		w.fixture("связь держателя замка: %v", err)
	}
	defer func() { _ = conn.Close(context.Background()) }()
	tx, err := conn.Begin(w.ctx)
	if err != nil {
		w.fixture("транзакция держателя: %v", err)
	}
	if _, err := tx.Exec(w.ctx, `LOCK TABLE kaname.interactive_clients IN ACCESS EXCLUSIVE MODE`); err != nil {
		w.fixture("замок держателя: %v", err)
	}
	rec := w.post(clienttokenhttp.TokenPath, exchangeForm(stalled), nil)
	_ = tx.Rollback(w.ctx)
	if rec.Code != http.StatusServiceUnavailable || rec.Body.String() != `{"error":"temporarily_unavailable"}`+"\n" {
		w.red("обмен при хранилище, не ответившем в срок вызова порта: %d %q, ожидалось 503 temporarily_unavailable",
			rec.Code, rec.Body.String())
	}

	twin := w.post(clienttokenhttp.TokenPath, exchangeForm(fresh), nil)
	if twin.Code != http.StatusOK {
		w.red("близнец: обмен после снятия замка ответил %d; тело %q", twin.Code, twin.Body.String())
	}
}
