// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// hooks_mux_audit_drop_row_integration_test.go — потеря записи журнала хуков,
// произведённая БАЗОЙ, двигает клетку ряда реестра через тот же корень, который
// собирает полосу (kaname#436, находка 1, вторая половина).
//
// # Зачем вторая проба рядом с пробой заведения клеток
//
// Заведение клеток (`TestHooksMuxSeedsTheAuditDropRowForEveryDeclaredKind`) видит
// витрину, но не видит, КАКОЙ приёмник корень подал полосам: заведи он клетки одним
// вызовом и подай полосам другой приёмник, клетки стояли бы нулём при любой потере.
// Эта проба судит само ребро — потерю, которую отвергла база, на клетке реестра.
//
// # Как создаётся потеря
//
// Настоящая база с применёнными миграциями, корень собран с её пулом. Хук
// обновления зовётся с субъектом, которого в базе нет: полоса отказывает (403) и
// пишет запись вида `authn.refresh.denied`. Законный близнец — тот же вызов, пока
// таблица журнала принимает строки: запись есть, клетка стоит нулём. Затем таблица
// получает ограничение, отвергающее каждую новую строку, — это ЕДИНСТВЕННЫЙ
// изменённый факт, — и тот же вызов обязан оставить строку незаписанной, а клетку
// своего вида сдвинуть ровно на одну.

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	handlerinternal "github.com/PRO-Robotech/kaname/internal/handler/iamhooks"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

func auditRowsOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, eventType string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.audit_outbox WHERE event_type = $1`, eventType).Scan(&n); err != nil {
		t.Fatalf("перепись журнала пробы: %v", err)
	}
	return n
}

// TestHooksMuxCountsARefusedAuditRecordOnTheRegistryRow — запись журнала, которую
// отвергла база, видна клеткой ряда потерь на реестре, поданном корню; записанная
// запись клетку не двигает.
func TestHooksMuxCountsARefusedAuditRecordOnTheRegistryRow(t *testing.T) {
	if testing.Short() {
		t.Skip("интеграция: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	if err != nil {
		t.Fatalf("пул к базе пробы: %v", err)
	}
	pgtest.ClosePoolAtEnd(t, pool)

	const secret = "audit-drop-row-hook-secret"
	cfg := roadCfg(config.IdentityProviderExternal, "9097")
	cfg.AuthN.HookSharedSecret = secret
	body := capturedHookBody(t, "provider-refresh-hook.json")
	declared := handlerinternal.AuditEventTypes()
	event := handlerinternal.AuditRefreshDenied

	// serve — один вызов хука обновления через полосу, собранную корнем со своим
	// реестром: исход, витрина реестра и число строк вида в журнале.
	serve := func(t *testing.T) (int, map[string]float64, int) {
		t.Helper()
		reg := metrics.NewRegistry()
		h, err := buildHooksMux(pool, nil, nil, nil, reg, cfg, quietLogger())
		if err != nil {
			t.Fatalf("предпосылка: корень отказал в сборке полосы хуков (%v) — судить не у чего", err)
		}
		if h == nil {
			t.Fatal("предпосылка: корень не собрал полосу хуков — судить не у чего")
		}
		req := httptest.NewRequestWithContext(ctx, http.MethodPost, "/iam/v1/hooks/refresh", bytes.NewReader(body))
		req.Header.Set("X-Kacho-Hook-Token", secret)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		return w.Code, scrapeAuditDropRow(t, reg), auditRowsOf(t, ctx, pool, event)
	}

	// Законный близнец: база принимает запись.
	status, cells, rows := serve(t)
	if status != http.StatusForbidden {
		t.Fatalf("предпосылка: хук обновления для субъекта без строки ответил %d, ожидался 403 — "+
			"сценарий прошёл не той дорогой, и запись %q НЕ ИЗМЕРЕНА", status, event)
	}
	if rows != 1 {
		t.Fatalf("предпосылка: база принимает строки журнала, а записей %q после отказа %d, ожидалась 1", event, rows)
	}
	if faults := auditDropRowFaults(declared, cells); len(faults) != 0 {
		t.Fatalf("законный близнец: запись %q записана, а ряд потерь не сходится с нулём: %v", event, faults)
	}

	// Единственный изменённый факт: база отвергает каждую новую строку журнала.
	if _, err := pool.Exec(ctx, `ALTER TABLE kaname.audit_outbox
		ADD CONSTRAINT probe_refuses_every_audit_row CHECK (false) NOT VALID`); err != nil {
		t.Fatalf("фикстура: ограничение, отвергающее строки журнала, не поставлено: %v", err)
	}

	status, cells, rows = serve(t)
	if status != http.StatusForbidden {
		t.Fatalf("под отвергающей журнал базой хук ответил %d, ожидался тот же 403 — полоса обязана "+
			"обслуживать дальше, и запись %q НЕ ИЗМЕРЕНА", status, event)
	}
	if rows != 1 {
		t.Fatalf("фикстура: база обязана была отвергнуть запись, а строк %q стало %d", event, rows)
	}
	t.Logf("перепись: видов объявлено %d · клеток на витрине %d · клетка %q после отвергнутой записи = %v",
		len(declared), len(cells), event, cells[event])
	if got, ok := cells[event]; !ok || got != 1 {
		t.Errorf("база отвергла запись %q, хук ответил %d, а клетка ряда %s этого вида на реестре корня "+
			"= %v (есть=%v), ожидалась 1 — приёмник, поданный полосам, не тот, что на витрине, и потеря "+
			"видна только строкой журнала процесса", event, status, metrics.AuthnHookAuditDropsMetric, got, ok)
	}
	for _, e := range declared {
		if e != event && cells[e] != 0 {
			t.Errorf("клетка вида %q двинулась (%v) без потери своего вида", e, cells[e])
		}
	}
}
