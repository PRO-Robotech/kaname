// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
	"github.com/PRO-Robotech/kacho/services/iam/internal/observability/metrics"
)

// Наблюдатель обращений к хранилищу прав (#720). Две вещи проверяются
// раздельно, потому что ломаются они раздельно: ЧТО он делает и ПРОВЯЗАН ли он.

func TestAuthzStoreObserver_CountsEveryOutcomeAndLogsOnlyTheInvisibleOne(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	reg := metrics.NewRegistry()
	observe := newAuthzStoreObserver(reg, logger)

	// Все исходы уезжают в счётчик — «ноль отказов за всю жизнь» обязано быть
	// отличимо от «никто не смотрел».
	for _, o := range []clients.FGACallOutcome{
		clients.FGAOutcomeOK,
		clients.FGAOutcomeStoreUnreachable,
		clients.FGAOutcomeStoreTimeout,
		clients.FGAOutcomePooledConnDropped,
	} {
		observe(clients.FGAAttempt{Op: "check", Attempt: 1, Outcome: o, Duration: time.Millisecond})
	}

	body := scrape(t, reg)
	for _, want := range []string{
		`kacho_iam_authz_store_attempts_total{op="check",outcome="ok",reused="false"} 1`,
		`kacho_iam_authz_store_attempts_total{op="check",outcome="store_unreachable",reused="false"} 1`,
		`kacho_iam_authz_store_attempts_total{op="check",outcome="store_timeout",reused="false"} 1`,
		`kacho_iam_authz_store_attempts_total{op="check",outcome="pooled_conn_dropped",reused="false"} 1`,
	} {
		require.Contains(t, body, want,
			"причина обязана быть ОТДЕЛЬНОЙ серией: по ней и ищут, когда отказ один на тысячу")
	}

	// В журнал идёт РОВНО один исход. Недоступность и молчание туда класть
	// нельзя: под настоящим отказом это строка на каждый запрос.
	log := buf.String()
	require.Equal(t, 1, strings.Count(log, "pooled connection gave no reply"),
		"мёртвое соединение из пула обязано быть видно в журнале — оно и было невидимым")
	require.NotContains(t, log, "store_unreachable",
		"недоступность в журнал не идёт: под отказом хранилища это строка на каждый запрос")
	require.NotContains(t, log, "store_timeout",
		"молчание в журнал не идёт по той же причине")
}

func TestAuthzStoreObserver_NilArgumentsAreLegal(t *testing.T) {
	t.Parallel()
	observe := newAuthzStoreObserver(nil, nil)
	require.NotPanics(t, func() {
		observe(clients.FGAAttempt{Op: "check", Outcome: clients.FGAOutcomePooledConnDropped})
	}, "наблюдатель без метрик и журнала обязан быть безвредным, а не падать")
}

// TestAuthzStoreObserver_IsWiredIntoTheCompositionRoot — поле Observe,
// объявленное и никем не заполненное, есть МЁРТВЫЙ наблюдатель: снаружи он
// неотличим от работающего, а причина отказа так и остаётся неназванной.
// Проверяется по дереву разбора, а не по тексту: упоминание в комментарии
// провязкой не является.
func TestAuthzStoreObserver_IsWiredIntoTheCompositionRoot(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "serve.go", nil, 0)
	require.NoError(t, err, "предпосылка: композиционный корень обязан разбираться")

	wired := false
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range assign.Lhs {
			sel, ok := lhs.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Observe" || i >= len(assign.Rhs) {
				continue
			}
			call, ok := assign.Rhs[i].(*ast.CallExpr)
			if !ok {
				continue
			}
			if id, ok := call.Fun.(*ast.Ident); ok && id.Name == "newAuthzStoreObserver" {
				wired = true
			}
		}
		return true
	})
	require.True(t, wired,
		"композиционный корень не заполняет Observe вызовом newAuthzStoreObserver: "+
			"наблюдатель объявлен и мёртв, причина отказа хранилища прав снова "+
			"не называется нигде (#720)")
}

// scrape — прочитать выставленное значение счётчиков так же, как их читает
// сборщик метрик: через тот же обработчик, а не через внутренности реестра.
func scrape(t *testing.T, reg *metrics.Registry) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	reg.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "предпосылка: обработчик метрик обязан отвечать")
	return rec.Body.String()
}
