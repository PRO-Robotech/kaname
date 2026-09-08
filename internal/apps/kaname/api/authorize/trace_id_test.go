// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authorize

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// `trace_id` объявлен на проверках доступа как «Correlation id for downstream logs /
// traces» — и не читался ничем. Вызывающий присылал идентификатор, получал ответ и
// имел основание считать, что по нему найдёт свою проверку в логах; в логах его не
// было ни в одной записи. Обещание корреляции — такое же обещание, как любое другое:
// либо исполняется, либо снимается с контракта.
//
// Исполняется: идентификатор попадает в те записи, которые хендлер вообще делает, —
// на недоступности бэкенда и на внутренней ошибке. На успешном пути записи нет, и
// заводить её ради поля нельзя: authz-Check стоит на КАЖДОМ RPC платформы, и лог на
// каждый успешный Check — это не корреляция, а шум, который её же и утопит.
//
// Тест подменяет ДЕФОЛТНЫЙ логгер, потому что хендлер пишет через пакетный
// `slog.ErrorContext` — так же, как все остальные его записи. Пакет не гоняет тесты
// параллельно, поэтому подмена безопасна; если здесь появится `t.Parallel()`, логгер
// придётся сначала протащить в Handler.
func captureErrorLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelError})))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// handlerWithUnavailableBackend — сервис БЕЗ источника вердикта: его Check
// возвращает типизированный «бэкенд недоступен», то есть ровно тот путь, на
// котором хендлер ПИШЕТ запись. Никаких дублёров сверх необходимого.
func handlerWithUnavailableBackend() *Handler {
	svc := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations: nil,
	})
	return NewHandler(svc, NewWhoAmIUseCase(nil, nil))
}

func TestAuthorizeCheck_TraceIdReachesTheLog(t *testing.T) {
	buf := captureErrorLog(t)
	h := handlerWithUnavailableBackend()

	_, err := h.Check(moduleCertCtx(), &iamv1.AuthorizeCheckRequest{
		Subject:  "user:usr_b3n7k1x9q2m5t8",
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_b3n7k1x9q2m5t8"},
		Action:   "iam.account.get",
		TraceId:  "trace-b3n7k1x9-q2m5t8",
	})
	require.Error(t, err)
	require.Contains(t, buf.String(), "trace-b3n7k1x9-q2m5t8",
		"вызывающий прислал корреляционный идентификатор — по контракту поля он обязан "+
			"оказаться в записи лога, иначе поле обещает корреляцию, которой нет")
}

func TestAuthorizeBatchCheck_TraceIdReachesTheLog(t *testing.T) {
	buf := captureErrorLog(t)
	h := handlerWithUnavailableBackend()

	_, err := h.BatchCheck(moduleCertCtx(), &iamv1.BatchAuthorizeCheckRequest{
		TraceId: "batch-trace-q2m5t8",
		Checks: []*iamv1.AuthorizeCheckRequest{{
			Subject:  "user:usr_b3n7k1x9q2m5t8",
			Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_b3n7k1x9q2m5t8"},
			Action:   "iam.account.get",
		}},
	})
	require.Error(t, err)
	require.Contains(t, buf.String(), "batch-trace-q2m5t8",
		"batch несёт свой корреляционный идентификатор — он обязан быть в записи лога")
}

// TestAuthorizeCheck_TraceIdIsBounded — предел 64 держит КОД, и только он.
// Механизма, ограничивающего длину на пути запроса, в дереве нет: идентификатор
// приходит от вызывающего произвольной длины, а лог обязан оставаться логом.
// Прежде предел объявлял и контракт — объявлением без исполнителя, снятым вместе
// со всем семейством (kacho#1255).
func TestAuthorizeCheck_TraceIdIsBounded(t *testing.T) {
	buf := captureErrorLog(t)
	h := handlerWithUnavailableBackend()

	long := strings.Repeat("z", 4096)
	_, err := h.Check(moduleCertCtx(), &iamv1.AuthorizeCheckRequest{
		Subject:  "user:usr_b3n7k1x9q2m5t8",
		Resource: &iamv1.ResourceRef{Type: "account", Id: "acc_b3n7k1x9q2m5t8"},
		Action:   "iam.account.get",
		TraceId:  long,
	})
	require.Error(t, err)
	out := buf.String()
	require.Contains(t, out, strings.Repeat("z", 64),
		"начало идентификатора остаётся — по нему и коррелируют")
	require.NotContains(t, out, strings.Repeat("z", 65),
		"объявленный предел 64 никем не энфорсится, поэтому обрезать обязан сам код: "+
			"иначе вызывающий пишет в лог сколько захочет")
}
