// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// list_subjects_page_size_integration_test.go — сценарии LSP-01…03 приёмки
// `docs/engineering/acceptance/list-subjects-page-size-is-the-platform-one.md`
// (kaname#615, отпечаток e6c4bc07…262756c95): размер страницы ListSubjects —
// по правилу платформы, `0` → 50 с продолжением.
//
// Мир — настоящая база (testcontainers) и та же дверь решения, что у края
// (`newAdmWorld`). Глагол зовётся ЧЕРЕЗ ОБРАБОТЧИК: формат запроса судится на
// его уровне, и проба на службе мимо обработчика спрашивала бы не то место.
// Вызывающий — человек `usr-lsp-01`, сам держащий `admin` на аккаунте, поэтому
// он проходит проверку полномочий вызывающего, подключённую к той же двери.
//
// Порядок несущий: сперва вся проверка фикстуры (держатели легли, у каждого
// подтверждён адрес, контрольный шаг дал `61 ≤ T ≤ 99`), и только потом
// вопрос о размере страницы. Сломанная фикстура обязана называть себя
// «НЕ-ВЫПОЛНИЛОСЬ(фикстура)», а не выдавать себя за отсутствие умолчания.
//
// Почему 61 человек с подтверждённым адресом: недопущенный держатель
// снимается со страницы после среза, и один такой среди первых 50 дал бы 49 —
// неотличимо от «умолчание 49». Верхняя граница 99 — условие ревью M1: при
// `T ≥ 100` вторая страница умолчания сама полная и несёт курсор, и
// утверждение LSP-03 («ровно T − 50, курсор пуст») перестаёт быть верным.
package service_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/operations"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/authorize"
)

const (
	lspAccount = "acc-lsp"
	lspOwner   = "usr-lsp-own"
	lspCaller  = "usr-lsp-01"
	// lspPersons — люди-держатели `admin` помимо владельца.
	lspPersons = 61
	// lspMinHolders и lspMaxHolders — границы T, на которых утверждения
	// LSP-01…03 верны (приёмка «Дано → писатель», условие ревью M1).
	lspMinHolders = 61
	lspMaxHolders = 99
)

// lspWorld — посеянный аккаунт, обработчик над дверью и контрольное множество
// держателей, снятое страницей 1000.
type lspWorld struct {
	h       *authorize.Handler
	ctx     context.Context
	holders []string
}

func newLSPWorld(t *testing.T) *lspWorld {
	t.Helper()
	w := newAdmWorld(t)
	w.ci.seedAccountWithOwner(t, lspAccount, lspOwner)
	for i := 1; i <= lspPersons; i++ {
		id := fmt.Sprintf("usr-lsp-%02d", i)
		w.ci.seedUser(t, id, lspAccount)
		w.ci.factThroughJournal(t, "user:"+id, "admin", "account", lspAccount)
	}

	var unverified, persons int
	require.NoError(t, w.pool.QueryRow(context.Background(),
		`SELECT count(*) FILTER (WHERE email_verified_at IS NULL)::int, count(*)::int
		   FROM kaname.users WHERE account_id = $1`, lspAccount).Scan(&unverified, &persons))
	require.Zerof(t, unverified,
		"НЕ-ВЫПОЛНИЛОСЬ(фикстура): в %s %d человек без подтверждённого адреса — срез "+
			"страницы снял бы их после LIMIT, и размер страницы перестал бы быть наблюдаем",
		lspAccount, unverified)
	require.Equalf(t, lspPersons+1, persons,
		"НЕ-ВЫПОЛНИЛОСЬ(фикстура): в %s легло %d человек, ждали %d (владелец и %d держателей)",
		lspAccount, persons, lspPersons+1, lspPersons)

	h := authorize.NewHandler(w.ci.svc, authorize.NewWhoAmIUseCase(nil, nil)).WithCallerAuthority(w.door)
	ctx := operations.WithPrincipal(context.Background(), operations.Principal{ID: lspCaller, Type: "user"})

	// Контрольный шаг: `pageSize = 1000` → все T держателей одной страницей.
	ctrl, err := h.ListSubjects(ctx, lspRequest(1000, ""))
	require.NoErrorf(t, err,
		"НЕ-ВЫПОЛНИЛОСЬ(фикстура): контрольный шаг (pageSize 1000) отказал — вызывающий "+
			"не прошёл проверку полномочий либо дверь не отвечает")
	require.Emptyf(t, ctrl.GetNextPageToken(),
		"НЕ-ВЫПОЛНИЛОСЬ(фикстура): контрольная страница 1000 несёт продолжение — T не снят целиком")
	holders := ctrl.GetSubjects()
	require.GreaterOrEqualf(t, len(holders), lspMinHolders,
		"НЕ-ВЫПОЛНИЛОСЬ(фикстура): T = %d < %d — посев не дал достаточно допущенных держателей: %v",
		len(holders), lspMinHolders, holders)
	require.LessOrEqualf(t, len(holders), lspMaxHolders,
		"НЕ-ВЫПОЛНИЛОСЬ(фикстура): T = %d > %d — утверждение LSP-03 о второй странице неверно при таком T",
		len(holders), lspMaxHolders)
	seen := make(map[string]struct{}, len(holders))
	for _, s := range holders {
		_, dup := seen[s]
		require.Falsef(t, dup, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): контрольная страница повторяет держателя %q", s)
		seen[s] = struct{}{}
	}
	require.Containsf(t, holders, "user:"+lspCaller,
		"НЕ-ВЫПОЛНИЛОСЬ(фикстура): вызывающий %s не назван держателем — посев факта не лёг", lspCaller)
	return &lspWorld{h: h, ctx: ctx, holders: holders}
}

func lspRequest(pageSize int64, pageToken string) *iamv1.ListSubjectsRequest {
	return &iamv1.ListSubjectsRequest{
		Resource:  &iamv1.ResourceRef{Type: "account", Id: lspAccount},
		Action:    "iam.account.admin",
		PageSize:  pageSize,
		PageToken: pageToken,
	}
}

// TestLSP01_ZeroPageSizeGivesFiftyWithContinuation — LSP-01.
func TestLSP01_ZeroPageSizeGivesFiftyWithContinuation(t *testing.T) {
	w := newLSPWorld(t)
	resp, err := w.h.ListSubjects(w.ctx, lspRequest(0, ""))
	require.NoError(t, err, "LSP-01: ответ без ошибки")
	require.Lenf(t, resp.GetSubjects(), 50,
		"LSP-01: pageSize 0 — страница умолчания платформы из 50 (T = %d)", len(w.holders))
	require.NotEmpty(t, resp.GetNextPageToken(), "LSP-01: при T > 50 продолжение непусто")
}

// TestLSP02_ExplicitSixtyGivesSixty — LSP-02, близнец LSP-01 (отличие — ровно
// `page_size = 60`): 50 в LSP-01 есть умолчание, а не потолок данных.
func TestLSP02_ExplicitSixtyGivesSixty(t *testing.T) {
	w := newLSPWorld(t)
	resp, err := w.h.ListSubjects(w.ctx, lspRequest(60, ""))
	require.NoError(t, err, "LSP-02: ответ без ошибки")
	require.Lenf(t, resp.GetSubjects(), 60, "LSP-02: явный pageSize 60 (T = %d)", len(w.holders))
	require.NotEmpty(t, resp.GetNextPageToken(), "LSP-02: при T > 60 продолжение непусто")
}

// TestLSP03_DefaultPageContinuationReachesTheEnd — LSP-03: продолжение
// страницы умолчания доводит обход до конца, без повторов и пропусков.
func TestLSP03_DefaultPageContinuationReachesTheEnd(t *testing.T) {
	w := newLSPWorld(t)
	first, err := w.h.ListSubjects(w.ctx, lspRequest(0, ""))
	require.NoError(t, err, "LSP-03: первая страница без ошибки")
	require.Lenf(t, first.GetSubjects(), 50,
		"LSP-03: первая страница умолчания — 50 (T = %d)", len(w.holders))
	require.NotEmpty(t, first.GetNextPageToken(), "LSP-03: первая страница умолчания несёт продолжение")

	second, err := w.h.ListSubjects(w.ctx, lspRequest(0, first.GetNextPageToken()))
	require.NoError(t, err, "LSP-03: вторая страница без ошибки")
	require.Lenf(t, second.GetSubjects(), len(w.holders)-50, "LSP-03: вторая страница — ровно T − 50")
	require.Empty(t, second.GetNextPageToken(), "LSP-03: продолжение после второй страницы пусто")

	union := make(map[string]struct{}, len(w.holders))
	for _, s := range append(append([]string{}, first.GetSubjects()...), second.GetSubjects()...) {
		_, dup := union[s]
		require.Falsef(t, dup, "LSP-03: держатель %q повторён между страницами", s)
		union[s] = struct{}{}
	}
	got := make([]string, 0, len(union))
	for s := range union {
		got = append(got, s)
	}
	require.ElementsMatch(t, w.holders, got,
		"LSP-03: объединение двух страниц — ровно множество T контрольного шага")
}
