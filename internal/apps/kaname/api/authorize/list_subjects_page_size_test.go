// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// list_subjects_page_size_test.go — модульная проба обработчика по сценариям
// LSP-04…09 приёмки
// `docs/engineering/acceptance/list-subjects-page-size-is-the-platform-one.md`
// (kaname#615, отпечаток e6c4bc07…262756c95).
//
// Уровень дублёра — ИСТОЧНИК ДЕРЖАТЕЛЕЙ (`service.Authorizer`) ПОД настоящей
// службой (условие ревью M6), а не сама служба: тогда отказ службы на
// `pageSize > 1000` проходит тем же путём, что в продукте, и LSP-06 спрашивает
// о настоящем тексте отказа. Второй дублёр — проверка полномочий вызывающего
// (`authorityStub`); оба считают обращения.
//
// У каждого отрицания назван положительный близнец, и мир кейса отличается от
// близнеца РОВНО одним фактом. Дельту вычисляет проба
// (`TestLSPTwinsDifferByExactlyOneFact`), объявление сверяется с вычисленным.
package authorize

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/service"
)

const (
	lspAccountA = "acc-lsp-a" // вызывающий его администрирует
	lspAccountB = "acc-lsp-b" // вызывающий на нём ролей не имеет
	lspCaller   = "usr-lsp-admin-a"
	// lspViolation — текст нарушения фундамента (`corevalidate.PageSize`),
	// приёмка LSP-04 дословно.
	lspViolation = "page_size must be in [0..1000] (0 means default)"
	// lspOldRefusal — текст прежней собственной проверки службы (LSP-06: не
	// производится).
	lspOldRefusal = "Illegal argument page_size 1001 > 1000"
)

// holderSource — дублёр источника держателей: считает обращения к
// перечислению и запоминает размер, с которым его спросили.
type holderSource struct {
	stubVerdict
	listCalls int
	listSizes []int
}

func (s *holderSource) ListSubjects(_ context.Context, _, _, _ string, pageSize int, _ string) ([]string, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listCalls++
	s.listSizes = append(s.listSizes, pageSize)
	return []string{"user:" + lspCaller}, "", nil
}

// lspCase — мир кейса: два факта, которыми кейсы различаются.
type lspCase struct {
	id       string
	account  string
	pageSize int64
}

var (
	lsp04 = lspCase{"LSP-04", lspAccountA, -1}
	lsp05 = lspCase{"LSP-05", lspAccountA, 0}
	lsp06 = lspCase{"LSP-06", lspAccountA, 1001}
	lsp07 = lspCase{"LSP-07", lspAccountA, 1000}
	lsp08 = lspCase{"LSP-08", lspAccountB, -1}
	lsp09 = lspCase{"LSP-09", lspAccountB, 0}
)

// lspRun — исход вызова и показания обоих дублёров.
type lspRun struct {
	resp      *iamv1.ListSubjectsResponse
	err       error
	source    *holderSource
	authority *authorityStub
}

func runLSP(c lspCase) lspRun {
	src := &holderSource{}
	auth := &authorityStub{allow: map[string]bool{"admin|account:" + lspAccountA: true}}
	svc := service.NewAuthorizeService(service.AuthorizeServiceConfig{Relations: src})
	h := NewHandler(svc, NewWhoAmIUseCase(nil, nil)).WithModuleRoster(testModuleRoster()).WithCallerAuthority(auth)
	resp, err := h.ListSubjects(userCtx(lspCaller), &iamv1.ListSubjectsRequest{
		Resource: &iamv1.ResourceRef{Type: "account", Id: c.account},
		Action:   "iam.account.get",
		PageSize: c.pageSize,
	})
	return lspRun{resp: resp, err: err, source: src, authority: auth}
}

// requireLSPFieldRefusal — отказ формата: INVALID_ARGUMENT, `invalid
// argument`, ровно одно нарушение поля `page_size` с текстом фундамента.
func requireLSPFieldRefusal(t *testing.T, id string, err error) {
	t.Helper()
	require.Errorf(t, err, "%s: ждали отказ INVALID_ARGUMENT, ответ без ошибки", id)
	st, _ := status.FromError(err)
	require.Equalf(t, codes.InvalidArgument, st.Code(), "%s: код (%v)", id, err)
	require.Equalf(t, "invalid argument", st.Message(), "%s: message", id)
	var violations []*errdetails.BadRequest_FieldViolation
	for _, d := range st.Details() {
		if br, ok := d.(*errdetails.BadRequest); ok {
			violations = append(violations, br.GetFieldViolations()...)
		}
	}
	require.Lenf(t, violations, 1, "%s: ровно одно нарушение поля в BadRequest (details=%v)", id, st.Details())
	require.Equalf(t, "page_size", violations[0].GetField(), "%s: имя поля", id)
	require.Equalf(t, lspViolation, violations[0].GetDescription(), "%s: текст нарушения", id)
}

// TestLSP04_NegativePageSizeIsInvalidArgumentWithField — LSP-04.
func TestLSP04_NegativePageSizeIsInvalidArgumentWithField(t *testing.T) {
	r := runLSP(lsp04)
	requireLSPFieldRefusal(t, lsp04.id, r.err)
	require.Zerof(t, r.source.listCalls, "LSP-04: источник держателей не опрошен (размеры %v)", r.source.listSizes)
}

// TestLSP05_ZeroPageSizeAsksTheSourceWithFifty — LSP-05, близнец LSP-04.
func TestLSP05_ZeroPageSizeAsksTheSourceWithFifty(t *testing.T) {
	r := runLSP(lsp05)
	require.NoError(t, r.err, "LSP-05: pageSize 0 принят")
	require.NotNil(t, r.resp.GetSubjects(), "LSP-05: subjects — массив")
	require.Equal(t, []int{50}, r.source.listSizes, "LSP-05: источник опрошен один раз с размером 50")
}

// TestLSP06_OverMaxIsInvalidArgumentWithField — LSP-06.
func TestLSP06_OverMaxIsInvalidArgumentWithField(t *testing.T) {
	r := runLSP(lsp06)
	if r.err != nil {
		require.NotContainsf(t, status.Convert(r.err).Message(), lspOldRefusal,
			"LSP-06: прежний собственный текст службы не производится")
	}
	requireLSPFieldRefusal(t, lsp06.id, r.err)
	require.Zerof(t, r.source.listCalls, "LSP-06: источник держателей не опрошен (размеры %v)", r.source.listSizes)
}

// TestLSP07_MaxPageSizeIsAccepted — LSP-07, близнец LSP-06.
func TestLSP07_MaxPageSizeIsAccepted(t *testing.T) {
	r := runLSP(lsp07)
	require.NoError(t, r.err, "LSP-07: pageSize 1000 принят")
	require.NotNil(t, r.resp.GetSubjects(), "LSP-07: subjects — массив")
	require.Equal(t, []int{1000}, r.source.listSizes, "LSP-07: источник опрошен один раз с размером 1000")
}

// TestLSP08_FormatIsJudgedBeforeCallerAuthority — LSP-08.
func TestLSP08_FormatIsJudgedBeforeCallerAuthority(t *testing.T) {
	r := runLSP(lsp08)
	requireLSPFieldRefusal(t, lsp08.id, r.err)
	require.Zerof(t, r.authority.calls, "LSP-08: проверка полномочий вызывающего не опрошена")
	require.Zero(t, r.source.listCalls, "LSP-08: источник держателей не опрошен")
}

// TestLSP09_LegalPageSizeOnForeignResourceIsDenied — LSP-09, близнец LSP-08
// (отрицание) и LSP-05 (положительный, отличие — аккаунт, условие ревью M3).
func TestLSP09_LegalPageSizeOnForeignResourceIsDenied(t *testing.T) {
	r := runLSP(lsp09)
	require.Error(t, r.err, "LSP-09: ждали отказ в правах")
	st, _ := status.FromError(r.err)
	require.Equalf(t, codes.PermissionDenied, st.Code(), "LSP-09: код (%v)", r.err)
	require.Equal(t, "permission denied", st.Message(), "LSP-09: message")
	require.Positive(t, r.authority.calls, "LSP-09: проверка полномочий опрошена — отказ дала она")
	require.Zero(t, r.source.listCalls, "LSP-09: без полномочий перечисления нет")
}

// TestLSPTwinsDifferByExactlyOneFact — у каждой пары «кейс — близнец» мир
// различается ровно одним фактом, и это именно объявленный факт.
func TestLSPTwinsDifferByExactlyOneFact(t *testing.T) {
	for _, p := range []struct {
		subject, twin lspCase
		fact          string
	}{
		{lsp04, lsp05, "pageSize"},
		{lsp06, lsp07, "pageSize"},
		{lsp06, lsp04, "pageSize"},
		{lsp08, lsp09, "pageSize"},
		{lsp08, lsp04, "account"},
		{lsp09, lsp05, "account"},
	} {
		var diff []string
		if p.subject.account != p.twin.account {
			diff = append(diff, "account")
		}
		if p.subject.pageSize != p.twin.pageSize {
			diff = append(diff, "pageSize")
		}
		require.Equalf(t, []string{p.fact}, diff, "%s против %s: вычисленная дельта", p.subject.id, p.twin.id)
	}
}
