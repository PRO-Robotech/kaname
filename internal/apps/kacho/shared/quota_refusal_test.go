// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared_test

// quota_refusal_test.go — отказ учёта на пути НАРУЖУ: код и признак полосы.
//
// ПРЕДМЕТ. Клиент различает полосы МАШИННО — по `reason`-токену в
// `google.rpc.ErrorInfo`, а не разбором прозы (`api-conventions.md`
// §By-lane code-split). Пять владельцев учёта приклеивают токен в одном месте на
// весь домен; шестой (`iam`) отказ учёта наружу не производил вовсе — он уходил
// последней ветвью классификации, то есть `INTERNAL "internal error"`.
//
// Проба утверждает ПАРУ (код + токен) и дословный текст: код без токена не
// отличает «поднять предел» от «завести предел», а токен без кода не проверяет
// того, что увидит край (`RESOURCE_EXHAUSTED` → 429, `FAILED_PRECONDITION` → 400).

import (
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/shared"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

// reasonOf возвращает пару (reason, domain) первого ErrorInfo; пустые строки
// означают «признака нет».
func reasonOf(st *status.Status) (string, string) {
	for _, d := range st.Details() {
		if info, ok := d.(*errdetails.ErrorInfo); ok {
			return info.GetReason(), info.GetDomain()
		}
	}
	return "", ""
}

func TestMapRepoErrProducesTheQuotaRefusal(t *testing.T) {
	const exceeded = "identity ext-42 has reached its limit of 5 iam.account"
	const notProvisioned = "iam.account has no limit on identity ext-42"
	const rateExceeded = "identity ext-42 has reached its admission rate of 3 iam.account per 3600 seconds"

	cases := []struct {
		name       string
		in         error
		wantCode   codes.Code
		wantMsg    string
		wantReason string
	}{
		{
			name:       "место кончилось — поднять предел",
			in:         iamerr.Wrapf(iamerr.ErrQuotaExceeded, "%s", exceeded),
			wantCode:   codes.ResourceExhausted,
			wantMsg:    exceeded,
			wantReason: "QUOTA_EXCEEDED",
		},
		{
			name: "предел не назван — завести предел",
			in:   iamerr.Wrapf(iamerr.ErrQuotaNotProvisioned, "%s", notProvisioned),
			// FAILED_PRECONDITION, а не INVALID_ARGUMENT: ввод арендатора
			// корректен, не выполнено предусловие ПЛАТФОРМЫ.
			wantCode:   codes.FailedPrecondition,
			wantMsg:    notProvisioned,
			wantReason: "QUOTA_NOT_PROVISIONED",
		},
		{
			// Полоса ТЕМПА. Код тот же, что у объёма, — на транспортном уровне
			// «повтори позже» верно для обеих, — а признак СВОЙ: повтор по объёму
			// не пройдёт никогда, повтор по темпу пройдёт в следующем окне.
			// Клиент, не различающий эти полосы, либо бросает работу там, где надо
			// повторить, либо повторяет вечно там, где повтор бесполезен.
			name:       "темп исчерпан — подождать следующего окна",
			in:         iamerr.Wrapf(iamerr.ErrQuotaRateExceeded, "%s", rateExceeded),
			wantCode:   codes.ResourceExhausted,
			wantMsg:    rateExceeded,
			wantReason: "QUOTA_RATE_EXCEEDED",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, ok := status.FromError(shared.MapRepoErr(tc.in))
			if !ok {
				t.Fatalf("MapRepoErr вернул не-status: %v", tc.in)
			}
			if st.Code() != tc.wantCode {
				t.Errorf("код = %v, ожидался %v", st.Code(), tc.wantCode)
			}
			if st.Message() != tc.wantMsg {
				t.Errorf("текст производителя обязан доехать дословно;\nполучено  %q\nожидалось %q",
					st.Message(), tc.wantMsg)
			}
			reason, domain := reasonOf(st)
			if reason != tc.wantReason {
				t.Errorf("reason = %q, ожидался %q — клиент ключуется на токен, а не на прозу",
					reason, tc.wantReason)
			}
			if domain != "iam.kacho.cloud" {
				t.Errorf("domain = %q, ожидался %q — источник отказа называется так же, "+
					"как домен его контракта", domain, "iam.kacho.cloud")
			}
		})
	}

	// Отрицание в паре с положительным: обычное предусловие домена НЕ обязано
	// вдруг обрасти признаком учёта, иначе токен перестанет что-либо различать.
	t.Run("положительный контроль — не-квотное предусловие остаётся без признака", func(t *testing.T) {
		st, ok := status.FromError(shared.MapRepoErr(
			iamerr.Wrapf(iamerr.ErrFailedPrecondition, "Account acc-1 contains projects and cannot be deleted")))
		if !ok {
			t.Fatal("MapRepoErr вернул не-status")
		}
		if st.Code() != codes.FailedPrecondition {
			t.Errorf("код = %v, ожидался FailedPrecondition", st.Code())
		}
		if reason, _ := reasonOf(st); reason != "" {
			t.Errorf("на обычном предусловии появился признак учёта %q", reason)
		}
	})
}
