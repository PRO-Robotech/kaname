// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// basic_refusal_census_test.go — второй потребитель авторитета базового
// секрета (полоса реестра) считает отказ ПО ПРИЧИНЕ тем же закрытым словарём,
// что глаголы внутреннего слушателя (задача kaname#390).
//
// # Предмет
//
// Полоса реестра отбрасывала причину отказа авторитета и отказов не считала:
// отсечка отзыва-всех, сработавшая на ней тысячу раз, была неотличима от
// перебора секрета и от полосы, не обслужившей ни одного входа.
//
// # Что утверждается
//
//   - на каждую причину словаря домена — ровно один исход переписи, и он
//     называет ЭТУ причину; исходы разных причин различны;
//   - отказ без названной причины — свой исход, не клетка первой попавшейся
//     причины;
//   - отказ, вынесенный полосой до авторитета (имя не называет удостоверения),
//     считается тоже — как отказ формы;
//   - ошибка наружу остаётся `ErrUnauthenticated` и НЕСЁТ причину внутрь — по
//     ней журналит обработчик;
//   - перепись исходов полосы объявлена целиком: каждая клетка — в
//     [CredentialKindOutcomes].
package registry_token

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/credsecret"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// refusingResolver — авторитет, отказывающий заданной ошибкой.
type refusingResolver struct {
	err   error
	calls int
}

func (r *refusingResolver) ResolveBasic(context.Context, string) (domain.BasicCredential, error) {
	r.calls++
	return domain.BasicCredential{}, r.err
}

func refusedLane(t *testing.T, res basicCredentialResolver) (*IssueRegistryTokenUseCase, *recordingObserver) {
	t.Helper()
	obs := newRecordingObserver()
	uc := mustUseCase(t, Config{Scope: "registry", AllowedAudiences: []string{"registry"}, DefaultService: "registry"},
		&fakeMinter{out: MintOutput{AccessToken: "minted", ExpiresIn: 300}}).
		WithBasicCredentialResolver(res).WithCredentialKindObserver(obs)
	return uc, obs
}

// onlyOutcome — единственный исход, увиденный счётчиком.
func onlyOutcome(t *testing.T, obs *recordingObserver) string {
	t.Helper()
	total := 0
	var last string
	for k, v := range obs.seen {
		total += v
		last = k
	}
	if total != 1 {
		t.Fatalf("исходов в переписи %d, ожидался ровно один: %v", total, obs.seen)
	}
	return last
}

func TestBasicLane_AuthorityRefusalIsCountedByItsReason(t *testing.T) {
	const credID = "soc_00000000000census"
	secret, _, err := credsecret.Mint(credID)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]domain.BasicCredentialRefusalReason{}
	for _, r := range domain.BasicCredentialRefusalReasons() {
		t.Run(string(r), func(t *testing.T) {
			uc, obs := refusedLane(t, &refusingResolver{err: domain.RefuseBasicCredential(r)})
			_, err := uc.Execute(context.Background(), IssueInput{Username: credID, Password: secret, Service: "registry"})
			if !errors.Is(err, ErrUnauthenticated) {
				t.Fatalf("отказ авторитета наружу обязан быть ErrUnauthenticated: %v", err)
			}
			if got, ok := domain.BasicCredentialRefusalReasonOf(err); !ok || got != r {
				t.Errorf("ошибка полосы не несёт причину внутрь: (%q, %v), ожидалась %q", got, ok, r)
			}
			outcome := onlyOutcome(t, obs)
			if !strings.Contains(outcome, strings.ReplaceAll(string(r), "-", "_")) {
				t.Errorf("исход %q не называет причину %q", outcome, r)
			}
			if prev, dup := seen[outcome]; dup {
				t.Errorf("исход %q уже назначен причине %q — причины слиты", outcome, prev)
			}
			seen[outcome] = r
		})
	}
	t.Run("причина не названа", func(t *testing.T) {
		uc, obs := refusedLane(t, &refusingResolver{err: domain.ErrBasicCredentialRefused})
		_, err := uc.Execute(context.Background(), IssueInput{Username: credID, Password: secret, Service: "registry"})
		if !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("отказ наружу обязан быть ErrUnauthenticated: %v", err)
		}
		outcome := onlyOutcome(t, obs)
		if _, taken := seen[outcome]; taken {
			t.Errorf("отказ без причины лёг в клетку причины %q", outcome)
		}
	})
	t.Run("имя не называет удостоверения — отказ формы до авторитета", func(t *testing.T) {
		res := &refusingResolver{}
		uc, obs := refusedLane(t, res)
		_, err := uc.Execute(context.Background(), IssueInput{Username: "soc_other0000000000", Password: secret, Service: "registry"})
		if !errors.Is(err, ErrUnauthenticated) {
			t.Fatalf("отказ наружу обязан быть ErrUnauthenticated: %v", err)
		}
		if res.calls != 0 {
			t.Errorf("авторитет спрошен %d раз: отказ формы решается до него", res.calls)
		}
		if got, ok := domain.BasicCredentialRefusalReasonOf(err); !ok || got != domain.BasicRefusalMalformed {
			t.Errorf("причина отказа формы (%q, %v), ожидалась %q", got, ok, domain.BasicRefusalMalformed)
		}
		outcome := onlyOutcome(t, obs)
		if seen[outcome] != domain.BasicRefusalMalformed {
			t.Errorf("отказ формы лёг в клетку %q, а не в клетку причины %q", outcome, domain.BasicRefusalMalformed)
		}
	})
}
