// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// anonymous_pace_test.go — темп анонимной выдачи на источник и её исходы в
// переписи полосы (kaname#928).
//
// # Пары
//
//   - источник сверх темпа получает отказ со сроком ожидания, чеканки нет;
//     законный близнец — другой источник в пределах темпа — получает токен;
//   - каждый исход анонимной выдачи попадает ровно в одну клетку той же
//     переписи, что исходы полосы предъявленного удостоверения;
//   - анонимный поток без темпа не строится; без анонимного потока темп не
//     требуется.
package registry_token

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/exchangepace"
)

// anonPaceSource / anonOtherSource — адреса двух источников.
const (
	anonPaceSource  = "192.0.2.10"
	anonOtherSource = "192.0.2.20"
)

// fixedPace — производственный темп на неподвижных часах: ведро не
// пополняется между вызовами пробы, и исход не зависит от скорости машины.
func fixedPace(t *testing.T, perSec int) *exchangepace.Pace {
	t.Helper()
	at := time.Unix(1_700_000_000, 0)
	p, err := exchangepace.New(perSec, func() time.Time { return at })
	if err != nil {
		t.Fatalf("темп пробы не построен: %v", err)
	}
	return p
}

// countingObserver — перепись исходов: клетка → число.
type countingObserver struct{ cells map[string]int }

func (c *countingObserver) ObserveCredentialKind(outcome string) {
	if c.cells == nil {
		c.cells = map[string]int{}
	}
	c.cells[outcome]++
}

// pacedAnonLane — анонимный поток с темпом perSec на источник.
func pacedAnonLane(t *testing.T, perSec int, m LocalMinter) (*IssueRegistryTokenUseCase, *countingObserver) {
	t.Helper()
	cfg := anonConfig()
	cfg.Anonymous.Pace = fixedPace(t, perSec)
	obs := &countingObserver{}
	return mustUseCase(t, cfg, m).WithCredentialKindObserver(obs), obs
}

func anonFrom(source string) AnonymousInput {
	return AnonymousInput{Service: "registry.kacho.local", Source: source}
}

func TestExecuteAnonymous_BeyondThePacePerSourceIsRefusedWithAWait(t *testing.T) {
	m := &countingMinter{out: MintOutput{AccessToken: "anon-jwt", ExpiresIn: 120}}
	uc, _ := pacedAnonLane(t, 2, m)

	for i := range 2 {
		if _, err := uc.ExecuteAnonymous(context.Background(), anonFrom(anonPaceSource)); err != nil {
			t.Fatalf("вход %d в пределах темпа отвергнут: %v", i+1, err)
		}
	}
	out, err := uc.ExecuteAnonymous(context.Background(), anonFrom(anonPaceSource))
	if !errors.Is(err, ErrAnonymousPaceExceeded) {
		t.Fatalf("третий вход источника при темпе 2 в секунду: err = %v, ждали превышения темпа", err)
	}
	var exceeded *AnonymousPaceExceededError
	if !errors.As(err, &exceeded) || exceeded.RetryAfter <= 0 {
		t.Fatalf("отказ по темпу не несёт срока ожидания: %v", err)
	}
	if out.Token != "" {
		t.Fatal("отказ по темпу выдал токен")
	}
	if m.calls != 2 {
		t.Fatalf("подписант позван %d раз; ждали 2 — сверх темпа чеканки нет", m.calls)
	}

	// Законный близнец: другой источник в пределах темпа той же полосы.
	twin, err := uc.ExecuteAnonymous(context.Background(), anonFrom(anonOtherSource))
	if err != nil || twin.Token != "anon-jwt" {
		t.Fatalf("другой источник в пределах темпа не получил токена: out=%+v err=%v", twin, err)
	}
}

func TestExecuteAnonymous_EveryOutcomeLandsInTheLaneCensus(t *testing.T) {
	cases := []struct {
		name string
		run  func(t *testing.T) *countingObserver
		want string
	}{
		{"выдано", func(t *testing.T) *countingObserver {
			uc, obs := pacedAnonLane(t, 5, &countingMinter{out: MintOutput{AccessToken: "x"}})
			_, _ = uc.ExecuteAnonymous(context.Background(), anonFrom(anonPaceSource))
			return obs
		}, OutcomeAnonymousIssued},
		{"превышение темпа", func(t *testing.T) *countingObserver {
			uc, obs := pacedAnonLane(t, 1, &countingMinter{out: MintOutput{AccessToken: "x"}})
			_, _ = uc.ExecuteAnonymous(context.Background(), anonFrom(anonPaceSource))
			obs.cells = nil
			_, _ = uc.ExecuteAnonymous(context.Background(), anonFrom(anonPaceSource))
			return obs
		}, OutcomeAnonymousPaceExceeded},
		{"отказ адресата", func(t *testing.T) *countingObserver {
			uc, obs := pacedAnonLane(t, 5, &countingMinter{out: MintOutput{AccessToken: "x"}})
			_, _ = uc.ExecuteAnonymous(context.Background(), AnonymousInput{Service: "foreign.example", Source: anonPaceSource})
			return obs
		}, OutcomeAnonymousAudienceRefused},
		{"издатель недоступен", func(t *testing.T) *countingObserver {
			uc, obs := pacedAnonLane(t, 5, &countingMinter{err: errors.New("signer down")})
			_, _ = uc.ExecuteAnonymous(context.Background(), anonFrom(anonPaceSource))
			return obs
		}, OutcomeAnonymousIssuerUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			obs := tc.run(t)
			total := 0
			for _, n := range obs.cells {
				total += n
			}
			if obs.cells[tc.want] != 1 || total != 1 {
				t.Fatalf("перепись = %v; ждали ровно одну запись в клетке %q", obs.cells, tc.want)
			}
		})
	}
}

func TestAnonymousOutcomesAreCellsOfTheLaneCensus(t *testing.T) {
	declared := CredentialKindOutcomes()
	for _, cell := range []string{
		OutcomeAnonymousIssued, OutcomeAnonymousPaceExceeded,
		OutcomeAnonymousAudienceRefused, OutcomeAnonymousIssuerUnavailable,
	} {
		if !slices.Contains(declared, cell) {
			t.Errorf("исход %q не объявлен клеткой переписи полосы %v", cell, declared)
		}
	}
	seen := map[string]bool{}
	for _, c := range declared {
		if seen[c] {
			t.Errorf("клетка %q объявлена дважды", c)
		}
		seen[c] = true
	}
}

func TestAnonymousLaneWithoutAPaceIsNotBuilt(t *testing.T) {
	noPace := anonConfig()
	noPace.Anonymous.Pace = nil // единственное отличие от исправного входа
	uc, err := NewIssueRegistryTokenUseCase(noPace, &fakeMinter{})
	if !errors.Is(err, ErrAnonymousPaceRequired) || uc != nil {
		t.Fatalf("анонимный поток без темпа построен: uc=%v err=%v", uc != nil, err)
	}
	// Законный близнец: без анонимного потока темп не требуется.
	off := noPace
	off.Anonymous.ClientID = ""
	if twin, terr := NewIssueRegistryTokenUseCase(off, &fakeMinter{}); terr != nil || twin == nil {
		t.Fatalf("полоса без анонимного потока не построена: %v", terr)
	}
}

// countingMinter — подписант, считающий обращения.
type countingMinter struct {
	calls int
	out   MintOutput
	err   error
}

func (c *countingMinter) MintToken(context.Context, MintInput) (MintOutput, error) {
	c.calls++
	return c.out, c.err
}
