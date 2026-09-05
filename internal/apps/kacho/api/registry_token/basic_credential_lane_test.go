// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// basic_credential_lane_test.go — ПОЛОСА ДОКЕРА ДЛЯ БАЗОВОГО СЕКРЕТА.
//
// Задача #1142, приёмка BAT-1 §5.5; сценарии BAT-1-37, 38, 39, 40, 41.

package registry_token

import (
	"context"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho/pkg/credsecret"
)

// fakeBasicResolver — авторитет о предъявленном базовом секрете.
type fakeBasicResolver struct {
	live  map[string]string // идентификатор → годная строка
	svaOf map[string]string // идентификатор → служебная учётка
	calls int
	err   error
}

func (f *fakeBasicResolver) ResolveBasic(_ context.Context, presented string) (domain.BasicCredential, error) {
	f.calls++
	if f.err != nil {
		return domain.BasicCredential{}, f.err
	}
	p, err := credsecret.Parse(presented)
	if err != nil {
		return domain.BasicCredential{}, domain.ErrBasicCredentialRefused
	}
	if f.live[p.CredentialID] != presented {
		return domain.BasicCredential{}, domain.ErrBasicCredentialRefused
	}
	return domain.BasicCredential{
		PrincipalType: "service_account",
		PrincipalID:   f.svaOf[p.CredentialID],
		CredentialID:  p.CredentialID,
	}, nil
}

type fakeMinter struct {
	got MintInput
	out MintOutput
	err error
}

func (f *fakeMinter) MintToken(_ context.Context, in MintInput) (MintOutput, error) {
	f.got = in
	return f.out, f.err
}

func basicDockerLane(t *testing.T, res *fakeBasicResolver) (*IssueRegistryTokenUseCase, *fakeMinter) {
	t.Helper()
	m := &fakeMinter{out: MintOutput{AccessToken: "minted", ExpiresIn: 300}}
	uc := NewIssueRegistryTokenUseCase(Config{
		Scope:            "registry",
		AllowedAudiences: []string{"registry"},
		// Умолчание объявлено НЕПУСТЫМ намеренно: с пустым запрос, адресата не
		// назвавший, получал бы пустой адресат — то есть «любой», — и проба
		// умолчания зеленела бы, ничего не утверждая.
		DefaultService:    "registry",
		AssertionAudience: "https://issuer.invalid/oauth2/token",
	}, &fakeSigner{}, &fakeExchanger{}).
		WithLocalMinter(m).
		WithBasicCredentialResolver(res)
	return uc, m
}

// BAT-1-37 / BAT-1-41 — положительный путь: вход по имени=идентификатор,
// пароль=строка. Утверждается ПАРА: чего на проводе нет и ЧТО на нём есть.
func TestBAT1_37_DockerLoginWithTheBasicSecretSucceeds(t *testing.T) {
	const credID, svaID = "soc_0000000000000bat1", "sva0000000000000bat1"
	secret, _, err := credsecret.Mint(credID)
	if err != nil {
		t.Fatal(err)
	}
	res := &fakeBasicResolver{
		live:  map[string]string{credID: secret},
		svaOf: map[string]string{credID: svaID},
	}
	uc, minter := basicDockerLane(t, res)

	out, err := uc.Execute(context.Background(), IssueInput{
		Username: credID,
		Password: secret,
		Service:  "registry",
	})
	if err != nil {
		t.Fatalf("вход отвергнут: %v", err)
	}
	if out.Token == "" {
		t.Fatal("удостоверение реестра не выдано")
	}
	// Положительный контроль: полученное удостоверение принадлежит ЭТОЙ учётке.
	if minter.got.Subject != svaID {
		t.Errorf("принципал выданного удостоверения = %q, ожидался %q", minter.got.Subject, svaID)
	}
	// Пара: сам секрет реестру НЕ достаётся ни в каком виде.
	if strings.Contains(out.Token, secret) {
		t.Error("секрет уехал в удостоверение реестра")
	}
	if minter.got.ConfirmationX5TS256 != "" {
		t.Error("вид предъявительский — материала привязки у него нет")
	}
	if res.calls != 1 {
		t.Errorf("обращений к авторитету %d, ожидалось 1", res.calls)
	}
}

// BAT-1-38 — имя ОБЯЗАНО совпадать с идентификатором, который несёт строка, и
// расхождение даёт отказ ДОСЛОВНО ТОТ ЖЕ, что при неверном секрете.
func TestBAT1_38_UsernameMustNameTheCredentialAndTheRefusalIsNoOracle(t *testing.T) {
	const credID, svaID = "soc_0000000000000bat1", "sva0000000000000bat1"
	secret, _, _ := credsecret.Mint(credID)
	res := &fakeBasicResolver{
		live:  map[string]string{credID: secret},
		svaOf: map[string]string{credID: svaID},
	}
	uc, _ := basicDockerLane(t, res)

	_, mismatch := uc.Execute(context.Background(), IssueInput{
		Username: "soc_0000000000000bat9",
		Password: secret,
		Service:  "registry",
	})
	if mismatch == nil {
		t.Fatal("вход с чужим именем прошёл")
	}

	wrong, _, _ := credsecret.Mint(credID)
	_, badSecret := uc.Execute(context.Background(), IssueInput{
		Username: credID,
		Password: wrong,
		Service:  "registry",
	})
	if badSecret == nil {
		t.Fatal("вход с неверным секретом прошёл")
	}
	if mismatch.Error() != badSecret.Error() {
		t.Errorf("отказы различимы: расхождение имени %q, неверный секрет %q — это оракул",
			mismatch, badSecret)
	}

	// Положительный контроль: совпадающее имя проходит.
	if _, err := uc.Execute(context.Background(), IssueInput{
		Username: credID, Password: secret, Service: "registry",
	}); err != nil {
		t.Fatalf("совпадающее имя отвергнуто: %v", err)
	}
}

// BAT-1-39 СНЯТ ВМЕСТЕ СО СВОИМ ПРЕДМЕТОМ.
//
// Он был зеркальным контролём фазы #1142: «ключевой материал по-прежнему
// принимается», и нёс предикат снятия прямо в тексте — «его снятие принадлежит
// #1143». Предикат сработал: приём снят, и проба, утверждавшая обратное, стала
// бы утверждением о несуществующем. Обратное свойство утверждается там, где
// живёт его предмет, — key_material_refused_test.go.

// BAT-1-40 — отозванное / истёкшее / принадлежащее неактивному владельцу
// отвергается ТЕМ ЖЕ отказом; живое проходит (положительный контроль).
func TestBAT1_40_RevokedOrExpiredIsRefusedByTheSameRefusal(t *testing.T) {
	const credID = "soc_0000000000000bat1"
	secret, _, _ := credsecret.Mint(credID)

	live := &fakeBasicResolver{
		live:  map[string]string{credID: secret},
		svaOf: map[string]string{credID: "sva0000000000000bat1"},
	}
	ucLive, _ := basicDockerLane(t, live)
	if _, err := ucLive.Execute(context.Background(), IssueInput{
		Username: credID, Password: secret, Service: "registry",
	}); err != nil {
		t.Fatalf("живое удостоверение отвергнуто: %v", err)
	}

	// Отозвано: авторитет строки не находит.
	revoked := &fakeBasicResolver{live: map[string]string{}}
	ucRevoked, _ := basicDockerLane(t, revoked)
	_, err := ucRevoked.Execute(context.Background(), IssueInput{
		Username: credID, Password: secret, Service: "registry",
	})
	if err == nil {
		t.Fatal("отозванное удостоверение прошло вход в реестр")
	}
	if err != ErrUnauthenticated {
		t.Errorf("отказ = %v, ожидался единый отказ полосы", err)
	}
}
