// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// our_minter_is_required_test.go — докерная полоса выдаёт ТОЛЬКО нашей чеканкой
// (kaname#494).
//
// # Предмет
//
// У полосы было два издателя: наш подписант и обмен утверждения у прежнего
// издателя, который шёл, когда подписант не провязан. Обмен снимается целиком,
// и полоса без нашего подписанта не выдаёт НИЧЕГО.
//
// # Свойства, которые до снятия утверждались только на ветке обмена
//
// Снятие ветки молча уносит всякую пробу, чьё свойство держалось лишь на ней.
// Поэтому каждое такое свойство утверждается здесь на ветке НАШЕЙ чеканки —
// до снятия и после него одной и той же пробой:
//
//	анонимный токен просит только чтение, ни одного глагола записи;
//	анонимный поток не объявлен → отказ аутентификации, чеканки нет;
//	отказ нашей чеканки на анонимном потоке → недоступность издателя, не токен.
package registry_token

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// anonOnOurMinting — анонимный поток на нашей чеканке. Удостоверение
// анонимного принципала — одно его имя: подписывать им больше нечего.
func anonOnOurMinting(t *testing.T, m LocalMinter) *IssueRegistryTokenUseCase {
	t.Helper()
	return mustUseCase(t, Config{
		AllowedAudiences: []string{"registry.kacho.local"},
		DefaultService:   "registry.kacho.local",
		Anonymous:        AnonymousIdentity{ClientID: "registry-anonymous"},
	}, m)
}

// TestUseCaseWithoutOurMinterIssuesNothing — без нашего подписанта полосы нет:
// построитель отказывает, и выдавать токен некому ни одним путём.
//
// До kaname#494 тот же вход (анонимный поток, подписанта нет) давал токен
// прежнего издателя через обмен; проба стояла красной ровно на этом. Теперь
// состояние «подписанта нет» непредставимо: use-case не строится вовсе.
// Законный близнец — тот же вход с подписантом (anonOnOurMinting ниже) — строится.
func TestUseCaseWithoutOurMinterIssuesNothing(t *testing.T) {
	uc, err := NewIssueRegistryTokenUseCase(anonConfig(), nil)
	if err == nil || uc != nil {
		t.Fatalf("полоса без нашего подписанта построена (uc=%v, err=%v) — издатель у неё один, "+
			"и без него выдачи нет", uc != nil, err)
	}
	if !errors.Is(err, ErrOwnMinterRequired) {
		t.Fatalf("отказ построения не называет отсутствие своего подписанта: %v", err)
	}
	if twin, terr := NewIssueRegistryTokenUseCase(anonConfig(), &fakeMinter{}); terr != nil || twin == nil {
		t.Fatalf("законный близнец с подписантом не построен: %v", terr)
	}
}

// TestExecuteAnonymous_IsEnabledByItsIdentityAlone — включённость анонимного
// потока определяется его идентичностью, а не ключом, которым больше ничего не
// подписывается.
func TestExecuteAnonymous_IsEnabledByItsIdentityAlone(t *testing.T) {
	m := &fakeMinter{out: MintOutput{AccessToken: "anon-minted", ExpiresIn: 60}}
	uc := anonOnOurMinting(t, m)

	if !uc.AnonymousEnabled() {
		t.Fatal("анонимный поток с объявленной идентичностью числится выключенным — включённость " +
			"держится на поле, у которого не осталось читателя")
	}
	out, err := uc.ExecuteAnonymous(context.Background(), "registry.kacho.local")
	if err != nil {
		t.Fatalf("ExecuteAnonymous: %v", err)
	}
	if out.Token != "anon-minted" || m.got.Subject != "registry-anonymous" {
		t.Fatalf("анонимный токен выпущен не нашей чеканкой за анонимного принципала: out=%+v, субъект=%q",
			out, m.got.Subject)
	}
}

// TestExecuteAnonymous_OnOurMinting_ReadOnlyScopeCarriesNoWriteVerb — пол
// чтения анонимного токена держится на ветке нашей чеканки.
func TestExecuteAnonymous_OnOurMinting_ReadOnlyScopeCarriesNoWriteVerb(t *testing.T) {
	m := &fakeMinter{out: MintOutput{AccessToken: "t", ExpiresIn: 60}}
	uc := anonOnOurMinting(t, m)
	// Включённость утверждает соседняя проба; эта — объём.
	uc.cfg.Anonymous = anonConfig().Anonymous

	if _, err := uc.ExecuteAnonymous(context.Background(), "registry.kacho.local"); err != nil {
		t.Fatalf("ExecuteAnonymous: %v", err)
	}
	if m.got.Scope != AnonymousReadScope {
		t.Fatalf("анонимный запрос объёма %q; ожидался только %q", m.got.Scope, AnonymousReadScope)
	}
	for _, writeVerb := range []string{"push", "write", "delete", "*"} {
		if strings.Contains(m.got.Scope, writeVerb) {
			t.Errorf("анонимный объём %q несёт глагол записи %q", m.got.Scope, writeVerb)
		}
	}
	if !strings.Contains(AnonymousReadScope, "pull") {
		t.Errorf("AnonymousReadScope = %q не несёт глагола чтения", AnonymousReadScope)
	}
}

// TestExecuteAnonymous_OnOurMinting_DisabledIsUnauthenticatedAndMintsNothing —
// необъявленный анонимный поток отказывает аутентификацией, и чеканки нет.
func TestExecuteAnonymous_OnOurMinting_DisabledIsUnauthenticatedAndMintsNothing(t *testing.T) {
	m := &fakeMinter{out: MintOutput{AccessToken: "should-not-happen"}}
	uc := anonOnOurMinting(t, m)
	uc.cfg.Anonymous = AnonymousIdentity{} // единственное отличие: поток не объявлен

	if uc.AnonymousEnabled() {
		t.Fatal("анонимный поток без идентичности числится включённым")
	}
	out, err := uc.ExecuteAnonymous(context.Background(), "registry.kacho.local")
	if !errors.Is(err, ErrUnauthenticated) {
		t.Fatalf("err = %v; ожидался ErrUnauthenticated (обработчик отдаёт 401-вызов)", err)
	}
	if out.Token != "" || m.got.Subject != "" {
		t.Fatal("необъявленный анонимный поток выпустил токен либо дошёл до чеканки")
	}
}

// TestExecuteAnonymous_OnOurMinting_MinterFailureIsIssuerUnavailable — отказ
// нашей чеканки на анонимном потоке — недоступность издателя (503), не токен и
// не отказ аутентификации.
func TestExecuteAnonymous_OnOurMinting_MinterFailureIsIssuerUnavailable(t *testing.T) {
	uc := anonOnOurMinting(t, &fakeMinter{err: errors.New("no signing key")})
	uc.cfg.Anonymous = anonConfig().Anonymous

	out, err := uc.ExecuteAnonymous(context.Background(), "registry.kacho.local")
	if !errors.Is(err, ErrIssuerUnavailable) {
		t.Fatalf("err = %v; ожидалась недоступность издателя", err)
	}
	if errors.Is(err, ErrUnauthenticated) {
		t.Error("отказ своей чеканки выдан за негодное удостоверение")
	}
	if out.Token != "" {
		t.Fatal("токен на отказе чеканки")
	}
}
