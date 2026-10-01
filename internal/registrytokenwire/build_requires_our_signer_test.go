// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// build_requires_our_signer_test.go — полоса выдачи докер-токена без НАШЕГО
// подписанта не собирается (kaname#494).
//
// # Предмет
//
// Своя чеканка — единственная дорога этой полосы: издателя, к которому можно
// было бы уйти, у службы нет. Сборка, принимающая пустого подписанта, строила
// бы выход реестра, который либо не выдаёт ничего, либо выдаёт чужим издателем
// — и оба исхода поднимаются Ready, а узнаётся о них по первому `docker login`.
// Поэтому пустой подписант — отказ в старте, и отказ называет ОБА выхода
// оператора: включить свою чеканку либо не поднимать слушатель реестра.
//
// # Почему «во всех режимах» держится построением
//
// Сборка режима посадки не читает вовсе: у неё нет входа, по которому боевой
// старт отличался бы от небоевого. Боевой старт с выключенной чеканкой сверх того
// отвергает страж настройки (строка таблицы требований полосы); здесь
// утверждается, что и небоевой не получает полосы без издателя.
package registrytokenwire_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/handler/registrytokenhttp"
	"github.com/PRO-Robotech/kaname/internal/registrytokenwire"
)

// laneWithoutSigner — вход сборки, исправный во всём, кроме подписанта.
func laneWithoutSigner() registrytokenwire.BuildConfig {
	return registrytokenwire.BuildConfig{
		Realm:                  "https://api.kacho.local/iam/token",
		Service:                "registry.probe.local",
		BasicCredentialTimeout: time.Second,
		TokenTTL:               5 * time.Minute,
	}
}

// TestBuild_WithoutOurSignerRefusesNamingBothExits — сборка без подписанта
// отказывает и называет обе ручки; законный близнец отличается ровно одним
// фактом — подписантом — и собирается.
func TestBuild_WithoutOurSignerRefusesNamingBothExits(t *testing.T) {
	mux, err := registrytokenwire.Build(nil, laneWithoutSigner())
	if err == nil {
		t.Fatalf("полоса собрана без нашего подписанта (mux=%v): выход реестра поднялся бы без "+
			"издателя — Ready на старте и отказ на каждом docker login", mux != nil)
	}
	for _, knob := range []string{"authn.token-signing.enabled", "api-server.registry-token.endpoint"} {
		if !strings.Contains(err.Error(), knob) {
			t.Errorf("отказ сборки не называет выход %q — оператор не узнает, что менять: %v", knob, err)
		}
	}

	// ЗАКОННЫЙ БЛИЗНЕЦ: тот же вход с нашим подписантом.
	twin := laneWithoutSigner()
	twin.Signer = ourSigner(t)
	mux, err = registrytokenwire.Build(nil, twin)
	if err != nil {
		t.Fatalf("полоса с нашим подписантом не собралась — отказ выше означал бы «сборка не "+
			"собирается ни на чём», а не «без подписанта»: %v", err)
	}
	// Собранная полоса — живая: вход без удостоверения получает вызов на
	// аутентификацию (анонимный поток не объявлен), а не пустоту.
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, registrytokenhttp.TokenPath, nil))
	if rec.Code != http.StatusUnauthorized || rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatalf("собранная полоса ответила %d без вызова на аутентификацию — собрано не то", rec.Code)
	}
}
