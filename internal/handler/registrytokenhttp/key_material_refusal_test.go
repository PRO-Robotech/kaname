// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// key_material_refusal_test.go — НАБЛЮДАЕМЫЙ отказ докерной полосы после снятия
// приёма ключевого материала (задача #1143, предикат снятия п.1 и п.2).
//
// # Почему проба здесь, а не только у use-case'а
//
// «Отказ не является оракулом» — свойство того, что видит КЛИЕНТ, а не того,
// что вернула функция. Клиент видит код, заголовок вызова и тело; различить их
// он может только по этим трём. Поэтому проба сверяет ответ ЦЕЛИКОМ и делает
// это через НАСТОЯЩИЙ use-case, а не через дублёра выдачи: дублёр отвечал бы
// тем, что ему прописали, и байтовое равенство доказывало бы свойство пробы.
//
// # Почему «называет годный вид» и «не оракул» не противоречат друг другу
//
// Тело одно на ВСЯКИЙ отказ этой полосы и не зависит от предъявленного. Оно
// называет годный вид СТАТИЧЕСКИ — как называет его страница документации, —
// а не по разбору того, что прислали. Из него нельзя узнать ничего о том, чем
// был предъявленный вход.
package registrytokenhttp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	registrytokenuc "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/registry_token"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho/pkg/credsecret"
)

// liveCredential — авторитет о базовом секрете: знает ровно одну годную строку.
// Снисходительнее продукта он не бывает — форму разбирает тем же объявлением.
type liveCredential struct {
	secret string
	sva    string
}

func (l liveCredential) ResolveBasic(_ context.Context, presented string) (domain.BasicCredential, error) {
	p, err := credsecret.Parse(presented)
	if err != nil || presented != l.secret {
		return domain.BasicCredential{}, domain.ErrBasicCredentialRefused
	}
	return domain.BasicCredential{
		PrincipalType: "service_account", PrincipalID: l.sva, CredentialID: p.CredentialID,
	}, nil
}

type constMinter struct{}

func (constMinter) MintToken(context.Context, registrytokenuc.MintInput) (registrytokenuc.MintOutput, error) {
	return registrytokenuc.MintOutput{AccessToken: "minted-1143", ExpiresIn: 300}, nil
}

// realDockerLane — настоящая полоса выдачи за настоящим обработчиком.
func realDockerLane(t *testing.T) (http.Handler, string, string) {
	t.Helper()
	const credID, svaID = "soc_0000000000001143h", "sva0000000000001143h"
	secret, _, err := credsecret.Mint(credID)
	if err != nil {
		t.Fatal(err)
	}
	uc := registrytokenuc.NewIssueRegistryTokenUseCase(registrytokenuc.Config{
		AllowedAudiences:  []string{"registry.kacho.local"},
		DefaultService:    "registry.kacho.local",
		AssertionAudience: "https://issuer.invalid/oauth2/token",
	}, nil, nil).
		WithLocalMinter(constMinter{}).
		WithBasicCredentialResolver(liveCredential{secret: secret, sva: svaID})
	return NewTokenHandler(Config{
		Realm:          "https://api.kacho.local/iam/token",
		DefaultService: "registry.kacho.local",
	}, uc), credID, secret
}

type observed struct {
	code int
	wwwa string
	body string
}

func login(t *testing.T, h http.Handler, user, pass string) observed {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, TokenPath+"?service=registry.kacho.local", nil)
	r.Header.Set("Authorization", basic(user, pass))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	b, _ := io.ReadAll(w.Result().Body)
	return observed{code: w.Code, wwwa: w.Header().Get("WWW-Authenticate"), body: string(b)}
}

// #1143 п.2 — наблюдаемый отказ БАЙТОВО одинаков для негодного вида и для
// неверного секрета; годная строка проходит (положительный контроль).
func TestRefusalIsByteIdenticalForKeyMaterialAndForAWrongSecret(t *testing.T) {
	h, credID, secret := realDockerLane(t)

	ok := login(t, h, credID, secret)
	if ok.code != http.StatusOK {
		t.Fatalf("положительный контроль отвергнут (%d %s) — отрицание ниже было бы вакуумным", ok.code, ok.body)
	}

	wrong, _, _ := credsecret.Mint(credID)
	keyMaterial := login(t, h, credID, "-----BEGIN PRIVATE KEY-----\nnot-a-real-key-1143\n-----END PRIVATE KEY-----")
	badSecret := login(t, h, credID, wrong)

	if keyMaterial.code != http.StatusUnauthorized {
		t.Fatalf("ключевой материал не отвергнут: %d %s", keyMaterial.code, keyMaterial.body)
	}
	if keyMaterial != badSecret {
		t.Errorf("отказы различимы снаружи — это оракул:\n  ключевой материал: %+v\n  неверный секрет:   %+v",
			keyMaterial, badSecret)
	}
}

// #1143 п.1 — отказ НАЗЫВАЕТ годный вид: без этого арендатор, настроенный
// по-старому, не узнает, чем заменить.
func TestRefusalNamesTheAcceptedCredentialKind(t *testing.T) {
	h, credID, _ := realDockerLane(t)
	got := login(t, h, credID, "-----BEGIN PRIVATE KEY-----\nnot-a-real-key-1143\n-----END PRIVATE KEY-----")

	if !strings.Contains(got.body, credsecret.Mark) {
		t.Errorf("тело отказа не называет годного вида (%q): %s", credsecret.Mark, got.body)
	}
	// Пара: тело обязано остаться ФИКСИРОВАННЫМ — ни имени, ни секрета, ни
	// разбора предъявленного в нём быть не может.
	if strings.Contains(got.body, credID) || strings.Contains(got.body, "PRIVATE KEY") {
		t.Errorf("тело отказа пересказывает предъявленное — это оракул: %s", got.body)
	}
}
