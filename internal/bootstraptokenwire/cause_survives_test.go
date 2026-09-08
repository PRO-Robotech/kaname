// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package bootstraptokenwire

// cause_survives_test.go — причина невозможности выпустить доезжает до ЖУРНАЛА,
// а полоса ответа остаётся прежней.
//
// # Предмет
//
// Наружу отказ выдачи первого удостоверения — одна полоса с фиксированным
// текстом: различать «нечем подписать», «состав не собрался» и «ключница не
// ответила» вызывающему нельзя, это оракул. Внутри — ровно наоборот: чинятся они
// противоположно, и первое, что спросит инженер, — что именно ответила
// зависимость.
//
// # Чего это стоило (наблюдалось 2026-08-11 на ПРЕЖНЕЙ полосе)
//
// Тогда контур ходил за токеном к внешнему поставщику, и адаптер, увидев полосу
// недоступности, возвращал голый признак: в журнал уходил пересказ собственного
// решения об отказе. Разбор на живом стенде занял двадцать минут при здоровой
// чужой стороне — вопрос закрыла бы одна строка настоящей причины.
//
// # Почему проба ЖИВЁТ, хотя её прежний предмет снят (задача #1119)
//
// Снята дорога к поставщику, а не класс. Наша чеканка отказывает по своим
// причинам, и они точно так же могут быть заменены пересказом решения об отказе.
// Проба перенесена на нашу полосу вместе с техникой; удалить её значило бы
// потерять урок вместе с кодом, который его породил.
//
// # Что утверждает проба
//
// Причина оборачивается, а не подменяется: признак по-прежнему опознаётся
// `errors.Is` (полоса ответа use-case не меняется), но текст ошибки НЕСЁТ
// исходную причину. Отдельно закреплено, что отказ ИНОЙ природы полосой
// недоступности не притворяется.

import (
	"context"
	"errors"
	"strings"
	"testing"

	bootstraptoken "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/bootstrap_token"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

// signerStub — подписант, отвечающий заданной ошибкой.
type signerStub struct {
	err error
	tok tokensigner.Token
}

func (s signerStub) Sign(context.Context, tokensigner.Request) (tokensigner.Token, error) {
	return s.tok, s.err
}

// claimsStub — состав утверждений, отвечающий заданной ошибкой либо картой.
type claimsStub struct {
	claims map[string]any
	err    error
}

func (c claimsStub) ClaimsForAssertionClient(context.Context, domain.AssertionClient, service.TokenHookContext) (map[string]any, service.ResolvedPrincipal, error) {
	if c.err != nil {
		return nil, service.ResolvedPrincipal{}, c.err
	}
	return c.claims, service.ResolvedPrincipal{Kind: service.PrincipalServiceAccount}, nil
}

func mintWith(t *testing.T, s TokenSigner, c ClaimsComposer) (bootstraptoken.MintOutput, error) {
	t.Helper()
	m := localMint{signer: s, claims: c}
	return m.MintToken(context.Background(), bootstraptoken.MintInput{
		SAKeyID:     "soc_db27d17291ff453b6",
		PrincipalID: "svab91854890de887e6d",
		Audience:    "https://api.kacho.cloud",
		TTL:         bootstraptoken.MaxTTL,
	})
}

func TestUnavailabilityKeepsItsCauseForTheLog(t *testing.T) {
	// Форма, в которой причину отдаёт ключница: признак + текст зависимости.
	cause := errors.New("dial tcp: lookup kaname-db.kacho.svc: no such host")
	wrapped := errors.Join(tokensigner.ErrNoSigningKey, cause)

	_, err := mintWith(t, signerStub{err: wrapped}, claimsStub{claims: map[string]any{}})

	if err == nil {
		t.Fatal("невозможность подписать не дала ошибки — выдача первого удостоверения открылась бы")
	}
	if !errors.Is(err, bootstraptoken.ErrMintingUnavailable) {
		t.Fatalf("полоса ответа сменилась: use-case опознаёт невозможность выпустить по признаку, "+
			"а получил %v", err)
	}
	if !strings.Contains(err.Error(), "no such host") {
		t.Fatalf("причина потеряна: в журнал уйдёт пересказ собственного решения об отказе, "+
			"а не то, что ответила зависимость.\nполучено: %q", err.Error())
	}
}

// TestOtherFailuresAreNotDressedAsUnavailability — отказ иной природы полосой
// недоступности не притворяется.
//
// Положительный контроль к пробе выше: без него «причина сохранена» зеленело бы
// и на адаптере, который объявляет недоступность ВСЕГДА — то есть перестал
// различать «нечем сейчас» и «не выйдет никогда», а это разные исходы с разной
// ценой: первый лечится повтором, второй им не лечится.
func TestOtherFailuresAreNotDressedAsUnavailability(t *testing.T) {
	rejection := errors.New("tokensigner: signing algorithm \"HS256\" is not one of [RS256 ES256 EdDSA]")

	_, err := mintWith(t, signerStub{err: rejection}, claimsStub{claims: map[string]any{}})

	if err == nil {
		t.Fatal("отказ подписи не дал ошибки")
	}
	if errors.Is(err, bootstraptoken.ErrMintingUnavailable) {
		t.Fatalf("негодный материал выдан за недоступность — повтор такого запроса не пройдёт "+
			"никогда, а полоса недоступности обещает обратное: %v", err)
	}
	if !strings.Contains(err.Error(), "HS256") {
		t.Fatalf("причина отказа потеряна: %q", err.Error())
	}
}

// TestClaimsFailureNeverYieldsAToken — состав утверждений не собрался ⇒ токена
// нет вовсе.
//
// Токен без принципала выглядит выданным и им не является: край принял бы его и
// не нашёл, за кого он говорит. Проба утверждает ОТСУТСТВИЕ токена, а не факт
// вызова: «функция не позвана» зеленеет и на реализации, которая зовёт её и
// молча идёт дальше.
func TestClaimsFailureNeverYieldsAToken(t *testing.T) {
	out, err := mintWith(t,
		signerStub{tok: tokensigner.Token{Token: "должен.не.появиться"}},
		claimsStub{err: errors.New("token enrichment: own-client port is not wired")})

	if err == nil {
		t.Fatal("несобранный состав утверждений не дал ошибки")
	}
	if out.AccessToken != "" {
		t.Fatalf("токен выпущен при несобранном составе утверждений: %q", out.AccessToken)
	}
	if !strings.Contains(err.Error(), "own-client port is not wired") {
		t.Fatalf("причина потеряна: %q", err.Error())
	}
}

// TestAudienceIsRequired — незаданный адресат означал бы «любой».
func TestAudienceIsRequired(t *testing.T) {
	m := localMint{
		signer: signerStub{tok: tokensigner.Token{Token: "должен.не.появиться"}},
		claims: claimsStub{claims: map[string]any{}},
	}
	out, err := m.MintToken(context.Background(), bootstraptoken.MintInput{
		SAKeyID:     "soc_db27d17291ff453b6",
		PrincipalID: "svab91854890de887e6d",
		TTL:         bootstraptoken.MaxTTL,
	})
	if err == nil {
		t.Fatal("удостоверение выпущено без адресата — cluster-admin, годный любому контуру")
	}
	if out.AccessToken != "" {
		t.Fatalf("токен выпущен без адресата: %q", out.AccessToken)
	}
}
