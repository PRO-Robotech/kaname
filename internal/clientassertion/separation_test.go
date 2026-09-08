// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// separation_test.go — разделение ДВУХ видов подписанного, направление первое
// (приёмка F2, §11 F, сценарий F2-34).
//
// # Откуда взялся предмет
//
// С этой фазы один издатель работает с двумя видами подписанного: он ВЫПУСКАЕТ
// токен доступа для наших поверхностей и ПРИНИМАЕТ утверждение, которым клиент
// себя аутентифицирует. До F2 предмета не существовало — вида было ровно два
// только вместе.
//
// Признаков разделения три, они независимы, и требование выполняется КАЖДЫМ по
// отдельности (§2.6):
//
//  1. объявленный тип        — at+jwt против client-authentication+jwt;
//  2. адресат                — ресурсная поверхность против нашего издателя;
//  3. чей ключ подписал      — ключница платформы против ключа клиента.
//
// # Почему проба ходит ЛЕСТНИЦЕЙ, а не одним входом
//
// Каждый признак по отдельности защитим и ровно поэтому опасен: первый снимает
// клиент, тип не проставивший; второй — совпадение адресатов при будущей
// посадке; третий держится тем, что два множества ключей не пересекаются, — а
// это свойство дерева, а не закон. Проба, подающая один вход, зелена при любом
// из трёх, взятом в одиночку: она не отличает «отвергнуто тремя» от
// «отвергнуто одним, а два не работают вовсе».
//
// Поэтому признаки СНИМАЮТСЯ ПО ОДНОМУ, и на каждой ступени требуется отказ от
// ОСТАВШИХСЯ. Последняя ступень показывает границу нападающего: ключ снять
// нечем — закрытой половины ключа клиента у него нет, и это единственный
// признак, который нельзя исправить подделкой поля.
package clientassertion_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/clientassertion"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

// testResourceAudience — адресат РЕСУРСНОЙ поверхности: то, что стоит в токене
// доступа. Он намеренно не равен идентификатору нашего издателя
// (`testIssuerID`), потому что именно их различие и есть второй признак.
const testResourceAudience = "https://api.kacho.local"

// platformKeyProvider — ключница платформы для пробы.
//
// Дублёр НЕ снисходительнее настоящей: он отдаёт ровно то, что настоящая
// отдаёт, — закреплённый за ключом алгоритм и закрытую половину, — и не
// подменяет ключ на «какой получится».
type platformKeyProvider struct {
	material tokensigner.SigningMaterial
}

func (p platformKeyProvider) ActiveSigningKey(context.Context) (tokensigner.SigningMaterial, error) {
	return p.material, nil
}

// ecPrivatePEM разворачивает закрытую половину ключа пробы в тот вид, который
// читает подписант. Оснастка проверяющего этой половины не публикует — ей она
// не нужна: там ключ ВСЕГДА клиентский. Здесь нужна вторая, платформенная.
func ecPrivatePEM(t *testing.T, k testKey) []byte {
	t.Helper()
	priv, ok := k.private.(*ecdsa.PrivateKey)
	require.Truef(t, ok, "оснастка ждёт ключ ECDSA, получила %T", k.private)
	der, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
}

// platformSigner строит НАШ подписант на ключе, которого нет в реестре
// клиентов. Издателем объявлен идентификатор нашего издателя — тот самый, что
// проверяющий утверждение ждёт адресатом.
func platformSigner(t *testing.T, key testKey) *tokensigner.Signer {
	t.Helper()
	s, err := tokensigner.New(tokensigner.Config{
		Issuer:      testIssuerID,
		Clock:       func() time.Time { return testNow },
		MaxTokenTTL: tokenpolicy.MaxTokenTTL,
	}, platformKeyProvider{material: tokensigner.SigningMaterial{
		KID:           domain.KeyID("platform-1"),
		Algorithm:     domain.SigningAlgES256,
		PrivateKeyPEM: ecPrivatePEM(t, key),
		PublicKeyPEM:  key.publicPEM,
	}})
	require.NoError(t, err)
	return s
}

// TestF2_34_AccessTokenPresentedAsClientAssertionIsRefused — F2-34: токен
// доступа, выданный НАШИМ подписантом, поданный эндпоинту как утверждение
// клиента, отвергается; признаки снимаются по одному, и отказ наступает при
// каждом оставшемся.
func TestF2_34_AccessTokenPresentedAsClientAssertionIsRefused(t *testing.T) {
	f := newFixture(t)
	// Ключ платформы — ОТДЕЛЬНЫЙ и в реестре клиентов не зарегистрирован. Возьми
	// проба один ключ на оба вида, третий признак исчез бы из пробы вместе с
	// предметом, а лестница ниже осталась бы зелёной.
	platformKey := newKey(t, tokenpolicy.AlgES256)
	require.NotEqual(t, f.key.publicPEM, platformKey.publicPEM,
		"предпосылка пробы: ключница платформы и реестр клиентов держат РАЗНЫЕ ключи")
	signer := platformSigner(t, platformKey)

	mint := func(t *testing.T, typ string, audience []string) string {
		t.Helper()
		tok, err := signer.Sign(context.Background(), tokensigner.Request{
			Subject:   testClientID,
			Audience:  audience,
			TokenType: typ,
			TTL:       2 * time.Minute,
		})
		require.NoError(t, err)
		return tok.Token
	}

	// Ступень 0 — токен доступа как есть. Все три признака на местах.
	t.Run("токен доступа как есть — отказ", func(t *testing.T) {
		res, err := f.verify(t, mint(t, tokenpolicy.TokenTypeAccess, []string{testResourceAudience}))
		requireOutcome(t, clientassertion.OutcomeTokenTypeMismatch, res, err)
	})

	// Ступень 1 — снят признак ТИПА: подписант проставил тип утверждения.
	// Остались адресат, ключ и личность.
	t.Run("исправлен тип — отказ", func(t *testing.T) {
		res, err := f.verify(t, mint(t, tokenpolicy.TokenTypeClientAssertion, []string{testResourceAudience}))
		requireOutcome(t, clientassertion.OutcomeIdentityMismatch, res, err)
	})

	// Ступень 2 — снят и признак АДРЕСАТА: токен адресован нашему издателю.
	// Отказ наступает всё равно — это и есть «ни один признак не единственный».
	t.Run("исправлен адресат — отказ", func(t *testing.T) {
		res, err := f.verify(t, mint(t, tokenpolicy.TokenTypeClientAssertion, []string{testIssuerID}))
		requireOutcome(t, clientassertion.OutcomeIdentityMismatch, res, err)
	})

	// Ступень 3 — снята и личность: издатель и субъект названы клиентом.
	//
	// Такой вход НАШ подписант не производит by construction — издателя он берёт
	// из своей настройки, — поэтому он собирается вручную ключом платформы. Это
	// сознательная уступка нападающему: мы даём ему больше, чем он мог бы
	// получить, и требуем отказа всё равно. Остаётся ровно один признак — чей
	// ключ подписал, — и снять его нечем: закрытой половины ключа клиента у
	// платформы нет.
	t.Run("исправлены тип, адресат и личность — остаётся ключ", func(t *testing.T) {
		raw := assertion{
			headerJSON:  goodHeader(platformKey.alg),
			payloadJSON: claims(goodClaims("jti-34-ladder")),
			key:         platformKey,
		}.sign(t)
		res, err := f.verify(t, raw)
		requireOutcome(t, clientassertion.OutcomeSignatureMismatch, res, err)
	})

	// Положительный контроль. Без него всё выше зелено на проверяющем,
	// отвергающем любой вход, — а это самый частый способ сломать такую пробу.
	t.Run("законное утверждение клиента принимается", func(t *testing.T) {
		raw := assertion{
			headerJSON:  goodHeader(f.key.alg),
			payloadJSON: claims(goodClaims("jti-34-ok")),
			key:         f.key,
		}.sign(t)
		res, err := f.verify(t, raw)
		require.NoError(t, err)
		require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)
	})
}

// TestF2_34_VerifierRequiresItsOwnTypeExplicitly — проверяющий требует СВОЕГО
// типа явно и не принимает отсутствие типа (§11 F, F2-36).
//
// Отдельная проба, а не ступень лестницы выше: там тип снимался ВМЕСТЕ с
// прочими признаками токена доступа, и «отвергнуто по типу» было неотличимо от
// «отвергнуто по чему-то ещё». Здесь всё остальное законно, поэтому решает
// ровно тип.
//
// Отсутствие типа стоит рядом с несовпадением намеренно: производитель типа на
// этой полосе — не мы, а клиент, и «типа нет» есть самый дешёвый для него
// способ снять первый признак целиком. Принять отсутствие значило бы объявить
// признак, который снимается пропуском поля.
func TestF2_34_VerifierRequiresItsOwnTypeExplicitly(t *testing.T) {
	f := newFixture(t)

	for name, hdr := range map[string]string{
		"тип токена доступа": header(
			jsonString("alg"), jsonString(f.key.alg),
			jsonString("typ"), jsonString(tokenpolicy.TokenTypeAccess)),
		"типа нет вовсе": header(jsonString("alg"), jsonString(f.key.alg)),
		"тип пуст": header(
			jsonString("alg"), jsonString(f.key.alg),
			jsonString("typ"), jsonString("")),
		"тип не строка": header(
			jsonString("alg"), jsonString(f.key.alg),
			jsonString("typ"), `42`),
	} {
		t.Run(name, func(t *testing.T) {
			raw := assertion{headerJSON: hdr, payloadJSON: claims(goodClaims("jti-36-" + name)), key: f.key}.sign(t)
			res, err := f.verify(t, raw)
			requireOutcome(t, clientassertion.OutcomeTokenTypeMismatch, res, err)
		})
	}

	// Положительный контроль: свой тип на месте — вход принимается.
	t.Run("свой тип на месте — приём", func(t *testing.T) {
		raw := assertion{
			headerJSON:  goodHeader(f.key.alg),
			payloadJSON: claims(goodClaims("jti-36-ok")),
			key:         f.key,
		}.sign(t)
		res, err := f.verify(t, raw)
		require.NoError(t, err)
		require.Equal(t, clientassertion.OutcomeAccepted, res.Outcome)
	})
}

// TestF2_34_DeclaredTypesOfBothKindsAreDistinct — два вида подписанного
// объявлены в ОДНОМ месте и попарно различны.
//
// Совпади они по недосмотру — первый признак исчез бы молча, а положительный
// путь обоих видов остался бы зелёным: токен продолжал бы выпускаться,
// утверждение — приниматься, и различия между ними просто не стало бы.
func TestF2_34_DeclaredTypesOfBothKindsAreDistinct(t *testing.T) {
	declared := tokenpolicy.SignedMaterialTypes()
	require.Len(t, declared, 2, "видов подписанного два: токен доступа и утверждение клиента")

	seen := map[string]bool{}
	for _, v := range declared {
		require.NotEmpty(t, v, "пустой объявленный тип означал бы «любой»")
		require.Falsef(t, seen[v], "объявленный тип %q встречается дважды: видов стало бы не два, а один", v)
		seen[v] = true
	}
	require.NotEqual(t, tokenpolicy.TokenTypeAccess, tokenpolicy.TokenTypeClientAssertion)
}
