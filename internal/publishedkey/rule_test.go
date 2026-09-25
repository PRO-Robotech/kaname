// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// rule_test.go — правило выбора ключа проверки из публикуемого набора: каждая
// ветвь отказа рядом со своим близнецом, и близнец отличается ОДНИМ фактом.
//
// Ветви правила, у которых по построению нет наблюдаемого исхода на
// настоящем наборе (форма `kid` при наборе законных идентификаторов;
// алгоритм, закреплённый за ключом, при закрытом словаре алгоритмов, где
// каждый вид ключа проверяет ровно один алгоритм), судятся на наборе, в
// котором исход есть: поиск, отвечающий на ЛЮБОЙ идентификатор, и запись
// набора, чей алгоритм расходится с видом её ключа. Без этого снятие ветви
// не роняло ни одной пробы ни у одного из трёх читателей.
package publishedkey

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/signingkeygen"
)

const testKID = "kaname-a"

// ringKey — ключ набора и его приватная половина.
type ringKey struct {
	published domain.PublishedKey
	private   []byte
}

func newRingKey(t *testing.T, kid string) ringKey {
	t.Helper()
	m, err := signingkeygen.Generate(domain.SigningAlgES256)
	require.NoError(t, err)
	return ringKey{
		published: domain.PublishedKey{KID: domain.KeyID(kid), Algorithm: domain.SigningAlgES256, PublicKeyPEM: m.PublicKeyPEM},
		private:   m.PrivateKeyPEM,
	}
}

// mint подписывает токен ключом кольца; shape правит заголовок до подписи.
func mint(t *testing.T, k ringKey, kid string, shape func(map[string]any)) string {
	t.Helper()
	key, err := jwt.ParseECPrivateKeyFromPEM(k.private)
	require.NoError(t, err)
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": "https://iam.kacho.local", "sub": "usr-0123456789abcdefg", "jti": "tok0123456789abcdefg",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(),
	})
	tok.Header["kid"] = kid
	tok.Header["typ"] = tokenpolicy.TokenTypeAccess
	if shape != nil {
		shape(tok.Header)
	}
	raw, err := tok.SignedString(key)
	require.NoError(t, err)
	return raw
}

// parser — разбор так, как его строит читатель: закрытый словарь алгоритмов,
// утверждения времени здесь не судятся.
func parser() *jwt.Parser {
	return jwt.NewParser(jwt.WithValidMethods(tokenpolicy.Algorithms()), jwt.WithoutClaimsValidation())
}

func parse(raw string, lookup Lookup) (*jwt.Token, error) {
	return Parse(parser(), raw, jwt.MapClaims{}, lookup)
}

// accepted — близнец: правило выбрало ключ, и подпись сошлась.
func accepted(t *testing.T, raw string, lookup Lookup) {
	t.Helper()
	tok, err := parse(raw, lookup)
	require.NoError(t, err, "близнец не принят — отрицание рядом зеленело бы на правиле, не принимающем ничего")
	require.True(t, tok.Valid)
	require.Equal(t, tokenpolicy.TokenTypeAccess, tok.Header["typ"])
}

// refused — отказ правила по НАЗВАННОЙ причине, и это суждение о токене, а не
// третий исход.
func refused(t *testing.T, raw string, lookup Lookup, reason error) error {
	t.Helper()
	tok, err := parse(raw, lookup)
	require.Error(t, err, "токен принят")
	require.Nil(t, tok, "при отказе отдан токен")
	require.ErrorIs(t, err, reason, "отказ не по той причине")
	require.NotErrorIs(t, err, ErrUnavailable, "суждение о токене названо сбоем набора")
	return err
}

// anyKID — поиск, отвечающий ключом k на ЛЮБОЙ идентификатор, и счётчик
// обращений: так видно, дошёл ли идентификатор до поиска.
func anyKID(k ringKey, asked *int) Lookup {
	return func(string) (domain.PublishedKey, bool, error) {
		*asked++
		return k.published, true, nil
	}
}

// Форма идентификатора ограничивается ДО поиска: негодная форма не доезжает
// до набора (у читателя предъявленного поиск — повод обновить снимок из
// хранилища). Близнец — законная форма у того же поиска: принят, поиск спрошен.
func TestRule_KeyIDFormIsJudgedBeforeTheLookup(t *testing.T) {
	k := newRingKey(t, testKID)

	var asked int
	err := refused(t, mint(t, k, "../../etc/passwd\x00", nil), anyKID(k, &asked), errKeyIDForm)
	require.Zero(t, asked, "идентификатор негодной формы дошёл до поиска")
	require.Contains(t, err.Error(), "key id has illegal form")

	asked = 0
	accepted(t, mint(t, k, "kaname-zz", nil), anyKID(k, &asked))
	require.Equal(t, 1, asked, "близнец: законный идентификатор не дошёл до поиска")
}

// Идентификатор, которого в наборе нет, — отказ. Близнец — тот же токен под
// идентификатором из набора.
func TestRule_KeyIDOutsideTheSetIsRefused(t *testing.T) {
	k := newRingKey(t, testKID)
	lookup := SetLookup([]domain.PublishedKey{k.published})

	refused(t, mint(t, k, "kaname-b", nil), lookup, errKeyIDUnresolved)
	accepted(t, mint(t, k, testKID, nil), lookup)
}

// Способ проверки выбирает КЛЮЧ, а не заголовок: запись набора закрепила за
// ключом иной алгоритм — токен под этим ключом не принимается, хотя подпись
// его материалом сошлась бы. Близнец — та же запись с закреплённым алгоритмом,
// равным заголовку.
func TestRule_HeaderAlgorithmMustBeTheOneBoundToTheKey(t *testing.T) {
	k := newRingKey(t, testKID)
	raw := mint(t, k, testKID, nil)

	misbound := k.published
	misbound.Algorithm = domain.SigningAlgRS256
	refused(t, raw, SetLookup([]domain.PublishedKey{misbound}), errAlgorithmNotBound)

	accepted(t, raw, SetLookup([]domain.PublishedKey{k.published}))
}

// Параметр, помеченный обязательным к пониманию и нами не исполняемый, —
// отказ ВСЕГО токена. Непомеченный незнакомый параметр игнорируется: это
// обратная полярность того же требования, и без неё правило, отвергающее
// всякое незнакомое, проходило бы отказ как правильное.
func TestRule_CriticalHeaderNotUnderstoodRefusesTheWholeToken(t *testing.T) {
	k := newRingKey(t, testKID)
	lookup := SetLookup([]domain.PublishedKey{k.published})

	for _, tc := range []struct {
		name  string
		crit  any
		named string
	}{
		{"помеченный непонятый параметр", []string{"kaname-not-implemented"}, "kaname-not-implemented"},
		{"crit — не перечень", "kaname-not-implemented", "<crit is not a list>"},
		{"элемент crit — не строка", []any{7}, "<crit entry is not a string>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := refused(t, mint(t, k, testKID, func(h map[string]any) {
				h["crit"] = tc.crit
				h["kaname-not-implemented"] = "whatever"
			}), lookup, errCriticalHeader)
			require.Contains(t, err.Error(), tc.named, "отказ не называет непонятый параметр")
		})
	}

	t.Run("близнец: тот же параметр БЕЗ пометки", func(t *testing.T) {
		accepted(t, mint(t, k, testKID, func(h map[string]any) { h["kaname-not-implemented"] = "whatever" }), lookup)
	})
	t.Run("близнец: пометки нет вовсе", func(t *testing.T) {
		accepted(t, mint(t, k, testKID, nil), lookup)
	})
}

// Чужая подпись под нашим идентификатором — суждение о токене, а не сбой.
func TestRule_ForeignSignatureIsARefusal(t *testing.T) {
	ours := newRingKey(t, testKID)
	foreign := newRingKey(t, testKID)
	lookup := SetLookup([]domain.PublishedKey{ours.published})

	refused(t, mint(t, foreign, testKID, nil), lookup, jwt.ErrTokenSignatureInvalid)
	accepted(t, mint(t, ours, testKID, nil), lookup)
}

// Опознать не удалось — ТРЕТИЙ исход, и он не есть «не наш»: набор не ответил
// либо СВОЙ ключ набора не разбирается. Смешать его с отказом значило бы
// сделать нашу поломку неотличимой от негодного токена. Причина сбоя остаётся
// в цепочке ошибки — ключ наш, предъявленное значение в ней не бывает.
func TestRule_UnavailableSetAndBrokenOwnKeyAreTheThirdOutcome(t *testing.T) {
	k := newRingKey(t, testKID)
	raw := mint(t, k, testKID, nil)
	accepted(t, raw, SetLookup([]domain.PublishedKey{k.published}))

	cause := errors.New("реестр ключей недоступен")
	t.Run("набор не ответил", func(t *testing.T) {
		_, err := parse(raw, func(string) (domain.PublishedKey, bool, error) {
			return domain.PublishedKey{}, false, cause
		})
		require.ErrorIs(t, err, ErrUnavailable)
		require.ErrorIs(t, err, cause, "причина сбоя набора потеряна")
	})

	notDER := k.published
	notDER.PublicKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not a key")}))
	x25519, err := ecdh.X25519().GenerateKey(rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(x25519.PublicKey())
	require.NoError(t, err)
	unsupported := k.published
	unsupported.PublicKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	notPEM := k.published
	notPEM.PublicKeyPEM = "-----BEGIN PUBLIC KEY-----\nnot base64 at all\n-----END PUBLIC KEY-----"

	for _, tc := range []struct {
		name   string
		broken domain.PublishedKey
		cause  string
	}{
		{"открытая половина — не PEM", notPEM, "not PEM"},
		{"открытая половина не разбирается", notDER, "asn1: structure error"},
		{"вид ключа вне словаря", unsupported, "unsupported public key type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(raw, SetLookup([]domain.PublishedKey{tc.broken}))
			require.ErrorIs(t, err, ErrUnavailable, "испорченный СВОЙ ключ прочитан как «не наш»")
			require.Contains(t, err.Error(), tc.cause, "причина поломки ключа потеряна")
		})
	}
}

// Поиск по набору: найденный ключ — (ключ, да); ключа нет — (_, нет), без
// ошибки: «в наборе нет» — суждение, а не сбой.
func TestSetLookup_FindsByKeyID(t *testing.T) {
	a, b := newRingKey(t, "kaname-a"), newRingKey(t, "kaname-b")
	lookup := SetLookup([]domain.PublishedKey{a.published, b.published})

	got, found, err := lookup("kaname-b")
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, b.published, got)

	_, found, err = lookup("kaname-c")
	require.NoError(t, err)
	require.False(t, found)
}

// Предъявленное значение не попадает ни в один текст отказа правила: ни
// целиком, ни сегментом.
func TestRule_RefusalTextCarriesNoPresentedValue(t *testing.T) {
	k := newRingKey(t, testKID)
	raw := mint(t, newRingKey(t, testKID), testKID, nil) // чужая подпись
	_, err := parse(raw, SetLookup([]domain.PublishedKey{k.published}))
	require.Error(t, err)
	for _, seg := range append(strings.Split(raw, "."), raw) {
		require.NotContains(t, err.Error(), seg)
	}
}
