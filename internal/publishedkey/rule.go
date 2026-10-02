// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package publishedkey — ОДНО правило, по которому читатель токена службы
// выбирает ключ проверки из её публикуемого набора (задача
// PRO-Robotech/kaname#396).
//
// Читателей три: читатель предъявленного на публичном слушателе
// (`presentedcred`), интроспекция для соседей (`handler/tokenintrospecthttp`)
// и опознание токена доступа церемонии (`ceremonyport`). Разбор каждый строит
// своими ограничениями — перечень алгоритмов, издатель, получатель, срок, —
// а ключ выбирают они одним правилом, и живёт оно здесь. До сведения правило
// было написано трижды, и копии уже разошлись: одна читала испорченный свой
// ключ набора как негодный токен. Держатель единственности —
// `TestPublishedKeyRuleHasOneHome` (`internal/check`).
//
// # Правило — в порядке ветвей
//
//  1. форма `kid` — ДО поиска: у читателя предъявленного поиск — повод
//     обновить снимок из хранилища, и негодная форма до него не доезжает;
//  2. ключ по `kid` — поиском вызывающего: у него свой снимок и свои поводы
//     его обновить;
//  3. алгоритм заголовка равен закреплённому за найденным ключом: способ
//     проверки выбирает КЛЮЧ, а заголовок только сверяется;
//  4. параметры заголовка, помеченные обязательными к пониманию (`crit`,
//     RFC 7515 §4.1.11), понятны — иначе отказ всего токена; непомеченные
//     незнакомые игнорируются (правило платформы `tokenpolicy`);
//  5. открытая половина ключа разбирается и её вид — из словаря платформы.
//
// # Исходов три — по ТИПУ
//
//   - токен принят — подпись найденным ключом сошлась и прочие ограничения
//     разбора вызывающего выполнены;
//   - отказ — суждение о токене: чужая подпись, ключа нет, ветвь правила не
//     выполнена, ограничение разбора не выполнено;
//   - ErrUnavailable — опознать не удалось: поиск по набору не ответил либо
//     СВОЙ ключ набора не разбирается. Это наша поломка, а не негодный вход, и
//     смешать её с отказом значило бы учить оператора смотреть не туда.
package publishedkey

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/golang-jwt/jwt/v5"

	"github.com/PRO-Robotech/corelib/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Lookup находит ключ набора по `kid`: (ключ, true, nil) — найден;
// (_, false, nil) — в наборе его нет, и это суждение; ошибка — спросить набор
// не удалось, и это третий исход.
type Lookup func(kid string) (domain.PublishedKey, bool, error)

// SetLookup — поиск по уже прочитанному набору.
func SetLookup(keys []domain.PublishedKey) Lookup {
	byKID := make(map[string]domain.PublishedKey, len(keys))
	for _, k := range keys {
		byKID[string(k.KID)] = k
	}
	return func(kid string) (domain.PublishedKey, bool, error) {
		k, ok := byKID[kid]
		return k, ok, nil
	}
}

// ErrUnavailable — опознать не удалось: набор не ответил либо свой ключ набора
// не разбирается. Не суждение о токене.
var ErrUnavailable = errors.New("the published key set could not vouch for the token")

// Отказы правила — суждения о токене. Тексты уходят только в журнал читателя
// и предъявленного значения не несут.
var (
	errKeyIDForm         = errors.New("key id has illegal form")
	errKeyIDUnresolved   = errors.New("key id does not resolve in our own registry")
	errAlgorithmNotBound = errors.New("header algorithm is not the one bound to the key")
	errCriticalHeader    = errors.New("critical header is not understood")
)

// Parse разбирает raw парсером вызывающего, выбирая ключ проверки по правилу
// набора. Исходы — см. шапку пакета: (токен, nil) · отказ · ErrUnavailable.
func Parse(p *jwt.Parser, raw string, claims jwt.Claims, lookup Lookup) (*jwt.Token, error) {
	// Третий исход несётся отдельно от ошибки разбора: различение не зависит
	// от того, как библиотека заворачивает ошибку ключа.
	var unavailable error
	tok, err := p.ParseWithClaims(raw, claims, func(t *jwt.Token) (any, error) {
		key, kerr := keyFor(t, lookup)
		if errors.Is(kerr, ErrUnavailable) {
			unavailable = kerr
		}
		return key, kerr
	})
	if unavailable != nil {
		return nil, unavailable
	}
	if err != nil {
		return nil, err
	}
	if !tok.Valid {
		return nil, errors.New("token did not verify")
	}
	return tok, nil
}

// keyFor — ветви правила по порядку шапки.
func keyFor(t *jwt.Token, lookup Lookup) (crypto.PublicKey, error) {
	kid, _ := t.Header["kid"].(string)
	if !domain.ValidKeyIDForm(kid) {
		return nil, errKeyIDForm
	}
	pub, found, err := lookup(kid)
	if err != nil {
		return nil, fmt.Errorf("%w: key set: %w", ErrUnavailable, err)
	}
	if !found {
		return nil, errKeyIDUnresolved
	}
	if t.Method.Alg() != string(pub.Algorithm) {
		return nil, errAlgorithmNotBound
	}
	if ok, name := tokenpolicy.CriticalHeadersUnderstood(criticalHeaders(t.Header)); !ok {
		return nil, fmt.Errorf("%w: %q", errCriticalHeader, name)
	}
	key, err := parsePublicKey(pub.PublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: key %s: %w", ErrUnavailable, pub.KID, err)
	}
	return key, nil
}

// criticalHeaders приводит `crit` к перечню имён.
//
// Разбор отдаёт заголовок как произвольный JSON, поэтому годятся ровно два
// вида: список строк и его отсутствие. Всё прочее — не перечень имён, и
// принимать по нему решение нельзя; такой вход даёт одно ЗАВЕДОМО неизвестное
// имя, то есть отказ. Молчаливый пропуск означал бы «параметр помечен
// обязательным, а мы не разобрали его форму и приняли токен».
func criticalHeaders(h map[string]any) []string {
	raw, ok := h["crit"]
	if !ok {
		return nil
	}
	list, ok := raw.([]any)
	if !ok {
		return []string{"<crit is not a list>"}
	}
	out := make([]string, 0, len(list))
	for _, v := range list {
		name, ok := v.(string)
		if !ok {
			return []string{"<crit entry is not a string>"}
		}
		out = append(out, name)
	}
	return out
}

// parsePublicKey разбирает открытую половину ключа набора. Причина сбоя
// остаётся в цепочке: ключ наш, и предъявленного значения в ней не бывает.
func parsePublicKey(pemStr string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("public half is not PEM")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("public half does not parse: %w", err)
	}
	switch pub.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		return pub, nil
	default:
		return nil, fmt.Errorf("unsupported public key type %T", pub)
	}
}
