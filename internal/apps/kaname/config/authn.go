// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// authn.go — helpers for the AuthN core config fields.
//
// Reading order of a secret:
//
//  1. value from YAML/ENV directly (e.g. authn.jwks-encryption-key-hex),
//  2. ENV variable referenced by the matching `-env` key (e.g.
//     authn.jwks-encryption-key-hex-env, default KANAME_JWKS_ENC_KEY).
//     Required because secrets are never written to YAML (workspace policy —
//     secretKeyRef-only).
//
// ResolveAudience() — derived from Domain. Умолчания у Domain нет: см.
// ResolveDomain.
//
// All methods are pure (no side-effects; only os.Getenv reads).
package config

import (
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/keywrap"
)

// JWKSEncryptionKeyEnvName — имя переменной окружения, из которой берётся ключ
// ОБЁРТКИ приватной половины, когда ручка не задана значением напрямую.
//
// Объявлено ОДНИМ местом: имя переменной называют текст отказа резолва, текст
// отказа старта при смене ключа и сам резолв. Три копии разошлись бы молча — на
// той, которую забыли поправить, и оператор искал бы не ту переменную.
func (c AuthNConfig) JWKSEncryptionKeyEnvName() string {
	if n := strings.TrimSpace(c.JWKSEncryptionKeyHexEnv); n != "" {
		return n
	}
	return "KANAME_JWKS_ENC_KEY"
}

// ResolveJWKSEncryptionKeys возвращает ПЕРЕЧЕНЬ ключей ОБЁРТКИ приватной
// половины подписного ключа, декодированный из hex: ПЕРВЫЙ оборачивает, ВСЕ
// открывают.
//
// Источник: authn.jwks-encryption-key-hex напрямую либо переменная окружения,
// названная authn.jwks-encryption-key-hex-env (по умолчанию
// KANAME_JWKS_ENC_KEY). Каждая запись обязана быть ровно ключом объявленного
// размера.
//
// # Почему перечень, а не вторая ручка (задача #1065)
//
// У ключа обёртки обязан быть путь смены. Одно значение его не даёт вовсе:
// новое не открывает ни одной уже записанной приватной половины. Перечень даёт
// смену без простоя и без переписывания хранилища — новый ключ встаёт первым,
// прежний остаётся для чтения.
//
// Второй ручки не заводится по той же причине, по какой её не завели прежде:
// одна из двух неизбежно оказалась бы необязательной, и профиль развёртывания,
// задавший «не ту», выглядел бы настроенным. Перечень из одного — сегодняшнее
// значение всякого профиля, и ни один из них не меняется.
//
// # Разделитель и вырожденное значение
//
// Читается общим предикатом перечней настройки (ParseCommaList): считаются
// ЭЛЕМЕНТЫ, а не длина строки. Свой предикат разошёлся бы с общим ровно на
// вырожденном значении — одинокая запятая даёт длину 1 и ноль элементов, — и
// служба поднялась бы без ключа обёртки вовсе.
//
// # Повтор значения отвергается
//
// Повтор означает смену, которой не было: оператор считает ключ сменённым, а
// обёрнуто и открывается всё тем же. Приняв его молча, мы получили бы число
// названных ключей, не равное числу ключей, которыми что-то можно открыть, —
// и печатаемая при старте величина начала бы лгать.
//
// # У этой ручки снова есть потребитель — и он ЕДИНСТВЕННЫЙ
//
// Ею оборачивается приватная половина подписного ключа в ключнице
// (internal/keywrap, задача #897). Приватная половина ложится в базу, класть её
// открытым текстом нельзя, значит ключ обёртки нужен по существу — вопрос был
// лишь в том, сколько ручек об одном предмете окажется в конфигурации.
//
// Второй ручки не заводится намеренно: две ручки об одном предмете дают ту, что
// неизбежно окажется необязательной, и профиль развёртывания, задавший «не ту»,
// выглядел бы настроенным. Форма совпадает — страж уже требовал ровно 32 байта,
// то есть размер ключа симметричного шифра, которым обёртка и делается.
//
// Имя ручки НЕ переименовано осознанно: переименование стоило бы правки каждого
// профиля развёртывания и дало бы окно, в котором старое имя молча
// игнорируется. Сменился смысл, и он записан здесь.
func (c AuthNConfig) ResolveJWKSEncryptionKeys() ([][]byte, error) {
	return resolveWrappingKeyRing("authn.jwks-encryption-key-hex", c.JWKSEncryptionKeyHex, c.JWKSEncryptionKeyEnvName())
}

// SecondFactorEncryptionKeyEnvName — имя переменной окружения, из которой
// берётся перечень ключей обёртки секретов второго фактора, когда ручка не
// задана значением напрямую. Объявлено одним местом по той же причине, что у
// соседней ручки.
func (c AuthNConfig) SecondFactorEncryptionKeyEnvName() string {
	if n := strings.TrimSpace(c.SecondFactorEncryptionKeyHexEnv); n != "" {
		return n
	}
	return "KANAME_SECOND_FACTOR_ENC_KEY"
}

// ResolveSecondFactorEncryptionKeys — перечень ключей ОБЁРТКИ секретов второго
// фактора (Ф12 Р2, kacho#1281): первый оборачивает, все открывают.
//
// Источник: authn.second-factor-encryption-key-hex напрямую либо переменная
// окружения, названная authn.second-factor-encryption-key-hex-env (по
// умолчанию KANAME_SECOND_FACTOR_ENC_KEY). Форма и правила перечня — те же,
// что у ручки подписного ключа (один разбор на обе, ниже); ручка — СВОЯ:
// секретов второго фактора много, по одному на человека, их срок жизни — срок
// фактора, радиус компрометации — вход людей, а не подпись службы; смена одного
// перечня не обязана останавливать другой. Ручка подписного ключа перечень
// второго фактора НЕ подменяет.
func (c AuthNConfig) ResolveSecondFactorEncryptionKeys() ([][]byte, error) {
	return resolveWrappingKeyRing("authn.second-factor-encryption-key-hex", c.SecondFactorEncryptionKeyHex, c.SecondFactorEncryptionKeyEnvName())
}

// resolveWrappingKeyRing — ОДИН разбор перечня ключей обёртки на обе ручки:
// две копии разошлись бы ровно на вырожденном значении.
func resolveWrappingKeyRing(knob, raw, envName string) ([][]byte, error) {
	if raw == "" {
		raw = os.Getenv(envName)
	}
	entries := ParseCommaList(raw)
	if len(entries) == 0 {
		return nil, fmt.Errorf("%s is empty (set ENV %s)", knob, envName)
	}
	// Размер ключа берётся у обёртки, а не из своей копии: два числа об одном
	// предмете разошлись бы так, что страж пропускал бы то, чем обернуть нельзя.
	keys := make([][]byte, 0, len(entries))
	seen := make(map[string]int, len(entries))
	for i, entry := range entries {
		key, err := hex.DecodeString(entry)
		if err != nil {
			return nil, fmt.Errorf("%s: entry #%d of %d: invalid hex: %w", knob, i+1, len(entries), err)
		}
		if len(key) != keywrap.KeySize {
			return nil, fmt.Errorf("%s: entry #%d of %d must decode to %d bytes (got %d)",
				knob, i+1, len(entries), keywrap.KeySize, len(key))
		}
		// Значение НЕ попадает в текст отказа ни при каком исходе — оператору
		// называется позиция, предъявителю не называется ничего.
		if first, dup := seen[string(key)]; dup {
			return nil, fmt.Errorf(
				"%s: entry #%d of %d repeats entry #%d — a repeated wrapping key is a change that did not happen",
				knob, i+1, len(entries), first)
		}
		seen[string(key)] = i + 1
		keys = append(keys, key)
	}
	return keys, nil
}

// ValidateSelfServiceFreshness — окно свежести правки своих данных объявлено
// (Ф12 Р8, Ф12-36): незаданное — отказ с именем ручки; величина без умолчания,
// дословный перенос «15 мин» Ф1 §4.1 объявляется профилем, а не построением.
func (c AuthNConfig) ValidateSelfServiceFreshness() error {
	if c.SelfServiceFreshness <= 0 {
		return fmt.Errorf("authn.self-service-freshness не задан (KANAME_AUTHN__SELF_SERVICE_FRESHNESS): " +
			"окно свежести правки своих данных — величина посадки без умолчания в коде; заведение второго фактора " +
			"и срок неподтверждённого заведения читают её, перенос Ф1 §4.1 (15m) объявляется профилем")
	}
	return nil
}

// ResolveDomain — доменное имя посадки, объявленное оператором. Умолчания НЕТ:
// пустое значение означает «не объявлено» и доезжает до стража старта.
//
// Прежде здесь стоял литерал доменного имени платформы. Он был не косметикой:
// из этого значения выводится клеймо АДРЕСАТА, уезжающее в каждом выпущенном
// удостоверении, — то есть подставленное построением имя чужого продукта
// адресовало удостоверения не туда на всякой посадке, ни одна из которых
// значения не объявляла. Поставщик теперь есть у профиля (чарт), а незаданное
// значение отвергает страж (`validateDeclaredDomain`).
func (c AuthNConfig) ResolveDomain() string {
	return strings.TrimSpace(c.Domain)
}

// ResolveAudience returns the caller-aud for tokens (`<domain>` without
// scheme). The claim composer of our own mint stamps it as the audience.
func (c AuthNConfig) ResolveAudience() string {
	return c.ResolveDomain()
}
