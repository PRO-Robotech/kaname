// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package mailkey — ключи почтового ящика kaname: две именованные производные
// от адреса, нормализованного corelib (замысел issue-2917 З11, CX2-20; §0.2
// О1, О2).
//
// Разбор адреса — только address.Normalize corelib: локальная часть без
// изменений, домен A-label. Своего разбора и своего IDNA у kaname нет. Входа-
// строки у производных нет: они принимают address.Normalized, а непустое
// значение этого типа вне notify/address строит только Normalize. Нулевое
// значение (address.Normalized{}) остаётся путём мимо Normalize, поэтому
// производные читают адрес только Value() и на address.ErrUnset отвечают
// ErrUnset, а не ключом пустой строки: иначе все такие вызовы делили бы один
// ключ «пустого адреса». Приёмника address.Domain здесь нет (О2).
//
// Кому какой ключ (З11): окна recovery, verification и страж попыток — Account
// (защищают учётку); окно registration и потолки приглашений на адресата —
// Abuse (защищают ящик от спама написаниями одного адреса). Ключи — разные
// типы: ключ одного назначения в окно другого не подставляется.
package mailkey

import (
	"errors"
	"fmt"
	"strings"

	"github.com/PRO-Robotech/corelib/notify/address"
)

// ErrUnset — ключа нет: адрес — нулевое address.Normalized либо ключ построен
// литералом мимо производных. errors.Is находит в ошибке производной и
// address.ErrUnset.
var ErrUnset = errors.New("mailkey: адрес не задан — ключа нет")

// AccountKey — ключ учётки: локальная часть в нижнем регистре, домен как есть
// (A-label из Normalize). Совпадает с правилом уникальности учётки
// lower(email). Строит его только Account.
type AccountKey struct{ v string }

// AbuseKey — ключ злоупотребления: ключ учётки без «+метки» локальной части.
// Строит его только Abuse.
type AbuseKey struct{ v string }

// Value — написание ключа; нулевой ключ — ErrUnset.
func (k AccountKey) Value() (string, error) { return valueOf(k.v) }

// Value — написание ключа; нулевой ключ — ErrUnset.
func (k AbuseKey) Value() (string, error) { return valueOf(k.v) }

func valueOf(v string) (string, error) {
	if v == "" {
		return "", ErrUnset
	}
	return v, nil
}

// Account — ключ учётки адреса n.
func Account(n address.Normalized) (AccountKey, error) {
	local, domain, err := split(n)
	if err != nil {
		return AccountKey{}, err
	}
	return AccountKey{v: strings.ToLower(local) + "@" + domain}, nil
}

// Abuse — ключ злоупотребления адреса n: то же, что Account, и локальная часть
// обрезана по первому «+». Локальная часть, начинающаяся с «+», — ящик сам по
// себе: пустой префикс ключом не становится.
func Abuse(n address.Normalized) (AbuseKey, error) {
	local, domain, err := split(n)
	if err != nil {
		return AbuseKey{}, err
	}
	local = strings.ToLower(local)
	if i := strings.IndexByte(local, '+'); i > 0 {
		local = local[:i]
	}
	return AbuseKey{v: local + "@" + domain}, nil
}

// split делит нормализованный адрес на локальную часть и домен по последнему
// «@» — тому же разделителю, по которому его собрал Normalize.
func split(n address.Normalized) (local, domain string, err error) {
	v, err := n.Value()
	if err != nil {
		return "", "", fmt.Errorf("%w: %w", ErrUnset, err)
	}
	at := strings.LastIndexByte(v, '@')
	if at <= 0 || at == len(v)-1 {
		// Normalize такого значения не строит: локальная часть и домен у него
		// непусты по построению. Ветка — страховка от смены формы corelib.
		return "", "", errors.New("mailkey: нормализованный адрес без локальной части или домена")
	}
	return v[:at], v[at+1:], nil
}
