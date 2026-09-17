// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys

// deps.go — зависимости глаголов и ДЕВЯТЬ величин контракта (Р2, Р9, Р4):
// три ручки посадки приходят через `Binding` (незаданные роняют старт стражем
// посадки — Ф7-13, он в `config`), шесть литералов объявлены здесь и «не
// задана» у них не бывает: значение не приходит извне — оно факт о ПРОДУКТЕ.

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/PRO-Robotech/kaname/internal/webauthnverify"
)

// Литералы контракта — шесть величин, чей объявитель контракт (Р9, Р4, врезка
// Ф7-34). Держит их декларативная проба §8 (объявление равно решению) и
// наблюдение в выданном испытании (Ф7-40, Ф7-42).
const (
	// RPDisplayName — видимое имя доверяющей стороны: переносится дословно из
	// настройки прежнего компонента, чтобы перенесённые и новые ключи не
	// читались человеком как два продукта (Р9).
	RPDisplayName = "Kacho Cloud"
	// UserVerificationRegistration — требование проверки пользователя на
	// регистрации: «предпочтительна» — «обязательна» отвергла бы ключи, её не
	// умеющие; «не требуется» сделала бы ступень «3» недостижимой (Р9).
	UserVerificationRegistration = "preferred"
	// UserVerificationAssertion — то же на предъявлении (Р9, Ф7-42).
	UserVerificationAssertion = "preferred"
	// ResidentKey — обнаруживаемое удостоверение «требуется»: полоса входа без
	// имени (Ф13) без него невозможна by construction (Р9).
	ResidentKey = "required"
	// Attestation — «нет»: аттестация не требуется, не проверяется и не
	// хранится (Р4).
	Attestation = "none"
	// ChallengeTTL — срок испытания, ОДИН на обе процедуры (§7 инв. 5): строго
	// меньше окна свежести Ф1 §4.1 (15 минут) — иначе испытание, собранное
	// внутри окна, предъявлялось бы снаружи и обходило Р5; не меньше одного
	// взаимодействия человека с ключом.
	ChallengeTTL = 5 * time.Minute
)

// ChallengeTTLBelowFreshness — арифметическое свойство двух объявленных
// величин (§8: «срок испытания меньше окна свежести»); зовёт его страж
// зависимостей, а декларативная проба — на объявлениях.
func ChallengeTTLBelowFreshness(freshness time.Duration) error {
	if ChallengeTTL >= freshness {
		return fmt.Errorf("access keys: challenge ttl %s is not below the self-service freshness window %s — "+
			"a challenge outliving the window lets a result gathered inside it be presented outside (Р5)",
			ChallengeTTL, freshness)
	}
	return nil
}

// Deps — зависимости глаголов; все обязательны, кроме наблюдателя, часов и
// журнала.
type Deps struct {
	Store     Store
	Freshness Freshness
	Methods   LoginMethods
	// Binding — три ручки посадки: имя доверяющей стороны, перечень
	// происхождений (пустой означает «никого»), перечень алгоритмов (непустой).
	Binding webauthnverify.Binding
	// FreshnessWindow — окно свежести правки своих данных (Ф1 §4.1, Р5).
	FreshnessWindow time.Duration
	Observer        Observer
	Now             func() time.Time
	Logger          *slog.Logger
}

func (d Deps) validate(verb string) (Deps, error) {
	switch {
	case d.Store == nil:
		return d, fmt.Errorf("%s: access key store required", verb)
	case d.Freshness == nil:
		return d, fmt.Errorf("%s: freshness reader required", verb)
	case d.Methods == nil:
		return d, fmt.Errorf("%s: login method reader required", verb)
	case d.Binding.RPID == "":
		return d, fmt.Errorf("%s: relying party id required", verb)
	case d.Binding.Origins == nil:
		return d, fmt.Errorf("%s: origin list required (empty list means nobody, nil means undeclared)", verb)
	case len(d.Binding.Algorithms) == 0:
		return d, fmt.Errorf("%s: algorithm list required", verb)
	case d.FreshnessWindow <= 0:
		return d, fmt.Errorf("%s: self-service freshness window must be positive", verb)
	}
	if err := ChallengeTTLBelowFreshness(d.FreshnessWindow); err != nil {
		return d, fmt.Errorf("%s: %w", verb, err)
	}
	if d.Observer == nil {
		d.Observer = NopObserver{}
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	return d, nil
}
