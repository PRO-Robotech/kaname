// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// Носитель учёта ПРИЕЗЖАЕТ В ОТВЕТЕ резолва.
//
// Задача `PRO-Robotech/kacho#401`.
//
// # Предмет
//
// Каталог держит пару — вид и носитель, — а разрешённая величина уезжала
// потребителю БЕЗ носителя. Потребитель, обязанный положить строку учёта под
// правильный носитель, узнать его не мог ниоткуда и ставил `project`
// константой. Для восьми плоских видов домена это совпадало со случайно верным
// ответом; для четырёх вложенных — нет: их носитель по каталогу есть
// родительский ресурс.
//
// Следствия у арендатора были две, и обе тихие: носитель в ответе назван
// неверно, а потребление таких строк не наполнится НИКОГДА — списание идёт по
// настоящему носителю.
//
// # Почему носитель нельзя вывести, а надо передать
//
// Форма токена носителя не определяет: `iam.project` — двухчастный вид, чей
// носитель НЕ проект (проекта, внутри которого считаются проекты, не бывает).
// Правило «две части ⇒ проект» ложно на первой же существующей записи каталога.
// Догадка в этом месте не отказывает громко — она считает верные строки против
// неверного владельца.

// TestResolveEffective_CarriesTheCarrierOfEveryKind — у каждой разрешённой
// величины назван носитель, и он тот же, что в каталоге.
func TestResolveEffective_CarriesTheCarrierOfEveryKind(t *testing.T) {
	const service = "vpc"

	kinds := domain.CountableKindsOfService(service)
	require.NotEmpty(t, kinds, "предусловие: у домена есть виды — иначе проба вакуумна")

	stated := make([]domain.Limit, 0, len(kinds))
	for i, k := range kinds {
		stated = append(stated, domain.Limit{
			Scope: domain.LimitScopeDefault,
			Kind:  k,
			Value: int64(10 + i),
		})
	}

	got := domain.ResolveEffective(service, stated)
	require.Len(t, got, len(kinds), "отвечено по каждому виду каталога")

	for _, e := range got {
		want, ok := domain.CarrierOfKind(e.Kind)
		require.True(t, ok, "вид %s обязан быть в каталоге", e.Kind)
		require.Equal(t, want, e.Carrier,
			"носитель вида %s обязан приехать в ответе и совпасть с каталогом", e.Kind)
		require.NotEmpty(t, e.Carrier, "носитель не может быть пустым: пустой читается как догадка")
	}
}

// TestResolveEffective_NestedKindsDoNotClaimTheProjectAsCarrier — вложенные
// виды называют носителем РОДИТЕЛЯ.
//
// Это и есть та четвёрка, из-за которой заведена задача. Проба названа отдельно
// от общей выше, потому что общая осталась бы зелёной и на реализации,
// проставляющей `project` всем подряд, если бы каталог вдруг оказался плоским, —
// а здесь предмет утверждения именно НЕплоскость.
func TestResolveEffective_NestedKindsDoNotClaimTheProjectAsCarrier(t *testing.T) {
	nested := map[domain.LimitKind]domain.LimitCarrier{}
	for _, k := range domain.CountableKindsOfService("vpc") {
		c, ok := domain.CarrierOfKind(k)
		require.True(t, ok)
		if c != domain.CarrierProject && c != domain.CarrierAccount {
			nested[k] = c
		}
	}
	require.NotEmpty(t, nested,
		"предмет пробы: у домена есть виды, считаемые в родителе. Исчезнут — проба вакуумна, и это надо заметить")

	stated := make([]domain.Limit, 0, len(nested))
	for k := range nested {
		stated = append(stated, domain.Limit{Scope: domain.LimitScopeDefault, Kind: k, Value: 4})
	}

	for _, e := range domain.ResolveEffective("vpc", stated) {
		want := nested[e.Kind]
		require.Equal(t, want, e.Carrier,
			"вид %s считается в %s, а не в проекте", e.Kind, want)
		require.NotEqual(t, domain.CarrierProject, e.Carrier)
	}
}

// TestResolveEffective_FlatKindsStillSayProject — положительный контроль.
//
// Без него фикс «носитель приезжает» был бы неотличим от фикса «носитель
// приезжает и он всегда родительский»: отрицание выше зеленело бы на реализации,
// сломавшей плоские виды.
func TestResolveEffective_FlatKindsStillSayProject(t *testing.T) {
	var flat []domain.LimitKind
	for _, k := range domain.CountableKindsOfService("vpc") {
		if c, _ := domain.CarrierOfKind(k); c == domain.CarrierProject {
			flat = append(flat, k)
		}
	}
	require.NotEmpty(t, flat)

	stated := make([]domain.Limit, 0, len(flat))
	for _, k := range flat {
		stated = append(stated, domain.Limit{Scope: domain.LimitScopeDefault, Kind: k, Value: 16})
	}

	for _, e := range domain.ResolveEffective("vpc", stated) {
		require.Equal(t, domain.CarrierProject, e.Carrier,
			"плоский вид %s по-прежнему считается в проекте", e.Kind)
	}
}

// TestResolveEffective_AccountCarriedKindsSayAccount — вид, живущий в аккаунте,
// называет аккаунт.
//
// `iam.project` — та самая запись, на которой ложно правило «две части ⇒
// проект»; ради неё носитель и объявляется, а не выводится.
func TestResolveEffective_AccountCarriedKindsSayAccount(t *testing.T) {
	var accountKinds []domain.LimitKind
	for _, k := range domain.CountableKindsOfService("iam") {
		if c, _ := domain.CarrierOfKind(k); c == domain.CarrierAccount {
			accountKinds = append(accountKinds, k)
		}
	}
	require.NotEmpty(t, accountKinds, "предмет: у iam есть виды, считаемые в аккаунте")

	stated := make([]domain.Limit, 0, len(accountKinds))
	for _, k := range accountKinds {
		stated = append(stated, domain.Limit{Scope: domain.LimitScopeDefault, Kind: k, Value: 16})
	}

	got := domain.ResolveEffective("iam", stated)
	require.Len(t, got, len(accountKinds))
	for _, e := range got {
		require.Equal(t, domain.CarrierAccount, e.Carrier,
			"вид %s считается в аккаунте, и ответ обязан это сказать", e.Kind)
	}
}
