// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// credential_ceiling_test.go — каталог знает потолок числа удостоверений на
// принципала (задача #1191, приёмка
// `services/iam/docs/engineering/acceptance/credential-ceiling-per-principal.md`).
//
// Предмет — ЗАПИСИ каталога, а не поведение списания: вид, которого каталог не
// объявляет, не получит ни величины, ни строки учёта, и потолок не наступит
// никогда. Поведение утверждают интеграционные пробы репозитория.

package domain_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// CRED-CAP-25 — оба вида объявлены, и каждый считается в СВОЁМ принципале.
//
// Совпадение носителя с родительской частью вида здесь НЕ переутверждается: это
// уже держит действующий гейт каталога для всех вложенных видов, и второе место
// об одном предмете разошлось бы первым.
func TestCredentialCeiling_BothKindsAreInTheCatalogue(t *testing.T) {
	t.Parallel()

	for kind, wantCarrier := range map[domain.LimitKind]domain.LimitCarrier{
		"iam.user.credential":           "iam.user",
		"iam.serviceAccount.credential": "iam.serviceAccount",
	} {
		carrier, known := domain.CarrierOfKind(kind)
		require.Truef(t, known,
			"вида %q в каталоге нет: потолка числа удостоверений не существует, и "+
				"накопить их можно сколько угодно", kind)
		require.Equalf(t, wantCarrier, carrier,
			"вид %q считается не в своём принципале: списание писало бы строки под одним "+
				"носителем, а отказ называл бы другого", kind)
	}
}

// Отрицание в паре: соседний вид того же домена считается НЕ в принципале.
// Без него проба выше зеленела бы и на каталоге, где носитель у всех один.
func TestCredentialCeiling_ANeighbourKindIsCarriedElsewhere(t *testing.T) {
	t.Parallel()

	carrier, known := domain.CarrierOfKind("iam.project")
	require.True(t, known)
	require.Equal(t, domain.CarrierAccount, carrier,
		"положительный контроль: у соседнего вида того же домена носитель другой, "+
			"поэтому совпадение выше — свойство записи, а не одинаковость каталога")
}

// CRED-CAP-26 — `iam.credential` объявлен ПОДЧИНЁННЫМ РЕСУРСОМ: два родителя,
// две таблицы, непустая причина.
//
// Подчинённый ресурс — сущность, адресуемая арендатором и не имеющая своего типа
// модели прав, потому что доступ к ней производен от родителя. Без такой записи
// вид `iam.user.credential` не прошёл бы гейт каталога: его вторая часть
// (`iam.credential`) типом модели прав не является и не может им стать — иначе
// на удостоверение можно было бы ВЫДАТЬ право, чего модель намеренно избегает.
func TestCredentialCeiling_CredentialIsADeclaredSubordinateResource(t *testing.T) {
	t.Parallel()

	rec, ok := domain.SubordinateResourceOf("iam.credential")
	require.True(t, ok,
		"`iam.credential` не объявлен подчинённым ресурсом: вид `iam.user.credential` "+
			"не пройдёт гейт каталога, и потолок нельзя будет даже назвать")

	require.ElementsMatch(t,
		[]domain.LimitKind{"iam.user", "iam.serviceAccount"}, rec.Parents,
		"родители подчинённого ресурса названы неверно: удостоверения одного принципала "+
			"считались бы в другом")
	require.ElementsMatch(t,
		[]string{"kaname.user_oauth_clients", "kaname.service_account_oauth_clients"},
		rec.Tables,
		"таблицы строк не названы: имя вида осталось бы самозаявлением, и опечатка в нём "+
			"дожила бы до первой выдачи")
	require.NotEmpty(t, rec.Why,
		"запись без причины неотличима от записи без предмета")
}

// CRED-CAP-15/16 (объявление) — применимость областей ОБЪЯВЛЕНА, а не выведена.
//
// Величина, назначенная на аккаунт, применима к удостоверениям служебной учётки
// (она ресурс ровно одного аккаунта) и НЕ применима к удостоверениям человека:
// человек состоит во многих аккаунтах, а его удостоверение действует во всех
// сразу, и величина одного администратора управляла бы доступом в чужих.
func TestCredentialCeiling_AccountScopeAppliesToTheMachineAndNotToThePerson(t *testing.T) {
	t.Parallel()

	require.True(t, domain.AccountScopeApplies("iam.serviceAccount.credential"),
		"область аккаунта не применима к удостоверениям машины: администратор аккаунта "+
			"не сможет сузить предел в СВОИХ границах")
	require.False(t, domain.AccountScopeApplies("iam.user.credential"),
		"область аккаунта применима к удостоверениям человека: величина одного аккаунта "+
			"управляла бы числом путей входа, действующих в других его аккаунтах")
}

// Всякий вид, объявленный област-но, обязан быть видом КАТАЛОГА.
// Иначе объявление переживает свой предмет и никем не читается.
func TestCredentialCeiling_ScopeDeclarationsNameCatalogueKinds(t *testing.T) {
	t.Parallel()

	declared := domain.AccountScopedKinds()
	require.NotEmpty(t, declared,
		"ни один вид не объявлен област-ным: перепись пуста, и утверждение выше вакуумно")
	for _, k := range declared {
		require.Truef(t, domain.IsCountableKind(k),
			"вид %q объявлен област-ным, но каталог его не знает", k)
	}
	t.Logf("перепись: видов каталога %d, объявленных областью аккаунта %d",
		len(domain.CountableKinds()), len(declared))
}
