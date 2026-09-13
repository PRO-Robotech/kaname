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
// НОСИТЕЛЬ ВЛОЖЕННОГО ВИДА ВЫВОДИТСЯ, А НЕ ОБЪЯВЛЯЕТСЯ — и после ухода закрытого
// каталога (`PRO-Robotech/kacho#2117`, стадия S4) это стало ЕДИНСТВЕННЫМ его
// источником. Прежде проба спрашивала каталог (`CarrierOfKind`); каталог ушёл
// вместе с авторитетом величин, а свойство осталось: вложенный вид считается в
// своём родителе, и родитель читается из самого имени вида.
func TestCredentialCeiling_BothKindsAreInTheCatalogue(t *testing.T) {
	t.Parallel()

	for kind, wantCarrier := range map[domain.LimitKind]domain.LimitKind{
		"iam.user.credential":           "iam.user",
		"iam.serviceAccount.credential": "iam.serviceAccount",
	} {
		require.Truef(t, domain.IsPostureStatedKind(kind),
			"вида %q словарь посадки не знает: потолка числа удостоверений не "+
				"существует, и накопить их можно сколько угодно", kind)
		require.Truef(t, kind.Nested(),
			"вид %q не вложенный: его носитель тогда не выводится ниоткуда", kind)
		require.Equalf(t, wantCarrier, kind.ParentKind(),
			"вид %q считается не в своём принципале: списание писало бы строки под одним "+
				"носителем, а отказ называл бы другого", kind)
	}
}

// Отрицание в паре: соседний вид того же домена считается НЕ в принципале.
// Без него проба выше зеленела бы и на словаре, где носитель у всех один.
func TestCredentialCeiling_ANeighbourKindIsCarriedElsewhere(t *testing.T) {
	t.Parallel()

	// Соседом был `iam.project` — вид СНЯТ вместе с пятью другими
	// (`PRO-Robotech/kacho#2117`, сценарий `KAN-Q3-04`). Контроль переведён на
	// `iam.account`: он живой, того же домена, и носитель у него ДРУГОЙ —
	// личность, а не принципал. Предмет контроля от замены не изменился.
	const neighbour domain.LimitKind = "iam.account"
	require.True(t, domain.IsPostureStatedKind(neighbour))
	require.Truef(t, domain.IsIdentityCarriedKind(neighbour),
		"положительный контроль: у соседнего вида того же домена носитель другой, "+
			"поэтому совпадение выше — свойство записи, а не одинаковость словаря")
	require.Falsef(t, neighbour.Nested(),
		"сосед оказался вложенным: тогда его носитель выводился бы так же, как у "+
			"двух видов выше, и контроль ничего не различал бы")
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

// Всякий вид, объявленный област-но, обязан быть видом СЛОВАРЯ ПОСАДКИ.
//
// Прежде сверка шла с закрытым каталогом авторитета; каталог ушёл стадией S4, и
// надмножеством стал словарь посадки — по построению, а не по совпадению: после
// ухода авторитета служба считает ровно те виды, чью величину объявляет посадка.
// Иначе объявление переживает свой предмет и никем не читается.
func TestCredentialCeiling_ScopeDeclarationsNameCatalogueKinds(t *testing.T) {
	t.Parallel()

	declared := domain.AccountScopedKinds()
	require.NotEmpty(t, declared,
		"ни один вид не объявлен област-ным: перепись пуста, и утверждение выше вакуумно")
	for _, k := range declared {
		require.Truef(t, domain.IsPostureStatedKind(k),
			"вид %q объявлен област-ным, но словарь посадки его не знает", k)
	}
	t.Logf("перепись: видов словаря посадки %d, объявленных областью аккаунта %d",
		len(domain.PostureStatedKinds()), len(declared))
}
