// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// Резолв по КОРНЮ АРЕНДЫ отвечает только про виды, которые в этом корне и
// считаются.
//
// ПРЕДМЕТ. `Resolve` спрашивают, называя проект либо аккаунт, — то есть корень
// аренды. Каталог же держит и виды, считаемые В РОДИТЕЛЬСКОМ РЕСУРСЕ: сколько
// подсетей в сети, сколько интерфейсов в подсети. У такого вида на уровне
// проекта нет единственного значения: подсетей столько-то в КАЖДОЙ сети, а не в
// проекте.
//
// ЧТО ЭТО СТОИЛО. Резолв отдавал домену vpc все двенадцать видов, потребитель
// проставлял каждому носителя «проект» константой, и арендатор получал четыре
// строки, которые:
//   - называют носителем проект, тогда как каталог называет родительский ресурс;
//   - показывают потребление, которое не наполнится никогда (списание идёт по
//     носителю, и строки с носителем-проектом для вложенного вида не касается
//     ни один триггер).
//
// Хуже того, состав ответа ЗАВИСЕЛ ОТ ИСТОРИИ проекта: свежий проект получал
// двенадцать строк резолвом, а тот же проект после первой мутации — восемь из
// собственных строк учёта. Одно и то же чтение отвечало по-разному, и разница
// не была ничем объявлена.
//
// ПОЧЕМУ ЭТО НЕ ЗАМЕТИЛИ. Обе пробы потребителя закрепляли восемь, потому что
// дублёр резолва отдавал восемь: он был снисходительнее настоящего, который
// отдаёт двенадцать. Класс `testing.md` §«Гейт на класс» — дублёр обязан
// выполнять контракт настоящего.
func TestResolveEffective_AnswersOnlyTenancyRootKinds(t *testing.T) {
	t.Parallel()

	// Все виды домена, каждый с назначенным пределом: если фильтр не работает,
	// в ответ попадут и вложенные.
	var stated []domain.Limit
	for _, k := range domain.CountableKindsOfService("vpc") {
		stated = append(stated, domain.Limit{
			Kind:  k,
			Scope: domain.LimitScopeDefault,
			Value: 16,
		})
	}
	require.NotEmpty(t, stated, "каталог не назвал ни одного вида домена vpc — предикат пробы устарел")

	got := domain.ResolveEffective("vpc", stated)
	require.NotEmpty(t, got, "резолв не вернул ничего на полном наборе назначенных пределов")

	for _, e := range got {
		carrier, known := domain.CarrierOfKind(e.Kind)
		require.True(t, known, "вид %s вернулся из резолва, но каталог его не знает", e.Kind)
		require.Contains(t,
			[]domain.LimitCarrier{domain.CarrierProject, domain.CarrierAccount}, carrier,
			"вид %s считается в %q, а не в корне аренды — на уровне проекта у него нет "+
				"единственного значения, и отдавать его этим чтением нельзя", e.Kind, carrier)
	}
}

// Положительный контроль: фильтр не съедает то, ради чего чтение существует.
//
// Без него проба выше зеленела бы и на резолве, который не возвращает НИЧЕГО, —
// то есть отрицание закрепляло бы поломку вместо свойства.
func TestResolveEffective_KeepsEveryTenancyRootKind(t *testing.T) {
	t.Parallel()

	var stated []domain.Limit
	want := map[domain.LimitKind]bool{}
	for _, k := range domain.CountableKindsOfService("vpc") {
		stated = append(stated, domain.Limit{Kind: k, Scope: domain.LimitScopeDefault, Value: 16})
		if c, ok := domain.CarrierOfKind(k); ok && (c == domain.CarrierProject || c == domain.CarrierAccount) {
			want[k] = true
		}
	}
	require.NotEmpty(t, want, "у домена vpc не нашлось ни одного вида, считаемого в корне аренды")

	got := domain.ResolveEffective("vpc", stated)
	seen := map[domain.LimitKind]bool{}
	for _, e := range got {
		seen[e.Kind] = true
	}
	for k := range want {
		require.True(t, seen[k], "вид %s считается в корне аренды и обязан быть в ответе", k)
	}
	require.Len(t, got, len(want), "в ответе оказалось больше видов, чем считается в корне аренды")
}

// Вложенные виды каталога СУЩЕСТВУЮТ — иначе две пробы выше не утверждают ничего.
//
// Проба-предпосылка: если вложенных видов у домена не окажется вовсе, фильтр
// станет тождественным, а отрицание — вакуумным. Тогда красное здесь скажет,
// что предмет исчез, и решение снять фильтр будет принято явно, а не по
// недосмотру.
func TestCatalogueStillHasNestedKinds(t *testing.T) {
	t.Parallel()

	nested := 0
	for _, k := range domain.CountableKindsOfService("vpc") {
		c, ok := domain.CarrierOfKind(k)
		if ok && c != domain.CarrierProject && c != domain.CarrierAccount {
			nested++
		}
	}
	require.NotZero(t, nested,
		"у домена vpc не осталось видов, считаемых в родительском ресурсе: фильтр в ResolveEffective "+
			"стал тождественным, и пробы на него больше ничего не утверждают")
	t.Logf("перепись: видов домена vpc %d, из них считаемых в родителе %d",
		len(domain.CountableKindsOfService("vpc")), nested)
}

// Носитель вложенного вида — двухчастный токен, а не корень аренды.
// Контроль формы: без него первая проба прошла бы и на каталоге, где носитель
// вложенного вида по ошибке записан как «проект».
func TestNestedKindCarrierNamesAParentType(t *testing.T) {
	t.Parallel()

	for _, k := range domain.CountableKindsOfService("vpc") {
		c, ok := domain.CarrierOfKind(k)
		require.True(t, ok, "каталог не знает носителя вида %s", k)
		if c == domain.CarrierProject || c == domain.CarrierAccount {
			continue
		}
		require.Equal(t, 2, len(strings.Split(string(c), ".")),
			"носитель %q вида %s не похож на тип родителя <домен>.<ресурс>", c, k)
	}
}
