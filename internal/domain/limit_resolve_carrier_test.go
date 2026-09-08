// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Резолв называет НОСИТЕЛЯ каждого вида и не скрывает вложенные.
//
// ПРЕДМЕТ. Величину вложенного вида («сколько слушателей помещается в ОДИН
// балансировщик») платформа назначает на проект ровно так же, как любую другую:
// одной строкой умолчания. Единственное, чем этот вид отличается, — ГДЕ он
// потом считается: в родительском ресурсе, а не в корне аренды. Различие несёт
// поле носителя, и потребитель по нему и разводит две полосы.
//
// ЧТО СТОИЛО ОБРАТНОЕ. Пока это чтение вложенные виды ВЫРЕЗАЛО, владелец типа
// не мог узнать величину, из которой берётся снимок при заведении родителя.
// Родитель заводился без строки учёта, и первый же ребёнок получал
// `QUOTA_NOT_PROVISIONED` — «потолок не назван» при потолке, названном
// умолчанием каталога. На сквозном прогоне это остановило создание слушателей и
// репозиториев целиком (три красных шарда, один корень).
//
// ЧТО ОСТАЁТСЯ ЗАЩИЩЁННЫМ. Исходная беда была не в наличии вложенных видов в
// ответе, а в том, что потребитель проставлял им носителя «проект» константой и
// заводил строку учёта, которая не наполнится никогда. Это закрывается
// носителем, едущим вместе с величиной, — его и закрепляет проба ниже.
func TestResolveEffective_AnswersNestedKindsWithTheirParentCarrier(t *testing.T) {
	t.Parallel()

	const service = "loadbalancer"

	var stated []domain.Limit
	nestedWant := map[domain.LimitKind]domain.LimitCarrier{}
	for _, k := range domain.CountableKindsOfService(service) {
		stated = append(stated, domain.Limit{Kind: k, Scope: domain.LimitScopeDefault, Value: 16})
		if c, ok := domain.CarrierOfKind(k); ok && c != domain.CarrierProject && c != domain.CarrierAccount {
			nestedWant[k] = c
		}
	}
	require.NotEmpty(t, stated, "каталог не назвал ни одного вида домена %s — предикат пробы устарел", service)
	require.NotEmpty(t, nestedWant,
		"у домена %s не осталось видов, считаемых в родителе: проба стала вакуумной, "+
			"и её надо снимать вместе с предметом, а не держать зелёной", service)

	got := domain.ResolveEffective(service, stated)

	seen := map[domain.LimitKind]domain.LimitCarrier{}
	for _, e := range got {
		seen[e.Kind] = e.Carrier
	}
	for k, wantCarrier := range nestedWant {
		carrier, ok := seen[k]
		require.True(t, ok,
			"вложенный вид %s не вернулся резолвом: владельцу типа неоткуда взять величину, "+
				"из которой заводится строка учёта родителя, и первый же ребёнок получит "+
				"отказ «потолок не назван» при названном умолчании", k)
		require.Equal(t, wantCarrier, carrier,
			"вид %s вернулся с носителем %q вместо %q — потребитель разводит полосы именно "+
				"по этому полю", k, carrier, wantCarrier)
	}
	t.Logf("перепись: домен %s, видов в ответе %d, из них вложенных %d",
		service, len(got), len(nestedWant))
}

// Ни один назначенный вид НИ ОДНОГО домена не пропадает из ответа.
//
// Положительный контроль к пробе выше: без него та зеленела бы и на резолве,
// который вырезает всё, кроме вложенных.
//
// Домены выводятся из каталога, а не выписываются: выписанный перечень не
// покрыл бы домен, заведённый завтра, — и его вложенный вид потерял бы
// производителя ровно так же молча, как это уже случилось однажды.
func TestResolveEffective_KeepsEveryStatedKindOfEveryService(t *testing.T) {
	t.Parallel()

	services := map[string]bool{}
	for _, e := range domain.CountableEntries() {
		services[domain.LimitKind(e.Kind).Service()] = true
	}
	require.NotEmpty(t, services, "каталог пуст — проба не читает ничего")

	checked := 0
	for service := range services {
		var stated []domain.Limit
		want := map[domain.LimitKind]bool{}
		for _, k := range domain.CountableKindsOfService(service) {
			stated = append(stated, domain.Limit{Kind: k, Scope: domain.LimitScopeDefault, Value: 16})
			want[k] = true
		}
		require.NotEmpty(t, want, "каталог не назвал ни одного вида домена %s", service)

		got := domain.ResolveEffective(service, stated)
		seen := map[domain.LimitKind]bool{}
		for _, e := range got {
			seen[e.Kind] = true
		}
		for k := range want {
			require.True(t, seen[k],
				"вид %s назначен пределом, но в ответе резолва его нет: у величины не осталось "+
					"производителя, и владелец типа не сможет завести строку учёта", k)
		}
		require.Len(t, got, len(want),
			"в ответе домена %s оказалось не столько видов, сколько назначено", service)
		checked += len(want)
	}
	t.Logf("перепись: доменов %d, видов осмотрено %d", len(services), checked)
}

// Носитель в ОТВЕТЕ совпадает с носителем в КАТАЛОГЕ — для каждого вида.
//
// Это и есть та защита, ради которой вводилось поле носителя: пока оно верно,
// потребитель не заведёт вложенному виду строку учёта на проект, а именно эта
// строка показывала бы арендатору потребление, которое не наполнится никогда.
// Проба намеренно обходит ВСЕ домены каталога: расхождение по одному виду —
// такой же дефект, как по всем.
func TestResolveEffective_CarrierInAnswerMatchesTheCatalogue(t *testing.T) {
	t.Parallel()

	services := map[string]bool{}
	for _, e := range domain.CountableEntries() {
		services[domain.LimitKind(e.Kind).Service()] = true
	}
	require.NotEmpty(t, services, "каталог пуст — проба не читает ничего")

	checked := 0
	for service := range services {
		var stated []domain.Limit
		for _, k := range domain.CountableKindsOfService(service) {
			stated = append(stated, domain.Limit{Kind: k, Scope: domain.LimitScopeDefault, Value: 16})
		}
		for _, e := range domain.ResolveEffective(service, stated) {
			carrier, known := domain.CarrierOfKind(e.Kind)
			require.True(t, known, "вид %s вернулся из резолва, но каталог его не знает", e.Kind)
			require.Equal(t, carrier, e.Carrier,
				"вид %s вернулся с носителем %q, а каталог называет %q — потребитель, "+
					"поверив ответу, заведёт строку учёта не на том носителе, и её "+
					"потребление не наполнится никогда", e.Kind, e.Carrier, carrier)
			require.NotEmpty(t, e.Carrier,
				"вид %s вернулся с пустым носителем — потребитель прочитает пустое как «проект»", e.Kind)
			checked++
		}
	}
	require.NotZero(t, checked, "ни одного вида не осмотрено — проба вакуумна")
	t.Logf("перепись: доменов %d, видов осмотрено %d", len(services), checked)
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
