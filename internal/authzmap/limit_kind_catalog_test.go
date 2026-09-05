// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// limit_kind_catalog_test.go — гейт на КЛАСС «вид ресурса появился, а потолка у
// него нет».
//
// # Предмет
//
// Перечень видов, за которые платит арендатор, выписан руками
// (domain.countableKinds). Рукописный перечень отстаёт от дерева ровно одним
// способом: заводят новый тенантный тип — потолка ему не заводят, и это не видно
// ничем. Именно так был потерян ВОСЬМОЙ вид vpc: инженерная записка вывела
// перечень из закрытого словаря проекции намерений исполнителю, а
// `vpc.cidrGroup` в проекцию не попадает — он именованный перечень префиксов, а
// не сущность data plane.
//
// # Почему сверка идёт с моделью прав, а не со словарём проекции
//
// Модель прав знает КАЖДЫЙ адресуемый арендатором тип: у него есть свой объект,
// на который выдаются права. Словарь проекции знает только то, что уезжает
// исполнителю. Первое — надмножество второго, и разница между ними и есть тот
// самый потерянный вид.
//
// # Предмет гейта — ВСЕ домены, а не один
//
// Прежняя редакция отбирала кандидатов условием `HasPrefix(k, "vpc.")`, поэтому
// её предмет был сужен одним доменом из шести: заведи новый тенантный тип в
// storage — не покраснело бы ничто. Замер на этой ревизии показал 17 грантуемых
// пар без потолка за пределами того сужения. Кандидат теперь — ЛЮБАЯ грантуемая
// пара закрытой таблицы.
//
// # Способность упасть доказывается инъекцией, а не прочтением
//
// TestLimitKindCatalogGateCanFail подаёт каждому предикату синтетический вход с
// дефектом и требует находку; рядом — законный близнец, на котором тот же
// предикат обязан молчать. Без второй половины «находок нет» было бы неотличимо
// от «предикат не смотрит».
package authzmap_test

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// excludedKinds — грантуемые пары, у которых потолка НЕТ, и причина по каждой.
//
// Это не список прощённых, а перечень с ПРЕДМЕТОМ у каждой записи: запись,
// которой больше нечего исключать, роняет гейт (TestExclusionsHaveSubject).
// Иначе исключение пережило бы свой тип и создало впечатление покрытия.
//
// Перечень назван «исключениями», а не «админскими»: причины у записей разные, и
// прежнее имя стало бы ложью на первой же не-админской записи — `iam.account`
// арендатор заводит себе сам.
var excludedKinds = map[string]string{
	"vpc.addressPool": "админский ресурс Internal*-сервиса: пул адресов заводит оператор платформы, не арендатор",
}

// TestLimitKindsAreKnownObjectTypes — каждый вид каталога называет РЕАЛЬНЫЕ типы
// модели прав: двухчастный — один, трёхчастный — ОБА своих.
//
// Опечатка в токене иначе доехала бы до администратора как рабочий вид, потолок
// на который никто не читает. Для трёхчастного вида проверяются обе части именно
// потому, что форма второй части в закрытой таблице НЕединообразна
// (единственное число у vpc/compute/iam, множественное у loadbalancer/storage/
// registry) — токен, написанный по памяти о названии ресурса, обязан быть
// отвергнут здесь, а не замечен арендатором.
func TestLimitKindsAreKnownObjectTypes(t *testing.T) {
	kinds := domain.CountableKinds()
	require.NotEmpty(t, kinds, "каталог видов пуст — предпосылка гейта сломана")

	nested := 0
	for _, k := range kinds {
		unknown := findUnknownKindParts(k, resolvesKindPart)
		require.Emptyf(t, unknown,
			"вид %q называет часть(и) %v, которых нет в закрытой таблице типов модели прав —\n"+
				"    потолок стоял бы на имени, которого в платформе нет, и не применился бы\n"+
				"    никогда. Части ВЫПИСЫВАЮТСЯ предикатом из fga_types.go, а не по памяти.",
			k, unknown)
		if k.Nested() {
			nested++
		}
	}
	t.Logf("перепись: видов каталога сверено %d, из них трёхчастных %d", len(kinds), nested)
}

// tenancyRoots — носители, которые НЕ являются типами модели прав: корни аренды.
//
// Перечень собран из объявленных констант доменного пакета. Выписанный
// литералами, он разошёлся бы с ними на первом же новом корне — и разошёлся бы
// тихо: гейт отправил бы законный корень на резолв, не нашёл его среди типов и
// объявил находкой то, что является решением.
var tenancyRoots = map[domain.LimitCarrier]bool{
	domain.CarrierProject:  true,
	domain.CarrierAccount:  true,
	domain.CarrierIdentity: true,
}

// TestEveryCatalogKindDeclaresACarrier — запись каталога есть ПАРА, и носитель
// объявлен, а не выведен.
//
// Вывести носитель из формы токена нельзя: `iam.project` двухчастен, а считается
// в АККАУНТЕ. Правило «две части ⇒ проект» ложно на первой же существующей
// записи, и ошибка эта не громкая — она считает верные строки против неверного
// владельца.
func TestEveryCatalogKindDeclaresACarrier(t *testing.T) {
	entries := domain.CountableEntries()
	require.NotEmpty(t, entries, "каталог пуст — предпосылка гейта сломана")

	byCarrier := map[domain.LimitCarrier]int{}
	for _, e := range entries {
		require.NoErrorf(t, e.Carrier.Validate(),
			"вид %q не объявил носителя учёта", e.Kind)

		// Носитель, не являющийся корнем аренды, обязан РЕЗОЛВИТЬСЯ — иначе учёт
		// вёлся бы в объекте, которого модель прав не знает.
		//
		// Корни перечислены ОБЪЯВЛЕННЫМИ константами, а не литералами: корень —
		// решение доменного пакета, и гейт, знающий их по написанию, разошёлся бы
		// с ним ровно на добавлении следующего. Слово, не являющееся объявленным
		// корнем, сюда не попадает — оно уходит на резолв и краснеет там.
		if !tenancyRoots[e.Carrier] {
			require.Emptyf(t, findUnknownKindParts(domain.LimitKind(e.Carrier), resolvesKindPart),
				"носитель %q вида %q не найден в закрытой таблице типов модели прав", e.Carrier, e.Kind)
		}

		// Носитель трёхчастного вида — ЕГО РОДИТЕЛЬ, а не что-нибудь ещё. Без
		// этого `vpc.network.subnet` мог бы объявить носителем `vpc.subnet` и
		// считать подсети в подсети, оставаясь зелёным на всех проверках выше.
		if e.Kind.Nested() {
			require.Equalf(t, domain.LimitCarrier(e.Kind.ParentKind()), e.Carrier,
				"вложенный вид %q обязан считаться в СВОЁМ родителе %q, а объявил %q",
				e.Kind, e.Kind.ParentKind(), e.Carrier)
		}
		byCarrier[e.Carrier]++
	}
	t.Logf("перепись: записей каталога %d, носителей различных %d (project %d, account %d, identity %d)",
		len(entries), len(byCarrier),
		byCarrier[domain.CarrierProject], byCarrier[domain.CarrierAccount],
		byCarrier[domain.CarrierIdentity])
}

// TestEveryTenantTypeIsCountable — ни один тенантный тип НИ ОДНОГО домена не
// остаётся без потолка молча. Новый тип обязан либо получить потолок, либо быть
// названным исключением с причиной.
func TestEveryTenantTypeIsCountable(t *testing.T) {
	keys := catalogDottedKeys(t)
	missing := findUncountableTenantKinds(keys, countableSet(), excludedKinds)
	for _, k := range missing {
		t.Errorf("тип %q адресуется арендатором, но потолка на него нет.\n"+
			"    Либо добавьте вид в domain.countableKinds С НОСИТЕЛЕМ, либо назовите его\n"+
			"    исключением в excludedKinds С ПРИЧИНОЙ — молчаливое отсутствие и есть тот\n"+
			"    механизм, которым восьмой вид был потерян в первый раз.", k)
	}
	t.Logf("перепись: грантуемых пар прочитано %d, видов каталога %d, названных исключениями %d",
		len(keys), len(countableSet()), len(excludedKinds))
}

// TestExclusionsHaveSubject — исключение живёт, пока у него есть предмет.
func TestExclusionsHaveSubject(t *testing.T) {
	present := map[string]bool{}
	for _, k := range catalogDottedKeys(t) {
		present[k] = true
	}
	for k, why := range excludedKinds {
		require.NotEmptyf(t, why, "исключение %q обязано нести причину", k)
		require.Truef(t, present[k],
			"исключение %q больше нечего исключать — типа в модели прав нет.\n"+
				"    Такая запись не безобидна: она создаёт впечатление разобранного случая,\n"+
				"    и её унаследует следующая слепая зона.", k)
	}
	t.Logf("перепись: исключений прочитано %d, все с предметом", len(excludedKinds))
}

// TestLimitKindCatalogGateCanFail — инъекция в ОБЕ стороны на синтетическом
// входе, по одному дефекту на предикат.
//
// Дефект подаётся НАСТОЯЩИМ входом того же вида, что читает гейт на дереве, а
// рядом стоит законный близнец: без него «гейт краснеет» было бы неотличимо от
// «гейт краснеет всегда».
func TestLimitKindCatalogGateCanFail(t *testing.T) {
	countable := countableSet()
	keys := catalogDottedKeys(t)

	t.Run("тенантный тип без потолка назван — и он НЕ из vpc", func(t *testing.T) {
		// Взят storage, а не vpc, именно потому, что прежний предикат смотрел
		// только на vpc: близнец из vpc остался бы зелёным на старом сужении и
		// не доказал бы расширения предмета.
		withNinth := append(append([]string{}, keys...), "storage.backups")
		require.Equal(t, []string{"storage.backups"},
			findUncountableTenantKinds(withNinth, countable, excludedKinds),
			"гейт обязан НАЗВАТЬ тенантный тип чужого домена, у которого нет потолка")

		require.Empty(t, findUncountableTenantKinds(keys, countable, excludedKinds),
			"законный близнец: на сегодняшнем дереве гейт обязан молчать")
	})

	t.Run("исключение принимается только с предметом", func(t *testing.T) {
		present := map[string]bool{}
		for _, k := range keys {
			present[k] = true
		}
		// Истёкшее исключение — то, чей тип из модели прав исчез. Гейт
		// TestExclusionsHaveSubject роняет ровно такую запись.
		require.False(t, present["storage.backups"],
			"истёкшее исключение обязано быть НЕнаходимым в таблице типов")
		require.True(t, present["vpc.addressPool"],
			"законный близнец: у действующего исключения предмет есть")
	})

	t.Run("часть трёхчастного вида, не являющаяся типом, названа", func(t *testing.T) {
		// Вторая часть выдумана.
		require.Equal(t, []string{"vpc.serviceEndpoint"},
			findUnknownKindParts("vpc.network.serviceEndpoint", authzmapResolves),
			"гейт обязан назвать ИМЕННО ту часть, которой нет")

		// Форма второй части взята «по памяти» — единственное число там, где
		// закрытая таблица держит множественное. Ровно на этом споткнулась
		// предыдущая редакция приёмки.
		require.Equal(t, []string{"registry.registry", "registry.repository"},
			findUnknownKindParts("registry.registry.repository", authzmapResolves),
			"токен, написанный по памяти о названии ресурса, обязан быть отвергнут")

		// Законный близнец — тот же домен, обе части выписаны из таблицы.
		require.Empty(t, findUnknownKindParts("registry.registries.repositories", authzmapResolves),
			"законный близнец: обе части выписаны из закрытой таблицы — гейт молчит")
		require.Empty(t, findUnknownKindParts("vpc.network.subnet", authzmapResolves),
			"законный близнец: действующий вложенный вид каталога")
	})

	t.Run("четыре части и одна часть — не виды", func(t *testing.T) {
		require.Equal(t, []string{"vpc.network.subnet.route"},
			findUnknownKindParts("vpc.network.subnet.route", authzmapResolves),
			"вид из четырёх частей обязан быть отвергнут целиком")
		require.Equal(t, []string{"vpc"},
			findUnknownKindParts("vpc", authzmapResolves),
			"вид из одной части обязан быть отвергнут целиком")
	})

	t.Run("носитель проверяется на форму", func(t *testing.T) {
		require.Error(t, domain.LimitCarrier("").Validate(),
			"пустой носитель обязан быть отвергнут — иначе вид без носителя проезжает молча")
		require.Error(t, domain.LimitCarrier("vpc.network.subnet").Validate(),
			"носителем не может быть трёхчастный токен")
		require.NoError(t, domain.CarrierProject.Validate(), "законный близнец: project")
		require.NoError(t, domain.LimitCarrier("vpc.network").Validate(), "законный близнец: тип-родитель")
	})
}

// findUnknownKindParts — предикат гейта, вынесенный отдельно ровно затем, чтобы
// его можно было прогнать на синтетическом входе. Проверка, которую нельзя
// покормить настоящим входом, о своей способности упасть не утверждает ничего.
//
// Возвращает те части вида, которые НЕ резолвятся; для вида недопустимой формы —
// сам вид, потому что назвать в нём нечего.
func findUnknownKindParts(k domain.LimitKind, resolves func(string) bool) []string {
	var candidates []domain.LimitKind
	switch len(k.Parts()) {
	case 2:
		candidates = []domain.LimitKind{k}
	case 3:
		candidates = []domain.LimitKind{k.ParentKind(), k.ChildKind()}
	default:
		return []string{string(k)}
	}
	var out []string
	for _, c := range candidates {
		if !resolves(string(c)) {
			out = append(out, string(c))
		}
	}
	sort.Strings(out)
	return out
}

// resolvesKindPart — часть вида резолвится, если она называет ЛИБО тип модели
// прав, ЛИБО объявленный подчинённый ресурс.
//
// Второй источник имён введён задачей #1191 и НЕ является ослаблением: множество
// имён остаётся закрытым, а истинность второй таблицы анкерена в дереве
// утверждениями G5/G6 (`services/iam/internal/migrations`) — таблицы строк
// существуют, и на них стоит триггер списания, называющий вид. Ослаблением было
// бы «часть, которая не резолвится, пропускается».
//
// Предмет расширения назван в приёмке §3.2: удостоверение адресуется арендатором,
// но типа модели прав не имеет и иметь не должно — право на него вычисляется от
// принципала, и объект, на который его можно было бы ВЫДАТЬ, расширил бы
// поверхность выдачи ради учёта.
func resolvesKindPart(dotted string) bool {
	if authzmapResolves(dotted) {
		return true
	}
	_, ok := domain.SubordinateResourceOf(domain.LimitKind(dotted))
	return ok
}

// authzmapResolves — членство двухчастного токена в закрытой таблице типов.
func authzmapResolves(dotted string) bool {
	module, resource, ok := authzmap.SplitObjectType(dotted)
	if !ok {
		return false
	}
	_, known := authzmap.ObjectType(module, resource)
	return known
}

// findUncountableTenantKinds — предикат покрытия. Кандидат — ЛЮБАЯ грантуемая
// пара закрытой таблицы, а не пара одного домена.
func findUncountableTenantKinds(dotted []string, countable map[string]bool, excluded map[string]string) []string {
	var out []string
	for _, k := range dotted {
		if countable[k] {
			continue
		}
		if _, excused := excluded[k]; excused {
			continue
		}
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func countableSet() map[string]bool {
	out := map[string]bool{}
	for _, k := range domain.CountableKinds() {
		out[string(k)] = true
	}
	return out
}

func catalogDottedKeys(t *testing.T) []string {
	t.Helper()
	entries := authzmap.Catalog()
	require.NotEmpty(t, entries, "таблица типов модели прав пуста — гейт осматривал бы ничто")
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Module+"."+e.Resource)
	}
	sort.Strings(out)
	return out
}
