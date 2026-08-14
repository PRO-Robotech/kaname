// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// limit_kind_catalog_test.go — гейт на КЛАСС «вид ресурса появился, а потолка у
// него нет».
//
// # Предмет
//
// Перечень видов, за которые арендатор платит, выписан руками
// (domain.CountableKinds). Рукописный перечень отстаёт от дерева ровно одним
// способом: заводят девятый ресурс — потолок ему не заводят, и это не видно ничем.
// Именно так был потерян ВОСЬМОЙ вид: инженерная записка вывела перечень из
// закрытого словаря проекции намерений исполнителю, а `vpc.cidrGroup` в проекцию
// не попадает — он именованный перечень префиксов, а не сущность data plane.
//
// # Почему сверка идёт с моделью прав, а не со словарём проекции
//
// Модель прав знает КАЖДЫЙ адресуемый арендатором тип: у него есть свой объект,
// на который выдаются права. Словарь проекции знает только то, что уезжает
// исполнителю. Первое — надмножество второго, и разница между ними и есть тот
// самый потерянный вид.
//
// # Способность упасть доказывается инъекцией, а не прочтением
//
// TestLimitKindCatalogGateCanFail подаёт гейту синтетический каталог с девятым
// тенантным типом vpc и требует находку; рядом — законный близнец (тот же
// каталог без девятого типа), на котором гейт обязан молчать. Без второй
// половины «находок нет» было бы неотличимо от «предикат не смотрит».
package authzmap_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// adminOnlyKinds — типы, которые арендатор НЕ заводит, поэтому потолка у них нет.
//
// Это не список прощённых, а перечень с ПРЕДМЕТОМ у каждой записи: запись,
// которой больше нечего исключать, роняет гейт (TestAdminOnlyExclusionsHaveSubject).
// Иначе исключение пережило бы свой тип и создало впечатление покрытия.
var adminOnlyKinds = map[string]string{
	"vpc.addressPool": "админский ресурс Internal*-сервиса: пул адресов заводит оператор платформы, не арендатор",
}

// TestLimitKindsAreKnownObjectTypes — каждый вид каталога потолков называет
// РЕАЛЬНЫЙ тип модели прав. Опечатка в токене иначе доехала бы до администратора
// как рабочий вид, потолок на который никто не читает.
func TestLimitKindsAreKnownObjectTypes(t *testing.T) {
	kinds := domain.CountableKinds()
	require.NotEmpty(t, kinds, "каталог видов пуст — предпосылка гейта сломана")

	for _, k := range kinds {
		module, resource, ok := authzmap.SplitObjectType(string(k))
		require.Truef(t, ok, "вид %q не разбирается на domain.resource", k)
		_, known := authzmap.ObjectType(module, resource)
		require.Truef(t, known,
			"вид %q не найден в закрытой таблице типов модели прав — потолок стоял бы на\n"+
				"    имени, которого в платформе нет, и не применился бы никогда", k)
	}
	t.Logf("перепись: видов каталога сверено %d", len(kinds))
}

// TestEveryTenantVpcTypeIsCountable — ни один тенантный тип vpc не остаётся без
// потолка молча. Девятый тип обязан либо получить потолок, либо быть названным
// админским с причиной.
func TestEveryTenantVpcTypeIsCountable(t *testing.T) {
	missing := findUncountableTenantKinds(catalogDottedKeys(t), countableSet(), adminOnlyKinds)
	for _, k := range missing {
		t.Errorf("тип %q адресуется арендатором, но потолка на него нет.\n"+
			"    Либо добавьте вид в domain.countableKinds, либо назовите его админским\n"+
			"    в adminOnlyKinds С ПРИЧИНОЙ — молчаливое отсутствие и есть тот механизм,\n"+
			"    которым восьмой вид был потерян в первый раз.", k)
	}
	t.Logf("перепись: ключей каталога прочитано %d, видов с потолком %d, названных админскими %d",
		len(catalogDottedKeys(t)), len(countableSet()), len(adminOnlyKinds))
}

// TestAdminOnlyExclusionsHaveSubject — исключение живёт, пока у него есть предмет.
func TestAdminOnlyExclusionsHaveSubject(t *testing.T) {
	present := map[string]bool{}
	for _, k := range catalogDottedKeys(t) {
		present[k] = true
	}
	for k, why := range adminOnlyKinds {
		require.NotEmptyf(t, why, "исключение %q обязано нести причину", k)
		require.Truef(t, present[k],
			"исключение %q больше нечего исключать — типа в модели прав нет.\n"+
				"    Такая запись не безобидна: она создаёт впечатление разобранного случая,\n"+
				"    и её унаследует следующая слепая зона.", k)
	}
}

// TestLimitKindCatalogGateCanFail — инъекция в ОБЕ стороны на синтетическом
// входе: девятый тенантный тип обязан быть назван, законный близнец — нет.
func TestLimitKindCatalogGateCanFail(t *testing.T) {
	countable := countableSet()

	withNinth := append(catalogDottedKeys(t), "vpc.serviceEndpoint")
	got := findUncountableTenantKinds(withNinth, countable, adminOnlyKinds)
	require.Equal(t, []string{"vpc.serviceEndpoint"}, got,
		"гейт обязан НАЗВАТЬ девятый тенантный тип vpc, у которого нет потолка")

	// Законный близнец — тот же вход без девятого типа. Без него «гейт краснеет»
	// было бы неотличимо от «гейт краснеет всегда».
	require.Empty(t, findUncountableTenantKinds(catalogDottedKeys(t), countable, adminOnlyKinds),
		"на сегодняшнем дереве гейт обязан молчать — иначе он ловит форму, а не существо")
}

// findUncountableTenantKinds — предикат гейта, вынесенный отдельно ровно затем,
// чтобы его можно было прогнать на синтетическом входе. Проверка, которую нельзя
// покормить настоящим входом, о своей способности упасть не утверждает ничего.
func findUncountableTenantKinds(dotted []string, countable map[string]bool, adminOnly map[string]string) []string {
	var out []string
	for _, k := range dotted {
		if !strings.HasPrefix(k, "vpc.") {
			continue
		}
		if countable[k] {
			continue
		}
		if _, excused := adminOnly[k]; excused {
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
