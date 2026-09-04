// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package check

// catalog_seed_parity_test.go — гейты каталога модуля (kacho#1030, приёмка
// `services/iam/docs/engineering/acceptance/rule-segments-have-a-referent.md`,
// требования Т1, Т2, Т6).
//
// # Почему гейт дерева, а не проба сервиса
//
// «Посев согласен с литералом» — свойство ДЕРЕВА, и проба сервиса о нём не
// утверждает ничего: она читает базу, в которую миграция уже применена, и
// зеленеет при любом литерале. Литерал же правится свободно, а применённая
// миграция правке не подлежит (запрет #5) — значит расхождение неизбежно, и
// вопрос не «как его не допустить», а «как сделать его ВИДИМЫМ».
//
// Проверок здесь ДВЕ, и предметы у них разные: паритет посева и форма ключа.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
)

// catalogRepoRoot — корень модуля. Своя копия обхода вверх не заводится: рядом
// уже есть `monorepoRoot`, но он живёт во внешнем тестовом пакете
// (`check_test`), а этот гейт — во внутреннем, потому что зовёт неэкспортируемое
// ядро. Это единственная причина, по которой обход здесь повторён.
func catalogRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("рабочий каталог: %v", err)
	}
	dir := wd
	for {
		if _, serr := os.Stat(filepath.Join(dir, "go.mod")); serr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("корень модуля (go.mod) не найден от %s", wd)
		}
		dir = parent
	}
}

// catalogMigrationPath — миграция, сеющая каталог модуля и ОБЕ половины словаря
// глаголов.
//
// # Здесь стояли ДВЕ координаты, и обе пережили свой предмет
//
// Пообъектную половину сеяла миграция 20260901113757, ярусную — 20260902062000,
// и порознь они сверялись не для удобства: первая была применена, а применённую
// не правят (запрет #5). Свод 171 миграции в одну первичную снял обе — файлов в
// каталоге ровно один (предикат: `ls services/iam/internal/migrations/*.sql | wc -l`
// → 1), — и обе константы стали ссылками в никуда.
//
// # Гейта по-прежнему ДВА, хотя тело у них одно
//
// Свести их в один значило бы потерять ответ на вопрос «какая половина словаря
// разошлась с литералом»: сверка идёт с РАЗНЫМИ половинами перечня, и слитая
// находка называла бы таблицу вместо половины. Половины теперь различаются не
// оператором, а значением `per_object` — см. шапку `catalog_seed_parity.go`.
const catalogMigrationPath = "services/iam/internal/migrations/0001_initial.sql"

// restrictDeferrableExempt — ключи, которым форма `RESTRICT … DEFERRABLE`
// прощена ПОИМЁННО, с причиной и предикатом снятия.
//
// # Почему ведомость появилась вместе со сводом
//
// Пока телом гейта была одна миграция, он видел семь объявлений ключа и объявлял
// `RESTRICT … DEFERRABLE` запрещённым «везде в этом дереве», ни разу этого не
// измерив. Свод сделал телом всю схему — объявлений стало 42, — и обнажил два
// объявления этой формы, оба СТАРШЕ гейта: они стояли в дереве и до свода, в
// миграциях, которых гейт не читал (предикат:
// `git grep -h RESTRICT <до-свода> -- 'services/iam/internal/migrations/*.sql' | grep DEFERRABLE`).
//
// # Почему прощены, а не объявлены находкой
//
// `accounts.owner_user_id → users.id` и `users.account_id → accounts.id` — цикл,
// и отложенность на нём НЕСУЩАЯ: заведение личного аккаунта вставляет строку
// пользователя первой, а сам аккаунт — следом, в той же транзакции. Это записано
// решением в дереве и цитирует оба ключа поимённо (снятая миграция
// 470001_memberships_expand.sql, комментарий у ключа членства).
//
// Опасность, которую называет запрет, к ним не относится: `ON DELETE RESTRICT`
// не откладывается никогда, но откладывается ПРОВЕРКА СО СТОРОНЫ ССЫЛАЮЩЕГОСЯ —
// ровно та половина, ради которой цикл и объявлен отложенным. Запрет остаётся
// верным там, где автор ждёт отложенности от самого действия удаления.
//
// # Предикат снятия
//
// Запись держится, пока объявление существует; исчезнет — гейт назовёт её
// потерявшей предмет и упадёт (проверено инъекцией). Правильность самой формы
// для этих двух ключей ЗДЕСЬ НЕ РЕШАЕТСЯ: ведомость фиксирует, что вопрос не
// рассматривался вместе с этим гейтом, а не что он решён.
var restrictDeferrableExempt = []string{"accounts_owner_fk", "users_account_fk"}

// literalCatalog — перечень, ВЫВЕДЕННЫЙ единственным производителем
// (`authzmap.CatalogSeed*`), а не выписанный здесь. Второй производитель того же
// перечня разошёлся бы с первым молча — ровно в тот момент, когда расхождение и
// опасно.
//
// Глаголы отдаются ПООБЪЕКТНЫЕ: ярусную половину той же таблицы сверяет
// `TestTierOnlyVerbSeedMatchesTheLiteral`. Половины лежат в ОДНОМ операторе и
// различаются значением `per_object` — прежде их различал текст оператора, и это
// свойство свод снял.
func literalCatalog() (modules, resources, verbs []string) {
	modules = authzmap.CatalogSeedModules()
	for _, r := range authzmap.CatalogSeedResources() {
		resources = append(resources, r.Dotted)
	}
	for _, v := range authzmap.CatalogSeedVerbs() {
		if !v.PerObject {
			continue
		}
		verbs = append(verbs, v.Module+"."+v.Resource+"."+v.Verb)
	}
	return modules, resources, verbs
}

// literalTierOnlyVerbs — ЯРУСНАЯ половина того же перечня, от того же
// производителя.
func literalTierOnlyVerbs() []string {
	var out []string
	for _, v := range authzmap.CatalogSeedVerbs() {
		if v.PerObject {
			continue
		}
		out = append(out, v.Module+"."+v.Resource+"."+v.Verb)
	}
	return out
}

// TestIAMCT114_CatalogSeedMatchesTheLiteral — Т6.
func TestIAMCT114_CatalogSeedMatchesTheLiteral(t *testing.T) {
	root := catalogRepoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, catalogMigrationPath))
	if err != nil {
		t.Fatalf("прочитать миграцию каталога: %v", err)
	}

	mods, res, verbs := literalCatalog()
	if len(mods) == 0 || len(res) == 0 || len(verbs) == 0 {
		t.Fatalf("литерал пуст (модулей %d, ресурсов %d, глаголов %d) — "+
			"сверять было бы не с чем, и «расхождений нет» означало бы «ничего не прочитано»",
			len(mods), len(res), len(verbs))
	}

	c, findings, aerr := auditCatalogSeed(string(body), mods, res, verbs)
	if aerr != nil {
		t.Fatalf("разобрать посев: %v", aerr)
	}
	// Перепись печатает ПРОЧИТАННОЕ и КЛАССИФИЦИРОВАННОЕ ПАРОЙ. Одного числа
	// мало: расширяя распознаватель, обязан двигаться объём осмотренного, и
	// именно эта пара отличает «прибавка была слепой зоной» от «дерево выросло».
	t.Logf("осмотрено: литерал — модулей %d, ресурсов %d, пообъектных глаголов %d; "+
		"прочитано строк — модуля %d, ресурса %d, глагола %d; "+
		"классифицировано — модулей %d, живых ресурсов %d, снятых ресурсов %d, "+
		"пообъектных глаголов %d",
		len(mods), len(res), len(verbs),
		c.ReadModuleRows, c.ReadResourceRows, c.ReadVerbRows,
		c.SeededModules, c.SeededResources, c.RetiredSeeded, c.SeededVerbs)

	if c.RetiredSeeded == 0 {
		t.Error("снятых строк посеяно ноль: снятие выражено запретительным списком в Go, " +
			"и перенос его строками — половина предмета #1030")
	}
	for _, f := range findings {
		t.Error(f)
	}
}

// TestIAMCT113_CatalogKeysCarryTheDeclaredForm — Т1 и Т2.
func TestIAMCT113_CatalogKeysCarryTheDeclaredForm(t *testing.T) {
	root := catalogRepoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, catalogMigrationPath))
	if err != nil {
		t.Fatalf("прочитать миграцию каталога: %v", err)
	}

	immediateOnly := []string{"role_rule_ref_res_fk", "role_rule_ref_verb_fk", "role_verb_type_fk"}
	scanned, findings := auditKeyForm(string(body), immediateOnly, restrictDeferrableExempt)
	t.Logf("осмотрено объявлений ключа: %d; проверено на немедленность: %d; "+
		"прощено на форме RESTRICT рядом с DEFERRABLE: %d",
		scanned, len(immediateOnly), len(restrictDeferrableExempt))
	if scanned == 0 {
		t.Fatal("объявлений ключа не прочитано ни одного — обход пуст, вердикт беспредметен")
	}
	for _, name := range immediateOnly {
		if !containsDeclaration(string(body), name) {
			t.Errorf("ключ %s не объявлен миграцией: гейт судил бы имя, которого в дереве нет", name)
		}
	}
	for _, f := range findings {
		t.Error(f)
	}
}

func containsDeclaration(body, name string) bool {
	return len(body) > 0 && len(name) > 0 &&
		indexOf(stripSQLComments(body), "ADD CONSTRAINT "+name) >= 0
}

func indexOf(hay, needle string) int {
	for i := 0; i+len(needle) <= len(hay); i++ {
		if hay[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// ─────────────────────────────────────────────────────────────────────────────
// Ярусная половина словаря (задача продукта #1863)

// TestTierOnlyVerbSeedMatchesTheLiteral — посев ярусной половины согласен с
// литералом, в ОБЕ стороны.
//
// Односторонняя сверка молчала бы на строке, посеянной СВЕРХ литерала: она
// открывает авторскому правилу глагол, о котором производитель не знает, — то
// есть ключ пропускает то, чего в словаре нет.
func TestTierOnlyVerbSeedMatchesTheLiteral(t *testing.T) {
	root := catalogRepoRoot(t)
	body, err := os.ReadFile(filepath.Join(root, catalogMigrationPath))
	if err != nil {
		t.Fatalf("прочитать миграцию ярусной половины: %v", err)
	}

	want := literalTierOnlyVerbs()
	if len(want) == 0 {
		t.Fatal("ярусная половина литерала пуста — сверять было бы не с чем, и " +
			"«расхождений нет» означало бы «ничего не прочитано»")
	}

	seeded, findings, aerr := auditTierOnlyVerbSeed(string(body), want)
	if aerr != nil {
		t.Fatalf("разобрать ярусный посев: %v", aerr)
	}
	t.Logf("осмотрено: литерал — ярусных пар %d; посев — ярусных пар %d "+
		"(из одной таблицы с пообъектной половиной, различает per_object)", len(want), seeded)
	if seeded == 0 {
		t.Fatal("ярусных пар не посеяно ни одной — обход пуст, вердикт беспредметен")
	}
	for _, f := range findings {
		t.Error(f)
	}
}

// TestTierOnlyVerbClassesArePartOfTheClosedActionSet — ПРЕДПОСЫЛКА гейта выше.
//
// Гейт сверяет посев с перечнем и о самом перечне не утверждает ничего: назови
// ярусным выдуманный токен — обе стороны сойдутся, а правило роли получило бы
// референт на глагол, которого платформа не знает. Поэтому предпосылка
// проверяется отдельно и здесь: ярусным вправе быть только КЛАСС ДЕЙСТВИЯ из
// закрытого набора.
//
// Вторая половина — что класс действительно НЕ производит пообъектного
// отношения у тех типов, которым посеян ярусным, — держится производителем by
// construction (`CatalogSeedVerbs` кладёт ярусную строку только там, где
// пообъектной нет) и проверяется самопроверкой миграции на живой базе.
func TestTierOnlyVerbClassesArePartOfTheClosedActionSet(t *testing.T) {
	tierOnly := authzmap.TierOnlyVerbClasses()
	if len(tierOnly) == 0 {
		t.Fatal("ярусных классов объявлено ноль — предпосылка беспредметна, а ярусная " +
			"половина словаря при этом посеяна")
	}
	canonical := map[string]bool{}
	for _, c := range manifest.CanonicalVerbs() {
		canonical[c] = true
	}
	if len(canonical) == 0 {
		t.Fatal("закрытый набор классов действия пуст — сверять не с чем")
	}
	t.Logf("осмотрено: ярусных классов %d, канонических классов %d", len(tierOnly), len(canonical))
	for _, c := range tierOnly {
		if !canonical[c] {
			t.Errorf("ярусный класс %q вне закрытого набора классов действия: правило роли "+
				"получило бы референт на глагол, которого платформа не знает", c)
		}
	}
}
