// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// migrator_showcase_name_test.go — ГЕЙТ КЛАССА: накатчик, названный на витрине
// Kaname, есть накатчик Kaname (задача #17, порт семейства
// `kanamemigratorshowcase`).
//
// Предмет, что забрал разрез, вывод законного имени у производителя и границы
// распознавателя — в шапке `migrator_showcase_name.go`; здесь они не
// пересказываются.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// migrator_showcase_name_injection_test.go.
//
// ─────────────────────────────────────────────────────────────────────────────
// ШОВ С СОСЕДНИМ СЕМЕЙСТВОМ, И ОН НАЗВАН С ОБЕИХ СТОРОН
//
// `migrator_verb_roster_test.go` судит ПЕРЕЧЕНЬ ПОДКОМАНД накатчика; этот гейт —
// его ИМЯ. Предметы разные, производитель ОДИН, и читается он одним разбором
// (`parseMigratorCommands`): второй разбор той же строки был бы вторым местом об
// одном предмете, расходящимся молча.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"

	"github.com/PRO-Robotech/kaname/internal/contractnaming"
)

// migratorShowcaseLedger — ведомость изъятий: координата → ПРИЧИНА, по которой
// файл вправе называть чужой накатчик.
//
// Запись, которой больше нечего изымать (чужой токен ушёл либо файл исчез), —
// НАХОДКА: послабление обязано истекать само, иначе оно переживает свой предмет,
// оставаясь на вид рабочим и молча расширяя слепую зону.
var migratorShowcaseLedger = map[string]string{
	// НОСИТЕЛЬ САМОГО ПРАВИЛА. Шапка распознавателя объясняет, ЧТО он ловит, и
	// объяснить это без литерала чужого имени нельзя: именно на нём показано,
	// почему сегмент, а не приставка (`kacho-nlb-migrator` несёт имя платформы
	// вторым словом от конца), и почему путь установки даёт тот же токен.
	//
	// Это ровно тот класс, что ловит проверку, судящую СЛОВО вместо УЗЛА:
	// она находит своё же объяснение и краснеет на нём. Здесь он
	// наступил НЕ в теории — гейт был зелен, пока файл лежал НЕОТСЛЕЖИВАЕМЫМ, и
	// покраснел первым же прогоном после посадки: состав берётся из индекса git,
	// поэтому гейт себя не видел. Первый зелёный был вердиктом не о том дереве.
	//
	// Правится ИЗЪЯТИЕМ, а не вычёркиванием примера: подгонять объяснение под
	// инструмент значит сделать правило непонятным ради зелёного, а непонятное
	// правило снимает следующий.
	"internal/supplyhygiene/migrator_showcase_name.go": "НОСИТЕЛЬ ПРАВИЛА: называет чужое " +
		"имя как ПРЕДМЕТ распознавателя — то же основание, по которому изъята проба. " +
		"Арендатору не едет: это объяснение проверки, а не инструкция",

	"docs/engineering/acceptance/roles-come-as-data-not-migrations.md": "ОДОБРЕННАЯ ПРИЁМКА: " +
		"вердикт есть утверждение о РЕВИЗИИ, которую прочитал проверяющий, и механическая " +
		"правка его не переносит. Координата в §2.2 называет двоичный файл именем платформы " +
		"и устарела вместе с выносом службы; её предмет — мёртвые координаты в приёмках " +
		"(kaname#11), а не имя на витрине",
}

// migratorShowcaseExemptReason — изъят ли файл из витрины, и почему.
//
// Изъятие по СВОЙСТВУ (проба) плюс поимённая ведомость. Проба называет имя как
// ПРЕДМЕТ своей проверки, а инъекция обязана вносить дефект НАСТОЯЩИМ именем:
// гейт, судящий собственную инъекцию, не смог бы доказать, что способен упасть.
// Витриной проба не является by construction — арендатору она не едет.
func migratorShowcaseExemptReason(rel string) (string, bool) {
	if strings.HasSuffix(rel, "_test.go") {
		return "проба: называет имя как ПРЕДМЕТ проверки, арендатору не едет", true
	}
	if reason, ok := migratorShowcaseLedger[rel]; ok {
		return reason, true
	}
	return "", false
}

// migratorShowcaseCorpus — файлы витрины из ДЕРЕВА, кроме изъятых.
//
// Обход и его отказ на пустоте держит ОДНА функция, и её зовут И гейт, И
// инъекция: копия доказывала бы свойство копии. Дерево приходит параметром,
// поэтому синтетика подаёт тот же отбор, что исполняется на боевом прогоне
// (задача #17). Прежде обход строился в теле пробы от корня своего модуля,
// премиса «прочитано НОЛЬ файлов витрины» стояла ниже разбора, и подать ей
// дерево без витрины было нечем: ветвь читалась глазами и не исполнялась ни разу.
//
// Держатель отказа — общий на оба гейтовых пакета (`check.ErrEmptyTraversal`):
// вторая его копия разошлась бы с первой молча, а расходится всегда та, которую
// не считали.
func migratorShowcaseCorpus(tree *treecorpus.Tree) (check.TreeCorpus, error) {
	return check.CorpusFrom(tree, func(rel string) bool {
		_, exempt := migratorShowcaseExemptReason(rel)
		return !exempt
	})
}

func TestKanameShowcaseNamesItsOwnMigrator(t *testing.T) {
	tree, err := treecorpus.NewTree(serviceRoot)
	require.NoError(t, err, "состав дерева не прочитан — «ноль находок» здесь означало бы "+
		"«ноль прочитанного»")

	// Законное имя — у ПРОИЗВОДИТЕЛЯ, тем же разбором, каким его читает
	// семейство перечня подкоманд.
	own, verbs, _, err := parseMigratorCommands(serviceRoot)
	require.NoError(t, err, "производитель имени не разобран")
	require.NotEmpty(t, own, "имя двоичного файла не прочитано у производителя — "+
		"судить витрину не с чем, и вердикт был бы беспредметен")
	require.NotEmpty(t, verbs, "подкоманд не прочитано ни одной — производитель разобран "+
		"наполовину")

	// Словарь имён продуктов ВЫВОДИТСЯ, а не выписывается.
	products := contractnaming.KnownOwners()
	require.GreaterOrEqual(t, len(products), 2, "имён продуктов выведено %d — словарь, "+
		"знающий одно имя, не отличил бы своего накатчика от чужого", len(products))

	corpus, err := migratorShowcaseCorpus(tree)
	require.NoError(t, err, "обход витрины: «ноль находок» здесь означало бы "+
		"«ноль прочитанного»")

	exemptReasons := map[string]int{}
	tracked, exempt := 0, 0
	for _, rel := range tree.SortedFiles() {
		tracked++
		if reason, ok := migratorShowcaseExemptReason(rel); ok {
			exempt++
			exemptReasons[reason]++
		}
	}
	files := map[string]string(corpus)

	findings, census := MigratorShowcaseScan(files, products, own)
	census.FilesTracked, census.FilesExempt = tracked, exempt
	census.ExemptReasons = exemptReasons

	// ── премисы: «ноль находок» отличимо от «ноль прочитанного» ─────────────
	//
	// Премиса ОБХОДА переехала в `migratorShowcaseCorpus`; здесь остаются те,
	// что про РАЗБОР прочитанного, а не про то, что обход что-то принёс.
	require.NotZero(t, census.TokensSeen, "на витрине НЕ ВСТРЕЧЕНО ни одного токена формы "+
		"`…%s` — распознаватель либо ослеп, либо витрина перестала называть накат вовсе; "+
		"и то и другое означает, что зелёный прогон ничего не утверждает", MigratorTokenSuffix)
	require.NotZero(t, census.TokensJudged, "ни один токен НЕ ПРИЗНАН именем накатчика "+
		"продукта — словарь имён разошёлся с витриной, и вердикт вынесен ни разу")

	t.Logf("перепись витрины: отслеживаемых файлов %d, изъято %d, прочитано %d",
		census.FilesTracked, census.FilesExempt, census.FilesRead)
	reasons := make([]string, 0, len(census.ExemptReasons))
	for r := range census.ExemptReasons {
		reasons = append(reasons, r)
	}
	sort.Strings(reasons)
	for _, r := range reasons {
		t.Logf("  изъято %3d — %s", census.ExemptReasons[r], r)
	}
	t.Logf("перепись имён: накатчик этого продукта %q (производитель — %s); имён продуктов "+
		"выведено %d (%s); токенов формы `…%s` встречено %d, признано именем накатчика "+
		"продукта %d, из них своих %d, диакритической формой %d",
		own, migratorCommandFile, len(products), strings.Join(products, ", "),
		MigratorTokenSuffix, census.TokensSeen, census.TokensJudged, census.TokensOwn,
		census.TokensDiacritic)

	for _, f := range findings {
		t.Errorf("%s", f)
	}

	// САМОИСТЕЧЕНИЕ ведомости: запись, которой нечего изымать, — находка.
	for rel, reason := range migratorShowcaseLedger {
		if !tree.HasFile(rel) {
			t.Errorf("ведомость изъятий называет %s, которого в составе дерева НЕТ: "+
				"послабление пережило свой файл (причина записи: %s)", rel, reason)
			continue
		}
		b, readErr := os.ReadFile(filepath.Join(serviceRoot, filepath.FromSlash(rel)))
		require.NoError(t, readErr, "изъятый файл %s не прочитан", rel)
		f, _ := MigratorShowcaseScan(map[string]string{rel: string(b)}, products, own)
		if len(f) == 0 {
			t.Errorf("записи ведомости нечего изымать: %s больше не называет чужой накатчик — "+
				"снимите запись, иначе она молча прощает СЛЕДУЮЩУЮ находку в этом файле "+
				"(причина записи: %s)", rel, reason)
		}
	}
}
