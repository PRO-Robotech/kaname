// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// tree_corpus_families_injection_test.go — доказательство, что премиса пустого
// обхода СРАБАТЫВАЕТ у КАЖДОГО семейства, а не только у помощника (задача #17).
//
// # ЧТО ЗДЕСЬ ДОКАЗЫВАЕТСЯ, А ЧТО НЕТ
//
// Доказывается, что отбор семейства, поданный дереву БЕЗ его предмета, даёт
// ОТКАЗ, а не «находок ноль», — и что на дереве С предметом он его берёт.
// Второе не украшение: без него отказ ниже объяснялся бы отбором, который не
// берёт ничего никогда, и семейство «прошло» бы проверку, будучи слепым.
//
// Не доказывается, ЧТО ИМЕННО семейство судит в прочитанном: это предмет его
// собственной инъекции, и она у каждого своя.
//
// # ПОЧЕМУ ТАБЛИЦА, А НЕ ПРОБА НА СЕМЕЙСТВО
//
// Перечень — ЕДИНСТВЕННОЕ место, где видно, сколько семейств строят обход и
// сколько из них доказаны. Восемь отдельных проб дали бы то же покрытие и не
// дали бы этого числа: «доказано 9 из 9» здесь печатается переписью, а не
// подсчитывается читателем по именам файлов.
//
// Семейство, заведшее свой обход и не вписанное сюда, останется недоказанным
// молча — и это названо границей прямо, потому что гейта на неё нет.
package check_test

import (
	"errors"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// corpusFamily — сборщик корпуса одного семейства и два дерева к нему.
type corpusFamily struct {
	// Name — семейство задачи #17, чьё имя сохранено дословно с монорепо.
	Name string
	// Build — ТА ЖЕ функция, что зовёт гейт. Не копия: копия доказывала бы
	// свойство копии.
	Build func(*treecorpus.Tree) (check.TreeCorpus, error)
	// Present — дерево, на котором отбор обязан взять ровно перечисленное.
	Present map[string]string
	// Absent — дерево ТОЙ ЖЕ формы без предмета отбора. Различие с Present
	// ровно одно: предмет убран.
	Absent map[string]string
	// Want — что обязано быть отобрано на Present.
	Want []string
}

// corpusFamilies — семейства, чей обход стал параметром (задача #17).
func corpusFamilies() []corpusFamily {
	const goBody = "package p\n"
	return []corpusFamily{
		{
			Name:    "limitexportprocedure",
			Build:   check.ExportProcedureGuides,
			Present: map[string]string{"INSTALL.md": "тело", "README.md": "не он"},
			Absent:  map[string]string{"README.md": "не он"},
			Want:    []string{"INSTALL.md"},
		},
		{
			Name:  "subjectchangeflushparity",
			Build: check.SubjectChangeProducerCorpus,
			Present: map[string]string{
				check.SubjectChangeProducerRootRel + "/user/list.go":      goBody,
				check.SubjectChangeProducerRootRel + "/user/list_test.go": goBody,
				"internal/repo/x.go": goBody,
			},
			Absent: map[string]string{
				check.SubjectChangeProducerRootRel + "/user/list_test.go": goBody,
				"internal/repo/x.go": goBody,
			},
			Want: []string{check.SubjectChangeProducerRootRel + "/user/list.go"},
		},
		{
			Name:    "mirrorcatalogcondition",
			Build:   check.MirrorCandidateCorpus,
			Present: map[string]string{"internal/repo/emitter.go": goBody, "internal/repo/emitter_test.go": goBody},
			Absent:  map[string]string{"internal/repo/emitter_test.go": goBody, "docs/x.go": goBody},
			Want:    []string{"internal/repo/emitter.go"},
		},
		{
			Name:    "clienttruth_kaname_exclusion_form",
			Build:   check.ExclusionFormGoCorpus,
			Present: map[string]string{check.ExclusionReaderDirRel + "/read.go": goBody, "INSTALL.md": "тело"},
			Absent:  map[string]string{"INSTALL.md": "тело", check.ExclusionReaderDirRel + "/read_test.go": goBody},
			Want:    []string{check.ExclusionReaderDirRel + "/read.go"},
		},
		{
			Name:    "clienttruth_iam_moduleset (объявление)",
			Build:   check.ModuleSetDeclCorpus,
			Present: map[string]string{check.ModuleSetPkgRel + "/tables.go": goBody, "internal/other/x.go": goBody},
			Absent:  map[string]string{"internal/other/x.go": goBody, check.ModuleSetPkgRel + "/sub/deep.go": goBody},
			Want:    []string{check.ModuleSetPkgRel + "/tables.go"},
		},
		{
			Name:    "clienttruth_iam_moduleset (поверхность)",
			Build:   check.ModuleSetSurfaceCorpus,
			Present: map[string]string{"docs/content/api.mdx": "текст", "docs/engineering/note.mdx": "текст"},
			Absent:  map[string]string{"docs/engineering/note.mdx": "текст", "docs/content/api.txt": "текст"},
			Want:    []string{"docs/content/api.mdx"},
		},
		{
			Name:    "manifestverbclassrule (правило)",
			Build:   check.VerbClassRuleCorpus,
			Present: map[string]string{"internal/manifest/resources.go": goBody, check.GeneratedStubsPrefix + "gen.go": goBody},
			Absent:  map[string]string{check.GeneratedStubsPrefix + "gen.go": goBody, "internal/manifest/resources_test.go": goBody},
			Want:    []string{"internal/manifest/resources.go"},
		},
		{
			Name:    "manifestverbclassrule (загрузчик)",
			Build:   check.ManifestLoaderCorpus,
			Present: map[string]string{check.ManifestLoaderDir + "/load.go": goBody, "internal/other/x.go": goBody},
			Absent:  map[string]string{"internal/other/x.go": goBody, check.ManifestLoaderDir + "/load_test.go": goBody},
			Want:    []string{check.ManifestLoaderDir + "/load.go"},
		},
		{
			// Отбор совпадает с `clienttruth_kaname_exclusion_form` по предикату и
			// РАЗЛИЧАЕТСЯ по предмету: там судят форму исключения, здесь —
			// объявление дренажа очередей. Сведение их в один сборщик дало бы имя,
			// лгущее об одном из двух семейств; общий у них `ProductionGoFile`, и
			// он объявлен ровно один раз.
			Name:    "drainorderdeclared",
			Build:   check.DrainSiteCorpus,
			Present: map[string]string{"cmd/kaname/wiring.go": goBody, "cmd/kaname/wiring_test.go": goBody},
			Absent:  map[string]string{"cmd/kaname/wiring_test.go": goBody, "docs/x.go": goBody},
			Want:    []string{"cmd/kaname/wiring.go"},
		},
		{
			Name:    "migrationnotawriterofmodulerole + keyalgorithmdictionary",
			Build:   check.MigrationCorpus,
			Present: map[string]string{check.MigrationsDirRel + "/0001_initial.sql": "-- sql", "internal/x.go": goBody},
			Absent:  map[string]string{"internal/x.go": goBody, check.MigrationsDirRel + "/README.md": "не sql"},
			Want:    []string{check.MigrationsDirRel + "/0001_initial.sql"},
		},
	}
}

// TestCorpusFamilies_EveryTraversalRefusesWhenItsSubjectIsGone — премиса каждого
// семейства, доказанная ИСПОЛНЕНИЕМ.
func TestCorpusFamilies_EveryTraversalRefusesWhenItsSubjectIsGone(t *testing.T) {
	t.Parallel()

	families := corpusFamilies()
	if len(families) == 0 {
		t.Fatal("перечень семейств пуст — доказывать нечего, и «ноль находок» означало бы " +
			"«ноль проверенного»")
	}

	proven := 0
	for _, f := range families {
		t.Run(f.Name, func(t *testing.T) {
			// ── КОНТРОЛЬ: предмет на месте — отбор его БЕРЁТ ─────────────────
			//
			// Без него отказ ниже доказывал бы лишь то, что отбор не берёт
			// ничего никогда: слепое семейство прошло бы эту пробу насквозь.
			corpus, err := f.Build(synthTree(t, f.Present))
			if err != nil {
				t.Fatalf("КОНТРОЛЬ: на дереве С предметом обход объявлен пустым: %v — "+
					"отбор семейства ослеп, и отказ ниже ничего не доказывает", err)
			}
			got := corpus.Rels()
			if len(got) != len(f.Want) {
				t.Fatalf("КОНТРОЛЬ: отобрано %v, ожидалось %v — отбор берёт не то, и «пусто» "+
					"ниже значило бы «отбор сломан», а не «предмета нет»", got, f.Want)
			}
			for i, want := range f.Want {
				if got[i] != want {
					t.Fatalf("КОНТРОЛЬ: отобрано %v, ожидалось %v", got, f.Want)
				}
			}

			// ── ИНЪЕКЦИЯ: дерево ТО ЖЕ, предмет убран — ОТКАЗ ────────────────
			//
			// Дерево остаётся НЕПУСТЫМ намеренно: пустое ловится и грубым
			// предикатом, а самый частый вид слепоты другой — предмет переехал
			// из-под отбора, а дерево на месте.
			if _, err := f.Build(synthTree(t, f.Absent)); !errors.Is(err, check.ErrEmptyTraversal) {
				t.Fatalf("предмет убран, а обход отказа НЕ ДАЛ (%v) — «находок ноль» стало бы "+
					"неотличимо от «прочитано ноль», и молчание гейта ничего бы не значило", err)
			}

			// ── ИНЪЕКЦИЯ: дерево ПУСТО — тот же отказ ────────────────────────
			if _, err := f.Build(synthTree(t, nil)); !errors.Is(err, check.ErrEmptyTraversal) {
				t.Fatalf("пустое дерево обход прошёл без отказа: %v", err)
			}
			proven++
		})
	}

	t.Logf("ОБЪЁМ ОСМОТРЕННОГО: сборщиков корпуса в перечне %d · доказано исполнением %d · "+
		"осей на каждом 3 (контроль · предмет убран · дерево пусто)", len(families), proven)
}
