// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// scope_depth_agreement_injection_test.go — доказательство в ОБЕ стороны
// (порт одноимённой пробы репозитория платформы, снят там вынесением службы
// доступа — `kacho#2597`).
//
// (а) верни дефект — сверка краснеет и НАЗЫВАЕТ ОБЕ координаты;
// (б) поставь рядом ЗАКОННУЮ конструкцию той же формы — сверка молчит.
//
// # Почему сверка вызывается напрямую, а не через настоящее дерево
//
// Уронить настоящее дерево нарочно нельзя, а гейт, который нельзя уронить, не
// отличается от гейта, который не может упасть. Поэтому суждение отделено от
// добычи (adjudicateScopeDepth) и здесь получает величины на вход.
package check_test

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

func TestScopeDepthAgreement_ProvenByInjection(t *testing.T) {
	t.Parallel()
	root, prefix := platformtree.RequireCorpus(t)

	// ── КОНТРОЛЬ. Без него краснота ниже неотличима от красноты дерева ──────
	planDepth, planFound := findScopeDepthPlan(t, root, prefix)
	if !planFound {
		t.Fatal("предел компилятора модели в дереве НЕ НАЙДЕН — доказывать нечего.\n" +
			"    Либо величину сняли (тогда снимите и эту пробу вместе с предметом), " +
			"либо обход снова смотрит не туда.")
	}
	t.Logf("контроль: предел компилятора модели найден, значение %d", planDepth)

	constPath := platformtree.Under(prefix, scopeDepthConstRel)
	migrationPath := platformtree.Under(prefix, scopeDepthMigrationRel)
	planPath := platformtree.Under(prefix, scopeDepthPlanFileRel)

	t.Run("расхождение третьей величины краснеет и называет ОБЕ координаты", func(t *testing.T) {
		found := adjudicateScopeDepth(scopeDepthTriple{
			goDepth: 4, sqlDepth: 4, planDepth: 3, planFound: true,
			constPath: constPath, migrationPath: migrationPath, planPath: planPath,
		})
		if len(found) != 1 {
			t.Fatalf("ожидалась 1 находка, получено %d: %v", len(found), found)
		}
		for _, want := range []string{planPath, constPath, "3", "4"} {
			if !strings.Contains(found[0], want) {
				t.Fatalf("находка не называет %q — по ней не видно, что чинить:\n%s", want, found[0])
			}
		}
	})

	t.Run("расхождение первых двух краснеет и называет ОБЕ координаты", func(t *testing.T) {
		found := adjudicateScopeDepth(scopeDepthTriple{
			goDepth: 4, sqlDepth: 2, planDepth: 4, planFound: true,
			constPath: constPath, migrationPath: migrationPath, planPath: planPath,
		})
		if len(found) != 1 {
			t.Fatalf("ожидалась 1 находка, получено %d: %v", len(found), found)
		}
		for _, want := range []string{constPath, migrationPath} {
			if !strings.Contains(found[0], want) {
				t.Fatalf("находка не называет %q:\n%s", want, found[0])
			}
		}
	})

	t.Run("расходятся все три — названы обе пары, а не первая попавшаяся", func(t *testing.T) {
		found := adjudicateScopeDepth(scopeDepthTriple{
			goDepth: 4, sqlDepth: 2, planDepth: 3, planFound: true,
			constPath: constPath, migrationPath: migrationPath, planPath: planPath,
		})
		if len(found) != 2 {
			t.Fatalf("ожидались 2 находки, получено %d: %v", len(found), found)
		}
	})

	// ── ЗАКОННЫЕ БЛИЗНЕЦЫ. Без них отрицание зеленело бы на всём сломанном ──
	t.Run("согласие трёх величин — сверка молчит", func(t *testing.T) {
		if found := adjudicateScopeDepth(scopeDepthTriple{
			goDepth: 4, sqlDepth: 4, planDepth: 4, planFound: true,
			constPath: constPath, migrationPath: migrationPath, planPath: planPath,
		}); len(found) != 0 {
			t.Fatalf("ложное срабатывание на согласии: %v", found)
		}
	})

	t.Run("ненайденная третья величина НЕ выдумывает расхождения", func(t *testing.T) {
		if found := adjudicateScopeDepth(scopeDepthTriple{
			goDepth: 4, sqlDepth: 4, planFound: false,
			constPath: constPath, migrationPath: migrationPath, planPath: planPath,
		}); len(found) != 0 {
			t.Fatalf("ненайденная величина принята за расхождение: %v", found)
		}
	})

	t.Run("согласие на ДРУГОМ числе — сверка по равенству, а не по литералу 4", func(t *testing.T) {
		if found := adjudicateScopeDepth(scopeDepthTriple{
			goDepth: 7, sqlDepth: 7, planDepth: 7, planFound: true,
			constPath: constPath, migrationPath: migrationPath, planPath: planPath,
		}); len(found) != 0 {
			t.Fatalf("сверка привязана к литералу, а не к равенству: %v", found)
		}
	})
}

// TestScopeDepthPlanFileCoordinateIsAlive — координата в тексте находки
// обязана существовать.
//
// Она не участвует в обходе (тот ищет по всему дереву модуля), поэтому её
// устаревание ничего не роняет само по себе: находка просто начнёт посылать
// читателя в несуществующий файл.
func TestScopeDepthPlanFileCoordinateIsAlive(t *testing.T) {
	t.Parallel()
	root, prefix := platformtree.RequireCorpus(t)
	dir := root
	if prefix != "" {
		dir = filepath.Join(root, filepath.FromSlash(prefix))
	}
	tree, err := treecorpus.NewTree(dir)
	if err != nil {
		t.Fatalf("состав дерева взять неоткуда: %v", err)
	}
	if !tree.HasFile(scopeDepthPlanFileRel) {
		t.Fatalf("координата третьей величины %q в составе дерева отсутствует: находка "+
			"послала бы читателя в файл, которого нет. Осмотрено файлов: %d",
			scopeDepthPlanFileRel, tree.Count())
	}
	t.Logf("ОБЪЁМ ОСМОТРЕННОГО: состав дерева %d файлов, координата %s жива",
		tree.Count(), scopeDepthPlanFileRel)
}

// TestScopeDepthRecogniserKnowsBothLegalFormsOfTheBound — распознаватель
// обязан знать КАЖДУЮ законную форму записи своего предмета.
//
// # Почему форм две и обе законны
//
// Границу пишет человек в миграции — `depth BETWEEN 1 AND 4`. Сведённую схему
// печатает `pg_dump`, а он печатает разложенную форму:
// `((depth >= 1) AND (depth <= 4))`. Это одно и то же ограничение, записанное
// двумя способами; выбирает способ не автор, а инструмент.
func TestScopeDepthRecogniserKnowsBothLegalFormsOfTheBound(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		what string
		body string
		want string
	}{
		{"форма миграции (пишет человек)", "    CHECK (depth BETWEEN 1 AND 4),", "4"},
		{"форма свода (печатает pg_dump)", "CONSTRAINT rpe_depth_bounded CHECK (((depth >= 1) AND (depth <= 4))),", "4"},
		{"форма свода с квалификатором", "((pe.depth >= 1) AND (pe.depth <= 7))", "7"},
	} {
		ms := reDepthCheck.FindAllStringSubmatch(c.body, -1)
		if len(ms) != 1 {
			t.Errorf("%s: совпадений %d, ожидалось 1 — форма распознавателю неизвестна, "+
				"и записанное в ней прошло бы ВНЕ наблюдения", c.what, len(ms))
			continue
		}
		got := ""
		for _, g := range ms[0][1:] {
			if g != "" {
				got = g
				break
			}
		}
		if got != c.want {
			t.Errorf("%s: извлечено %q, ожидалось %q", c.what, got, c.want)
		}
	}

	for _, c := range []struct {
		what string
		body string
	}{
		{"чужое поле с тем же хвостом имени", "CHECK ((max_depth <= 9))"},
		{"нижняя граница отдельно — не предмет", "CHECK ((depth >= 1))"},
		{"проза о границе, а не сама граница", "-- глубина ограничена значением 4"},
	} {
		if ms := reDepthCheck.FindAllStringSubmatch(c.body, -1); len(ms) != 0 {
			t.Errorf("%s: распознан как объявление границы (%d совпадений) — расширение "+
				"формы куплено ложным срабатыванием, а гейт с ложными находками снимают первым",
				c.what, len(ms))
		}
	}

	root, prefix := platformtree.RequireCorpus(t)
	migrationPath := platformtree.Under(prefix, scopeDepthMigrationRel)
	body := readFileForDepth(t, filepath.Join(root, filepath.FromSlash(migrationPath)))
	ms := reDepthCheck.FindAllStringSubmatch(body, -1)
	t.Logf("ОБЪЁМ ОСМОТРЕННОГО: %s, совпадений границы глубины %d", migrationPath, len(ms))
	if len(ms) != 1 {
		t.Fatalf("в %s совпадений %d, ожидалось ровно 1", migrationPath, len(ms))
	}
}
