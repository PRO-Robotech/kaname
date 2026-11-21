// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
	base := scopeDepthTriple{
		goDepth: 5, sqlDepth: 4, planDepth: 5, pointerDepth: 5, storedDepth: 4, fanout: 4,
		constPath: scopeDepthConstRel, migrationPath: scopeDepthMigrationRel,
		planPath: scopeDepthPlanFileRel, sharedPath: scopeDepthSharedRel,
	}
	for _, tc := range []struct {
		name        string
		change      func(*scopeDepthTriple)
		want        int
		coordinates []string
	}{
		{"independent_axes", func(_ *scopeDepthTriple) {}, 0, nil},
		{"model_mismatch", func(v *scopeDepthTriple) { v.planDepth = 3 }, 1, []string{scopeDepthPlanFileRel, scopeDepthSharedRel, "3", "5"}},
		{"traversal_mismatch", func(v *scopeDepthTriple) { v.goDepth = 4 }, 1, []string{scopeDepthConstRel, scopeDepthSharedRel}},
		{"schema_mismatch", func(v *scopeDepthTriple) { v.sqlDepth = 2 }, 1, []string{scopeDepthMigrationRel, scopeDepthSharedRel}},
		{"all_mismatches", func(v *scopeDepthTriple) { v.goDepth = 3; v.planDepth = 2; v.sqlDepth = 1 }, 3, nil},
		{"both_consumers_drift", func(v *scopeDepthTriple) { v.goDepth = 4; v.planDepth = 4 }, 2, nil},
		{"other_consistent_values", func(v *scopeDepthTriple) {
			v.goDepth = 7
			v.planDepth = 7
			v.pointerDepth = 7
			v.storedDepth = 6
			v.sqlDepth = 6
			v.fanout = 2
		}, 0, nil},
		{"zero_hops", func(v *scopeDepthTriple) { v.goDepth = 0; v.planDepth = 0; v.pointerDepth = 0 }, 1, nil},
		{"zero_fanout", func(v *scopeDepthTriple) { v.fanout = 0 }, 1, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value := base
			tc.change(&value)
			found := adjudicateScopeDepth(value)
			if len(found) != tc.want {
				t.Fatalf("находок %d, нужно %d: %v", len(found), tc.want, found)
			}
			for _, coordinate := range tc.coordinates {
				if !strings.Contains(strings.Join(found, "\n"), coordinate) {
					t.Errorf("находка не называет %s: %v", coordinate, found)
				}
			}
		})
	}
}

// Настоящий extractor проверяется отдельно от суждения: отсутствие, подмена
// import, комментарий и дубли не становятся ложным согласием чисел.
func TestScopeDepthAliasesAndMalformedDeclarations(t *testing.T) {
	t.Parallel()
	shared := "package hierarchy\nconst MaxPointerHops = 5\n"
	alias := "package p\nimport h \"" + scopeDepthSharedImport + "\"\nconst MaxAncestorDepth = h.MaxPointerHops\n"
	for _, tc := range []struct {
		name, body, source string
		want               int
		fail               bool
	}{
		{"literal", "package p\nconst MaxAncestorDepth = 5", shared, 5, false},
		{"alias", alias, shared, 5, false},
		{"default_import", strings.ReplaceAll(strings.Replace(alias, "import h ", "import ", 1), "h.MaxPointerHops", "hierarchy.MaxPointerHops"), shared, 5, false},
		{"different_literal_is_extracted", "package p\nconst MaxAncestorDepth = 3", shared, 3, false},
		{"missing", "package p", shared, 0, true},
		{"comment_only", "package p\n// const MaxAncestorDepth = 5", shared, 0, true},
		{"duplicate", "package p\nconst MaxAncestorDepth = 5\nconst MaxAncestorDepth = 5", shared, 0, true},
		{"var_not_const", "package p\nvar MaxAncestorDepth = 5", shared, 0, true},
		{"foreign_import", strings.Replace(alias, scopeDepthSharedImport, "example.org/hierarchy", 1), shared, 0, true},
		{"wrong_axis", strings.Replace(alias, "h.MaxPointerHops", "h.MaxStoredParentLinks", 1), shared, 0, true},
		{"missing_import", "package p\nconst MaxAncestorDepth = h.MaxPointerHops", shared, 0, true},
		{"missing_shared", alias, "package hierarchy", 0, true},
		{"duplicate_shared", alias, shared + "const MaxPointerHops = 5\n", 0, true},
		{"expression_not_understood", "package p\nconst MaxAncestorDepth = 4 + 1", shared, 0, true},
		{"implicit_value", "package p\nconst (x = 5; MaxAncestorDepth)", shared, 0, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveScopeDepth(tc.body, "MaxAncestorDepth", tc.source, "MaxPointerHops")
			if (err != nil) != tc.fail || !tc.fail && got != tc.want {
				t.Fatalf("получено %d / %v, нужно %d / error=%v", got, err, tc.want, tc.fail)
			}
		})
	}
}

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

// Вторая координата принципиальна: single-file extractor не видит такой drift.
func TestScopeDepthGlobalCensusSecondFileInjections(t *testing.T) {
	t.Parallel()
	const second = "tools/probe/limits.go"
	const samePackage = "internal/authzplan/other.go"
	shared := "package hierarchy\nconst MaxPointerHops = 5\n"
	canonical := "package authzplan\nimport h \"" + scopeDepthSharedImport + "\"\nconst MaxPointerDepth = h.MaxPointerHops\n"
	alias := "package probe\nimport p \"github.com/PRO-Robotech/kaname/internal/authzplan\"\nconst MaxPointerDepth = p.MaxPointerDepth\n"
	for _, tc := range []struct {
		name, path, body string
		fail             bool
		count            int
	}{
		{"actual_tools_alias", second, alias, false, 2},
		{"equal_independent_literal", second, "package probe; const MaxPointerDepth = 5", false, 2},
		{"equal_shared_alias", second, strings.Replace(canonical, "package authzplan", "package probe", 1), false, 2},
		{"comment_is_not_declaration", second, "package probe\n// const MaxPointerDepth = 3", false, 1},
		{"conflicting_second_file", second, "package probe; const MaxPointerDepth = 3", true, 0},
		{"same_package_duplicate_equal", samePackage, "package authzplan; const MaxPointerDepth = 5", true, 0},
		{"same_package_duplicate_conflicting", samePackage, "package authzplan; const MaxPointerDepth = 3", true, 0},
		{"second_file_unknown_expression", second, "package probe; const MaxPointerDepth = unknown()", true, 0},
		{"second_file_foreign_alias", second, strings.Replace(alias, "github.com/PRO-Robotech/kaname/internal/authzplan", "example.org/authzplan", 1), true, 0},
		{"second_file_parse_failure", second, "package probe; func broken(", true, 0},
		{"second_file_var", second, "package probe; var MaxPointerDepth = 5", true, 0},
		{"second_file_local_shadow", second, "package probe; func f() { const MaxPointerDepth = 3 }", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			corpus := map[string]string{scopeDepthPlanFileRel: canonical, tc.path: tc.body}
			n, count, err := scopeDepthPlanCensus(corpus, shared)
			if (err != nil) != tc.fail || !tc.fail && (n != 5 || count != tc.count) {
				t.Fatalf("получено n=%d count=%d error=%v, нужно fail=%v count=%d", n, count, err, tc.fail, tc.count)
			}
			if tc.fail && !strings.Contains(err.Error(), tc.path) {
				t.Fatalf("отказ не называет второй файл %s: %v", tc.path, err)
			}
		})
	}
	t.Run("missing_canonical", func(t *testing.T) {
		if _, _, err := scopeDepthPlanCensus(map[string]string{second: alias}, shared); err == nil {
			t.Fatal("отсутствие canonical compiler молча принято")
		}
	})
}
