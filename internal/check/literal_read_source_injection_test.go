// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// literal_read_source_injection_test.go — ДОКАЗАТЕЛЬСТВО того, что гейт
// `TestIAMCT2_LiteralIsNotAReadSource` способен упасть и способен смолчать
// (kacho#1816, сценарии IAM-CT-2-08 · -09 · -10).
//
// Инъекция подаётся СИНТЕТИЧЕСКИМ деревом, а не порчей живого: доказательство,
// требующее испортить дерево, в конвейере не исполняется никогда, а потому и не
// доказывает ничего.
//
// Инъекция роняет ТОЛЬКО проверяемое. Каждый случай отличается от контроля
// ОДНИМ обстоятельством — символом, который называет файл, — и никаким другим:
// пакет, импорт и форма файла одни и те же. Инъекция вида «завести ещё один
// элемент» доказательством не является, потому что новый элемент нарушает всё,
// что требуется от элементов вообще.

import (
	"os"
	"path/filepath"
	"testing"
)

// injectionTree — синтетический ОДИН прод-файл, импортирующий пакет-литерал под
// именем `alias`. Возвращает корень и ПЕРЕЧЕНЬ состава — тот самый параметр,
// которым разбор кормится и в живом дереве (там его даёт индекс git).
func injectionTree(t *testing.T, alias, body string) (root string, files []string) {
	t.Helper()
	root = t.TempDir()
	dir := filepath.Join(root, iamTreeRel, "internal", "probe")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("создать каталог: %v", err)
	}
	imp := "\t" + `"` + authzmapImportPath + `"`
	if alias != "" {
		imp = "\t" + alias + " " + `"` + authzmapImportPath + `"`
	}
	src := "package probe\n\nimport (\n" + imp + "\n)\n\n" + body
	path := filepath.Join(dir, "probe.go")
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatalf("записать пробу: %v", err)
	}
	return root, []string{path}
}

// TestIAMCT2_08_09_GateInjection — обе стороны на одном наборе случаев.
func TestIAMCT2_08_09_GateInjection(t *testing.T) {
	cases := []struct {
		name    string
		alias   string
		body    string
		wantHit bool
	}{
		{
			// `-09`: ЗАКОННЫЙ БЛИЗНЕЦ. Переходник имени типа остаётся на
			// литерале по решению §2.2 приёмки, и гейт обязан на нём молчать.
			name:    "контроль: переходник имени типа — молчание",
			body:    "var _ = authzmap.FGAObjectType\nvar _ = authzmap.CatalogTypeName\n",
			wantHit: false,
		},
		{
			// Гейт судит УЗЕЛ РАЗБОРА, а не слово: имя запрещённого символа в
			// комментарии — это объяснение запрета, а не его нарушение. Без
			// этого случая гейт краснел бы на собственной документации.
			name:    "контроль: запрещённый символ в КОММЕНТАРИИ — молчание",
			body:    "// Здесь нельзя звать authzmap.VerbsOfType — см. kacho#1816.\nvar _ = authzmap.FGAObjectType\n",
			wantHit: false,
		},
		{
			name:    "инъекция: набор глаголов спрашивается у литерала",
			body:    "var _ = authzmap.VerbsOfType\n",
			wantHit: true,
		},
		{
			name:    "инъекция: проекция роли считается по литералу",
			body:    "var _ = authzmap.RoleVerbsFromSelectors\n",
			wantHit: true,
		},
		{
			// Псевдоним импорта — форма столь же законная, и всё записанное в
			// ней оказалось бы ВНЕ наблюдения, знай гейт только написание
			// `authzmap.`.
			name:    "инъекция: тот же символ под ПСЕВДОНИМОМ импорта",
			alias:   "am",
			body:    "var _ = am.CommonVerbVocabulary\n",
			wantHit: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root, files := injectionTree(t, tc.alias, tc.body)
			uses, importers, err := authzmapUses(root, files, catalogFactSymbols)
			if err != nil {
				t.Fatalf("обход синтетического дерева: %v", err)
			}
			if importers != 1 {
				t.Fatalf("импортёров осмотрено %d, ожидался 1 — инъекция не прочитана, "+
					"и её исход ничего не доказывает", importers)
			}
			if got := len(uses) > 0; got != tc.wantHit {
				t.Fatalf("обращений %d (ожидалось hit=%v): %+v", len(uses), tc.wantHit, uses)
			}
			if tc.wantHit {
				// `-08`: находка называет ФАЙЛ и СИМВОЛ. Без этого гейт
				// краснеет, а искать причину читателю негде.
				u := uses[0]
				if u.File == "" || u.Symbol == "" || u.Line == 0 {
					t.Fatalf("находка не называет координату: %+v", u)
				}
			}
		})
	}
}

// TestIAMCT2_10_EmptyWalkIsAVerdictlessRun — `-10`: обход пуст ⇒ вердикт
// беспредметен.
//
// Проверяется на дереве, где импортёров НЕТ вовсе: гейт обязан отличать «ноль
// находок» от «ноль прочитанного», иначе снятие пакета из-под обхода читалось бы
// как достижение цели.
func TestIAMCT2_10_EmptyWalkIsAVerdictlessRun(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, iamTreeRel, "internal", "probe")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("создать каталог: %v", err)
	}
	path := filepath.Join(dir, "probe.go")
	if err := os.WriteFile(path, []byte("package probe\n\nvar _ = 1\n"), 0o644); err != nil {
		t.Fatalf("записать пробу: %v", err)
	}
	_, importers, err := authzmapUses(root, []string{path}, catalogFactSymbols)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if importers != 0 {
		t.Fatalf("импортёров %d на дереве без импортёров — распознаватель считает не то", importers)
	}
	// Сам вердикт «беспредметно» ставит гейт: здесь доказано, что величина, по
	// которой он это решает, на таком дереве действительно ноль.
}
