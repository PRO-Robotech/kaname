// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// development_corpus_coordinate_injection_test.go — доказательство того, что ось
// имени документа СПОСОБНА упасть, и того, что она молчит на законных близнецах.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОДИН ФАКТ ПРОТИВ БЛИЗНЕЦА
//
// Годное дерево собрано один раз; каждая проба меняет в нём РОВНО ОДИН факт —
// одну строку одного файла. Инъекция вида «добавить ещё один файл» здесь не
// годится: новый файл менял бы и перепись, и множество разрешимых имён разом.
// Контроль («всё резолвится — находок ноль») стоит первым.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕТЫРЕ ЗАКОННЫХ БЛИЗНЕЦА, И КАЖДЫЙ БЫЛ БЫ КРАСНЫМ У НАИВНОГО ПРЕДИКАТА
//
//  1. ИМЯ, КОТОРОЕ РЕЗОЛВИТСЯ. Комментарий вправе назвать соседний документ
//     дерева по имени — предмет оси не в этом.
//  2. БЕЗРАСШИРЕННЫЙ БЛИЗНЕЦ. Перечень оснований файла лицензии называет
//     `LICENSE.md` образцом входа; документ в дереве есть, только без
//     расширения. Ось, красневшая на нём, ловила бы форму записи.
//  3. КООРДИНАТА С КАТАЛОГОМ. У неё свой держатель, и две оси об одном предмете
//     разошлись бы молча.
//  4. ПРОБА. Полоса `*_test.go` этой осью не судится — это объявленная граница,
//     и она подаётся входом: объявление без пробы неотличимо от слепоты.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЛИТЕРАЛ СУДИТСЯ НАРАВНЕ С КОММЕНТАРИЕМ, И ЭТО ПРОВЕРЯЕТСЯ ОТДЕЛЬНО
//
// Имя документа в тексте отказа уезжает оператору. Ось, читающая только
// комментарии, молчала бы ровно на худшем вхождении класса.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/stretchr/testify/require"
)

// corpusGoodProd — прод-файл, называющий только разрешимые имена.
const corpusGoodProd = `package serve

// Отказ несёт фиксированный текст (§Hardening, п. 1).
// Форма имени миграции объявлена в docs/architecture/naming.md.
// Перечень оснований файла лицензии: ` + "`LICENSE`" + `, ` + "`LICENSE.md`" + `.
// Установка описана в INSTALL.md.
func Serve() string { return "ok" }
`

// corpusGoodTest — проба рядом: полоса, объявленная вне оси.
const corpusGoodTest = `package serve

// Разбор класса взят из security.md — проба осью не судится.
func TestServe(t interface{}) {}
`

// syntheticCorpusTree — дерево: прод-файл, проба и два документа, чьи имена
// названы. Всякая проба ниже строит СВОЁ и меняет ровно один факт.
func syntheticCorpusTree(t *testing.T, prod, probe string) *treecorpus.Tree {
	t.Helper()

	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "internal", "serve"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(root, "internal", "serve", "serve.go"), []byte(prod), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "internal", "serve", "serve_test.go"), []byte(probe), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "docs", "architecture"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(root, "docs", "architecture", "naming.md"), []byte("# naming\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "INSTALL.md"), []byte("# install\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "LICENSE"), []byte("AGPL\n"), 0o600))

	tree, err := treecorpus.SyntheticTree(root)
	require.NoError(t, err)
	return tree
}

// requireCorpusFinding — находка с названной подстрокой есть, и перепись непуста.
func requireCorpusFinding(t *testing.T, tree *treecorpus.Tree, want string) {
	t.Helper()
	census, findings, err := scanDevelopmentCorpusCoordinates(tree)
	require.NoError(t, err)
	require.NotZero(t, census.namesSeen, "инъекция беспредметна: имён документов не распознано")

	var rendered []string
	for _, f := range findings {
		rendered = append(rendered, f.file+":"+itoa(f.line)+" "+f.kind+" "+f.name)
	}
	joined := strings.Join(rendered, "\n")
	require.Containsf(t, joined, want,
		"ось НЕ упала на внесённом дефекте — она вакуумна.\nнаходки:\n%s", joined)
}

// TestCorpusCoordinateInjection_ControlIsSilent — КОНТРОЛЬ: все названные имена
// резолвятся, находок ноль.
func TestCorpusCoordinateInjection_ControlIsSilent(t *testing.T) {
	t.Parallel()
	tree := syntheticCorpusTree(t, corpusGoodProd, corpusGoodTest)

	census, findings, err := scanDevelopmentCorpusCoordinates(tree)
	require.NoError(t, err)
	require.Equal(t, 1, census.filesParsed, "разобран один прод-файл: проба вне полосы")
	require.Equal(t, 2, census.namesSeen,
		"голых имён два — `LICENSE.md` и `INSTALL.md`; координата с каталогом этой осью не судится")
	require.Equal(t, 2, census.namesResolved, "оба резолвятся")
	require.Empty(t, findings, "на верном входе находок быть не должно")
}

// TestCorpusCoordinateInjection_BareCorpusNameInComment — ДЕФЕКТ, ради которого
// ось заведена: комментарий прод-кода называет документ регламента.
func TestCorpusCoordinateInjection_BareCorpusNameInComment(t *testing.T) {
	t.Parallel()
	broken := strings.Replace(corpusGoodProd,
		"// Отказ несёт фиксированный текст (§Hardening, п. 1).",
		"// Отказ несёт фиксированный текст (`security.md` §Hardening, п. 1).", 1)
	require.NotEqual(t, corpusGoodProd, broken, "инъекция не внесена: вход не изменился")

	tree := syntheticCorpusTree(t, broken, corpusGoodTest)
	requireCorpusFinding(t, tree, "internal/serve/serve.go:3 комментарий security.md")
}

// TestCorpusCoordinateInjection_BareCorpusNameInLiteral — ХУДШЕЕ ВХОЖДЕНИЕ
// класса: имя уезжает оператору текстом отказа. Ось, читающая только
// комментарии, молчала бы именно здесь.
func TestCorpusCoordinateInjection_BareCorpusNameInLiteral(t *testing.T) {
	t.Parallel()
	broken := strings.Replace(corpusGoodProd,
		`func Serve() string { return "ok" }`,
		`func Serve() string { return "refused (security.md §AuthN)" }`, 1)
	require.NotEqual(t, corpusGoodProd, broken, "инъекция не внесена: вход не изменился")

	tree := syntheticCorpusTree(t, broken, corpusGoodTest)
	requireCorpusFinding(t, tree, "строковый литерал security.md")
}

// TestCorpusCoordinateInjection_ExtensionlessTwinIsSilent — ЗАКОННЫЙ БЛИЗНЕЦ:
// `LICENSE.md` назван образцом входа, а документ в дереве есть без расширения.
// Проверяется СНЯТИЕМ близнеца: без файла `LICENSE` то же имя обязано краснеть.
func TestCorpusCoordinateInjection_ExtensionlessTwinIsSilent(t *testing.T) {
	t.Parallel()
	tree := syntheticCorpusTree(t, corpusGoodProd, corpusGoodTest)

	_, findings, err := scanDevelopmentCorpusCoordinates(tree)
	require.NoError(t, err)
	require.Empty(t, findings, "имя с безрасширенным близнецом в дереве разрешимо")

	require.NoError(t, os.Remove(filepath.Join(tree.Root(), "LICENSE")))
	narrowed, err := treecorpus.SyntheticTree(tree.Root())
	require.NoError(t, err)
	requireCorpusFinding(t, narrowed, "LICENSE.md")
}

// TestCorpusCoordinateInjection_CoordinateWithADirectoryIsNotJudged — ЗАКОННЫЙ
// БЛИЗНЕЦ: координата с сегментом каталога у оси не судится даже тогда, когда
// не резолвится. У неё свой держатель; две оси об одном предмете разошлись бы.
func TestCorpusCoordinateInjection_CoordinateWithADirectoryIsNotJudged(t *testing.T) {
	t.Parallel()
	broken := strings.Replace(corpusGoodProd,
		"docs/architecture/naming.md", "docs/architecture/no-such-page.md", 1)
	require.NotEqual(t, corpusGoodProd, broken, "близнец не подан: вход не изменился")

	tree := syntheticCorpusTree(t, broken, corpusGoodTest)
	_, findings, err := scanDevelopmentCorpusCoordinates(tree)
	require.NoError(t, err)
	require.Empty(t, findings, "координата с каталогом — предмет другой оси")
}

// TestCorpusCoordinateInjection_ProbeLaneIsOutsideTheAxis — ОБЪЯВЛЕННАЯ ГРАНИЦА,
// поданная входом: то же имя в пробе находкой не является. Объявление без пробы
// неотличимо от слепоты.
func TestCorpusCoordinateInjection_ProbeLaneIsOutsideTheAxis(t *testing.T) {
	t.Parallel()
	tree := syntheticCorpusTree(t, corpusGoodProd, corpusGoodTest)

	census, findings, err := scanDevelopmentCorpusCoordinates(tree)
	require.NoError(t, err)
	require.Empty(t, findings, "проба называет security.md и осью не судится")
	require.Equal(t, 1, census.filesParsed, "в перепись прод-файлов проба не попала")
}

// TestCorpusCoordinateInjection_GeneratedStubsAreExcludedAndCounted — ИСКЛЮЧЕНИЕ
// САМОИСТЕКАЕТ: полоса сгенерированных стабов не судится, но её вхождения
// СЧИТАЮТСЯ. Ноль в этой величине означает, что исключать больше нечего.
func TestCorpusCoordinateInjection_GeneratedStubsAreExcludedAndCounted(t *testing.T) {
	t.Parallel()
	tree := syntheticCorpusTree(t, corpusGoodProd, corpusGoodTest)

	stub := filepath.Join(tree.Root(), generatedStubsPrefix, "iam", "v1")
	require.NoError(t, os.MkdirAll(stub, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(stub, "svc.pb.go"),
		[]byte("package v1\n\n// authN on both listeners (security.md).\nvar X = 1\n"), 0o600))

	widened, err := treecorpus.SyntheticTree(tree.Root())
	require.NoError(t, err)

	census, findings, err := scanDevelopmentCorpusCoordinates(widened)
	require.NoError(t, err)
	require.Empty(t, findings, "стаб осью не судится: его комментарий производит контракт")
	require.Equal(t, 1, census.excludedHits,
		"вхождение в исключённой полосе обязано быть СОСЧИТАНО — иначе исключение не истечёт")
}

// TestCorpusCoordinateInjection_TreeWithoutNamesIsVoidNotGreen — ПУСТОЙ ОБХОД:
// имён документов в прод-коде нет вовсе. Главный тест на такой переписи падает
// своим стражем, а не зеленеет.
func TestCorpusCoordinateInjection_TreeWithoutNamesIsVoidNotGreen(t *testing.T) {
	t.Parallel()
	tree := syntheticCorpusTree(t, "package serve\n\n// Ничего не названо.\nfunc Serve() {}\n", corpusGoodTest)

	census, findings, err := scanDevelopmentCorpusCoordinates(tree)
	require.NoError(t, err)
	require.Empty(t, findings)
	require.Zero(t, census.namesSeen,
		"имён нет — на этой переписи главный тест обязан падать стражем, а не зеленеть")
}

// syntheticExemptedTree — дерево, где прощённый поимённо файл существует.
// Отдельный конструктор, чтобы проба меняла один факт — СОДЕРЖИМОЕ этого файла.
func syntheticExemptedTree(t *testing.T, exempted string) *treecorpus.Tree {
	t.Helper()

	tree := syntheticCorpusTree(t, corpusGoodProd, corpusGoodTest)
	path := filepath.Join(tree.Root(), filepath.FromSlash(fingerprintedLiteralFile))
	require.NoError(t, os.MkdirAll(filepath.Dir(path), 0o750))
	require.NoError(t, os.WriteFile(path, []byte(exempted), 0o600))

	widened, err := treecorpus.SyntheticTree(tree.Root())
	require.NoError(t, err)
	return widened
}

// TestCorpusCoordinateInjection_NamedExemptionHasItsSubjectCounted — ПРОЩЕНИЕ
// РАБОТАЕТ И СЧИТАЕТСЯ: вхождение в прощённом файле находкой не становится, но
// попадает в свою величину переписи.
func TestCorpusCoordinateInjection_NamedExemptionHasItsSubjectCounted(t *testing.T) {
	t.Parallel()
	tree := syntheticExemptedTree(t, "package relverdict\n\n"+
		"const q = `-- достижимы верхние уровни security.md §«Три уровня»`\n")

	census, findings, err := scanDevelopmentCorpusCoordinates(tree)
	require.NoError(t, err)
	require.Empty(t, findings, "прощённый поимённо файл находкой не становится")
	require.Equal(t, 1, census.exemptedHits, "вхождение обязано быть СОСЧИТАНО, иначе прощение не истечёт")
}

// TestCorpusCoordinateInjection_NamedExemptionWithoutASubjectIsAFinding —
// ПРОЩЕНИЕ САМОИСТЕКАЕТ: предмета больше нет, величина ноль, и главный тест на
// такой переписи падает своим стражем. Без этой половины запись пережила бы свой
// предмет и унаследовала бы следующую слепую зону.
func TestCorpusCoordinateInjection_NamedExemptionWithoutASubjectIsAFinding(t *testing.T) {
	t.Parallel()
	tree := syntheticExemptedTree(t, "package relverdict\n\nconst q = `-- верхние уровни супер-доступа`\n")

	census, findings, err := scanDevelopmentCorpusCoordinates(tree)
	require.NoError(t, err)
	require.Empty(t, findings)
	require.Zero(t, census.exemptedHits,
		"прощать стало нечего — на этой переписи главный тест обязан падать стражем")
}
