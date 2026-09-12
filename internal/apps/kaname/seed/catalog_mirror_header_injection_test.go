// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed_test

// catalog_mirror_header_injection_test.go — опыт: способен ли гейт шапки упасть и
// способен ли он смолчать.
//
// Инъекция идёт по КАЖДОЙ оси отдельно. Одна общая проба «сломай что-нибудь»
// зеленела бы на гейте, у которого работает лишь одна ось: находка есть, а какая
// именно — не сказано.
//
// Вход берётся ИЗ ДЕРЕВА и портится по одной величине за раз. Полностью
// синтетический вход доказывал бы лишь то, что предикат различает две строки.

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/stretchr/testify/require"
)

// mirrorFactsFromTree — вход предиката, собранный из настоящего дерева.
func mirrorFactsFromTree(t *testing.T) (catalogHeaderFacts, *treecorpus.Tree) {
	t.Helper()
	tree, err := treecorpus.NewTree(treeRootFromSeed)
	require.NoError(t, err, "состав дерева службы не собран — инъекция беспредметна")
	root := tree.Root()

	comments := fileComments(t, filepath.Join(root, filepath.FromSlash(mirrorHeaderFile)))
	prod, fixture, _, _ := registryReaders(t, tree, true)
	entries, noPerm, noRel := catalogComposition(t, filepath.Join(root, filepath.FromSlash(mirrorCatalogFile)))
	return catalogHeaderFacts{
		Comments: comments, ProdReaders: prod, FixtureReaders: fixture,
		Entries: entries, NoPermission: noPerm, NoRelation: noRel,
		DocPaths: docPathsIn(comments, tree),
		OwnRefs:  ownRefsIn(comments, packageDeclarations(t, tree, mirrorPackageDir)),
	}, tree
}

// TestCatalogMirrorHeaderGate_SilentOnTheTree — положительный контроль.
//
// Без него всякое отрицание ниже зеленело бы и на предикате, который находит
// нарушение всегда.
func TestCatalogMirrorHeaderGate_SilentOnTheTree(t *testing.T) {
	facts, _ := mirrorFactsFromTree(t)
	require.Empty(t, auditCatalogMirrorHeader(facts),
		"гейт находит нарушение на исправной шапке — он ловит форму, а не существо")
}

// TestCatalogMirrorHeaderGate_FallsOnEachMarker — по одной порче на маркер.
//
// Портится ЗАМЕР, а не проза: так опыт не зависит от того, какими словами
// написана шапка, и остаётся годным после её следующей правки.
func TestCatalogMirrorHeaderGate_FallsOnEachMarker(t *testing.T) {
	base, _ := mirrorFactsFromTree(t)
	require.Empty(t, auditCatalogMirrorHeader(base), "ПРЕДПОСЫЛКА ОПЫТА: шапка обязана быть исправной")

	t.Run("прод-читатель появился, шапка молчит", func(t *testing.T) {
		f := base
		f.ProdReaders = append(append([]string(nil), base.ProdReaders...), "internal/synthetic/reader.go")
		requireMirrorFinding(t, auditCatalogMirrorHeader(f), "читателей реестра в прод-коде")
	})

	t.Run("прод-читатель исчез, шапка держит прежнее число", func(t *testing.T) {
		require.NotEmpty(t, base.ProdReaders, "ПРЕДПОСЫЛКА: портить нечего")
		f := base
		f.ProdReaders = base.ProdReaders[:len(base.ProdReaders)-1]
		requireMirrorFinding(t, auditCatalogMirrorHeader(f), "читателей реестра в прод-коде")
	})

	t.Run("читатель оснастки исчез", func(t *testing.T) {
		require.NotEmpty(t, base.FixtureReaders, "ПРЕДПОСЫЛКА: портить нечего")
		f := base
		f.FixtureReaders = nil
		requireMirrorFinding(t, auditCatalogMirrorHeader(f), "читателей реестра в оснастке проб")
	})

	t.Run("записей в каталоге стало больше", func(t *testing.T) {
		f := base
		f.Entries = base.Entries + 1
		requireMirrorFinding(t, auditCatalogMirrorHeader(f), "записей каталога")
	})

	t.Run("запись без права появилась", func(t *testing.T) {
		f := base
		f.NoPermission = base.NoPermission + 1
		requireMirrorFinding(t, auditCatalogMirrorHeader(f), "записей без права")
	})

	t.Run("записей без отношения стало меньше", func(t *testing.T) {
		f := base
		f.NoRelation = base.NoRelation - 1
		requireMirrorFinding(t, auditCatalogMirrorHeader(f), "записей без требуемого отношения")
	})
}

// TestCatalogMirrorHeaderGate_FallsWhenMarkerDisappears — маркер, стёртый
// правкой прозы, есть находка, а не тишина.
//
// Это тот самый исход, ради которого маркер обязан встречаться ровно один раз:
// иначе «шапка сверена» стало бы неотличимо от «сверять было нечего».
func TestCatalogMirrorHeaderGate_FallsWhenMarkerDisappears(t *testing.T) {
	base, _ := mirrorFactsFromTree(t)
	for _, m := range mirrorMarkers {
		t.Run("маркер исчез: "+m.name, func(t *testing.T) {
			hit := m.re.FindString(base.Comments)
			require.NotEmptyf(t, hit, "ПРЕДПОСЫЛКА: маркера %q в шапке нет — портить нечего", m.name)
			f := base
			f.Comments = strings.Replace(base.Comments, hit, "величина примерно такая", 1)
			requireMirrorFinding(t, auditCatalogMirrorHeader(f), "встречается 0 раз(а)")
		})
		t.Run("маркер удвоился: "+m.name, func(t *testing.T) {
			hit := m.re.FindString(base.Comments)
			require.NotEmpty(t, hit)
			f := base
			f.Comments = base.Comments + "\n" + hit + "\n"
			requireMirrorFinding(t, auditCatalogMirrorHeader(f), "встречается 2 раз(а)")
		})
	}
}

// TestCatalogMirrorHeaderGate_FallsOnAnUnresolvableDocument — ось координаты, и
// у неё ОБЕ половины.
//
// Без положительной половины ось зеленела бы на предикате, объявляющем
// нерезолвимым всё: «документов не названо» стало бы неотличимо от «названный
// документ на месте».
func TestCatalogMirrorHeaderGate_FallsOnAnUnresolvableDocument(t *testing.T) {
	base, tree := mirrorFactsFromTree(t)

	resolvable := "docs/engineering/architecture/sa-key-issuance-leaves-the-provider.md"
	require.Truef(t, tree.HasFile(resolvable),
		"ПРЕДПОСЫЛКА ОПЫТА: %s обязан быть в составе дерева — иначе положительная "+
			"половина оси доказывала бы обратное тому, что называет", resolvable)

	t.Run("названный документ резолвится — молчание", func(t *testing.T) {
		f := base
		f.Comments = base.Comments + "\nсм. " + resolvable + "\n"
		f.DocPaths = docPathsIn(f.Comments, tree)
		require.Empty(t, auditCatalogMirrorHeader(f),
			"резолвимая координата объявлена находкой — ось отключила бы всякую ссылку в шапке")
	})

	t.Run("названный документ не резолвится — находка", func(t *testing.T) {
		f := base
		f.Comments = base.Comments + "\nсм. docs/architecture/09-permission-catalog-source-of-truth.md\n"
		f.DocPaths = docPathsIn(f.Comments, tree)
		requireMirrorFinding(t, auditCatalogMirrorHeader(f), "которого в дереве нет")
	})
}

// TestCatalogMirrorHeaderGate_ProdCensusIsNotVacuous — исключение проб обязано
// что-то ИСКЛЮЧАТЬ.
//
// Фильтр, который ничего не отсеивает, выглядит работающим и не работает: число в
// шапке совпало бы с полным составом, и первый же вызов из пробы читался бы как
// читатель на пути запроса.
func TestCatalogMirrorHeaderGate_ProdCensusIsNotVacuous(t *testing.T) {
	tree, err := treecorpus.NewTree(treeRootFromSeed)
	require.NoError(t, err)

	prod, fixture, prodScanned, _ := registryReaders(t, tree, true)
	all, allFixture, allScanned, _ := registryReaders(t, tree, false)

	require.Greaterf(t, len(all)+len(allFixture), len(prod)+len(fixture),
		"полный состав (%d) не шире прод-состава (%d) — исключение проб перестало исключать, "+
			"и перепись меряет не то", len(all)+len(allFixture), len(prod)+len(fixture))
	require.Greater(t, allScanned, prodScanned,
		"файлов в полном обходе не больше, чем в прод-обходе — фильтр не работает вовсе")

	for _, p := range append(append([]string(nil), prod...), fixture...) {
		require.NotContainsf(t, p, "_test.go", "проба %q зачтена за читателя прод-кода", p)
	}
	t.Logf("перепись: читателей всего %d, из них вне проб %d (прод %d · оснастка %d); "+
		"файлов в обходе: полном %d, прод %d",
		len(all)+len(allFixture), len(prod)+len(fixture), len(prod), len(fixture), allScanned, prodScanned)
}

func requireMirrorFinding(t *testing.T, found []string, want string) {
	t.Helper()
	require.NotEmptyf(t, found, "порча не найдена: гейт молчит там, где обязан назвать величину (%s)", want)
	require.Truef(t, strings.Contains(strings.Join(found, "\n"), want),
		"находка есть, но не та: ждали %q, получили %v", want, found)
}

// TestCatalogMirrorHeaderGate_FallsOnANameThePackageDoesNotDeclare — пятая ось, и
// у неё ОБЕ половины.
//
// Без положительной половины ось зеленела бы на предикате, объявляющем
// ненайденным всё: «имён не названо» стало бы неотличимо от «названное объявлено».
func TestCatalogMirrorHeaderGate_FallsOnANameThePackageDoesNotDeclare(t *testing.T) {
	base, tree := mirrorFactsFromTree(t)
	declared := packageDeclarations(t, tree, mirrorPackageDir)

	require.True(t, declared[registryLoader],
		"ПРЕДПОСЫЛКА ОПЫТА: загрузчик реестра обязан быть в перечне объявлений")

	t.Run("названное имя объявлено — молчание", func(t *testing.T) {
		f := base
		f.Comments = base.Comments + "\nвход — " + mirrorPackageQualifier + "." + registryLoader + "\n"
		f.OwnRefs = ownRefsIn(f.Comments, declared)
		require.Empty(t, auditCatalogMirrorHeader(f),
			"объявленное имя названо находкой — ось отключила бы всякую ссылку шапки на свой пакет")
	})

	t.Run("названного имени пакет не объявляет — находка", func(t *testing.T) {
		f := base
		f.Comments = base.Comments + "\nвход — " + mirrorPackageQualifier + ".RunTheWholeSeed()\n"
		f.OwnRefs = ownRefsIn(f.Comments, declared)
		requireMirrorFinding(t, auditCatalogMirrorHeader(f), "чего пакет не объявляет")
	})

	t.Run("чужой квалификатор с тем же хвостом — молчание", func(t *testing.T) {
		// `myseed.X` нашим пакетом не является: левая граница распознавателя
		// закрыта, и без этой пробы она бы молча разошлась с прозой.
		f := base
		f.Comments = base.Comments + "\nсосед зовёт my" + mirrorPackageQualifier + ".RunTheWholeSeed()\n"
		f.OwnRefs = ownRefsIn(f.Comments, declared)
		require.Empty(t, auditCatalogMirrorHeader(f),
			"чужой пакет с тем же хвостом имени зачтён за наш — распознаватель судит подстроку")
	})
}

// TestCatalogMirrorHeaderGate_MethodIsNotAddressableByPackageQualifier — почему
// перечень объявлений НЕ содержит методов.
//
// Это опыт над собственной ошибкой: первая редакция перечня методы считала, и
// находка про точку входа пропала молча — в пакете есть метод с тем же именем у
// совсем другого типа. Ссылкой `seed.X` метод адресовать нельзя, поэтому метод в
// перечне означал бы, что ось молчит ровно на том дефекте, ради которого заведена.
func TestCatalogMirrorHeaderGate_MethodIsNotAddressableByPackageQualifier(t *testing.T) {
	_, tree := mirrorFactsFromTree(t)
	declared := packageDeclarations(t, tree, mirrorPackageDir)

	const methodOnlyName = "Run"
	require.False(t, declared[methodOnlyName],
		"метод %q попал в перечень объявлений верхнего уровня — ссылка %s.%s «нашлась» бы, "+
			"хотя адресовать метод так нельзя",
		methodOnlyName, mirrorPackageQualifier, methodOnlyName)

	// Положительный контроль к тому же перечню: тип верхнего уровня в нём есть.
	require.True(t, declared["PermissionRegistry"],
		"тип верхнего уровня в перечне отсутствует — перечень собран не по тому каталогу, "+
			"и отрицание выше вакуумно")
	t.Logf("перепись: объявлений верхнего уровня в пакете %d; метод %q в перечне: %t",
		len(declared), methodOnlyName, declared[methodOnlyName])
}
