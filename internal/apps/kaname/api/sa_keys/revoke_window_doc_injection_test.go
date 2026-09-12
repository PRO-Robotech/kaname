// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package sa_keys

// revoke_window_doc_injection_test.go — опыт: способен ли гейт разбора скорости
// отзыва упасть и способен ли он смолчать.
//
// Инъекция идёт по КАЖДОЙ оси отдельно. Одна общая проба «сломай что-нибудь»
// зеленела бы на гейте, у которого работает лишь одна ось: находка есть, а какая
// именно — не сказано.
//
// Вход берётся ИЗ ДЕРЕВА и портится по одной величине за раз. Полностью
// синтетический вход доказывал бы лишь то, что предикат различает две строки.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/stretchr/testify/require"
)

// revokeFactsFromTree — вход предиката, собранный из настоящего дерева.
func revokeFactsFromTree(t *testing.T) (revokeWindowFacts, *treecorpus.Tree) {
	t.Helper()
	tree, err := treecorpus.NewTree(treeRootFromSAKeys)
	require.NoError(t, err, "состав дерева службы не собран — инъекция беспредметна")

	comments := revokeFileComments(t, filepath.Join(tree.Root(), filepath.FromSlash(revokeDocFile)))
	surfaces, _, _ := revocationReadSites(t, tree, true)
	inSchema, _ := cutoffTriggerDeclared(t, tree)
	inRule, _ := cutoffClaimInRule(t, tree)
	return revokeWindowFacts{
		Comments: comments, CutoffSurfaces: surfaces,
		TriggerNamed: strings.Contains(comments, cutoffTrigger), TriggerInSchema: inSchema,
		ClaimNamed: strings.Contains(comments, saCutoffClaim), ClaimInRule: inRule,
		DocPaths: revokeDocPathsIn(comments, tree),
	}, tree
}

// TestRevokeWindowDocGate_SilentOnTheTree — положительный контроль.
func TestRevokeWindowDocGate_SilentOnTheTree(t *testing.T) {
	facts, _ := revokeFactsFromTree(t)
	require.Empty(t, auditRevokeWindowDoc(facts),
		"гейт находит нарушение на исправной прозе — он ловит форму, а не существо")
}

// TestRevokeWindowDocGate_FallsOnTheSurfaceCount — ось числа поверхностей.
func TestRevokeWindowDocGate_FallsOnTheSurfaceCount(t *testing.T) {
	base, _ := revokeFactsFromTree(t)
	require.Empty(t, auditRevokeWindowDoc(base), "ПРЕДПОСЫЛКА ОПЫТА: проза обязана быть исправной")
	require.NotEmpty(t, base.CutoffSurfaces, "ПРЕДПОСЫЛКА: портить нечего")

	t.Run("поверхность появилась, проза молчит", func(t *testing.T) {
		f := base
		f.CutoffSurfaces = append(append([]string(nil), base.CutoffSurfaces...), "internal/synthetic/surface.go")
		requireRevokeFinding(t, auditRevokeWindowDoc(f), "разбор дерева нашёл")
	})

	t.Run("поверхность исчезла, проза держит прежнее число", func(t *testing.T) {
		f := base
		f.CutoffSurfaces = base.CutoffSurfaces[:len(base.CutoffSurfaces)-1]
		requireRevokeFinding(t, auditRevokeWindowDoc(f), "разбор дерева нашёл")
	})

	t.Run("маркер исчез", func(t *testing.T) {
		hit := cutoffSurfaceMarker.FindString(base.Comments)
		require.NotEmpty(t, hit, "ПРЕДПОСЫЛКА: маркера в прозе нет — портить нечего")
		f := base
		f.Comments = strings.Replace(base.Comments, hit, "поверхностей примерно столько", 1)
		requireRevokeFinding(t, auditRevokeWindowDoc(f), "встречается 0 раз(а)")
	})

	t.Run("маркер удвоился", func(t *testing.T) {
		hit := cutoffSurfaceMarker.FindString(base.Comments)
		require.NotEmpty(t, hit)
		f := base
		f.Comments = base.Comments + "\n" + hit + "\n"
		requireRevokeFinding(t, auditRevokeWindowDoc(f), "встречается 2 раз(а)")
	})
}

// TestRevokeWindowDocGate_FallsOnBothTriggerDirections — ось отсечки, ОБЕ стороны.
//
// Односторонняя ось оставила бы ровно исходный дефект: «названный и снятый» ловит
// ложь о настоящем, «живой и неназванный» — тот же вопрос без ответа.
func TestRevokeWindowDocGate_FallsOnBothTriggerDirections(t *testing.T) {
	base, _ := revokeFactsFromTree(t)
	require.True(t, base.TriggerNamed, "ПРЕДПОСЫЛКА ОПЫТА: проза обязана называть триггер")
	require.True(t, base.TriggerInSchema, "ПРЕДПОСЫЛКА ОПЫТА: схема обязана его объявлять")

	t.Run("схема триггер сняла, проза держит прежнее", func(t *testing.T) {
		f := base
		f.TriggerInSchema = false
		requireRevokeFinding(t, auditRevokeWindowDoc(f), "которого схема больше не объявляет")
	})

	t.Run("проза перестала называть триггер при живой схеме", func(t *testing.T) {
		f := base
		f.TriggerNamed = false
		requireRevokeFinding(t, auditRevokeWindowDoc(f), "а проза его не называет")
	})
}

// TestRevokeWindowDocGate_FallsOnBothClaimDirections — ось ключа отсечки, ОБЕ стороны.
func TestRevokeWindowDocGate_FallsOnBothClaimDirections(t *testing.T) {
	base, _ := revokeFactsFromTree(t)
	require.True(t, base.ClaimNamed, "ПРЕДПОСЫЛКА ОПЫТА: проза обязана называть ключ отсечки")
	require.True(t, base.ClaimInRule, "ПРЕДПОСЫЛКА ОПЫТА: перечень правила обязан его содержать")

	t.Run("ключ выпал из перечня правила", func(t *testing.T) {
		f := base
		f.ClaimInRule = false
		requireRevokeFinding(t, auditRevokeWindowDoc(f), "не содержит")
	})

	t.Run("проза перестала называть ключ при живом перечне", func(t *testing.T) {
		f := base
		f.ClaimNamed = false
		requireRevokeFinding(t, auditRevokeWindowDoc(f), "а проза его не называет")
	})
}

// TestRevokeWindowDocGate_TriggerExistenceIsJudgedByTheStatement — почему
// существование триггера судится НАЧАЛОМ ОПЕРАТОРА, а не упоминанием имени.
//
// Имя триггера стоит в схеме трижды, и только одно вхождение его объявляет.
// Предикат по подстроке зеленел бы на схеме, где триггер снят, а комментарий о
// нём остался, — то есть ровно на том исходе, ради которого ось заведена.
func TestRevokeWindowDocGate_TriggerExistenceIsJudgedByTheStatement(t *testing.T) {
	_, tree := revokeFactsFromTree(t)

	// Положительный близнец: настоящий оператор из дерева распознаётся.
	declared, files := cutoffTriggerDeclared(t, tree)
	require.True(t, declared, "оператор объявления триггера в дереве не распознан")
	require.Positive(t, files, "файлов схемы не прочитано ни одного")

	// Инъекция отличается от близнеца РОВНО ОДНИМ фактом: оператора нет, а
	// упоминания имени — есть, дословно как в выгрузке схемы.
	synthetic := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(synthetic, migrationsDir), 0o750))
	mentionsOnly := "-- Name: service_account_oauth_clients " + cutoffTrigger + "; Type: TRIGGER\n" +
		"COMMENT ON TRIGGER " + cutoffTrigger + " ON kaname.service_account_oauth_clients IS 'зеркало';\n"
	require.NoError(t, os.WriteFile(
		filepath.Join(synthetic, migrationsDir, "0001_initial.sql"), []byte(mentionsOnly), 0o600))

	tree2, err := treecorpus.SyntheticTree(synthetic)
	require.NoError(t, err, "состав синтетического корня не собран — инъекция беспредметна")
	declared2, files2 := cutoffTriggerDeclared(t, tree2)
	require.Positive(t, files2, "синтетический корень не дал ни одного файла схемы — портить было нечего")
	require.False(t, declared2,
		"упоминание имени в комментарии и в COMMENT ON TRIGGER зачтено за объявление — "+
			"предикат судит подстроку, и снятый триггер прошёл бы как живой")
	t.Logf("перепись: файлов схемы в дереве %d (объявлен: %t); в синтетическом корне %d (объявлен: %t)",
		files, declared, files2, declared2)
}

// TestRevokeWindowDocGate_FallsOnAnUnresolvableCoordinate — ось координаты, ОБЕ
// половины, и отдельно — граница между координатой и именем документа.
func TestRevokeWindowDocGate_FallsOnAnUnresolvableCoordinate(t *testing.T) {
	base, tree := revokeFactsFromTree(t)

	require.NotEmpty(t, base.DocPaths,
		"проза не называет НИ ОДНОЙ координаты документа — ось не проверяет ничего, и "+
			"«координат не названо» стало бы неотличимо от «названная на месте»")
	for p, ok := range base.DocPaths {
		require.Truef(t, ok, "ПРЕДПОСЫЛКА ОПЫТА: координата %s дерева не резолвится", p)
	}

	t.Run("координата не резолвится — находка", func(t *testing.T) {
		f := base
		f.Comments = base.Comments + "\nсм. docs/architecture/09-permission-catalog-source-of-truth.md\n"
		f.DocPaths = revokeDocPathsIn(f.Comments, tree)
		requireRevokeFinding(t, auditRevokeWindowDoc(f), "которого в составе дерева нет")
	})

	t.Run("голое имя документа координатой не является — молчание", func(t *testing.T) {
		// Регламент разработки в поставку продукта не входит, и имя без сегмента
		// каталога обещает не путь, а документ. Без этой половины ось краснела бы
		// на 214 вхождениях в 160 файлах — на классе с другим предметом.
		f := base
		f.Comments = base.Comments + "\nсокрытие существования — security.md §Hide-existence\n"
		f.DocPaths = revokeDocPathsIn(f.Comments, tree)
		require.Empty(t, auditRevokeWindowDoc(f),
			"голое имя документа объявлено нерезолвимой координатой — ось вышла за свой предмет")
	})
}

// TestRevokeWindowDocGate_ProdCensusIsNotVacuous — исключение проб и самого
// пакета правила обязано что-то ИСКЛЮЧАТЬ.
func TestRevokeWindowDocGate_ProdCensusIsNotVacuous(t *testing.T) {
	tree, err := treecorpus.NewTree(treeRootFromSAKeys)
	require.NoError(t, err)

	prod, prodScanned, _ := revocationReadSites(t, tree, true)
	all, allScanned, _ := revocationReadSites(t, tree, false)

	require.Greaterf(t, len(all), len(prod),
		"полный состав (%d) не шире прод-состава (%d) — исключение перестало исключать, "+
			"и перепись меряет не то", len(all), len(prod))
	require.Greater(t, allScanned, prodScanned,
		"файлов в полном обходе не больше, чем в прод-обходе — фильтр не работает вовсе")
	for _, p := range prod {
		require.NotContainsf(t, p, "_test.go", "проба %q зачтена за поверхность прод-кода", p)
	}
	t.Logf("перепись: читателей правила всего %d, из них прод-поверхностей %d; "+
		"файлов в обходе: полном %d, прод %d", len(all), len(prod), allScanned, prodScanned)
}

func requireRevokeFinding(t *testing.T, found []string, want string) {
	t.Helper()
	require.NotEmptyf(t, found, "порча не найдена: гейт молчит там, где обязан назвать координату (%s)", want)
	require.Truef(t, strings.Contains(strings.Join(found, "\n"), want),
		"находка есть, но не та: ждали %q, получили %v", want, found)
}
