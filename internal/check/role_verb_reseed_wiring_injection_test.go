// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// role_verb_reseed_wiring_injection_test.go — инъекция гейта «досев
// дотягивается до писателя через порт» — В ОБЕ СТОРОНЫ.
//
// Порт с монорепо: доказательство инъекцией семейства
// `roleverbreseedwiring` (координата монорепо не пишется целиком —
// путь доказательства читался бы как обещание в ЭТОМ дереве),
// снят вынесением службы — `kacho#2597`). Дословно: все двенадцать прогонов
// (обе оси). Изменилось только: пакет (`repohygiene` → `check_test`,
// экспортированное имя `check.RoleVerbTable` осталось прежним по значению).
// Синтетические пути `services/iam/...` в фикстурах оставлены дословно — они
// не читаются с диска (только текстовые литералы, поданные напрямую разбору)
// и координате реального дерева kaname не обязаны соответствовать.
//
// Признак воспроизводится над СИНТЕТИЧЕСКИМ входом: правкой настоящего дерева
// инъекция не ставится — она рвала бы чужие прогоны в общей рабочей копии.
package check_test

import (
	"strings"
	"testing"
)

func writerPkgOf(t *testing.T, rel, src string) (string, bool) {
	t.Helper()
	pkg, isWriter, err := roleVerbWriterPackageOf(rel, src)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	return pkg, isWriter
}

const injWriterSrc = `package pg

func (w *roleWriter) ReplaceRoleVerbs(ctx context.Context) error {
	_, err := w.tx.Exec(ctx, ` + "`DELETE FROM kaname.role_verb WHERE role_id = $1`" + `)
	return err
}
`

const injReaderSrc = `package scalegrid

func count(ctx context.Context) error {
	return row(ctx, ` + "`SELECT count(*)::bigint FROM kaname.role_verb`" + `)
}
`

// TestReseedWiring_WriterPackageIsRecognisedAndReaderIsNot — ось «кто
// писатель» различает ЗАПИСЬ и ЧТЕНИЕ.
func TestReseedWiring_WriterPackageIsRecognisedAndReaderIsNot(t *testing.T) {
	t.Parallel()
	pkg, isWriter := writerPkgOf(t, "services/iam/internal/repo/kaname/pg/role_repo.go", injWriterSrc)
	if !isWriter {
		t.Fatal("признак МОЛЧИТ на файле, который пишет проекцию, — гейт не способен " +
			"найти предмет, и его зелёный на дереве ничего не значит")
	}
	if want := importOfTreeRel("services/iam/internal/repo/kaname/pg"); pkg != want {
		t.Errorf("путь пакета писателя %q, а ожидался %q — находка укажет не туда", pkg, want)
	}

	if _, isWriter := writerPkgOf(t, "services/iam/internal/repo/kaname/pg/scalegrid/census.go", injReaderSrc); isWriter {
		t.Error("читатель проекции признан ПИСАТЕЛЕМ — тогда гейт запретил бы слою " +
			"use-case импортировать пакет переписи, к записи отношения не имеющий")
	}
}

// TestReseedWiring_InjectionRedOnAUseCaseImportingTheWriter — файл use-case,
// импортирующий пакет писателя, → находка С КООРДИНАТОЙ.
func TestReseedWiring_InjectionRedOnAUseCaseImportingTheWriter(t *testing.T) {
	t.Parallel()
	writerPkgs := map[string]string{
		importOfTreeRel("services/iam/internal/repo/kaname/pg/roleverb"): "services/iam/internal/repo/kaname/pg/roleverb/roleverb.go",
	}
	apps := []useCaseFileImports{{
		Rel: "services/iam/internal/apps/kaname/seed/role_verb_reseed.go",
		Imports: []string{
			"context",
			importOfTreeRel("services/iam/internal/repo/kaname/pg/roleverb"),
		},
	}}
	got := useCaseWriterImportFindings(apps, writerPkgs)
	if len(got) != 1 {
		t.Fatalf("находок %d, а обязана быть одна: %v — гейт не способен покраснеть "+
			"на прямом импорте адаптера из use-case", len(got), got)
	}
	if !strings.HasPrefix(got[0], "services/iam/internal/apps/kaname/seed/role_verb_reseed.go ") {
		t.Errorf("находка не названа координатой файла: %q — читатель пойдёт искать "+
			"её и не найдёт", got[0])
	}
}

// TestReseedWiring_InjectionSilentOnANeighbouringAdapterImport — законный
// близнец: use-case импортирует ДРУГОЙ пакет того же слоя адаптера.
func TestReseedWiring_InjectionSilentOnANeighbouringAdapterImport(t *testing.T) {
	t.Parallel()
	writerPkgs := map[string]string{
		importOfTreeRel("services/iam/internal/repo/kaname/pg"): "services/iam/internal/repo/kaname/pg/role_repo.go",
	}
	apps := []useCaseFileImports{{
		Rel: "services/iam/internal/apps/kaname/seed/migrate_backfill.go",
		Imports: []string{
			importOfTreeRel("services/iam/internal/repo/kaname/pg/fga_outbox"),
			importOfTreeRel("services/iam/internal/repo/kaname"),
			importOfTreeRel("services/iam/internal/apps/kaname/shared"),
		},
	}}
	if got := useCaseWriterImportFindings(apps, writerPkgs); len(got) != 0 {
		t.Errorf("гейт покраснел на законной форме: %v — импорт ПОРТА и соседнего "+
			"адаптера нарушением не является, и ложная находка отключит гейт первой", got)
	}
}

// TestReseedWiring_LayerPredicateSeparatesUseCaseFromRepo — сам писатель
// лежит в `repo/` и обязан оставаться вне выборки.
func TestReseedWiring_LayerPredicateSeparatesUseCaseFromRepo(t *testing.T) {
	t.Parallel()
	if !isUseCaseLayer("services/iam/internal/apps/kaname/seed/role_verb_reseed.go") {
		t.Error("файл слоя use-case не опознан — выборка гейта пуста, и его молчание " +
			"ничего не значит")
	}
	if isUseCaseLayer("services/iam/internal/repo/kaname/pg/role_repo.go") {
		t.Error("файл слоя repo/ отнесён к use-case — гейт краснел бы на самом писателе")
	}
}

const injSeedInsideCallSrc = `package seed

func BackfillOwnerBindings(ctx context.Context, pool *pgxpool.Pool) error {
	if _, rerr := ReseedSystemRoleVerbs(ctx, pool, nil); rerr != nil {
		return rerr
	}
	return nil
}
`

const injSeedNeighbourCallSrc = `package seed

func BackfillOwnerBindings(ctx context.Context, pool *pgxpool.Pool) error {
	if err := SyncAllSystemRoleSelectors(ctx, pool); err != nil {
		return err
	}
	return nil
}
`

// TestReseedWiring_InjectionRedOnAnInPackageReseedCall — вызов пересчёта
// изнутри чужого досева.
func TestReseedWiring_InjectionRedOnAnInPackageReseedCall(t *testing.T) {
	t.Parallel()
	entries := map[string]bool{"ReseedSystemRoleVerbs": true}
	got, err := roleVerbReseedRefsIn("migrate_backfill.go", injSeedInsideCallSrc, entries)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("находок %d, а обязана быть одна: %v — гейт не способен покраснеть "+
			"на внутрипакетном вызове пересчёта", len(got), got)
	}
	if !strings.Contains(got[0], "::BackfillOwnerBindings → ReseedSystemRoleVerbs") {
		t.Errorf("находка не приписана объемлющей функции: %q", got[0])
	}
}

// TestReseedWiring_InjectionSilentOnANeighbouringSeedCall — законный близнец.
func TestReseedWiring_InjectionSilentOnANeighbouringSeedCall(t *testing.T) {
	t.Parallel()
	entries := map[string]bool{"ReseedSystemRoleVerbs": true}
	got, err := roleVerbReseedRefsIn("migrate_backfill.go", injSeedNeighbourCallSrc, entries)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("гейт покраснел на вызове СОСЕДНЕГО досева: %v — ось запрещает "+
			"внутрипакетный вызов ПЕРЕСЧЁТА, а не всякий вызов вообще", got)
	}
}

// TestReseedWiring_InjectionSilentOnTheDeclarationItself — объявление самой
// точки входа вызовом не является.
func TestReseedWiring_InjectionSilentOnTheDeclarationItself(t *testing.T) {
	t.Parallel()
	src := `package seed

func ReseedSystemRoleVerbs(ctx context.Context, repo kanamerepo.Repository) error {
	return nil
}
`
	entries := map[string]bool{"ReseedSystemRoleVerbs": true}
	got, err := roleVerbReseedRefsIn("role_verb_reseed.go", src, entries)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("объявление точки входа принято за её вызов: %v — гейт краснел бы "+
			"на любом дереве, где пересчёт вообще существует", got)
	}
}

// TestReseedWiring_EntryPointDetectionSeparatesExportedFromHelpers — точка
// входа опознаётся ЭКСПОРТИРОВАННЫМ именем.
func TestReseedWiring_EntryPointDetectionSeparatesExportedFromHelpers(t *testing.T) {
	t.Parallel()
	src := `package seed

func ReseedSystemRoleVerbs(ctx context.Context) error { return nil }

func replaceRoleVerbsInOwnTx(ctx context.Context) error { return nil }

func BackfillOwnerBindings(ctx context.Context) error { return nil }

func (s *sweeper) ReseedRoleVerbsMethod(ctx context.Context) error { return nil }
`
	got, err := exportedRoleVerbEntryPointsIn("role_verb_reseed.go", src)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if len(got) != 1 || got[0] != "ReseedSystemRoleVerbs" {
		t.Fatalf("точек входа %v, а обязана быть одна — `ReseedSystemRoleVerbs`.\n"+
			"Неэкспортированный помощник и метод с получателем точкой входа пакета "+
			"не являются: их зовут изнутри по построению, и находка на них была бы ложной.", got)
	}
}

// TestReseedWiring_EntryPointDetectionIsEmptyWithoutTheSubject — предпосылка.
func TestReseedWiring_EntryPointDetectionIsEmptyWithoutTheSubject(t *testing.T) {
	t.Parallel()
	src := `package seed

func BackfillOwnerBindings(ctx context.Context) error { return nil }
`
	got, err := exportedRoleVerbEntryPointsIn("migrate_backfill.go", src)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("точки входа найдены там, где предмета нет: %v", got)
	}
}

const injReseedQualifiedCallSrc = `package role

func materializeOnCreate(ctx context.Context) error {
	if _, rerr := seed.ReseedSystemRoleVerbs(ctx, repo, pool, nil); rerr != nil {
		return rerr
	}
	return nil
}
`

const injReseedValueCaptureSrc = `package seed

func BackfillOwnerBindings(ctx context.Context) error {
	run := ReseedSystemRoleVerbs
	_, err := run(ctx, nil, nil, nil)
	return err
}
`

// TestReseedWiring_InjectionRedOnAQualifiedReseedCallAnywhereInTheTree —
// квалифицированная форма вне пакета досева.
func TestReseedWiring_InjectionRedOnAQualifiedReseedCallAnywhereInTheTree(t *testing.T) {
	t.Parallel()
	entries := map[string]bool{"ReseedSystemRoleVerbs": true}
	got, err := roleVerbReseedRefsIn(
		"services/iam/internal/apps/kaname/api/role/create.go", injReseedQualifiedCallSrc, entries)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("находок %d, а обязана быть одна: %v\n"+
			"Пересчёт спрятан в чужом пакете КВАЛИФИЦИРОВАННЫМ вызовом, и гейт его "+
			"не видит.", len(got), got)
	}
	if !strings.Contains(got[0], "::materializeOnCreate → ReseedSystemRoleVerbs") {
		t.Errorf("находка не приписана объемлющей функции: %q", got[0])
	}
}

// TestReseedWiring_InjectionRedOnAReseedTakenAsAValue — пересчёт, взятый
// ЗНАЧЕНИЕМ.
func TestReseedWiring_InjectionRedOnAReseedTakenAsAValue(t *testing.T) {
	t.Parallel()
	entries := map[string]bool{"ReseedSystemRoleVerbs": true}
	got, err := roleVerbReseedRefsIn(
		"services/iam/internal/apps/kaname/seed/migrate_backfill.go", injReseedValueCaptureSrc, entries)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("находок %d, а обязана быть одна: %v\n"+
			"Пересчёт взят значением (`run := ReseedSystemRoleVerbs`) и позван через "+
			"переменную.", len(got), got)
	}
}

// TestReseedWiring_BootRootIsTheOnlyPlaceWhereAReferenceIsLegal — законный
// близнец расширенной оси.
func TestReseedWiring_BootRootIsTheOnlyPlaceWhereAReferenceIsLegal(t *testing.T) {
	t.Parallel()
	if !isBootCompositionRoot(bootCompositionRoot) {
		t.Errorf("композиционный корень (%s) не опознан как законное место ссылки — "+
			"гейт краснел бы на верном дереве", bootCompositionRoot)
	}
	for _, rel := range []string{
		"services/iam/internal/apps/kaname/seed/migrate_backfill.go",
		"services/iam/internal/apps/kaname/api/role/create.go",
		"services/iam/cmd/migrator/main.go",
	} {
		if isBootCompositionRoot(rel) {
			t.Errorf("%s принят за композиционный корень — спрятанный там вызов "+
				"находкой не станет, и вся ось вакуумна", rel)
		}
	}
}
