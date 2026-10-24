// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// binding_subject_pair_injection_test.go — способность гейта пары субъекта
// выдачи упасть (kaname#917): в копию пакета выдачи наложением вносится файл с
// каждой формой доступа к паре и с законным близнецом каждой формы. Прогонов
// три: контроль (копия без файла — перепись совпадает с живой), инъекция
// (каждый дефект — находка с координатой файла и строки), близнецы (молчат).
package check_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// bindingPairProbePkg — пакет, в копию которого вносится инъекция.
const bindingPairProbePkg = "internal/apps/kaname/api/access_binding"

// bindingPairProbeFile — внесённый файл.
const bindingPairProbeFile = "zz_binding_pair_probe.go"

// bindingPairProbeSrc — каждая форма доступа и её законный близнец. Имя
// функции — место, по которому проба ищет находку.
const bindingPairProbeSrc = `package access_binding

import (
	"github.com/PRO-Robotech/kaname/internal/domain"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
)

// ДЕФЕКТ: селектор поля пары у значения.
func probeReadsPairValue(b domain.AccessBinding) string { return string(b.SubjectID) }

// ДЕФЕКТ: селектор поля пары через указатель.
func probeReadsPairPointer(b *domain.AccessBinding) domain.SubjectType { return b.SubjectType }

// ДЕФЕКТ: ключ составного литерала.
func probeBuildsPair() domain.AccessBinding { return domain.AccessBinding{SubjectID: "usr_probe"} }

// БЛИЗНЕЦ: член набора — другой объект с тем же именем поля.
func probeReadsSet(b domain.AccessBinding) domain.SubjectID { return b.Subjects[0].ID }

// БЛИЗНЕЦ: одноимённое поле другого типа (фильтр перечня).
func probeReadsNamesake(f repoab.ListFilter) string { return f.SubjectID }

// ОТКАТ С НАБОРОМ: законен под классом отката.
func probeFallbackWithSet(b domain.AccessBinding) []domain.Subject {
	if len(b.Subjects) > 0 {
		return b.Subjects
	}
	return []domain.Subject{{Type: b.SubjectType, ID: b.SubjectID}}
}

// ДЕФЕКТ: колонка пары с псевдонимом выдачи.
func probeSQLQualified() string {
	return "SELECT ab.id FROM access_bindings ab WHERE ab.subject_id = $1"
}

// ДЕФЕКТ: фрагмент условия без таблицы — колонка внешнего запроса.
func probeSQLFragment() string { return "(subject_type = $1 AND subject_id = $2)" }

// ДЕФЕКТ: таблица названа лишь во вложенном запросе — внешнюю он не затеняет.
func probeSQLNestedForeign() string {
	return "status = 'ACTIVE' AND (subject_id = $1 OR resource_id IN (SELECT id FROM projects))"
}

// ДЕФЕКТ: квалификатор — глагол формата.
func probeSQLFormat() string { return "%[1]s.subject_id = $1" }

// ДЕФЕКТ: перечень колонок без ключевого слова.
func probeSQLColumnList() string { return "id, subject_type, subject_id" }

// БЛИЗНЕЦ: колонка набора по псевдониму.
func probeSQLSetQualified() string {
	return "SELECT s.binding_id FROM access_binding_subjects s WHERE s.subject_id = $1"
}

// БЛИЗНЕЦ: колонка набора без квалификатора.
func probeSQLSetUnqualified() string {
	return "SELECT binding_id FROM access_binding_subjects WHERE subject_id = $1"
}

// БЛИЗНЕЦ: одноимённая колонка чужой таблицы.
func probeSQLForeignTable() string {
	return "INSERT INTO subject_change_outbox (subject_id, op) VALUES ($1, $2)"
}

// БЛИЗНЕЦ: ключ JSON — не SQL.
func probeJSONKey() string { return "subject_id" }

// ДЕФЕКТ: CTE над выдачей, колонка без квалификатора.
func probeSQLCTEUnqualified() string {
	return "WITH live AS (SELECT * FROM access_bindings WHERE revoked_at IS NULL) SELECT id FROM live WHERE subject_type = $1 AND subject_id = $2"
}

// ДЕФЕКТ: CTE над выдачей под псевдонимом.
func probeSQLCTEAliased() string {
	return "WITH live AS (SELECT * FROM access_bindings) SELECT l.id FROM live l WHERE l.subject_id = $1"
}

// ДЕФЕКТ: производная таблица над выдачей.
func probeSQLDerived() string {
	return "SELECT d.id FROM (SELECT * FROM access_bindings WHERE revoked_at IS NULL) d WHERE d.subject_id = $1"
}

// ДЕФЕКТ: колонка в верхнем регистре.
func probeSQLUpper() string { return "SELECT ab.id FROM access_bindings ab WHERE ab.SUBJECT_ID = $1" }

// ДЕФЕКТ: выдача второй таблицей списка через запятую, свежий псевдоним.
func probeSQLCommaAlias() string {
	return "SELECT u.id FROM users u, access_bindings x WHERE x.subject_id = u.id"
}

// ДЕФЕКТ: то же без псевдонима, колонка без квалификатора.
func probeSQLCommaBare() string {
	return "SELECT u.id FROM users u, access_bindings WHERE subject_id = u.id"
}

// БЛИЗНЕЦ: набор второй таблицей списка через запятую.
func probeSQLCommaSet() string {
	return "SELECT u.id FROM users u, access_binding_subjects s WHERE s.subject_id = u.id"
}

// БЛИЗНЕЦ: перечень значений после IN — не таблица списка.
func probeSQLCommaIn() string {
	return "SELECT binding_id FROM access_binding_subjects WHERE subject_id IN ($1, $2)"
}

// ДЕФЕКТ: перечень FROM, элемент после запятой — выдача.
func probeSQLLateral() string {
	return "SELECT l.subject_id FROM users u, LATERAL (SELECT * FROM access_bindings ab WHERE ab.id = u.id) l"
}

// ДЕФЕКТ: перечень FROM, элемент после запятой — выдача.
func probeSQLLateralAs() string {
	return "SELECT l.subject_id FROM users u, LATERAL (SELECT * FROM access_bindings ab WHERE ab.id = u.id) AS l"
}

// ДЕФЕКТ: перечень FROM, элемент после запятой — выдача.
func probeSQLLateralCTE() string {
	return "WITH live AS (SELECT * FROM access_bindings) SELECT l.subject_id FROM users u, LATERAL (SELECT * FROM live) l"
}

// ДЕФЕКТ: перечень FROM, элемент после запятой — выдача.
func probeSQLLateralThenComma() string {
	return "SELECT l.subject_id FROM users u, LATERAL (SELECT * FROM access_bindings) l, projects p"
}

// ДЕФЕКТ: перечень FROM, элемент после запятой — выдача.
func probeSQLCommaDerived() string {
	return "SELECT d.subject_id FROM users u, (SELECT * FROM access_bindings) d"
}

// ДЕФЕКТ: перечень FROM, элемент после запятой — выдача.
func probeSQLCommaFunc() string {
	return "SELECT x.subject_id FROM users u, generate_series(1,3) g, access_bindings x"
}

// ДЕФЕКТ: перечень FROM, элемент после запятой — выдача.
func probeSQLCommaOnly() string {
	return "SELECT x.subject_id FROM users u, ONLY access_bindings x"
}

// ДЕФЕКТ: перечень FROM, элемент после запятой — выдача.
func probeSQLCommaSample() string {
	return "SELECT x.subject_id FROM users u, access_bindings x TABLESAMPLE SYSTEM (10) REPEATABLE (1), projects p"
}

// БЛИЗНЕЦ: перечень FROM без выдачи (набор либо чужая таблица).
func probeSQLCommaPairThenSet() string {
	return "SELECT bs.subject_id FROM access_bindings ab, access_binding_subjects bs WHERE bs.binding_id = ab.id"
}

// БЛИЗНЕЦ: перечень FROM без выдачи (набор либо чужая таблица).
func probeSQLCommaGrant() string {
	return "SELECT u.id FROM cluster_admin_grants g, users u WHERE g.subject_id = u.id"
}

// БЛИЗНЕЦ: перечень FROM без выдачи (набор либо чужая таблица).
func probeSQLCommaCTEGrant() string {
	return "WITH cg AS (SELECT * FROM cluster_admin_grants) SELECT u.id FROM users u, cg WHERE cg.subject_id = u.id"
}

// БЛИЗНЕЦ: перечень FROM без выдачи (набор либо чужая таблица).
func probeSQLCommaFuncSet() string {
	return "SELECT x.subject_id FROM users u, generate_series(1,3) g, access_binding_subjects x"
}

// БЛИЗНЕЦ: перечень FROM без выдачи (набор либо чужая таблица).
func probeSQLCommaRowsSet() string {
	return "SELECT x.subject_id FROM users u, ROWS FROM (f(1,2)) r, access_binding_subjects x"
}

// БЛИЗНЕЦ: перечень FROM без выдачи (набор либо чужая таблица).
func probeSQLCommaStarSet() string {
	return "SELECT x.subject_id FROM users u, access_binding_subjects * x"
}

// БЛИЗНЕЦ: перечень FROM без выдачи (набор либо чужая таблица).
func probeSQLCommaSampleSet() string {
	return "SELECT x.subject_id FROM users u, access_binding_subjects x TABLESAMPLE SYSTEM (10) REPEATABLE (1), projects p"
}

// БЛИЗНЕЦ: перечень FROM без выдачи (набор либо чужая таблица).
func probeSQLCommaDerivedSet() string {
	return "SELECT d.subject_id FROM users u, (SELECT * FROM access_binding_subjects) d"
}

// БЛИЗНЕЦ: перечень FROM без выдачи (набор либо чужая таблица).
func probeSQLLateralSet() string {
	return "SELECT l.subject_id FROM users u, LATERAL (SELECT * FROM access_binding_subjects ab WHERE ab.id = u.id) AS l"
}

// БЛИЗНЕЦ: перечень FROM без выдачи (набор либо чужая таблица).
func probeSQLLateralFuncSet() string {
	return "SELECT x.subject_id FROM users u, LATERAL f(u.id) fn, access_binding_subjects x"
}

// БЛИЗНЕЦ: перечень FROM без выдачи (набор либо чужая таблица).
func probeSQLCommaOnlySet() string {
	return "SELECT x.subject_id FROM users u, ONLY access_binding_subjects x"
}

// БЛИЗНЕЦ: перечень FROM без выдачи (набор либо чужая таблица).
func probeSQLSampleFirstSet() string {
	return "SELECT x.subject_id FROM users u TABLESAMPLE SYSTEM (10) REPEATABLE (1), access_binding_subjects x"
}

// БЛИЗНЕЦ: перечень FROM без выдачи (набор либо чужая таблица).
func probeSQLCommaRowsOrdSet() string {
	return "SELECT x.subject_id FROM users u, ROWS FROM (f(1,2)) WITH ORDINALITY r, access_binding_subjects x"
}

// БЛИЗНЕЦ: перечень FROM без выдачи (набор либо чужая таблица).
func probeSQLCommaFuncOrdSet() string {
	return "SELECT x.subject_id FROM users u, generate_series(1,3) WITH ORDINALITY g, access_binding_subjects x"
}

// БЛИЗНЕЦ: перечень FROM без выдачи (набор либо чужая таблица).
func probeSQLAliasColsSet() string {
	return "SELECT x.subject_id FROM users AS u (a, b), access_binding_subjects x"
}

// ДЕФЕКТ: перечень FROM, элемент после запятой — выдача.
func probeSQLSampleFirst() string {
	return "SELECT x.subject_id FROM users u TABLESAMPLE SYSTEM (10) REPEATABLE (1), access_bindings x"
}

// ДЕФЕКТ: перечень FROM, элемент после запятой — выдача.
func probeSQLCommaRowsOrd() string {
	return "SELECT x.subject_id FROM users u, ROWS FROM (f(1,2)) WITH ORDINALITY r, access_bindings x"
}

// ДЕФЕКТ: перечень FROM, элемент после запятой — выдача.
func probeSQLCommaFuncOrd() string {
	return "SELECT x.subject_id FROM users u, generate_series(1,3) WITH ORDINALITY g, access_bindings x"
}

// ДЕФЕКТ: перечень FROM, элемент после запятой — выдача.
func probeSQLAliasCols() string {
	return "SELECT x.subject_id FROM users AS u (a, b), access_bindings x"
}

// БЛИЗНЕЦ: перечень FROM без выдачи; функция с именем-ключевым словом.
func probeSQLCommaKwFuncSet() string {
	return "SELECT x.subject_id FROM users u, left(u.name, 1) l, access_binding_subjects x"
}

// БЛИЗНЕЦ: перечень FROM без выдачи; таблица с именем-ключевым словом.
func probeSQLCommaKwTableSet() string {
	return "SELECT x.subject_id FROM users u, set s, access_binding_subjects x"
}

// ДЕФЕКТ: перечень FROM, элемент после функции с именем-ключевым словом — выдача.
func probeSQLCommaKwFunc() string {
	return "SELECT x.subject_id FROM users u, left(u.name, 1) l, access_bindings x"
}

// ДЕФЕКТ: перечень FROM, элемент после таблицы с именем-ключевым словом — выдача.
func probeSQLCommaKwTable() string {
	return "SELECT x.subject_id FROM users u, set s, access_bindings x"
}

// БЛИЗНЕЦ: CTE над набором.
func probeSQLCTESet() string {
	return "WITH s2 AS (SELECT * FROM access_binding_subjects) SELECT binding_id FROM s2 WHERE subject_id = $1"
}

// БЛИЗНЕЦ: производная таблица над набором.
func probeSQLDerivedSet() string {
	return "SELECT d.binding_id FROM (SELECT * FROM access_binding_subjects) d WHERE d.subject_id = $1"
}

// БЛИЗНЕЦ: текст ошибки, называющий колонку, — не SQL.
func probeErrorText() string { return "Illegal argument subject_id %q on a non-system access binding" }

// Вызов геттера домена: чтение пары стоит в домене, находка — там.
func probeCallsGetter(b domain.AccessBinding) domain.SubjectID { return b.ZzProbePrimary() }

// БЛИЗНЕЦ: комментарий SQL не исполняется.
func probeSQLComment() string {
	return "SELECT 1 FROM access_binding_subjects s -- ab.subject_id\n WHERE s.binding_id = $1"
}
`

// bindingPairProbeDefects — место дефекта → форма и что напечатано.
var bindingPairProbeDefects = map[string][2]string{
	"probeReadsPairValue":      {check.BindingPairFormSelector, ".SubjectID"},
	"probeReadsPairPointer":    {check.BindingPairFormSelector, ".SubjectType"},
	"probeBuildsPair":          {check.BindingPairFormLiteral, "SubjectID:"},
	"probeSQLQualified":        {check.BindingPairFormSQL, "ab.subject_id"},
	"probeSQLFragment":         {check.BindingPairFormSQL, "subject_type"},
	"probeSQLNestedForeign":    {check.BindingPairFormSQL, "subject_id"},
	"probeSQLFormat":           {check.BindingPairFormSQL, "<формат>.subject_id"},
	"probeSQLColumnList":       {check.BindingPairFormSQL, "subject_id"},
	"probeSQLCTEUnqualified":   {check.BindingPairFormSQL, "subject_type"},
	"probeSQLCTEAliased":       {check.BindingPairFormSQL, "l.subject_id"},
	"probeSQLDerived":          {check.BindingPairFormSQL, "d.subject_id"},
	"probeSQLUpper":            {check.BindingPairFormSQL, "ab.subject_id"},
	"probeSQLCommaAlias":       {check.BindingPairFormSQL, "x.subject_id"},
	"probeSQLCommaBare":        {check.BindingPairFormSQL, "subject_id"},
	"probeSQLLateral":          {check.BindingPairFormSQL, "l.subject_id"},
	"probeSQLLateralAs":        {check.BindingPairFormSQL, "l.subject_id"},
	"probeSQLLateralCTE":       {check.BindingPairFormSQL, "l.subject_id"},
	"probeSQLLateralThenComma": {check.BindingPairFormSQL, "l.subject_id"},
	"probeSQLCommaDerived":     {check.BindingPairFormSQL, "d.subject_id"},
	"probeSQLCommaFunc":        {check.BindingPairFormSQL, "x.subject_id"},
	"probeSQLCommaOnly":        {check.BindingPairFormSQL, "x.subject_id"},
	"probeSQLCommaSample":      {check.BindingPairFormSQL, "x.subject_id"},
	"probeSQLSampleFirst":      {check.BindingPairFormSQL, "x.subject_id"},
	"probeSQLCommaRowsOrd":     {check.BindingPairFormSQL, "x.subject_id"},
	"probeSQLCommaFuncOrd":     {check.BindingPairFormSQL, "x.subject_id"},
	"probeSQLAliasCols":        {check.BindingPairFormSQL, "x.subject_id"},
	"probeSQLCommaKwFunc":      {check.BindingPairFormSQL, "x.subject_id"},
	"probeSQLCommaKwTable":     {check.BindingPairFormSQL, "x.subject_id"},
}

// bindingPairOtherFiles — внесённое вне файла пробы: файл → исходник.
// Ключ — путь относительно корня модуля; пакет берётся из каталога.
var bindingPairOtherFiles = map[string]string{
	// Геттер домена, читающий пару, — новое место в домене.
	"internal/domain/zz_binding_pair_getter.go": `package domain

func (b AccessBinding) ZzProbePrimary() SubjectID { return b.SubjectID }
`,
	// Файл под ограничением сборки, которое прод-сборка (CGO_ENABLED=0)
	// выполняет, а сборка пробы — нет.
	bindingPairProbePkg + "/zz_binding_pair_notcgo.go": `//go:build !cgo

package access_binding

import "github.com/PRO-Robotech/kaname/internal/domain"

func probeNotCgo(b domain.AccessBinding) string { return string(b.SubjectID) }
`,
	// Файл, которого нет в прод-сборке: судится ведомостью файлов вне сборки.
	bindingPairProbePkg + "/zz_binding_pair_cgo.go": `//go:build cgo

package access_binding

func probeCgoOnly() string { return "" }
`,
	// Новый пакет радиуса, не слинкованный в службу.
	"internal/repo/kaname/pg/zzpairprobe/zzpairprobe.go": `package zzpairprobe

import "github.com/PRO-Robotech/kaname/internal/domain"

func Read(b domain.AccessBinding) string { return string(b.SubjectID) }
`,
}

// bindingPairOtherDefects — места дефектов вне файла пробы.
var bindingPairOtherDefects = map[string]string{
	"internal/domain/zz_binding_pair_getter.go::AccessBinding.ZzProbePrimary": ".SubjectID",
	bindingPairProbePkg + "/zz_binding_pair_notcgo.go::probeNotCgo":           ".SubjectID",
	"internal/repo/kaname/pg/zzpairprobe/zzpairprobe.go::Read":                ".SubjectID",
}

// bindingPairProbeTwins — места, где доступа к паре нет.
var bindingPairProbeTwins = []string{
	"probeReadsSet", "probeReadsNamesake", "probeSQLSetQualified", "probeSQLSetUnqualified",
	"probeSQLForeignTable", "probeJSONKey", "probeSQLComment", "probeSQLCTESet", "probeSQLDerivedSet",
	"probeErrorText", "probeCallsGetter", "probeSQLCommaSet", "probeSQLCommaIn",
	"probeSQLCommaPairThenSet", "probeSQLCommaGrant", "probeSQLCommaCTEGrant", "probeSQLCommaFuncSet", "probeSQLCommaRowsSet", "probeSQLCommaStarSet", "probeSQLCommaSampleSet", "probeSQLCommaDerivedSet", "probeSQLLateralSet", "probeSQLLateralFuncSet",
	"probeSQLCommaOnlySet", "probeSQLSampleFirstSet", "probeSQLCommaRowsOrdSet", "probeSQLCommaFuncOrdSet", "probeSQLAliasColsSet",
	"probeSQLCommaKwFuncSet", "probeSQLCommaKwTableSet",
}

// bindingPairPlace — ключ места внесённой функции.
func bindingPairPlace(fn string) string {
	return bindingPairProbePkg + "/" + bindingPairProbeFile + "::" + fn
}

// bindingPairLineOf — строка объявления функции во внесённом файле.
func bindingPairLineOf(t *testing.T, fn string) int {
	t.Helper()
	for i, ln := range strings.Split(bindingPairProbeSrc, "\n") {
		if strings.HasPrefix(ln, "func "+fn+"(") {
			return i + 1
		}
	}
	t.Fatalf("фикстура: функции %s во внесённом файле нет — условие не создано", fn)
	return 0
}

var (
	bindingPairOverlayOnce   sync.Once
	bindingPairOverlayCensus check.BindingPairCensus
	bindingPairControlCensus check.BindingPairCensus
	bindingPairOverlayErr    error
)

// bindingPairCopy — копия непроверочных файлов пакета в каталог dir.
func bindingPairCopy(root, rel, dir string) error {
	src := filepath.Join(root, filepath.FromSlash(rel))
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	copied := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		data, rerr := os.ReadFile(filepath.Join(src, name)) // #nosec G304 -- каталог пакета своего дерева
		if rerr != nil {
			return rerr
		}
		if werr := os.WriteFile(filepath.Join(dir, name), data, 0o600); werr != nil {
			return werr
		}
		copied++
	}
	if copied == 0 {
		return fmt.Errorf("в %s ни одного файла", src)
	}
	return nil
}

// bindingPairCensuses — контроль и инъекция, собранные один раз на процесс.
func bindingPairCensuses(t *testing.T) (control, injected check.BindingPairCensus) {
	t.Helper()
	bindingPairOverlayOnce.Do(func() {
		root := ceremonyModuleRoot(t)
		modPath := ceremonyModulePath(t, root)
		// Каталоги — свои на процесс, не t.TempDir(): перепись кэшируется для
		// всех подпроб, а каталог подпробы снимается с её концом.
		base, err := os.MkdirTemp("", "binding-pair-probe-")
		if err != nil {
			bindingPairOverlayErr = err
			return
		}
		defer func() { _ = os.RemoveAll(base) }()
		// Копируются пакеты, в которые вносится инъекция: выдачи и домен.
		copied := []string{bindingPairProbePkg, "internal/domain"}
		build := func(name string, extra map[string]string) (map[string]string, error) {
			overlay := map[string]string{}
			for _, rel := range copied {
				dir := filepath.Join(base, name, filepath.FromSlash(rel))
				if mkErr := os.MkdirAll(dir, 0o750); mkErr != nil {
					return nil, mkErr
				}
				if cpErr := bindingPairCopy(root, rel, dir); cpErr != nil {
					return nil, cpErr
				}
				overlay[modPath+"/"+rel] = dir
			}
			for rel, src := range extra {
				dir := filepath.Join(base, name, filepath.FromSlash(filepath.Dir(rel)))
				if mkErr := os.MkdirAll(dir, 0o750); mkErr != nil {
					return nil, mkErr
				}
				if werr := os.WriteFile(filepath.Join(base, name, filepath.FromSlash(rel)), []byte(src), 0o600); werr != nil {
					return nil, werr
				}
				overlay[modPath+"/"+filepath.ToSlash(filepath.Dir(rel))] = dir
			}
			return overlay, nil
		}
		ctrl, err := build("control", nil)
		if err != nil {
			bindingPairOverlayErr = err
			return
		}
		extra := map[string]string{bindingPairProbePkg + "/" + bindingPairProbeFile: bindingPairProbeSrc}
		var onDisk []string
		for rel, src := range bindingPairOtherFiles {
			extra[rel] = src
			onDisk = append(onDisk, rel)
		}
		inj, err := build("injected", extra)
		if err != nil {
			bindingPairOverlayErr = err
			return
		}
		bindingPairControlCensus, bindingPairOverlayErr = check.CollectBindingSubjectPair(t.Context(),
			check.BindingPairSpec{ModuleRoot: root, Overlay: ctrl})
		if bindingPairOverlayErr != nil {
			return
		}
		bindingPairOverlayCensus, bindingPairOverlayErr = check.CollectBindingSubjectPair(t.Context(),
			check.BindingPairSpec{ModuleRoot: root, Overlay: inj, OnDisk: onDisk})
	})
	if bindingPairOverlayErr != nil {
		t.Fatalf("гейт НЕ ИСПОЛНИЛСЯ на фикстуре — условие не создано: %v", bindingPairOverlayErr)
	}
	return bindingPairControlCensus, bindingPairOverlayCensus
}

// TestBindingSubjectPairControlCopyIsSilent — копия пакета без инъекции даёт
// ту же перепись, что живое дерево, и молчит: наложение само ничего не вносит.
func TestBindingSubjectPairControlCopyIsSilent(t *testing.T) {
	control, _ := bindingPairCensuses(t)
	live := collectLiveBindingPair(t)
	if len(control.Accesses) != len(live.Accesses) || control.Files != live.Files {
		t.Fatalf("контроль разошёлся с живым деревом: копия %s; живое %s", control.Summary(), live.Summary())
	}
	if f := check.JudgeBindingSubjectPair(control, check.BindingSubjectPairLedger); len(f) > 0 {
		t.Fatalf("контроль не молчит (%d находок):\n%s", len(f), strings.Join(f, "\n"))
	}
}

// TestBindingSubjectPairInjectionEveryFormIsFound — каждая форма доступа к
// паре в неперечисленном месте — находка, называющая файл и строку.
func TestBindingSubjectPairInjectionEveryFormIsFound(t *testing.T) {
	_, injected := bindingPairCensuses(t)
	findings := check.JudgeBindingSubjectPair(injected, check.BindingSubjectPairLedger)
	for fn, want := range bindingPairProbeDefects {
		place := bindingPairPlace(fn)
		var hit string
		for _, f := range findings {
			if strings.HasPrefix(f, place+" ") {
				hit = f
				break
			}
		}
		if hit == "" {
			t.Errorf("ИНЪЕКЦИЯ НЕ ПОЙМАНА: %s (%s %s) — находки нет\nперепись: %s", fn, want[0], want[1], injected.Summary())
			continue
		}
		line := bindingPairLineOf(t, fn)
		coord := bindingPairProbePkg + "/" + bindingPairProbeFile + ":"
		if !strings.Contains(hit, want[0]) || !strings.Contains(hit, want[1]) || !strings.Contains(hit, coord) {
			t.Errorf("находка по %s не называет форму %q, доступ %q и координату %s…:\n%s", fn, want[0], want[1], coord, hit)
		}
		// Координата — строка самого доступа: функция однострочная либо
		// доступ стоит не выше её объявления.
		found := false
		for d := 0; d <= 3; d++ {
			if strings.Contains(hit, coord+strconv.Itoa(line+d)+" ") {
				found = true
			}
		}
		if !found {
			t.Errorf("находка по %s не называет строку доступа (объявление — строка %d):\n%s", fn, line, hit)
		}
	}
	for place, what := range bindingPairOtherDefects {
		found := false
		for _, f := range findings {
			if strings.HasPrefix(f, place+" ") && strings.Contains(f, what) {
				found = true
			}
		}
		if !found {
			t.Errorf("ИНЪЕКЦИЯ НЕ ПОЙМАНА: %s (%s) — находки нет\nперепись: %s", place, what, injected.Summary())
		}
	}
	cgo := bindingPairProbePkg + "/zz_binding_pair_cgo.go"
	found := false
	for _, f := range findings {
		if strings.HasPrefix(f, cgo+" — непроверочный файл радиуса вне прод-сборки") {
			found = true
		}
	}
	if !found {
		t.Errorf("ИНЪЕКЦИЯ НЕ ПОЙМАНА: файл вне прод-сборки %s не назван находкой; вне сборки: %v", cgo, injected.OutsideBuild)
	}
}

// TestBindingSubjectPairInjectionTwinsAreSilent — законные близнецы каждой
// формы доступа в переписи не появляются.
func TestBindingSubjectPairInjectionTwinsAreSilent(t *testing.T) {
	_, injected := bindingPairCensuses(t)
	places := injected.Places()
	for _, fn := range bindingPairProbeTwins {
		if acc := places[bindingPairPlace(fn)]; len(acc) > 0 {
			t.Errorf("БЛИЗНЕЦ НЕ МОЛЧИТ: %s — %v", fn, acc)
		}
	}
	if len(places[bindingPairPlace("probeReadsPairValue")]) == 0 {
		t.Fatalf("близнецы «молчат» на переписи без инъекции — это не вердикт: %s", injected.Summary())
	}
}

// TestBindingSubjectPairLedgerAxes — ведомость: перечисленное место молчит,
// изменившееся число, откат без набора, запись без предмета, основание вне
// словаря и без слов — находки.
func TestBindingSubjectPairLedgerAxes(t *testing.T) {
	_, injected := bindingPairCensuses(t)
	with := func(extra map[string]check.BindingPairEntry) []string {
		ledger := map[string]check.BindingPairEntry{}
		for k, v := range check.BindingSubjectPairLedger {
			ledger[k] = v
		}
		for k, v := range extra {
			ledger[k] = v
		}
		// Прочие места инъекции — в перечень точно, чтобы судилась одна ось.
		for p, acc := range injected.Places() {
			if _, ok := ledger[p]; ok {
				continue
			}
			e := check.BindingPairEntry{Class: check.BindingPairProjection, Why: "проба"}
			for _, a := range acc {
				if a.Form == check.BindingPairFormSQL {
					e.SQL++
				} else {
					e.Go++
				}
			}
			ledger[p] = e
		}
		var out []string
		for _, f := range check.JudgeBindingSubjectPair(injected, ledger) {
			// Ось файлов вне сборки судится своей пробой выше.
			if !strings.Contains(f, "вне прод-сборки") {
				out = append(out, f)
			}
		}
		return out
	}
	value := bindingPairPlace("probeReadsPairValue")
	fallback := bindingPairPlace("probeFallbackWithSet")

	t.Run("перечисленное место молчит", func(t *testing.T) {
		f := with(map[string]check.BindingPairEntry{
			value:    {Go: 1, Class: check.BindingPairProjection, Why: "проба"},
			fallback: {Go: 2, Class: check.BindingPairFallback, Why: "проба: набор рядом"},
		})
		if len(f) > 0 {
			t.Fatalf("законный близнец не молчит:\n%s", strings.Join(f, "\n"))
		}
	})
	cases := []struct {
		name  string
		extra map[string]check.BindingPairEntry
		want  []string
	}{
		{"число в месте изменилось", map[string]check.BindingPairEntry{
			value:    {Go: 2, Class: check.BindingPairProjection, Why: "проба"},
			fallback: {Go: 2, Class: check.BindingPairFallback, Why: "проба"},
		}, []string{value, "число доступов к паре изменилось", "ведомость Go 2", "в дереве Go 1"}},
		{"откат без набора", map[string]check.BindingPairEntry{
			value:    {Go: 1, Class: check.BindingPairFallback, Why: "проба"},
			fallback: {Go: 2, Class: check.BindingPairFallback, Why: "проба"},
		}, []string{value, "набор субъектов в нём не читается"}},
		{"запись без предмета", map[string]check.BindingPairEntry{
			value:                         {Go: 1, Class: check.BindingPairProjection, Why: "проба"},
			fallback:                      {Go: 2, Class: check.BindingPairFallback, Why: "проба"},
			bindingPairPlace("probeNone"): {Go: 1, Class: check.BindingPairProjection, Why: "проба"},
		}, []string{bindingPairPlace("probeNone"), "запись ведомости без предмета"}},
		{"основание вне словаря", map[string]check.BindingPairEntry{
			value:    {Go: 1, Class: "так исторически", Why: "проба"},
			fallback: {Go: 2, Class: check.BindingPairFallback, Why: "проба"},
		}, []string{value, "вне закрытого словаря"}},
		{"основание без слов", map[string]check.BindingPairEntry{
			value:    {Go: 1, Class: check.BindingPairProjection, Why: " "},
			fallback: {Go: 2, Class: check.BindingPairFallback, Why: "проба"},
		}, []string{value, "без основания словами"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := with(tc.extra)
			for _, x := range f {
				ok := true
				for _, w := range tc.want {
					if !strings.Contains(x, w) {
						ok = false
					}
				}
				if ok {
					return
				}
			}
			t.Fatalf("ИНЪЕКЦИЯ НЕ ПОЙМАНА: нет находки с %q; находки (%d):\n%s", tc.want, len(f), strings.Join(f, "\n"))
		})
	}
}

// TestBindingSubjectPairEmptyWalkIsNotAVerdict — обход, не нашедший ни
// одного файла, — «не выполнилось», а не зелёное; файл радиуса вне бинаря
// печатается неосмотренным.
func TestBindingSubjectPairEmptyWalkIsNotAVerdict(t *testing.T) {
	root := ceremonyModuleRoot(t)
	_, err := check.CollectBindingSubjectPair(t.Context(), check.BindingPairSpec{
		ModuleRoot: root,
		Dirs:       []string{"internal/no/such/dir"},
	})
	if err == nil || !strings.Contains(err.Error(), "обход пуст") {
		t.Fatalf("пустой обход не назван «не выполнилось»: %v", err)
	}
	census, err := check.CollectBindingSubjectPair(t.Context(), check.BindingPairSpec{
		ModuleRoot: root,
		OnDisk:     []string{bindingPairProbePkg + "/zz_not_linked.go"},
	})
	if err != nil {
		t.Fatalf("гейт НЕ ИСПОЛНИЛСЯ: %v", err)
	}
	if len(census.OutsideBuild) != 1 || census.OutsideBuild[0] != bindingPairProbePkg+"/zz_not_linked.go" {
		t.Fatalf("файл вне прод-сборки не назван: %v", census.OutsideBuild)
	}
}
