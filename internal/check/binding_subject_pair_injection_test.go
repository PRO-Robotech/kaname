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

// БЛИЗНЕЦ: комментарий SQL не исполняется.
func probeSQLComment() string {
	return "SELECT 1 FROM access_binding_subjects s -- ab.subject_id\n WHERE s.binding_id = $1"
}
`

// bindingPairProbeDefects — место дефекта → форма и что напечатано.
var bindingPairProbeDefects = map[string][2]string{
	"probeReadsPairValue":   {check.BindingPairFormSelector, ".SubjectID"},
	"probeReadsPairPointer": {check.BindingPairFormSelector, ".SubjectType"},
	"probeBuildsPair":       {check.BindingPairFormLiteral, "SubjectID:"},
	"probeSQLQualified":     {check.BindingPairFormSQL, "ab.subject_id"},
	"probeSQLFragment":      {check.BindingPairFormSQL, "subject_type"},
	"probeSQLNestedForeign": {check.BindingPairFormSQL, "subject_id"},
	"probeSQLFormat":        {check.BindingPairFormSQL, "<формат>.subject_id"},
	"probeSQLColumnList":    {check.BindingPairFormSQL, "subject_id"},
}

// bindingPairProbeTwins — места, где доступа к паре нет.
var bindingPairProbeTwins = []string{
	"probeReadsSet", "probeReadsNamesake", "probeSQLSetQualified", "probeSQLSetUnqualified",
	"probeSQLForeignTable", "probeJSONKey", "probeSQLComment",
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
func bindingPairCopy(root, dir string) error {
	src := filepath.Join(root, filepath.FromSlash(bindingPairProbePkg))
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
		spec := func(dir string) check.BindingPairSpec {
			return check.BindingPairSpec{
				ModuleRoot:  root,
				RootPackage: modPath + "/" + ceremonyRootDir,
				Overlay:     map[string]string{modPath + "/" + bindingPairProbePkg: dir},
			}
		}
		// Каталоги — свои на процесс, не t.TempDir(): перепись кэшируется для
		// всех подпроб, а каталог подпробы снимается с её концом.
		base, err := os.MkdirTemp("", "binding-pair-probe-")
		if err != nil {
			bindingPairOverlayErr = err
			return
		}
		defer func() { _ = os.RemoveAll(base) }()
		ctrlDir, injDir := filepath.Join(base, "control"), filepath.Join(base, "injected")
		for _, d := range []string{ctrlDir, injDir} {
			if mkErr := os.MkdirAll(d, 0o750); mkErr != nil {
				bindingPairOverlayErr = mkErr
				return
			}
			if cpErr := bindingPairCopy(root, d); cpErr != nil {
				bindingPairOverlayErr = cpErr
				return
			}
		}
		if werr := os.WriteFile(filepath.Join(injDir, bindingPairProbeFile), []byte(bindingPairProbeSrc), 0o600); werr != nil {
			bindingPairOverlayErr = werr
			return
		}
		bindingPairControlCensus, bindingPairOverlayErr = check.CollectBindingSubjectPair(t.Context(), spec(ctrlDir))
		if bindingPairOverlayErr != nil {
			return
		}
		bindingPairOverlayCensus, bindingPairOverlayErr = check.CollectBindingSubjectPair(t.Context(), spec(injDir))
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
		// Прочие дефекты пробы — в перечень, чтобы судилась одна ось.
		for fn, want := range bindingPairProbeDefects {
			p := bindingPairPlace(fn)
			if _, ok := ledger[p]; ok {
				continue
			}
			n := len(injected.Places()[p])
			e := check.BindingPairEntry{Class: check.BindingPairProjection, Why: "проба"}
			if want[0] == check.BindingPairFormSQL {
				e.SQL = n
			} else {
				e.Go = n
			}
			ledger[p] = e
		}
		return check.JudgeBindingSubjectPair(injected, ledger)
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
	modPath := ceremonyModulePath(t, root)
	_, err := check.CollectBindingSubjectPair(t.Context(), check.BindingPairSpec{
		ModuleRoot:  root,
		RootPackage: modPath + "/" + ceremonyRootDir,
		Dirs:        []string{"internal/no/such/dir"},
	})
	if err == nil || !strings.Contains(err.Error(), "обход пуст") {
		t.Fatalf("пустой обход не назван «не выполнилось»: %v", err)
	}
	census, err := check.CollectBindingSubjectPair(t.Context(), check.BindingPairSpec{
		ModuleRoot:  root,
		RootPackage: modPath + "/" + ceremonyRootDir,
		OnDisk:      []string{bindingPairProbePkg + "/zz_not_linked.go"},
	})
	if err != nil {
		t.Fatalf("гейт НЕ ИСПОЛНИЛСЯ: %v", err)
	}
	if len(census.Unlinked) != 1 || census.Unlinked[0] != bindingPairProbePkg+"/zz_not_linked.go" {
		t.Fatalf("файл вне бинаря не назван неосмотренным: %v", census.Unlinked)
	}
}
