// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelcompose_test

// system_class_subject_word_test.go — слово субъекта `system_class` манифеста
// после снятия перевода `user:*` → `system_class` из сборщика модели
// (kaname#836; перевод вводила kaname#829).
//
// Перевод держал взаимную блокировку двух стволов: манифест registry kacho писал
// `user:*`, канон — класс. Манифест переведён (PRO-Robotech/kacho#3251), и
// сборщик больше не переписывает ни одного слова субъекта: вход переносится в
// порождённую строку как есть.
//
// Пробы меняют ровно один факт против соседней:
//
//	1  манифест несёт `system_class` у типа КАНОНА → блок побайтово равен
//	   каноническому, композиция его подтверждает;
//	2  тот же манифест со словом `user:*` → слово переносится дословно, блок
//	   канону НЕ равен, композиция отказывает — перевода нет;
//	3  `user:*` у НОВОГО типа модуля → слово дословно, допуск даёт находку Д3
//	   с записью `user:*`;
//	4  `system_class` у НОВОГО типа модуля → допуск даёт находку Д3 с записью
//	   класса: снятие перевода дорогу классу не открыло;
//	5  законный близнец без обоих слов → блок прежний, Д3 молчит.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	"github.com/PRO-Robotech/kaname/internal/modelrender"
)

// registryRepositoryManifest — ресурс `repositories` манифеста registry платформы
// в той форме, в какой его несёт kacho после PRO-Robotech/kacho#3251: слово `system_class` в составе
// субъектов действия `get`. Проза примечаний — дословно его же: канон несёт её
// побайтово, и равенство это утверждает.
const registryRepositoryManifest = `apiVersion: iam/v1
module: registry
resources:
  - name: repositories
    objectType: registry_repository
    parents:
      - {name: parent, type: registry_registry}
    producer: authored
    notes:
      - before: super_admin
        text: |
          # A repository has no project pointer of its own — it is a child of its
          # registry, and the registry is the one anchored to a project.
      - before: v_get
        text: |
          # RG-1 D-7: ` + "`user:*`" + ` public-read wildcard — anonymous pull of a PUBLIC repo.
          # The wildcard grants v_get ONLY on repos that ALSO carry an explicit
          # ` + "`user:* v_get`" + ` tuple emitted by the registry overlay (visibility=PUBLIC);
          # absent that tuple ` + "`user:*`" + ` has no access → uniform 404. ONLY v_get gains
          # the wildcard — no write relation does (anon is a read-only floor, B14).
          # #64 Defect A: v_* derive from ` + "`owner`" + ` (repo creator/pusher owner-tuple) so
          # the repo owner fully manages their own repository; ` + "`user:*`" + ` wildcard stays
          # on v_get ONLY (anonymous public-read floor, B14).
    relations:
      - name: owner
        definition: '[user, service_account]'
        position: beforeTiers
    verbs:
      - {name: get, subjects: [system_class, user, service_account, 'group#member'], from: [owner, super_admin]}
      - {name: list, from: [owner, super_admin]}
      - {name: update, from: [owner, super_admin]}
      - {name: delete, from: [owner, super_admin]}
`

func loadOne(t *testing.T, doc string) *manifest.Manifest {
	t.Helper()
	m, err := manifest.Load([]byte(doc))
	if err != nil {
		t.Fatalf("загрузчик отверг вход: %v", err)
	}
	if len(m.Resources) != 1 {
		t.Fatalf("ресурсов %d, ожидался один", len(m.Resources))
	}
	return m
}

func canonBlock(t *testing.T, typeName string) []byte {
	t.Helper()
	for _, b := range modelrender.SplitCanon([]byte(authzmodel.DSL)) {
		if b.Type == typeName {
			return b.Body
		}
	}
	t.Fatalf("канон не объявляет %q — проба беспредметна", typeName)
	return nil
}

// Проба 1: слово `system_class` манифеста даёт блок канона побайтово.
func TestSC836_ClassWordRendersTheCanonBlockVerbatim(t *testing.T) {
	want := canonBlock(t, "registry_repository")
	// КОНТРОЛЬ ПРЕДПОСЫЛКИ: канон несёт класс в позиции субъекта; иначе
	// равенство ниже утверждало бы не то.
	if !strings.Contains(string(want), "define v_get: [system_class, user, service_account, group#member]") {
		t.Fatalf("канон не несёт класса в v_get registry_repository — предпосылка отпала:\n%s", want)
	}

	m := loadOne(t, registryRepositoryManifest)
	got, err := modelrender.Render(m.Resources[0])
	if err != nil {
		t.Fatalf("рендер отказал: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("блок манифеста со словом system_class не равен канону побайтово (рендер %d Б, канон %d Б)\nрендер:\n%s\nканон:\n%s",
			len(got), len(want), got, want)
	}

	_, rep, cerr := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m})
	t.Logf("перепись композиции: %s", rep.Census())
	if cerr != nil {
		t.Fatalf("композиция отвергла блок, равный канону: %v", cerr)
	}
	if len(rep.Reaffirmed) != 1 || rep.Reaffirmed[0] != "registry_repository" || len(rep.Composed) != 0 {
		t.Fatalf("ожидалось подтверждение ровно registry_repository и ноль добавленных: %s", rep.Census())
	}
}

// Проба 2: прежнее слово `user:*` больше не переводится — блок канону не равен.
func TestSC836_WildcardWordIsCarriedVerbatimAndNoLongerEqualsTheCanon(t *testing.T) {
	doc := strings.Replace(registryRepositoryManifest,
		"subjects: [system_class, user,", "subjects: ['user:*', user,", 1)
	if doc == registryRepositoryManifest {
		t.Fatal("подстановка слова не состоялась — проба беспредметна")
	}
	m := loadOne(t, doc)
	got, err := modelrender.Render(m.Resources[0])
	if err != nil {
		t.Fatalf("рендер отказал: %v", err)
	}
	const verbatim = "    define v_get: [user:*, user, service_account, group#member] or owner or super_admin\n"
	if !strings.Contains(string(got), verbatim) {
		t.Fatalf("слово user:* не перенесено дословно — перевод не снят:\n%s", got)
	}
	if string(got) == string(canonBlock(t, "registry_repository")) {
		t.Fatal("блок со словом user:* равен канону: сборщик всё ещё переводит слово")
	}
	if _, rep, cerr := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m}); cerr == nil {
		t.Fatalf("композиция приняла блок типа канона, разошедшийся с ним: %s", rep.Census())
	}
}

const newModuleWithWildcard = `apiVersion: iam/v1
module: probemod
resources:
  - name: alphas
    objectType: probemod_alpha
    parents: [project]
    producer: authored
    verbs:
      - {name: get, subjects: ['user:*', user, service_account, 'group#member']}
      - list
`

// d3Of — находки Д3 допуска над композицией одного манифеста.
func d3Of(t *testing.T, doc, wantLine string) []authzmodel.Finding {
	t.Helper()
	m := loadOne(t, doc)
	composed, rep, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m})
	t.Logf("перепись композиции: %s", rep.Census())
	if err != nil {
		t.Fatalf("композиция не состоялась: %v", err)
	}
	if !strings.Contains(composed, wantLine) {
		t.Fatalf("блок нового типа порождён не строкой %q:\n%s", wantLine, composed[len(authzmodel.DSL):])
	}
	adm, aerr := authzmodel.Admit(composed)
	if aerr != nil {
		t.Fatalf("допуск вернул ошибку вместо отчёта: %v", aerr)
	}
	var d3 []authzmodel.Finding
	for _, f := range adm.Findings {
		if f.Rule == authzmodel.RuleD3 {
			d3 = append(d3, f)
		}
	}
	t.Logf("перепись допуска: %s", adm.Census())
	return d3
}

// Проба 3: `user:*` у нового типа модуля — дословно и находка Д3.
func TestSC836_WildcardWordInANewModuleTypeIsRefusedByD3(t *testing.T) {
	d3 := d3Of(t, newModuleWithWildcard,
		"    define v_get: [user:*, user, service_account, group#member] or super_admin\n")
	if len(d3) != 1 {
		t.Fatalf("подстановка в новом типе модуля обязана быть ровно одной находкой Д3, получено %v", d3)
	}
	if d3[0].Type != "probemod_alpha" || d3[0].Relation != "v_get" || !strings.Contains(d3[0].Term, "user:*") {
		t.Fatalf("находка Д3 обязана назвать тип, отношение и запись user:*, получено %+v", d3[0])
	}
}

// Проба 4: `system_class` у нового типа модуля — находка Д3: снятие перевода
// дорогу классу не открыло.
func TestSC836_ClassWordInANewModuleTypeIsRefusedByD3(t *testing.T) {
	doc := strings.Replace(newModuleWithWildcard, "'user:*', ", "system_class, ", 1)
	d3 := d3Of(t, doc,
		"    define v_get: [system_class, user, service_account, group#member] or super_admin\n")
	if len(d3) != 1 {
		t.Fatalf("класс в новом типе модуля обязан быть ровно одной находкой Д3, получено %v", d3)
	}
	if d3[0].Type != "probemod_alpha" || d3[0].Relation != "v_get" || !strings.Contains(d3[0].Term, "system_class") {
		t.Fatalf("находка Д3 обязана назвать тип, отношение и запись класса, получено %+v", d3[0])
	}
}

// Проба 5: законный близнец — манифест без обоих слов рендерится как прежде.
func TestSC836_ManifestWithoutEitherWordRendersAsBefore(t *testing.T) {
	doc := strings.Replace(newModuleWithWildcard, "'user:*', ", "", 1)
	if d3 := d3Of(t, doc, "    define v_get: [user, service_account, group#member] or super_admin\n"); len(d3) != 0 {
		t.Fatalf("близнец без класса и подстановки дал находки Д3: %v", d3)
	}
}
