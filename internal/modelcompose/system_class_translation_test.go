// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelcompose_test

// system_class_translation_test.go — перевод слова субъекта `user:*` в
// `system_class` сборщиком модели (kaname#829; снятие перевода — kaname#836).
//
// Три пробы одной правки, каждая меняет ровно один факт против соседней:
//
//	1  манифест несёт `user:*` у типа КАНОНА → блок с `system_class`,
//	   побайтово равный каноническому, и композиция его подтверждает;
//	2  тот же `user:*` у НОВОГО типа модуля → перевод не открывает модулю
//	   дорогу к классу: допуск даёт находку Д3 с записью `system_class`;
//	3  законный близнец пробы 2 без `user:*` → блок прежний, Д3 молчит.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	"github.com/PRO-Robotech/kaname/internal/modelrender"
)

// registryRepositoryManifest — ресурс `repositories` манифеста registry платформы
// в той форме, в какой его несёт ствол kacho сегодня: слово `user:*` в составе
// субъектов действия `get`. Проза примечаний — дословно его же: перевод её не
// трогает, и равенство канону это утверждает.
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
      - {name: get, subjects: ['user:*', user, service_account, 'group#member'], from: [owner, super_admin]}
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

// Проба 1: слово `user:*` манифеста даёт блок канона побайтово.
func TestSC829_PublicWildcardWordRendersAsTheClassAndEqualsTheCanon(t *testing.T) {
	want := canonBlock(t, "registry_repository")
	// КОНТРОЛЬ ПРЕДПОСЫЛКИ: канон несёт класс в позиции субъекта, а не слово
	// `user:*`; иначе равенство ниже доказывало бы дословный перенос.
	if !strings.Contains(string(want), "define v_get: [system_class, user, service_account, group#member]") {
		t.Fatalf("канон не несёт класса в v_get registry_repository — предпосылка отпала:\n%s", want)
	}

	m := loadOne(t, registryRepositoryManifest)
	got, err := modelrender.Render(m.Resources[0])
	if err != nil {
		t.Fatalf("рендер отказал: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("блок манифеста со словом user:* не равен канону побайтово (рендер %d Б, канон %d Б)\nрендер:\n%s\nканон:\n%s",
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

// Проба 2: перевод не вносит класс в НОВЫЙ тип модуля мимо допуска.
func TestSC829_TranslatedClassInANewModuleTypeIsStillRefusedByD3(t *testing.T) {
	m := loadOne(t, newModuleWithWildcard)
	composed, rep, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m})
	t.Logf("перепись композиции: %s", rep.Census())
	if err != nil {
		t.Fatalf("композиция не состоялась: %v", err)
	}
	if !strings.Contains(composed, "    define v_get: [system_class, user, service_account, group#member] or super_admin\n") {
		t.Fatalf("блок нового типа не несёт перевода слова user:* в класс:\n%s", composed[len(authzmodel.DSL):])
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
	if len(d3) != 1 {
		t.Fatalf("класс в новом типе модуля обязан быть ровно одной находкой Д3, получено %v; перепись: %s",
			adm.Findings, adm.Census())
	}
	if d3[0].Type != "probemod_alpha" || d3[0].Relation != "v_get" || !strings.Contains(d3[0].Term, "system_class") {
		t.Fatalf("находка Д3 обязана назвать тип, отношение и запись класса, получено %+v", d3[0])
	}
}

// Проба 3: законный близнец — манифест без `user:*` рендерится как прежде.
func TestSC829_ManifestWithoutTheWildcardWordRendersAsBefore(t *testing.T) {
	m := loadOne(t, strings.Replace(newModuleWithWildcard, "'user:*', ", "", 1))
	composed, rep, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m})
	t.Logf("перепись композиции: %s", rep.Census())
	if err != nil {
		t.Fatalf("композиция не состоялась: %v", err)
	}
	added := composed[len(authzmodel.DSL):]
	if strings.Contains(added, "system_class") {
		t.Fatalf("блок без слова user:* несёт класс:\n%s", added)
	}
	if !strings.Contains(added, "    define v_get: [user, service_account, group#member] or super_admin\n") {
		t.Fatalf("блок без слова user:* порождён не прежней строкой:\n%s", added)
	}
	adm, aerr := authzmodel.Admit(composed)
	if aerr != nil {
		t.Fatalf("допуск вернул ошибку: %v", aerr)
	}
	if !adm.Admitted() {
		t.Fatalf("близнец без класса не допущен: %v; перепись: %s", adm.Findings, adm.Census())
	}
}
