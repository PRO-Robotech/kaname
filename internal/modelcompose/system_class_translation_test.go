// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelcompose_test

// system_class_translation_test.go — перевод слова субъекта `user:*` в
// `system_class` сборщиком модели (kaname#829; снятие перевода — kaname#836).
//
// Три пробы одной правки, каждая меняет ровно один факт против соседней:
//
//	1  манифест несёт `user:*` у типа КАНОНА → блок с `system_class`,
//	   побайтово равный каноническому, и композиция его подтверждает
//	   (манифест registry целиком: блок репозитория канона несёт следствие
//	   ключа контейнера, kaname#856);
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
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

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

	// Манифест — registry ЦЕЛИКОМ, с контейнером `registries`: блок
	// репозитория канона несёт `public_reader from parent` (kaname#856), а это
	// следствие ключа контейнера ТОГО ЖЕ документа. Один ресурс `repositories`
	// рендерит прежнюю редакцию (Р10), и равенство канону на нём не определено.
	m := loadRegistryWithContainer(t)
	var repo manifest.Resource
	for _, r := range m.Resources {
		if r.ObjectType == "registry_repository" {
			repo = r
		}
	}
	got, err := modelrender.Render(repo)
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
	if len(rep.Reaffirmed) != 2 || rep.Reaffirmed[1] != "registry_repository" || len(rep.Composed) != 0 ||
		len(rep.PriorEdition) != 0 {
		t.Fatalf("ожидалось подтверждение ровно registry_registry и registry_repository, ноль добавленных "+
			"и ноль прежней редакции: %s", rep.Census())
	}
}

// loadRegistryWithContainer — манифест registry новой редакции (фикстура П6):
// слово `user:*` у действия `get` репозитория и ключ публичного чтения у реестра.
func loadRegistryWithContainer(t *testing.T) *manifest.Manifest {
	t.Helper()
	doc, err := publicreadfixture.Read(publicreadfixture.NewEditionFile)
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	if !strings.Contains(string(doc), "subjects: ['user:*'") {
		t.Fatalf("фикстура не несёт слова user:* в составе субъектов — проба перевода беспредметна")
	}
	m, err := manifest.Load(doc)
	if err != nil {
		t.Fatalf("загрузчик отверг фикстуру: %v", err)
	}
	return m
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
