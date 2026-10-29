// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest_test

// rolechildren_canon_test.go — судья `children` берёт `parents` из канона модели
// прав для типов, которые манифест модуля НЕ объявил (kaname#951).
//
// Вход — та же НАСТОЯЩАЯ фикстура П1 (`registry.public-read-fixture.yaml`), что у
// проб ND-04, без раздела `resources` целиком: ровно та форма, к которой приходит
// манифест registry, переставший копировать раздел канона. Законный близнец
// «раздел есть» — `TestManifest_ND04_UnmodifiedFixtureLoadsWithTheNestedRule`.
//
// Канон вносится переходником образа (`manifestoracle.CanonTypes`) — тем же, что
// вносит путь старта. Пар здесь четыре, и в каждой отличие — один факт:
//
//	без раздела, канон НЕ внесён                      → прежний отказ «не лежит под»;
//	без раздела, children над потомком по канону      → загрузка успешна;
//	без раздела, владелец и вложенный переставлены    → прежний отказ ND-04 (а):
//	                                                    канон родство НАПРАВЛЯЕТ,
//	                                                    а не разрешает всё подряд;
//	без раздела, children над типом вне канона        → отказ «тип не объявлен».

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/manifestoracle"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

// canonFixtureWithoutResources — фикстура П1 без раздела `resources`: от строки
// `resources:` до строки `roles:` (не включая её).
func canonFixtureWithoutResources(t *testing.T) []byte {
	t.Helper()
	doc, err := publicreadfixture.Read(publicreadfixture.NewEditionFile)
	if err != nil {
		t.Fatalf("фикстура П1: %v", err)
	}
	raw := string(doc)
	from := strings.Index(raw, "\nresources:\n")
	to := strings.Index(raw, "\nroles:\n")
	if from < 0 || to < 0 || to < from {
		t.Fatalf("разделы resources и roles фикстуры П1 не найдены в порядке документа — проба судила бы не тот документ")
	}
	cut := raw[:from+1] + raw[to+1:]
	if strings.Contains(cut, "objectType:") || strings.Contains(cut, "\nresources:\n") {
		t.Fatalf("после выреза в документе остался раздел resources — проба судила бы не тот документ")
	}
	if !strings.Contains(cut, "\nroles:\n") || strings.Count(cut, "children:") == 0 {
		t.Fatalf("после выреза в документе нет ролей с children — предмету пробы нечего судить")
	}
	return []byte(cut)
}

// canonMutateReader — документ без раздела `resources` с одной правкой внутри
// блока `registry.reader` (тот же блок, что правят пробы ND-04).
func canonMutateReader(t *testing.T, old, new string) []byte {
	t.Helper()
	doc := canonFixtureWithoutResources(t)
	if strings.Count(string(doc), ndReaderBlock) != 1 {
		t.Fatalf("блок registry.reader в документе без resources не найден ровно один раз")
	}
	if strings.Count(ndReaderBlock, old) != 1 {
		t.Fatalf("правка %q стоит в блоке registry.reader не ровно один раз", old)
	}
	block := strings.Replace(ndReaderBlock, old, new, 1)
	twin := []byte(strings.Replace(string(doc), ndReaderBlock, block, 1))
	removed, added := publicreadfixture.Delta(doc, twin)
	if len(removed) == 0 && len(added) == 0 {
		t.Fatalf("правка %q → %q ничего не изменила", old, new)
	}
	return twin
}

// withImageCanon — родство типов КАНОНА ОБРАЗА тем же переходником, что вносит
// его путь старта (`cmd/kaname`, `loadDelivery`): дублёр канона здесь судил бы
// своей копией родства, а не родством модели.
func withImageCanon(t *testing.T) manifest.LoadOption {
	t.Helper()
	canon, err := manifestoracle.CanonTypes()
	if err != nil {
		t.Fatalf("канон модели прав образа не разобран: %v", err)
	}
	return manifest.WithTypeCanon(canon)
}

func canonRequireFinding(t *testing.T, doc []byte, finding string) {
	t.Helper()
	_, err := manifest.Load(doc, withImageCanon(t))
	if err == nil {
		t.Fatalf("загрузка приняла документ; ждали находку %q", finding)
	}
	if !strings.Contains(err.Error(), finding) {
		t.Fatalf("находка судьи формы\n ждали  %q\n получено %v", finding, err)
	}
}

// Канон — ВНОСИМОЕ свойство: без внесения судья видит только раздел
// `resources`, и тот же документ отвергается прежней находкой (как до
// kaname#951). Отличие от пробы ниже — один факт: внесён ли канон.
func TestManifest_951_WithoutTheCanonOnlyTheDocumentIsJudged(t *testing.T) {
	ndRequireFinding(t, canonFixtureWithoutResources(t), `roles[1].rules[0].children[0].resources: тип "registry.repositories" не лежит под "registry.registries" ни по одному объявленному указателю parents; вложенное правило действует только на потомков типа правила-владельца`)
}

// Манифест без `resources`, чьи роли с `children` называют типы канона,
// загружается и проходит суд ролей; вложенное правило доезжает до формы домена.
func TestManifest_951_ManifestWithoutResourcesJudgesChildrenByTheCanon(t *testing.T) {
	m, err := manifest.Load(canonFixtureWithoutResources(t), withImageCanon(t))
	if err != nil {
		t.Fatalf("манифест без раздела resources отвергнут, хотя родство его типов объявляет канон: %v", err)
	}
	if len(m.Resources) != 0 {
		t.Fatalf("документ без раздела resources дал %d ресурсов", len(m.Resources))
	}
	var nested int
	for _, r := range m.Roles {
		for _, rule := range r.Rules {
			got := rule.DomainRule()
			if len(got.Children) == 0 {
				continue
			}
			nested++
			if len(got.Children[0].Resources) != 1 || got.Children[0].Resources[0] != "repositories" {
				t.Errorf("роль %s: вложенное правило в форме домена не над repositories: %+v", r.ID, got.Children)
			}
		}
	}
	if nested == 0 {
		t.Fatalf("ни одна роль загруженного документа не несёт вложенного правила — суд children не исполнялся")
	}
}

// Канон родство НАПРАВЛЯЕТ: владелец над repositories, вложенное над registries
// отвергается тем же текстом ND-04 (а), что и при объявленном разделе.
func TestManifest_951_CanonParentsKeepTheirDirection(t *testing.T) {
	doc := canonMutateReader(t,
		"        resources: [registries]\n        classes: [get, list]\n        children:\n          - resources: [repositories]",
		"        resources: [repositories]\n        classes: [get, list]\n        children:\n          - resources: [registries]")
	canonRequireFinding(t, doc, `roles[1].rules[0].children[0].resources: тип "registry.registries" не лежит под "registry.repositories" ни по одному объявленному указателю parents; вложенное правило действует только на потомков типа правила-владельца`)
}

// Близнец: `children` над типом, которого нет ни в манифесте, ни в каноне, —
// отказ, называющий именно эту причину.
func TestManifest_951_ChildTypeOutsideManifestAndCanonIsRefused(t *testing.T) {
	doc := canonMutateReader(t, "          - resources: [repositories]\n", "          - resources: [images]\n")
	canonRequireFinding(t, doc, `roles[1].rules[0].children[0].resources: тип "registry.images" не объявлен ни разделом resources этого манифеста, ни каноном модели прав; указателей parents у него нет, и потомком типа правила-владельца он не бывает`)
}
