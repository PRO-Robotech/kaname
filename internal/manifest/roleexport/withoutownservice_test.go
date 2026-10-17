// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// withoutownservice_test.go — правило роли над ресурсом БЕЗ собственной службы
// судится глаголами модели его типа (kaname#872).
//
// # Вход — НАСТОЯЩИЙ
//
// Манифест — фикстура registry новой редакции (kacho#3274), та самая, на которой
// судья формы отверг роль `registry.public.read`: правило `[get, list]` над
// `registries` и `repositories`. Каталог прав — встроенный, тот, что читает
// посев; факт модели — тот же снимок, которым его берёт сборочная команда.
//
// # Пары держатся близнецами, каждый меняет РОВНО ОДИН факт
//
//	новая редакция как есть                 → находок 0 (предмет)
//	+ класс `create` в правиле              → находка о `create` на repositories
//	− действия `registries` в каталоге      → прежний отказ о ресурсе
//	модель без `get`/`list` у типа          → находки о `get` и `list`
//	`verbs:` вместо `classes:`              → прежний отказ о ресурсе
//
// Второй близнец доказывает, что исключение не всеразрешающее: класс вне
// глаголов типа по-прежнему отвергается. Третий — что ресурс СО своей службой
// судится как прежде: пустой каталог у него остаётся находкой. Четвёртый — что
// вердикт читает ГЛАГОЛЫ МОДЕЛИ через порт, а не одно лишь членство в перечне
// исключений: та же роль на модели, в которой у типа нет `get` и `list`,
// краснеет.
package roleexport_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/manifest/roleexport"
	"github.com/PRO-Robotech/kaname/internal/manifestoracle"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

// Ресурс без своей службы и тип модели, которым его называет закрытая таблица.
const (
	withoutServiceModule   = "registry"
	withoutServiceResource = "repositories"
	withoutServiceType     = "registry_repository"
	publicReadRule         = "        classes: [get, list]"
)

// requireWithoutServicePremise — предпосылка проб файла: ресурс объявлен без
// собственной службы и резолвится в тип модели.
//
// Без неё близнецы ниже судили бы не тот путь: если запись снимут, ресурс уйдёт
// в общий путь, и «находок 0» стало бы свойством каталога, а не предмета.
func requireWithoutServicePremise(t *testing.T) {
	t.Helper()
	if _, ok := authzmap.CatalogResourcesWithoutOwnService()[withoutServiceModule+"."+withoutServiceResource]; !ok {
		t.Fatalf("предпосылка не держится: %s.%s не объявлен ресурсом без собственной службы — "+
			"пробы этого файла судили бы общий путь", withoutServiceModule, withoutServiceResource)
	}
	if got, ok := authzmap.ObjectType(withoutServiceModule, withoutServiceResource); !ok || got != withoutServiceType {
		t.Fatalf("предпосылка не держится: пара (%s, %s) резолвится в %q (ok=%v), ожидался %q",
			withoutServiceModule, withoutServiceResource, got, ok, withoutServiceType)
	}
}

// publicReadEdition — текст фикстуры новой редакции, после замены `old` на `repl`.
//
// Замена обязана сработать ровно один раз: близнец, не изменивший ничего, судил
// бы основу и выдал бы её вердикт за свой.
func publicReadEdition(t *testing.T, old, repl string) *manifest.Manifest {
	t.Helper()
	data, err := publicreadfixture.Read(publicreadfixture.NewEditionFile)
	if err != nil {
		t.Fatalf("фикстура новой редакции: %v", err)
	}
	doc := string(data)
	if old != "" {
		if n := strings.Count(doc, old); n != 1 {
			t.Fatalf("близнец: заменяемая строка %q встречается %d раз, нужна ровно одна", old, n)
		}
		doc = strings.Replace(doc, old, repl, 1)
	}
	oracle, err := manifestoracle.Canon()
	if err != nil {
		t.Fatalf("канон модели прав не разобран: %v", err)
	}
	m, err := manifest.Load([]byte(doc), manifest.WithRelationOracle(oracle))
	if err != nil {
		t.Fatalf("фикстура отвергнута загрузчиком: %v", err)
	}
	return m
}

// findingsOn — находки правил роли о названном ресурсе.
func findingsOn(faults []error, resource string) []roleexport.Finding {
	var out []roleexport.Finding
	for _, f := range faults {
		var got roleexport.Finding
		if errors.As(f, &got) && got.Resource == resource {
			out = append(out, got)
		}
	}
	return out
}

// TestRuleOnResourceWithoutOwnServiceIsJudgedByModelVerbs — предмет: роль
// новой редакции проходит ВСЕ четыре стадии, а пары над repositories судятся
// глаголами модели, и это видно в переписи.
func TestRuleOnResourceWithoutOwnServiceIsJudgedByModelVerbs(t *testing.T) {
	requireWithoutServicePremise(t)
	m := publicReadEdition(t, "", "")

	rep := roleexport.Check(catalogfixture.Facts(), m, mustActions(t))
	t.Logf("перепись: %s", rep.Summary())

	if len(rep.Faults) != 0 {
		t.Fatalf("роль новой редакции отвергнута (%d): %v", len(rep.Faults), rep.Faults)
	}
	if !rep.RulesJudged || !rep.NamedJudged {
		t.Fatalf("стадии не исполнялись: правила %v, поимённая форма %v — "+
			"«находок 0» без исполнения не вердикт", rep.RulesJudged, rep.NamedJudged)
	}
	// Два ресурса по два класса; из них по глаголам модели — ровно пары
	// repositories. Ноль здесь значил бы, что предмет не судился вовсе.
	if rep.Rules.PairsJudged != 4 {
		t.Errorf("пар (ресурс, класс) осмотрено %d, правило называет 4", rep.Rules.PairsJudged)
	}
	if rep.Rules.PairsJudgedByModelVerbs != 2 {
		t.Errorf("пар по глаголам модели %d, ожидалось 2 (get и list над repositories)",
			rep.Rules.PairsJudgedByModelVerbs)
	}
	if !strings.Contains(rep.Rules.Summary(), "по глаголам модели 2") {
		t.Errorf("перепись не называет судимое по модели: %s", rep.Rules.Summary())
	}
}

// TestRuleOnResourceWithoutOwnServiceRefusesAClassOutsideModelVerbs — близнец:
// класс, которого нет среди глаголов типа, по-прежнему находка.
//
// У `registry_repository` глаголы модели — get, list, update, delete; `create`
// пообъектного отношения на репозитории не имеет, и правило его не выдаёт.
func TestRuleOnResourceWithoutOwnServiceRefusesAClassOutsideModelVerbs(t *testing.T) {
	requireWithoutServicePremise(t)
	m := publicReadEdition(t, publicReadRule, "        classes: [get, list, create]")

	faults, census := roleexport.CheckRoleRules(catalogfixture.Facts(), m, mustActions(t))
	t.Logf("перепись: %s", census.Summary())

	got := findingsOn(faults, withoutServiceResource)
	if len(got) != 1 {
		t.Fatalf("находок о %s %d, ожидалась одна (класс create): %v", withoutServiceResource, len(got), got)
	}
	f := got[0]
	if !errors.Is(f, roleexport.ErrClassIsNotAModelVerbOfType) || f.Class != "create" {
		t.Fatalf("находка не та: вид %v, класс %q — ожидался отказ о классе create вне глаголов модели",
			f.Kind, f.Class)
	}
	for _, want := range []string{`"create"`, withoutServiceType, "delete, get, list, update"} {
		if !strings.Contains(f.Detail, want) {
			t.Errorf("отказ не называет %q: %s", want, f.Detail)
		}
	}
}

// TestResourceWithOwnServiceAndEmptyCatalogIsStillRefused — близнец: ресурс,
// у которого служба ЕСТЬ, а действий в каталоге нет, судится как прежде.
//
// Из каталога снимаются действия ровно одного ресурса — `registries`; остальное
// у входа то же, и repositories при этом по-прежнему молчит.
func TestResourceWithOwnServiceAndEmptyCatalogIsStillRefused(t *testing.T) {
	requireWithoutServicePremise(t)
	m := publicReadEdition(t, "", "")

	all := mustActions(t)
	kept := make([]roleexport.Action, 0, len(all))
	dropped := 0
	for _, a := range all {
		if a.Module == withoutServiceModule && a.Resource == "registries" {
			dropped++
			continue
		}
		kept = append(kept, a)
	}
	if dropped == 0 {
		t.Fatal("близнец ничего не изменил: действий registries в каталоге ноль — " +
			"отказ ниже был бы вердиктом основы, а не близнеца")
	}

	faults, census := roleexport.CheckRoleRules(catalogfixture.Facts(), m, kept)
	t.Logf("снято действий registries %d · перепись: %s", dropped, census.Summary())

	reg := findingsOn(faults, "registries")
	if len(reg) != 1 || !errors.Is(reg[0], roleexport.ErrRuleResourceUnknownToCatalog) {
		t.Fatalf("ресурс со своей службой и пустым каталогом не отвергнут прежним отказом: %v", reg)
	}
	if repo := findingsOn(faults, withoutServiceResource); len(repo) != 0 {
		t.Errorf("repositories покраснел от снятия чужих действий: %v", repo)
	}
}

// narrowedFacts — факт модели, в котором у одного типа глаголы ЗАМЕНЕНЫ.
//
// Остальное отвечает настоящий снимок: инъекция роняет только проверяемое.
type narrowedFacts struct {
	*catalog.Facts
	fgaType string
	verbs   []string
}

func (n narrowedFacts) VerbsOfType(fgaType string) []string {
	if fgaType == n.fgaType {
		return append([]string(nil), n.verbs...)
	}
	return n.Facts.VerbsOfType(fgaType)
}

// TestRuleOnResourceWithoutOwnServiceReadsModelVerbsThroughThePort — инъекция:
// та же роль на модели, где у типа остался один `delete`, даёт две находки.
//
// Молчание здесь значило бы, что вердикт выносит членство в перечне исключений,
// а глаголы модели не читаются вовсе — то есть исключение стало всеразрешающим.
func TestRuleOnResourceWithoutOwnServiceReadsModelVerbsThroughThePort(t *testing.T) {
	requireWithoutServicePremise(t)
	m := publicReadEdition(t, "", "")
	facts := narrowedFacts{Facts: catalogfixture.Facts(), fgaType: withoutServiceType, verbs: []string{"delete"}}

	faults, census := roleexport.CheckRoleRules(facts, m, mustActions(t))
	t.Logf("перепись: %s", census.Summary())

	got := findingsOn(faults, withoutServiceResource)
	classes := map[string]bool{}
	for _, f := range got {
		if errors.Is(f, roleexport.ErrClassIsNotAModelVerbOfType) {
			classes[f.Class] = true
		}
	}
	if len(got) != 2 || !classes["get"] || !classes["list"] {
		t.Fatalf("на модели без get/list ожидались две находки (get, list) о %s, получено %v",
			withoutServiceResource, got)
	}
}

// TestRuleOnResourceWithoutOwnServiceRefusesATypeWithoutModelVerbs — тип, не
// объявляющий в модели ни одного глагола, не покрывается НИ ОДНИМ классом.
//
// Запасного словаря у ветви нет: подмени она пустой набор общим словарём, обе
// пары молчали бы. Две находки, по одной на класс, и текст называет причину.
func TestRuleOnResourceWithoutOwnServiceRefusesATypeWithoutModelVerbs(t *testing.T) {
	requireWithoutServicePremise(t)
	m := publicReadEdition(t, "", "")
	facts := narrowedFacts{Facts: catalogfixture.Facts(), fgaType: withoutServiceType, verbs: nil}

	faults, census := roleexport.CheckRoleRules(facts, m, mustActions(t))
	t.Logf("перепись: %s", census.Summary())

	got := findingsOn(faults, withoutServiceResource)
	classes := map[string]bool{}
	for _, f := range got {
		if !errors.Is(f, roleexport.ErrClassIsNotAModelVerbOfType) {
			t.Errorf("находка не того вида: %v", f)
			continue
		}
		if !strings.Contains(f.Detail, "не объявляет в модели ни одного глагола") {
			t.Errorf("отказ не называет причину «у типа нет глаголов»: %s", f.Detail)
		}
		classes[f.Class] = true
	}
	if len(got) != 2 || !classes["get"] || !classes["list"] {
		t.Fatalf("на типе без глаголов модели ожидались две находки (get, list) о %s, получено %v",
			withoutServiceResource, got)
	}
}

// deprecatedVerbsSection — раздел снятых глаголов, дописываемый в конец
// фикстуры: `read` разрешается в `get` (глагол модели репозитория), `make` — в
// `create` (его у типа репозитория нет).
const deprecatedVerbsSection = `
deprecatedVerbs:
  read:
    class: get
    since: "2026-08-23"
    reason: >
      Синоним чтения из прежней грамматики. Ни одного RPC не адресует;
      проецируется в отношение чтения наравне с get и list.
    removeWhen: >
      Ни одна выданная привязка не ссылается на роль, чьи права содержат
      сегмент чтения прежней грамматики. Предикат: выдач с таким правом ноль.
  make:
    class: create
    since: "2026-08-23"
    reason: >
      Синоним создания из прежней грамматики. Ни одного RPC не адресует;
      проецируется в класс создания и пообъектного отношения не имеет.
    removeWhen: >
      Ни одна выданная привязка не ссылается на роль, чьи права содержат
      сегмент создания прежней грамматики. Предикат: выдач с таким правом ноль.
`

// TestRuleOnResourceWithoutOwnServiceJudgesTheClassADeprecatedVerbResolvesTo —
// снятый глагол в правиле судится КЛАССОМ, в который он разрешается, а не
// своим именем.
//
// Оба случая отличаются от общей основы ровно одним фактом — глаголом правила:
//
//	classes: [read]  → read разрешается в get → находок о repositories 0
//	classes: [make]  → make разрешается в create → одна находка о классе create
//
// Мутант, судящий имя глагола вместо класса, краснеет на обоих: `read` не
// глагол модели, а находка о `make` назвала бы класс "make".
func TestRuleOnResourceWithoutOwnServiceJudgesTheClassADeprecatedVerbResolvesTo(t *testing.T) {
	requireWithoutServicePremise(t)
	data, err := publicreadfixture.Read(publicreadfixture.NewEditionFile)
	if err != nil {
		t.Fatalf("фикстура новой редакции: %v", err)
	}
	if strings.Contains(string(data), "deprecatedVerbs:") {
		t.Fatal("предпосылка не держится: в фикстуре уже есть раздел deprecatedVerbs — " +
			"дописанный второй дал бы документ, который загрузчик судит иначе")
	}
	base := string(data) + deprecatedVerbsSection

	judge := func(t *testing.T, classes string) []roleexport.Finding {
		t.Helper()
		const old = "        classes: [get, list]"
		if n := strings.Count(base, old); n != 1 {
			t.Fatalf("близнец: заменяемая строка встречается %d раз, нужна ровно одна", n)
		}
		doc := strings.Replace(base, old, "        classes: "+classes, 1)
		oracle, err := manifestoracle.Canon()
		if err != nil {
			t.Fatalf("канон модели прав не разобран: %v", err)
		}
		m, err := manifest.Load([]byte(doc), manifest.WithRelationOracle(oracle))
		if err != nil {
			t.Fatalf("близнец отвергнут загрузчиком: %v", err)
		}
		faults, census := roleexport.CheckRoleRules(catalogfixture.Facts(), m, mustActions(t))
		t.Logf("classes %s · перепись: %s", classes, census.Summary())
		if census.PairsJudgedByModelVerbs != 1 {
			t.Fatalf("пар по глаголам модели %d, ожидалась 1 — repositories не судился моделью",
				census.PairsJudgedByModelVerbs)
		}
		return findingsOn(faults, withoutServiceResource)
	}

	t.Run("read разрешается в get и молчит", func(t *testing.T) {
		if got := judge(t, "[read]"); len(got) != 0 {
			t.Fatalf("снятый read (класс get) отвергнут на repositories: %v", got)
		}
	})
	t.Run("make разрешается в create и даёт находку", func(t *testing.T) {
		got := judge(t, "[make]")
		if len(got) != 1 {
			t.Fatalf("находок о repositories %d, ожидалась одна (класс create): %v", len(got), got)
		}
		f := got[0]
		if !errors.Is(f, roleexport.ErrClassIsNotAModelVerbOfType) || f.Class != "create" {
			t.Fatalf("находка не та: вид %v, класс %q — ожидался класс create", f.Kind, f.Class)
		}
		if !strings.Contains(f.Detail, `глагол "make" объявлен снятым и разрешается в класс "create"`) {
			t.Errorf("отказ не называет разрешение снятого глагола: %s", f.Detail)
		}
	})
}

// TestNamedFormOnResourceWithoutOwnServiceKeepsThePriorRefusal — близнец:
// поимённая форма (`verbs:` вместо `classes:`) над ресурсом без своей службы
// получает прежний отказ, а не молчание с нулём пар.
//
// Имена действий сводятся к классу по действиям каталога, а их у такого
// ресурса нет: принять перечень значило бы принять право, полноту которого
// никто не считал.
func TestNamedFormOnResourceWithoutOwnServiceKeepsThePriorRefusal(t *testing.T) {
	requireWithoutServicePremise(t)
	m := publicReadEdition(t, publicReadRule, "        verbs: [get, list]")

	faults, census := roleexport.CheckRoleRules(catalogfixture.Facts(), m, mustActions(t))
	t.Logf("перепись: %s", census.Summary())

	got := findingsOn(faults, withoutServiceResource)
	if len(got) != 1 || !errors.Is(got[0], roleexport.ErrRuleResourceUnknownToCatalog) {
		t.Fatalf("поимённая форма над %s не получила прежнего отказа: %v", withoutServiceResource, got)
	}
	if !strings.Contains(got[0].Detail, "поимённую форму `verbs`") {
		t.Errorf("отказ не называет причину для ресурса без своей службы: %s", got[0].Detail)
	}
	if census.PairsJudgedByModelVerbs != 0 {
		t.Errorf("поимённая форма засчитана судимой по модели: пар %d", census.PairsJudgedByModelVerbs)
	}
}
