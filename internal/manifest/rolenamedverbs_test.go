// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// rolenamedverbs_test.go — ПОИМЁННАЯ форма права роли: ключ `verbs`
// (задача kacho#1844, половина 2; приёмка
// `services/iam/docs/engineering/acceptance/module-manifest-roles-and-seed-grants.md`
// §3.6, сценарии MOD-RL-04 и MOD-RL-04a).
//
// # Почему ключ ВЕРНУЛСЯ, и почему только сейчас
//
// Он был снят приёмкой `classes-form-of-role-right.md` (§3.2) и отвергался
// пред-разборной проверкой со своим сентинелом. Снятие было ПОРЯДКОМ, а не
// запретом: §10 п. 2 той же приёмки говорит дословно, что поимённая форма
// заводится **вместе с** проверкой её полноты и что ключ возвращает эта задача.
// Принять перечень ИМЁН, не умея проверить его полноту по классу, значит свести
// его к классу МОЛЧА и выдать право шире просимого.
//
// # Что судит ЗАГРУЗЧИК, а что — экспортёр
//
// Здесь — ФОРМА и СУЩЕСТВОВАНИЕ названного: две формы права не стоят рядом
// (§3.1), а каждое названное имя объявлено разделом `resources` либо разделом
// `deprecatedVerbs` этого же манифеста (MOD-RL-04). Обе проверки
// манифест-внутренние: каталог прав для них не нужен, и спрашивать его здесь
// значило бы тянуть его в разбор.
//
// ПОЛНОТУ перечня по классу (MOD-RL-18) и ПРИГОДНОСТЬ названного действия
// (MOD-RL-19) судит `roleexport` — им нужен каталог. Разделение стадий — §3.6,
// врезка «Чья это стадия»: вердикт загрузчика «целостно» не означает
// «экспортируемо», и MOD-RL-04a c MOD-RL-18 стоят на ОДНОМ входе с разными
// исходами именно поэтому.
package manifest_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
)

// namedVerbManifest — манифест с ОДНИМ ресурсом и одной ролью, записанными
// дословно. Раздел `resources` здесь обязателен: MOD-RL-04 судит названное имя
// против него, и манифест без ресурсов сделал бы отказ беспредметным.
//
// Действия `subnet` взяты у фикстуры соседних проб (`testdata/`), а не выдуманы:
// класс `update` обязан покрывать ровно `{update, addCidrBlocks,
// removeCidrBlocks}`, иначе положительный контроль MOD-RL-04a перестал бы
// различать предмет.
func namedVerbManifest(subnetVerbs, rule string) string {
	return "apiVersion: iam/v1\nmodule: vpc\n" +
		"resources:\n" +
		"  - name: subnet\n    objectType: vpc_subnet\n    parents: [project]\n" +
		"    producer: derived\n    verbs:\n" + subnetVerbs +
		"roles:\n" +
		"  - id: vpc.viewer\n    description: Читает топологию сетей проекта.\n" +
		"    tier: {tierType: iam.project, tierId: prj000000000000000}\n" +
		"    rules:\n      - " + rule + "\n"
}

// subnetVerbsFull — раздел действий `subnet` c действием `addCidrBlocks` НА МЕСТЕ.
const subnetVerbsFull = "" +
	"      - get\n      - list\n      - create\n      - update\n      - delete\n" +
	"      - {name: listOperations,    class: list}\n" +
	"      - {name: addCidrBlocks,     class: update}\n" +
	"      - {name: removeCidrBlocks,  class: update}\n"

// subnetVerbsWithoutAddCidr — тот же раздел, из которого действие `addCidrBlocks`
// СНЯТО. Ровно один знак разницы с предыдущим — иначе пара различала бы не то.
const subnetVerbsWithoutAddCidr = "" +
	"      - get\n      - list\n      - create\n      - update\n      - delete\n" +
	"      - {name: listOperations,    class: list}\n" +
	"      - {name: removeCidrBlocks,  class: update}\n"

// ── MOD-RL-04 ───────────────────────────────────────────────────────────────

// TestMODRL04RetiredActionInANamedRightIsRefused — отрицательный.
//
// Given роль с правом `verbs: [addCidrBlocks]` на ресурсе `subnet`
// And действие `addCidrBlocks` из раздела `resources` СНЯТО
// When валидатор целостности читает манифест
// Then отказ называет роль, модуль, ресурс и действие и говорит, что такого
// действия в контракте нет.
func TestMODRL04RetiredActionInANamedRightIsRefused(t *testing.T) {
	_, err := manifest.Load([]byte(namedVerbManifest(subnetVerbsWithoutAddCidr,
		"{module: vpc, resources: [subnet], verbs: [addCidrBlocks]}")))
	if err == nil {
		t.Fatal("право назвало снятое действие, и манифест принят: право, ссылающееся " +
			"на несуществующее действие, применилось бы и выглядело бы действующим")
	}
	if !errors.Is(err, manifest.ErrRoleRuleVerbUnknownToContract) {
		t.Errorf("отказ не отнесён к своей причине (ожидался ErrRoleRuleVerbUnknownToContract): %v", err)
	}
	// Четыре координаты отказа — по одной на каждую, чтобы «отказ называет» не
	// вырождалось в «отказ существует».
	for _, want := range []string{"vpc.viewer", "vpc", "subnet", "addCidrBlocks"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}
	if !strings.Contains(err.Error(), "line ") {
		t.Errorf("отказ не называет номер строки: %v", err)
	}
}

// TestMODRL04aActionPresentIsSilent — ПАРНЫЙ ПОЛОЖИТЕЛЬНЫЙ.
//
// Тот же манифест, где действие на месте: валидатор молчит, вердикт «целостно».
// Без него отказ MOD-RL-04 зеленел бы на загрузчике, отвергающем ВСЯКИЙ
// поимённый перечень, — то есть на реализации, ключ так и не вернувшей.
//
// > «Целостно» — вердикт ЗАГРУЗЧИКА и не означает «экспортируемо». Тот же вход
// > стои́т `Given`-ом у MOD-RL-18 и там отвергается: названное имя существует
// > (это и проверил загрузчик), а перечень не полон по классу `update`.
func TestMODRL04aActionPresentIsSilent(t *testing.T) {
	m, err := manifest.Load([]byte(namedVerbManifest(subnetVerbsFull,
		"{module: vpc, resources: [subnet], verbs: [addCidrBlocks]}")))
	if err != nil {
		t.Fatalf("парный положительный отвергнут: %v", err)
	}
	if len(m.Roles) != 1 || len(m.Roles[0].Rules) != 1 {
		t.Fatalf("ролей %d, правил у первой %d — документ несёт по одному",
			len(m.Roles), len(m.Roles[0].Rules))
	}
	got, named := m.Roles[0].Rules[0].Right()
	if !named {
		t.Errorf("право прочитано как форма классов, а документ несёт поимённую")
	}
	if len(got) != 1 || got[0] != "addCidrBlocks" {
		t.Errorf("поимённое право прочитано как %#v, документ несёт [addCidrBlocks]", got)
	}
}

// TestMODRL04SnatchedActionNamedByDeprecatedVerbsIsNotSnatched — снятое действие,
// названное `deprecatedVerbs`, действием ОСТАЁТСЯ (MOD-RL-06, здесь — на
// поимённой форме).
//
// Отрицательный контроль внутри сценария: без чтения `deprecatedVerbs` ярус
// чтения, воспроизводимый дословно, получил бы отказ на первом же своём глаголе.
func TestMODRL04SnatchedActionNamedByDeprecatedVerbsIsNotSnatched(t *testing.T) {
	doc := namedVerbManifest(subnetVerbsFull,
		"{module: vpc, resources: [subnet], verbs: [read]}") +
		"deprecatedVerbs:\n  read:\n    class: get\n    since: \"2026-08-23\"\n" +
		"    reason: Синоним чтения из прежней грамматики.\n" +
		"    removeWhen: Выдач с правом `.read` ноль.\n"
	if _, err := manifest.Load([]byte(doc)); err != nil {
		t.Fatalf("снятое действие, объявленное `deprecatedVerbs`, отвергнуто: %v", err)
	}
}

// ── Форма: две записи права рядом не стоят ──────────────────────────────────

// TestNamedAndClassFormsDoNotStandTogether — §3.1: значение, выразимое двумя
// способами, даёт вопрос «какой из них решает», у которого нет ответа в коде.
//
// Наследник MOD-RC-04: его предмет («наличие `classes:` не делает `verbs:`
// законным») снят вместе с запретом ключа, а сама взаимоисключаемость — нет.
func TestNamedAndClassFormsDoNotStandTogether(t *testing.T) {
	_, err := manifest.Load([]byte(namedVerbManifest(subnetVerbsFull,
		"{module: vpc, resources: [subnet], classes: [update], verbs: [addCidrBlocks]}")))
	if err == nil {
		t.Fatal("правило с обеими формами принято: одна из них уехала бы молча")
	}
	if !errors.Is(err, manifest.ErrRoleRuleRightFormsCollide) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	for _, want := range []string{"classes", "verbs", "roles[0].rules[0]"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}

	// Парные положительные — ОБА, по одному на форму: отказ обязан вызывать
	// соседство двух записей, а не любая из них по отдельности.
	for _, rule := range []string{
		"{module: vpc, resources: [subnet], classes: [update]}",
		"{module: vpc, resources: [subnet], verbs: [addCidrBlocks]}",
	} {
		if _, err := manifest.Load([]byte(namedVerbManifest(subnetVerbsFull, rule))); err != nil {
			t.Errorf("парный положительный %q отвергнут: %v", rule, err)
		}
	}
}

// TestNamedRightDoesNotReachTheApplierUnreduced — ПРИМЕНИТЕЛЬ не получает
// поимённого права несведённым (§3.6 п. 5).
//
// Сведение поимённого перечня к классу законно ТОЛЬКО после проверки его
// полноты, а она требует каталога прав, которого у загрузчика нет. Значит
// `DomainRule()` — путь применителя — обязан отдавать поимённое право
// НЕПРИГОДНЫМ к применению, а не сводить его сам: сведение без проверки и есть
// то молчаливое расширение, ради запрета которого форма снималась.
//
// Fail-closed проверяется ИСХОДОМ домена, а не формой вызова: правило без
// глаголов домен отвергает, и применитель на нём останавливается.
func TestNamedRightDoesNotReachTheApplierUnreduced(t *testing.T) {
	m, err := manifest.Load([]byte(namedVerbManifest(subnetVerbsFull,
		"{module: vpc, resources: [subnet], verbs: [addCidrBlocks]}")))
	if err != nil {
		t.Fatalf("манифест отвергнут: %v", err)
	}
	if got := m.Roles[0].Rules[0].DomainRule().Verbs; len(got) != 0 {
		t.Errorf("путь применителя отдал поимённое право как %#v: несведённый перечень "+
			"имён домен трактует поглагольно, то есть выдал бы право ИНОЕ, чем просили", got)
	}

	// Парный положительный: форма классов тем же путём проходит ДОСЛОВНО —
	// иначе отрицание зеленело бы на `DomainRule`, обнуляющем всё подряд.
	m2, err := manifest.Load([]byte(namedVerbManifest(subnetVerbsFull,
		"{module: vpc, resources: [subnet], classes: [update]}")))
	if err != nil {
		t.Fatalf("парный положительный отвергнут: %v", err)
	}
	got := m2.Roles[0].Rules[0].DomainRule().Verbs
	if len(got) != 1 || got[0] != "update" {
		t.Errorf("форма классов на пути применителя дала %#v, документ несёт [update]", got)
	}
}
