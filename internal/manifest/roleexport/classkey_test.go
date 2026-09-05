// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// classkey_test.go — стадия 1 судит значение НОВОГО ключа права роли
// (приёмка `classes-form-of-role-right.md`, §3.1 и §4.3; сценарии
// MOD-RC-09, MOD-RC-10, MOD-RC-12).
//
// # Почему эти сценарии живут здесь, а не у загрузчика
//
// Загрузчик судит ФОРМУ: ключ, тип, мощность. ЗНАЧЕНИЕ — покрывает ли класс
// хотя бы одно пригодное действие названного ресурса — судит стадия 1, и
// закрытой проверки набора на загрузке к ключу `classes:` намеренно НЕТ (§3.1):
// словарь снятых имён принадлежит самому манифесту, поэтому «имя вне обоих
// словарей» есть суждение о значении, а не о форме.
//
// # MOD-RC-10 утверждает ПЕРЕПИСЬ, а не находки
//
// Проверка, ослепшая после смены ключа, даёт НОЛЬ находок — то есть выглядит
// ровно так же, как исправная. Отличает их только вторая величина: сколько пар
// (ресурс, класс) осмотрено. Инъекция И7 воспроизводит именно это состояние.
package roleexport_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/manifest/roleexport"
	"github.com/PRO-Robotech/kacho-iam/internal/testsupport/catalogfixture"
)

// classKeyManifest — манифест, у которого стадия 1 зелена, а право роли
// записано ОСНОВНОЙ формой. Подставляется только перечень классов.
//
// Раздел `deprecatedVerbs` объявлен намеренно: он и есть второй законный
// словарь значения ключа `classes:` (§3.1), и без него парный положительный
// MOD-RC-12 был бы невыразим.
func classKeyManifest(classes string) string {
	return `apiVersion: iam/v1
module: vpc
resources:
  - name: network
    objectType: vpc_network
    parents: [project]
    producer: derived
    verbs: [get, list, create, update, delete, {name: listOperations, class: list}]
roles:
  - id: vpc.viewer
    description: Роль пробы ключа classes.
    tier: {tierType: iam.project, tierId: prj000000000000000}
    rules:
      - module: vpc
        resources: [network]
        classes: ` + classes + `
deprecatedVerbs:
  read:
    class: get
    since: "2026-08-23"
    reason: Синоним чтения из прежней грамматики.
    removeWhen: Выдач с правом ` + "`.read`" + ` ноль.
`
}

// ── MOD-RC-09 ───────────────────────────────────────────────────────────────

// TestMODRC09StageOneJudgesTheClassesKey — пустой класс по-прежнему
// отвергается, и отказ приходит по НОВОМУ ключу.
//
// Пара `(network, create)` взята у MOD-RL-05 приёмки #1090 ДОСЛОВНО, а не
// выведена заново: второй вывод той же величины разошёлся бы с первым молча —
// у типа `vpc_network` отношения `v_create` нет.
func TestMODRC09StageOneJudgesTheClassesKey(t *testing.T) {
	rep := roleexport.Check(catalogfixture.Facts(),
		mustLoadManifest(t, classKeyManifest("[create]")), mustActions(t))
	t.Logf("перепись: %s", rep.Summary())

	if !rep.RulesJudged {
		t.Fatal("стадия 2 не исполнялась — вход пробы не производит того, что она утверждает")
	}
	var empty int
	for _, f := range rep.Faults {
		if errors.Is(f, roleexport.ErrClassCoversNoSuitableAction) {
			empty++
		}
	}
	if empty != 1 {
		t.Fatalf("находок пустого класса %d, ожидалась одна: правило записано ключом "+
			"classes, и стадия 1 обязана его читать; находки: %v", empty, rep.Faults)
	}
	if rep.Rules.PairsJudged < 1 {
		t.Fatalf("пар (ресурс, класс) осмотрено %d — находка при нулевой переписи была бы "+
			"свойством обхода, а не дерева", rep.Rules.PairsJudged)
	}

	// Парный положительный: класс `get` покрывает одно пригодное действие
	// (`NetworkService/Get` под `v_get@vpc_network`); `internalGetNetwork`
	// непригоден — его гейт спрашивает `system_viewer` на `cluster`.
	ok := roleexport.Check(catalogfixture.Facts(),
		mustLoadManifest(t, classKeyManifest("[get]")), mustActions(t))
	t.Logf("перепись парного положительного: %s", ok.Summary())
	if len(ok.Faults) != 0 {
		t.Fatalf("парный положительный дал находки: %v", ok.Faults)
	}
	if ok.Rules.PairsJudged != 1 {
		t.Errorf("у парного положительного пар осмотрено %d, ожидалась одна", ok.Rules.PairsJudged)
	}
}

// ── MOD-RC-10 ───────────────────────────────────────────────────────────────

// TestMODRC10BlindStageOneIsSeenByTheCensusNotByTheFindings — стадия 1,
// ослепшая после смены ключа, краснеет ПЕРЕПИСЬЮ.
//
// Вход тот же, что у MOD-RC-09, но утверждение здесь — ВТОРАЯ величина:
// проверка, не прочитавшая ни одной пары, даёт ноль находок и выглядит
// зелёной. Это единственный способ отличить «нарушений нет» от «не прочитано
// ничего».
func TestMODRC10BlindStageOneIsSeenByTheCensusNotByTheFindings(t *testing.T) {
	for _, classes := range []string{"[create]", "[get]"} {
		rep := roleexport.Check(catalogfixture.Facts(),
			mustLoadManifest(t, classKeyManifest(classes)), mustActions(t))
		t.Logf("классы %s → перепись: %s", classes, rep.Summary())
		if rep.Rules.PairsJudged != 1 {
			t.Errorf("классы %s: пар (ресурс, класс) осмотрено %d, а правило называет "+
				"один ресурс и один класс — проверка читает не тот ключ",
				classes, rep.Rules.PairsJudged)
		}
		if rep.Rules.RulesRead != 1 {
			t.Errorf("классы %s: правил осмотрено %d, в манифесте одно", classes, rep.Rules.RulesRead)
		}
	}
}

// ── MOD-RC-12 ───────────────────────────────────────────────────────────────

// TestMODRC12NameOutsideBothVocabulariesIsJudgedByStageOne — имя вне ОБОИХ
// словарей отвергается позже и СВОЕЙ причиной.
//
// Сценарий закрепляет решение §3.1: закрытая проверка набора на загрузке к
// ключу `classes:` НЕ применяется. Без него исполнитель повторит
// `ErrVerbClassUnknown` «по аналогии» с разделом `resources`, и снятое имя
// `read` не доживёт до `domain.Rule` — MOD-RC-02 стал бы неисполним.
func TestMODRC12NameOutsideBothVocabulariesIsJudgedByStageOne(t *testing.T) {
	// Загрузчик документ ПРИНИМАЕТ: его предмет — форма.
	m := mustLoadManifest(t, classKeyManifest("[addCidrBlocks]"))
	if got := m.Roles[0].Rules[0].Classes; len(got) != 1 || got[0] != "addCidrBlocks" {
		t.Fatalf("значение ключа classes прочитано как %#v", got)
	}

	rep := roleexport.Check(catalogfixture.Facts(), m, mustActions(t))
	t.Logf("перепись: %s", rep.Summary())
	var found int
	var detail string
	for _, f := range rep.Faults {
		if errors.Is(f, roleexport.ErrClassCoversNoSuitableAction) {
			found++
			detail = f.Error()
		}
	}
	if found != 1 {
		t.Fatalf("находок пустого класса %d, ожидалась одна: имя вне обоих словарей судит "+
			"стадия 1, а не загрузчик; находки: %v", found, rep.Faults)
	}
	for _, want := range []string{"addCidrBlocks", "network", "vpc"} {
		if !strings.Contains(detail, want) {
			t.Errorf("отказ не называет %q: %s", want, detail)
		}
	}

	// Парный положительный: снятое имя, ОБЪЯВЛЕННОЕ разделом deprecatedVerbs
	// этого же манифеста, разрешается в класс `get` — находок ноль.
	ok := roleexport.Check(catalogfixture.Facts(),
		mustLoadManifest(t, classKeyManifest("[read]")), mustActions(t))
	t.Logf("перепись парного положительного: %s", ok.Summary())
	if len(ok.Faults) != 0 {
		t.Fatalf("снятое имя, объявленное манифестом, дало находки: %v", ok.Faults)
	}
	if ok.Rules.PairsJudged != 1 {
		t.Errorf("у парного положительного пар осмотрено %d, ожидалась одна", ok.Rules.PairsJudged)
	}
}
