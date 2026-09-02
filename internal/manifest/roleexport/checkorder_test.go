// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// checkorder_test.go — §3.6 п. 6: три проверки идут в ОБЪЯВЛЕННОМ порядке, и
// первая решает, что такое класс.
//
// Приёмка: services/iam/docs/engineering/acceptance/module-manifest-roles-and-seed-grants.md
// §3.6 п. 6 · MOD-RL-22 (Then, третья строка).
//
// # Порядок — свойство ФУНКЦИИ, а не вызывающего
//
// Проверка порядка, живущая в команде обхода дерева, не защищает второго
// вызывающего той же связки, а «валидирует команду» верно лишь для того пути,
// который до неё доходит. Поэтому порядок объявлен в `roleexport.Check`, и
// проба спрашивает ЕЁ, а не тонкую обёртку `main`.
//
// # Почему замыкание, а не «просто собрать все находки»
//
// Приёмка говорит это прямо: пока первая проверка красна, вопрос «полон ли
// перечень» и «названо ли непригодное» не имеет ОПРЕДЕЛЁННОГО МНОЖЕСТВА, по
// которому считается. Отдать вместе с отказом о классе ещё и вердикт второй
// стадии значило бы напечатать число, посчитанное по множеству, которое сама же
// первая стадия объявила неверным.
package roleexport_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest/roleexport"
	"github.com/PRO-Robotech/kacho/services/iam/internal/testsupport/catalogfixture"
)

// TestStageOneRunsBeforeStageTwoInsideTheSameFunction — порядок и замыкание.
//
// Вход несёт находки ОБЕИХ стадий сразу, и это существенно: манифест только с
// одной из них не отличил бы «порядок соблюдён» от «второй стадии здесь нечего
// сказать».
//
//   - стадия 1 (MOD-RL-22): `network.listOperations` объявлен классом `get`,
//     гейт спрашивает `v_list`;
//   - стадия 2 (MOD-RL-05): роль называет ресурс `network` классом `create`,
//     пригодных действий у которого ноль (гейт `editor@project`).
func TestStageOneRunsBeforeStageTwoInsideTheSameFunction(t *testing.T) {
	m := mustLoadManifest(t, bothStagesManifest)
	rep := roleexport.Check(catalogfixture.Facts(), m, mustActions(t))

	t.Logf("перепись: %s", rep.Summary())

	if len(findingsOf(rep.Faults, roleexport.ErrDeclaredClassDoesNotSatisfyGate)) != 1 {
		t.Fatalf("отказа стадии 1 нет — вход пробы не производит того, что она утверждает: %v",
			rep.Faults)
	}
	for _, f := range rep.Faults {
		if errors.Is(f, roleexport.ErrClassCoversNoSuitableAction) {
			t.Errorf("вердикт стадии 2 вынесен по множеству, которое стадия 1 объявила "+
				"неверным: %v", f)
		}
	}
	if rep.RulesJudged {
		t.Error("стадия 2 объявлена исполненной при красной стадии 1")
	}
	// «Не выполнилось» обязано быть НАЗВАНО, а не выведено из нуля находок.
	if !strings.Contains(rep.Summary(), "НЕ ИСПОЛНЯЛАСЬ") {
		t.Errorf("перепись не говорит, что вторая стадия не исполнялась: %s", rep.Summary())
	}
}

// TestStageTwoRunsWhenStageOneIsGreen — законный близнец порядка.
//
// Тот же манифест с ЕДИНСТВЕННОЙ правкой — класс `listOperations` приведён к
// `list`. Стадия 1 молчит, и вердикт стадии 2 обязан появиться. Без этой пробы
// замыкание зеленело бы на реализации, не зовущей вторую стадию НИКОГДА.
func TestStageTwoRunsWhenStageOneIsGreen(t *testing.T) {
	m := mustLoadManifest(t, strings.Replace(bothStagesManifest,
		"{name: listOperations, class: get}", "{name: listOperations, class: list}", 1))
	rep := roleexport.Check(catalogfixture.Facts(), m, mustActions(t))

	t.Logf("перепись: %s", rep.Summary())
	if !rep.RulesJudged {
		t.Fatal("стадия 1 зелена, а стадия 2 не исполнялась — замыкание безусловно")
	}
	if len(findingsOf(rep.Faults, roleexport.ErrDeclaredClassDoesNotSatisfyGate)) != 0 {
		t.Fatalf("стадия 1 обязана молчать: %v", rep.Faults)
	}
	if len(rep.Faults) == 0 {
		t.Fatal("стадия 2 исполнена и молчит — а её вход несёт пустой класс `create` " +
			"на названном поимённо ресурсе")
	}
	var empty bool
	for _, f := range rep.Faults {
		if errors.Is(f, roleexport.ErrClassCoversNoSuitableAction) {
			empty = true
		}
	}
	if !empty {
		t.Errorf("отказ стадии 2 не того вида: %v", rep.Faults)
	}
}

// bothStagesManifest — вход, несущий находку каждой из двух стадий.
const bothStagesManifest = `apiVersion: iam/v1
module: vpc
resources:
  - name: network
    objectType: vpc_network
    parents: [project]
    producer: derived
    verbs: [get, list, create, update, delete, {name: listOperations, class: get}]
roles:
  - id: vpc.creator
    description: Роль пробы порядка.
    tier: {tierType: iam.project, tierId: prj000000000000000}
    rules:
      - module: vpc
        resources: [network]
        classes: [create]
`
