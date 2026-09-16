// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package deploy_test

// chart_raise_has_a_holder_injection_test.go — ОПЫТ: способен ли гейт держателя
// подъёма упасть и способен ли он смолчать.
//
// Каждая пара отличается РОВНО ОДНИМ фактом против своего законного близнеца.
// Вход синтетический и подаётся тем же предикатом, который исполняется на
// дереве: своя копия предиката доказывала бы свойство копии.

import (
	"strings"
	"testing"
)

// wf — процесс из одного задания с одним шагом названного тела.
func wf(run string) map[string]string {
	return map[string]string{"синтетика.yml": "" +
		"on:\n  push:\n    branches: [main]\njobs:\n  chart:\n    steps:\n" +
		"      - name: шаг\n        run: |\n" + indent(run)}
}

func indent(s string) string {
	var b strings.Builder
	for _, l := range strings.Split(strings.TrimRight(s, "\n"), "\n") {
		b.WriteString("          " + l + "\n")
	}
	return b.String()
}

// legalBody — тело шага, каким его несёт дерево: подъём, сверка, снос и разбор
// исхода с третьей категорией.
const legalBody = `rc=0
.github/scripts/stand-chart.sh up || rc=$?
case "$rc" in
  0) echo ok ;;
  75) echo "::error::УСЛОВИЕ НЕ СОЗДАНО"; exit 1 ;;
  *) exit "$rc" ;;
esac
.github/scripts/stand-chart.sh assert
.github/scripts/stand-chart.sh down || true`

// TestChartRaiseGate_SilentOnTheLegalBody — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
//
// Без него всякое отрицание ниже зеленело бы и на предикате, который находит
// нарушение всегда.
func TestChartRaiseGate_SilentOnTheLegalBody(t *testing.T) {
	found, census, err := auditChartRaise(wf(legalBody))
	if err != nil {
		t.Fatalf("разбор синтетики отказал: %v", err)
	}
	if len(found) != 0 {
		t.Fatalf("законное тело объявлено находкой: %v", found)
	}
	if census.UpCalls != 1 || census.Asserts != 1 || census.Teardown != 1 || census.Unmet != 1 {
		t.Fatalf("перепись законного тела: %+v — предикат считает не то", census)
	}
}

// TestChartRaiseGate_MentionInProseIsNotACall — РАСПОЗНАВАТЕЛЬ ЗНАЕТ, ЧТО
// КОММЕНТАРИЙ НЕ ВЫЗОВ.
//
// Отличие от близнеца ровно одно: те же строки закомментированы. Без этой
// стороны гейт зеленел бы на задании, которое подъёмщик лишь упоминает, — то
// есть ровно там, где держателя нет.
func TestChartRaiseGate_MentionInProseIsNotACall(t *testing.T) {
	var prose strings.Builder
	for _, l := range strings.Split(legalBody, "\n") {
		prose.WriteString("# " + l + "\n")
	}
	_, census, err := auditChartRaise(wf(prose.String()))
	if err != nil {
		t.Fatalf("разбор синтетики отказал: %v", err)
	}
	if census.UpCalls != 0 || census.Asserts != 0 || census.Teardown != 0 {
		t.Fatalf("упоминание в прозе зачтено за вызов: %+v", census)
	}
}

// TestChartRaiseGate_RaiseWithoutTheThirdOutcomeIsAFinding — ИНЪЕКЦИЯ.
//
// Отличие от законного тела ровно одно: ветвь по коду 75 снята. Тогда
// неподнявшийся кластер доедет красным как находка о дереве — то есть «условие
// не создано» будет подано вердиктом о продукте.
func TestChartRaiseGate_RaiseWithoutTheThirdOutcomeIsAFinding(t *testing.T) {
	body := strings.ReplaceAll(legalBody, `  75) echo "::error::УСЛОВИЕ НЕ СОЗДАНО"; exit 1 ;;`+"\n", "")
	if body == legalBody {
		t.Fatal("ПРЕДПОСЫЛКА ОПЫТА: портить было нечего — законное тело не несло ветви 75")
	}
	found, census, err := auditChartRaise(wf(body))
	if err != nil {
		t.Fatalf("разбор синтетики отказал: %v", err)
	}
	if census.UpCalls != 1 {
		t.Fatalf("подъём не распознан: %+v — красное пришло бы по обеднённому миру", census)
	}
	if len(found) == 0 {
		t.Fatal("подъём без третьей категории прошёл молча: гейт потерял способность падать")
	}
	if !strings.Contains(strings.Join(found, "\n"), "условие не создано") {
		t.Fatalf("находка есть, но не та: %v", found)
	}
}

// TestChartRaiseGate_EmptyWalkIsNotSilence — пустой обход виден ЧИСЛАМИ.
//
// «Находок ноль» на пустом входе обязано быть отличимо от «находок ноль» на
// прочитанном дереве — это и есть та половина, которой гейт без переписи не
// имеет.
func TestChartRaiseGate_EmptyWalkIsNotSilence(t *testing.T) {
	found, census, err := auditChartRaise(map[string]string{})
	if err != nil {
		t.Fatalf("разбор пустого входа отказал: %v", err)
	}
	if len(found) != 0 {
		t.Fatalf("пустой обход дал находки: %v", found)
	}
	if census.Files != 0 || census.Steps != 0 || census.UpCalls != 0 {
		t.Fatalf("перепись пустого обхода непуста: %+v", census)
	}
}
