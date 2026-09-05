// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// attributionspelling_injection_test.go — доказательство способности проб
// написания падать И молчать (задача #1884).
//
// Инъекция подаёт синтетический вход ТЕМ ЖЕ функциям, которые судят настоящий
// (judgeSpellingReach, judgeSpellingDivergences), — не их похожей копии: копия,
// которую нельзя скомпилировать против оригинала, расходится молча.
//
// # Прогонов ТРИ на каждую сторону, и третий несущий
//
//	контроль             — вход согласован, находок ноль;
//	инъекция НОВОГО      — краснеет ровно проверяемое свойство;
//	инъекция СУЩЕСТВУЮЩЕГО — краснеет ровно соседнее, и не вместе с новым.
//
// Без третьего молчание соседней проверки неотличимо от молчания мёртвой.
package roleexport_test

import (
	"strings"
	"testing"
)

func spellingFixture() (produced map[string]struct{}, keys []string, without map[string]string) {
	produced = map[string]struct{}{
		"vpc.network":               {},
		"loadbalancer.targetGroups": {},
	}
	keys = []string{"vpc.network", "loadbalancer.targetGroups", "registry.repositories"}
	without = map[string]string{"registry.repositories": "своей службы нет"}
	return produced, keys, without
}

func TestSpellingReachJudgeIsSilentWhenEveryKeyIsProduced(t *testing.T) {
	produced, keys, without := spellingFixture()

	unreachable, reached := judgeSpellingReach(produced, keys, without)
	t.Logf("контроль: ключей %d · производится %d · исключений %d",
		len(keys), reached, len(without))

	if len(unreachable) != 0 {
		t.Fatalf("контроль покраснел на согласованном входе: %v", unreachable)
	}
	// Законный близнец назван ЧИСЛОМ: ключ без своей службы не произведён и
	// находкой не стал, при этом счётчик произведённых его не засчитал.
	if reached != 2 {
		t.Fatalf("произведённых %d, ожидалось 2 — исключение зачтено в произведённые "+
			"либо близнец не подан", reached)
	}
}

func TestSpellingReachJudgeCatchesAKeyNoServiceNameProduces(t *testing.T) {
	produced, keys, without := spellingFixture()
	keys = append(keys, "storage.volumes") // ключ есть, привязка его не производит

	unreachable, reached := judgeSpellingReach(produced, keys, without)
	t.Logf("инъекция ключа: ключей %d · производится %d", len(keys), reached)

	if len(unreachable) != 1 || unreachable[0] != "storage.volumes" {
		t.Fatalf("ожидалась ровно одна находка с координатой `storage.volumes`, получено %v",
			unreachable)
	}
}

// TestSpellingReachJudgeIsSilentOnAKeyDeclaredWithoutItsOwnService — законный
// близнец отдельным прогоном: ключ, не произведённый привязкой, но объявленный
// не имеющим своей службы, находкой НЕ становится.
//
// Без него сторона достижимости краснела бы на всяком грантуемом ресурсе, у
// которого службы нет by construction, и первое ложное срабатывание сняло бы
// пробу целиком.
func TestSpellingReachJudgeIsSilentOnAKeyDeclaredWithoutItsOwnService(t *testing.T) {
	produced, keys, without := spellingFixture()
	keys = append(keys, "storage.volumes")
	without["storage.volumes"] = "объявлено без своей службы"

	unreachable, reached := judgeSpellingReach(produced, keys, without)
	t.Logf("законный близнец: ключей %d · производится %d · исключений %d",
		len(keys), reached, len(without))

	if len(unreachable) != 0 {
		t.Fatalf("проба покраснела на объявленном исключении: %v", unreachable)
	}
}

func TestSpellingDivergenceJudgeIsSilentOnALiveEntry(t *testing.T) {
	keys := map[string]struct{}{"loadbalancer.targetGroups": {}}
	div := map[string]string{"loadbalancer.targetGroup": "loadbalancer.targetGroups"}

	faults := judgeSpellingDivergences(div, keys)
	t.Logf("контроль: записей %d · ключей %d", len(div), len(keys))

	if len(faults) != 0 {
		t.Fatalf("контроль покраснел на живой записи:\n  %s", strings.Join(faults, "\n  "))
	}
}

func TestSpellingDivergenceJudgeCatchesAnEntryWithoutASubject(t *testing.T) {
	keys := map[string]struct{}{"loadbalancer.targetGroups": {}}

	cases := map[string]struct {
		div  map[string]string
		want string
	}{
		"стороны совпали": {
			div:  map[string]string{"loadbalancer.targetGroups": "loadbalancer.targetGroups"},
			want: "к самому себе",
		},
		"цель не ключ таблицы": {
			div:  map[string]string{"loadbalancer.targetGroup": "loadbalancer.targetGroupses"},
			want: "ведёт в никуда",
		},
		"источник сам ключ таблицы": {
			div:  map[string]string{"loadbalancer.targetGroups": "loadbalancer.targetGroup"},
			want: "ИСТОЧНИК сам является ключом",
		},
	}

	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			faults := judgeSpellingDivergences(c.div, keys)
			if len(faults) == 0 {
				t.Fatal("инъекция не покраснела: запись без предмета принята за живую")
			}
			joined := strings.Join(faults, "\n")
			if !strings.Contains(joined, c.want) {
				t.Fatalf("находка пришла не от той ветви: %s", joined)
			}
		})
	}
}
