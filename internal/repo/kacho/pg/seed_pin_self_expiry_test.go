// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// seed_pin_self_expiry_test.go — САМОИСТЕЧЕНИЕ перечня пинов, вынесенное в одно
// место и доказанное инъекцией.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Оба гейта сегмента посева несут перечень пинов — записей, чья нерезолвимость
// объявлена осознанно: [knownUnresolvableSeedPairs] (ресурсная половина) и
// [knownUnresolvableSeedVerbs] (глагольная). Послабление обязано истекать САМО:
// запись, которой больше нечего исключать, есть находка, иначе перечень
// переживает свой предмет и становится ложным утверждением о дереве.
//
// Свойство у обоих гейтов БЫЛО, и оно верно. Держалось оно, однако, разовым
// прогоном рецензента, а не деревом: правка, снимающая самоистечение, не могла
// покраснить ничего — перечень живёт в теле гейта, который требует Postgres, а
// ни одна проба его не трогала (#1841).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ОДНА ФУНКЦИЯ НА ДВА ГЕЙТА
//
// Предмет у них один — «запись без предмета», — а перечни разные. Вторая
// реализация самоистечения разошлась бы с первой молча: обе дают «ноль находок»
// на честном перечне, и различие видно только на том входе, ради которого они
// написаны. Поэтому разбор здесь ОДИН, а гейты передают ему свой перечень и своё
// имя.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТА ПРОБА НЕ ТРЕБУЕТ POSTGRES
//
// Она судит РАЗБОР, а не посев: множество увиденных ключей подаётся ей прямо.
// Требуй она контейнера — доказательство способности упасть жило бы там же, где
// и раньше: в прогоне, который на этой машине не запускался ни разу за круг.
package pg_test

import (
	"sort"
	"strings"
	"testing"
)

// stalePinFindings — записи перечня, которым больше нечего исключать.
//
// Возвращает готовые тексты находок, а не ключи: сообщение — часть свойства, и
// два гейта, пишущие его порознь, разошлись бы в том, что читает человек.
// `ledger` — имя перечня в исходнике, `subject` — чем он пинит («пары»,
// «глагола»), оба входят в текст.
func stalePinFindings(ledger, subject string, pins map[string]string, seen map[string]bool) []string {
	var stale []string
	for key := range pins {
		if !seen[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)

	out := make([]string, 0, len(stale))
	for _, key := range stale {
		out = append(out, "запись пина без предмета: «"+key+"» перечислена в "+ledger+
			", но такого "+subject+" в посеве нет.\n"+
			"Имя привели к словарю, роль удалили либо правило сняли — сними и запись, "+
			"иначе перечень описывает мир, которого нет.")
	}
	return out
}

// TestSeedPinSelfExpiry_CanFailAndStaysSilent — способность самоистечения упасть
// и СМОЛЧАТЬ, обе стороны в одном прогоне.
//
// Разбор вызывается с подставным перечнем и подставным множеством увиденного:
// инъекция подменяет ВХОД, а не сам разбор.
func TestSeedPinSelfExpiry_CanFailAndStaysSilent(t *testing.T) {
	const ledger = "knownUnresolvableSeedVerbs"
	const subject = "нерезолвящегося глагола"

	cases := []struct {
		name  string
		pins  map[string]string
		seen  map[string]bool
		want  []string
		quiet bool
		why   string
	}{
		{
			name:  "законный близнец: у записи предмет есть",
			pins:  map[string]string{"vpc.network.read": "зеркало строки прав"},
			seen:  map[string]bool{"vpc.network.read": true},
			quiet: true,
			why: "положительный контроль: без него всякое красное ниже могло бы приходить " +
				"от самого разбора, а не от предмета",
		},
		{
			name: "запись, которой нечего исключать",
			pins: map[string]string{"vpc.network.read": "зеркало строки прав"},
			seen: map[string]bool{},
			want: []string{"vpc.network.read"},
			why: "ровно предмет самоистечения: глагол привели к словарю, а запись осталась — " +
				"перечень описывает мир, которого нет",
		},
		{
			name: "две записи без предмета названы ОБЕ и по порядку",
			pins: map[string]string{
				"vpc.network.read": "зеркало",
				"iam.account.read": "зеркало",
			},
			seen: map[string]bool{},
			want: []string{"iam.account.read", "vpc.network.read"},
			why: "находка, называющая одну запись из двух, оставляет вторую невидимой, " +
				"а недетерминированный порядок делает вывод нечитаемым",
		},
		{
			name: "часть записей жива, часть истекла",
			pins: map[string]string{
				"vpc.network.read": "зеркало",
				"iam.account.read": "зеркало",
			},
			seen: map[string]bool{"vpc.network.read": true},
			want: []string{"iam.account.read"},
			why:  "живая запись не должна попадать в находки вместе с истёкшей",
		},
		{
			name:  "перечень пуст — это ЦЕЛЬ, а не поломка",
			pins:  map[string]string{},
			seen:  map[string]bool{"vpc.network.read": true},
			quiet: true,
			why: "проба, падающая на достижении своей цели, толкает держать запись ради " +
				"зелёного (testing.md §«Проба не имеет права падать на ДОСТИЖЕНИИ СВОЕЙ ЦЕЛИ»)",
		},
		{
			name:  "увиденного нет вовсе и перечень пуст",
			pins:  map[string]string{},
			seen:  map[string]bool{},
			quiet: true,
			why: "разбор о пустом посеве не высказывается: предпосылки гейта судятся " +
				"отдельно и до вердикта",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := stalePinFindings(ledger, subject, tc.pins, tc.seen)
			if tc.quiet {
				if len(got) != 0 {
					t.Fatalf("разбор нашёл на законном близнеце то, чего в нём нет — первое же "+
						"ложное срабатывание снимает самоистечение.\nнаходки:\n  %s",
						strings.Join(got, "\n  "))
				}
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("находок %d, ждали %d — самоистечение НЕ способно упасть по этой оси.\n"+
					"что должно было ловиться: %s\nнаходки:\n  %s",
					len(got), len(tc.want), tc.why, strings.Join(got, "\n  "))
			}
			for i, key := range tc.want {
				if !strings.Contains(got[i], "«"+key+"»") {
					t.Fatalf("находка %d не называет запись %q — читателю нечего снимать:\n  %s",
						i+1, key, got[i])
				}
				if !strings.Contains(got[i], ledger) {
					t.Fatalf("находка %d не называет перечень %q — читатель не знает, где снимать:\n  %s",
						i+1, ledger, got[i])
				}
			}
		})
	}
}

// TestSeedPinSelfExpiry_BothLedgersUseTheSameParse — оба перечня судятся ОДНИМ
// разбором.
//
// Утверждение о дереве, а не о функции: вторая реализация самоистечения
// разошлась бы с первой молча, и различие было бы видно только на том входе,
// ради которого обе написаны.
func TestSeedPinSelfExpiry_BothLedgersUseTheSameParse(t *testing.T) {
	// Перечни объявлены и непусты как понятия — иначе утверждение ниже
	// беспредметно: разбор, которому не дали ни одного перечня, о дереве не
	// говорит ничего.
	ledgers := []struct {
		name string
		pins map[string]string
	}{
		{"knownUnresolvableSeedPairs", knownUnresolvableSeedPairs},
		{"knownUnresolvableSeedVerbs", knownUnresolvableSeedVerbs},
	}
	if len(ledgers) != 2 {
		t.Fatalf("перечней пина осмотрено %d — обход пуст", len(ledgers))
	}

	total := 0
	for _, l := range ledgers {
		total += len(l.pins)
		// Ни один перечень не вправе объявить своей записью то, чего нет: подаём
		// ему ПУСТОЕ увиденное и требуем ровно len(pins) находок. На пустом
		// перечне это ноль — и это законно.
		got := stalePinFindings(l.name, "предмета", l.pins, map[string]bool{})
		if len(got) != len(l.pins) {
			t.Fatalf("перечень %s: записей %d, находок на пустом увиденном %d — "+
				"разбор считает не все записи", l.name, len(l.pins), len(got))
		}
	}
	t.Logf("перепись: перечней пина 2 · записей в них всего %d "+
		"(пустой перечень — цель, а не поломка)", total)
}
