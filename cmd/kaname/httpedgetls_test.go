// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// httpedgetls_test.go — доказательство того, что страж транспорта HTTP-рёбер
// СПОСОБЕН упасть и способен смолчать.
//
// Каждый случай меняет РОВНО ОДИН факт против законного близнеца: иначе
// неизвестно, который из двух дал вердикт. Случаев об объявленном исключении
// открытого текста здесь больше нет: механизм снят вместе с единственным
// ребром, у которого исключение было, — слушателем вебхуков внешнего
// поставщика (kaname#363).
package main

import (
	"strings"
	"testing"
)

// edgeOK / edgeBare — законный близнец и его единственное отличие.
func edgeOK() httpEdgeTLS {
	return httpEdgeTLS{
		name: "внутренний REST-фронт", knob: "KNOB_A", addr: "0.0.0.0:9099",
		enabled: true, why: "по проводу идёт удостоверение модуля",
	}
}

func edgeBare() httpEdgeTLS {
	e := edgeOK()
	e.enabled = false
	return e
}

func TestRequireHTTPEdgeTLS_CanFailAndStaysSilent(t *testing.T) {
	second := httpEdgeTLS{
		name: "публикатор ключей", knob: "KNOB_B", addr: "0.0.0.0:9097",
		enabled: false, why: "предпосылка снятой аутентификации — односторонняя TLS",
	}

	cases := []struct {
		name       string
		production bool
		edges      []httpEdgeTLS
		want       []string
		silent     bool
		why        string
	}{
		{
			name: "законный близнец: транспорт объявлен", production: true,
			edges: []httpEdgeTLS{edgeOK()}, silent: true,
			why: "верное объявление обязано молчать, иначе первый ложный срабат снимет стража",
		},
		{
			name: "боевая посадка, ребро открытым текстом", production: true,
			edges: []httpEdgeTLS{edgeBare()},
			want:  []string{"KNOB_A", "0.0.0.0:9099", "удостоверение модуля", "in the clear"},
			why:   "отказ обязан назвать ручку, адрес и ЧТО едет — иначе оператор снимет ручку, а не заведёт материал",
		},
		{
			name: "не боевая посадка — no-op", production: false,
			edges: []httpEdgeTLS{edgeBare(), second}, silent: true,
			why: "стенд байт-идентичен: умолчание выключено, и это решение, а не недосмотр",
		},
		{
			name: "адрес пуст — слушателя нет, судить нечего", production: true,
			edges:  []httpEdgeTLS{{name: "скрейп", knob: "KNOB_C", addr: "  ", why: "счётчики"}},
			silent: true,
			why:    "отказ, выведенный из неподнятого слушателя, отказал бы верной посадке",
		},
		{
			name: "ВСЕ голые рёбра названы, а не первое", production: true,
			edges: []httpEdgeTLS{edgeBare(), second},
			want:  []string{"KNOB_A", "KNOB_B"},
			why:   "страж, останавливающийся на первом, продаёт три круга подъёма вместо одного",
		},
		{
			name: "перечень пуст — ОТКАЗ, а не тишина", production: true,
			edges: nil,
			want:  []string{"вердикт беспредметен"},
			why:   "«нарушений нет» обязано быть отличимо от «рёбер не передано ни одного»",
		},
		{
			name: "перечень пуст и посадка НЕ боевая — всё равно отказ", production: false,
			edges: nil,
			want:  []string{"вердикт беспредметен"},
			why:   "беспредметный вызов есть дефект вызывающего, и посадка его не оправдывает",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := requireHTTPEdgeTLS(tc.production, tc.edges)
			if tc.silent {
				if err != nil {
					t.Fatalf("законный близнец обязан молчать (%s), а страж сказал: %v", tc.why, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("страж обязан отказать (%s), а он смолчал", tc.why)
			}
			for _, want := range tc.want {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("отказ обязан назвать %q (%s); сказано: %v", want, tc.why, err)
				}
			}
		})
	}
}
