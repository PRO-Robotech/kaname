// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// observability_page_provider_roads_injection_test.go — сверка строки семейства
// дорог СПОСОБНА упасть и молчит на законном близнеце.
//
// Годная строка собрана один раз; каждая проба меняет в ней РОВНО ОДИН факт.
// Словарь синтетический и тоже один: две дороги и две клетки исхода. Настоящий
// набор здесь не нужен — предмет инъекции распознаватель, а не дерево.
package supplyhygiene

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const synthFamily = "kaname_synthetic_road_outcomes_total"

// synthCells — закрытые наборы синтетического семейства: дороги и клетки исхода.
var synthCells = []string{"admin", "token_exchange", "ok", "absent"}

// synthRow — строка таблицы семейства с данной ячейкой толкования.
func synthRow(meaning string) string {
	return "| `" + synthFamily + "` | `road`, `outcome` | " + meaning + " |\n"
}

// synthPage — страница с заголовком таблицы и данными строками.
func synthPage(rows ...string) string {
	return "## Ряды\n\n| Ряд | Метки | Что значит |\n|---|---|---|\n" + strings.Join(rows, "")
}

// twinMeaning — ЗАКОННЫЙ БЛИЗНЕЦ: обе дороги и обе клетки названы значением
// метки, метки — своими именами, имя ряда — своим именем.
const twinMeaning = "исходы по дорогам: `road` — `admin` либо `token_exchange`; " +
	"`outcome` — `ok`, `absent`. Пара с `kaname_other_total` не нужна"

func TestFamilyRowInjection(t *testing.T) {
	for _, tc := range []struct {
		name string
		page string
		want []string // подстроки, каждая из которых обязана стоять в своей находке
	}{
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: наборы названы словарём семейства — молчание",
			page: synthPage(synthRow(twinMeaning)),
		},
		{
			name: "названа дорога, которой семейство не считает, — находка, называющая её",
			page: synthPage(synthRow(twinMeaning + ", снятая `jwks`")),
			want: []string{"называет `jwks`"},
		},
		{
			name: "дорога закрытого набора не названа — находка, называющая её",
			page: synthPage(synthRow(strings.Replace(twinMeaning, " либо `token_exchange`", "", 1))),
			want: []string{"не называет `token_exchange`"},
		},
		{
			name: "клетка исхода не названа — находка, называющая её",
			page: synthPage(synthRow(strings.Replace(twinMeaning, ", `absent`", "", 1))),
			want: []string{"не называет `absent`"},
		},
		{
			name: "дорога названа не написанием метки — находка о чужом и о пропущенном",
			page: synthPage(synthRow(strings.Replace(twinMeaning, "`admin`", "`ADMIN`", 1))),
			want: []string{"называет `ADMIN`", "не называет `admin`"},
		},
		{
			name: "прежняя строка страницы: три контура заглавными — семь находок",
			page: synthPage(synthRow("по каждому из трёх контуров (`ADMIN`, `JWKS`, `TOKEN`)")),
			want: []string{"называет `ADMIN`", "называет `JWKS`", "называет `TOKEN`",
				"не называет `admin`", "не называет `token_exchange`",
				"не называет `ok`", "не называет `absent`"},
		},
		{
			name: "строки семейства нет — находка, а не молчание",
			page: synthPage("| `kaname_neighbour_total` | `outcome` | " + twinMeaning + " |\n"),
			want: []string{"строки семейства " + synthFamily + " на странице нет"},
		},
		{
			name: "строк семейства две — находка о двух местах",
			page: synthPage(synthRow(twinMeaning), synthRow(twinMeaning)),
			want: []string{"строк семейства " + synthFamily + " на странице 2"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			census, findings := judgeFamilyRow(tc.page, synthFamily, synthCells)
			require.NotZero(t, census.tableRows, "синтетическая страница не разобрана — проба беспредметна")
			require.Lenf(t, findings, len(tc.want), "находок не столько, сколько фактов изменено: %v", findings)
			for _, w := range tc.want {
				hit := false
				for _, f := range findings {
					hit = hit || strings.Contains(f, w)
				}
				require.Truef(t, hit, "ни одна находка не называет %q: %v", w, findings)
			}
		})
	}
}
