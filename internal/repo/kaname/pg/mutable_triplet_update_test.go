// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mutable_triplet_update_test.go — что статический оператор записи ОБЯЗАН
// сохранить, когда список `SET` перестал собираться форматированием строки
// (задача продукта #2065).
//
// Гейт-сосед (`update_statement_not_assembled_test.go`) утверждает про ФОРМУ:
// оператор не собирается в рантайме. Здесь утверждается про СМЫСЛ: та же маска
// пишет те же колонки теми же значениями, а перечень подстановок оператора
// сходится с перечнем аргументов. Второе компилятор не ловит: `QueryRow`
// принимает `...any`, поэтому рассогласование оператора и его аргументов — это
// отказ ПРОГОНА, дошедшего до этой ветви, и ровно того класса, ради которого
// правка делалась.
package pg

import (
	"errors"
	"regexp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// TestMutableTripletUpdateArgs_MaskDecidesApplicabilityNotStatementText —
// маска решает ПРИЗНАКИ применимости, а не текст оператора.
func TestMutableTripletUpdateArgs_MaskDecidesApplicabilityNotStatementText(t *testing.T) {
	const (
		id   = "acc-0000000000000001"
		name = "renamed"
		desc = "описание"
	)
	labels := []byte(`{"k":"v"}`)

	cases := []struct {
		name                       string
		mask                       []string
		wantName, wantDesc, wantLb bool
		wantChanged                bool
		why                        string
	}{
		{
			name: "пустая маска — полная правка: все три поля",
			mask: nil, wantName: true, wantDesc: true, wantLb: true, wantChanged: true,
			why: "прежний сборщик на пустой маске выставлял все три присваивания",
		},
		{
			name: "маска называет одно поле — остальные переписываются сами в себя",
			mask: []string{"name"}, wantName: true, wantChanged: true,
			why: "прежний сборщик клал в SET ровно одно присваивание",
		},
		{
			name: "маска называет два поля",
			mask: []string{"labels", "description"}, wantDesc: true, wantLb: true, wantChanged: true,
			why: "порядок в маске на порядок подстановок не влияет — он у оператора свой",
		},
		{
			name: "повтор поля в маске идемпотентен",
			mask: []string{"name", "name"}, wantName: true, wantChanged: true,
			why: "прежний сборщик клал присваивание один раз — множество, а не список",
		},
		{
			name:     "все три названы явно — тождественно пустой маске",
			mask:     []string{"name", "description", "labels"},
			wantName: true, wantDesc: true, wantLb: true, wantChanged: true,
			why: "положительный контроль к первому случаю: обе формы дают один и тот же вход",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			args, changed, err := mutableTripletUpdateArgs(id, name, desc, labels, tc.mask)
			require.NoError(t, err)
			require.Equal(t, tc.wantChanged, changed, tc.why)
			require.Len(t, args, 7,
				"подстановок у оператора семь: id + три пары «признак, значение»")

			require.Equal(t, id, args[0], "идентификатор всегда первый — он сторож WHERE")
			require.Equal(t, tc.wantName, args[1], tc.why)
			require.Equal(t, name, args[2], "значение приезжает ВСЕГДА: его выбирает признак, а не наличие")
			require.Equal(t, tc.wantDesc, args[3], tc.why)
			require.Equal(t, desc, args[4])
			require.Equal(t, tc.wantLb, args[5], tc.why)
			require.Equal(t, labels, args[6])
		})
	}
}

// TestMutableTripletUpdateArgs_UnknownFieldKeepsTheContractText — неизвестное
// поле маски отвергается тем же кодом и тем же текстом, что и до правки.
func TestMutableTripletUpdateArgs_UnknownFieldKeepsTheContractText(t *testing.T) {
	// Отрицание в паре с положительным: без второго случая проба зеленела бы на
	// сборщике, отвергающем ВСЁ.
	_, _, ok := mutableTripletUpdateArgs("id", "n", "d", []byte(`{}`), []string{"labels"})
	require.NoError(t, ok, "положительный контроль: известное поле обязано проходить")

	_, changed, err := mutableTripletUpdateArgs("id", "n", "d", []byte(`{}`), []string{"owner_user_id"})
	require.Error(t, err)
	require.False(t, changed, "на отказе применимость не объявляется")
	require.True(t, errors.Is(err, iamerr.ErrInvalidArg),
		"класс отказа — часть контракта: неизвестное поле маски это INVALID_ARGUMENT")
	require.ErrorContains(t, err, `Illegal argument update_mask field "owner_user_id"`,
		"текст отказа — часть контракта и правкой формы оператора не меняется; "+
			"обёртка сентинела приставляет к нему свой класс, и это прежнее поведение")
}

// TestResourceUpdateStatementsMatchTheirArguments — перечень подстановок
// оператора сходится с перечнем аргументов, и оператор адресует СВОЙ ресурс.
//
// Это то, чего компилятор не проверяет: `QueryRow` принимает `...any`, поэтому
// оператор с восемью подстановками и семью аргументами собирается и падает
// только на прогоне.
func TestResourceUpdateStatementsMatchTheirArguments(t *testing.T) {
	args, _, err := mutableTripletUpdateArgs("id", "n", "d", []byte(`{}`), nil)
	require.NoError(t, err)

	statements := map[string]struct {
		sql   string
		table string
		cols  string
	}{
		"account": {accountUpdateQ, "UPDATE accounts SET", accountCols},
		"group":   {groupUpdateQ, "UPDATE groups SET", groupCols},
		"project": {projectUpdateQ, "UPDATE projects SET", projectCols},
	}

	var checked int
	for res, st := range statements {
		t.Run(res, func(t *testing.T) {
			require.Contains(t, st.sql, st.table, "оператор адресует свою таблицу")
			require.Contains(t, st.sql, "RETURNING "+st.cols,
				"чтение после записи отдаёт полный набор колонок ресурса")
			require.Contains(t, st.sql, "WHERE id = $1",
				"сторож стоит по идентификатору, и он первая подстановка")
			for _, col := range []string{"name", "description", "labels"} {
				require.Regexp(t, col+`\s+= CASE WHEN`, st.sql,
					"колонка %s пишется через признак применимости", col)
			}
			require.Equal(t, len(args), maxPlaceholder(st.sql),
				"подстановок оператора и аргументов — поровну")
		})
		checked++
	}
	require.Equal(t, 3, checked, "осмотрено операторов: перепись не должна быть пустой")
	t.Logf("перепись: операторов записи осмотрено %d · подстановок у каждого %d · аргументов %d",
		checked, maxPlaceholder(accountUpdateQ), len(args))
}

// TestMaxPlaceholder_ProvenByInjection — счётчик подстановок способен назвать
// разное на разном входе; иначе предыдущая проба сравнивала бы две константы.
func TestMaxPlaceholder_ProvenByInjection(t *testing.T) {
	require.Equal(t, 0, maxPlaceholder("UPDATE t SET a = a"), "подстановок нет — ноль")
	require.Equal(t, 7, maxPlaceholder("... $1 ... $7 ..."), "берётся наибольший, а не последний")
	require.Equal(t, 12, maxPlaceholder("$12 $3"), "число читается целиком, а не первой цифрой")
}

var placeholderRe = regexp.MustCompile(`\$(\d+)`)

// maxPlaceholder — наибольший номер подстановки в операторе.
func maxPlaceholder(sql string) int {
	var max int
	for _, m := range placeholderRe.FindAllStringSubmatch(sql, -1) {
		n, err := strconv.Atoi(m[1])
		if err == nil && n > max {
			max = n
		}
	}
	return max
}
