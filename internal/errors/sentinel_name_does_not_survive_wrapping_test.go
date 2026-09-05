// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package errors_test

// sentinel_name_does_not_survive_wrapping_test.go — имя сентинела не уезжает
// вызывающему, КОГДА БЫ ОНО НИ ОКАЗАЛОСЬ В СЕРЕДИНЕ сообщения (задача #1889).
//
// ПРЕДМЕТ. `StripSentinel` снимала имя признака ПРЕФИКСОМ. Вызывающий,
// добавивший свой контекст перед отказом репозитория (`fmt.Errorf("%w: %s: %w",
// ErrWriteFailed, name, err)`), ставит свой текст ВПЕРЁД — префикс перестаёт
// совпадать, и служебное имя остаётся в середине:
//
//	moduleroles: writing the declared role failed: vpc.network.admin:
//	failed precondition: resources: probeWithdrawn is not a live platform resource
//
// Класс уже назван кодом статуса, поэтому в тексте он лишний и вдобавок
// сообщает имя внутренней переменной. Чистота текста держалась не свойством
// функции, а тем, что до сих пор никто не оборачивал.
//
// ЗАКОННЫЙ БЛИЗНЕЦ СТОИТ РЯДОМ, и он несущий. Наивная починка — вырезать слова
// признака из текста поиском — испортила бы отказ, который называет эти слова
// ПО ДЕЛУ (арендатор прислал их строкой). Поэтому проба требует ОБЕИХ сторон:
// имя, произведённое обёрткой признака, уходит; те же слова, пришедшие прозой,
// остаются дословно.

import (
	stderrors "errors"
	"fmt"
	"strings"
	"testing"

	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

func TestSentinelNameDoesNotSurviveCallerWrapping(t *testing.T) {
	// errWriteFailed — контекст вызывающего в той же форме, в какой его ставит
	// применитель ролей модуля: свой признак впереди, отказ репозитория позади.
	errWriteFailed := stderrors.New("moduleroles: writing the declared role failed")

	cases := []struct {
		name string
		err  error
		want string
		// why — что именно утверждает строка; без него перечень читается как
		// набор совпадений, а не как перечень свойств.
		why string
	}{
		{
			name: "признак префиксом — снимается, как и прежде",
			err:  iamerr.Wrapf(iamerr.ErrNotFound, "Account %s not found", "acc-1"),
			want: "Account acc-1 not found",
			why:  "положительный контроль: прежнее поведение сохранено",
		},
		{
			name: "контекст вызывающего впереди — имя признака уходит из СЕРЕДИНЫ",
			err: fmt.Errorf("%w: %s: %w", errWriteFailed, "vpc.network.admin",
				iamerr.Wrapf(iamerr.ErrFailedPrecondition,
					"resources: %s is not a live platform resource", "probeWithdrawn")),
			want: "moduleroles: writing the declared role failed: vpc.network.admin: " +
				"resources: probeWithdrawn is not a live platform resource",
			why: "предмет задачи #1889",
		},
		{
			name: "две обёртки контекста — имя признака всё равно уходит",
			err: fmt.Errorf("применение манифеста: %w",
				fmt.Errorf("%w: %s: %w", errWriteFailed, "vpc.network.admin",
					iamerr.Wrapf(iamerr.ErrInvalidArg, "verbs: %s is unknown", "frobnicate"))),
			want: "применение манифеста: moduleroles: writing the declared role failed: " +
				"vpc.network.admin: verbs: frobnicate is unknown",
			why: "глубина обёртки предмета не меняет",
		},
		{
			name: "вложенный признак — снимается ПОЛНЫЙ, а не общий",
			err: fmt.Errorf("%w: %s: %w", errWriteFailed, "vpc.network.admin",
				iamerr.Wrapf(iamerr.ErrReferenceMissing, "Project %s not found", "prj-1")),
			want: "moduleroles: writing the declared role failed: vpc.network.admin: " +
				"Project prj-1 not found",
			why: "порядок перечня признаков сохранён и в середине тоже",
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: те же слова прозой — остаются дословно",
			err: iamerr.Wrapf(iamerr.ErrInvalidArg,
				"name: %q is not a valid role name", "failed precondition: x"),
			want: `name: "failed precondition: x" is not a valid role name`,
			why:  "вырезание по тексту испортило бы отказ, называющий эти слова по делу",
		},
		{
			name: "ЗАКОННЫЙ БЛИЗНЕЦ: чужой отказ без признака — не трогается",
			err:  stderrors.New("moduleroles: not found: nothing of ours"),
			want: "moduleroles: not found: nothing of ours",
			why:  "признак не выводится из совпадения слов",
		},
		{
			name: "вырожденный: обёртка без текста — замещается именем признака",
			err:  iamerr.Wrapf(iamerr.ErrNotFound, "%s", ""),
			want: "not found",
			why:  "отказ БЕЗ СООБЩЕНИЯ остаётся невозможным (#1658)",
		},
		{
			name: "нет отказа — нет текста",
			err:  nil,
			want: "",
			why:  "вырожденный вход",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := iamerr.StripSentinel(c.err); got != c.want {
				t.Errorf("StripSentinel = %q,\n              хотел %q\n(%s)", got, c.want, c.why)
			}
		})
	}

	// Перепись: сколько строк осмотрено. «Ноль находок» обязано быть отличимо
	// от «ноль прочитанного» — перечень из нуля строк прошёл бы молча.
	t.Logf("перепись: строк перечня %d", len(cases))
	if len(cases) == 0 {
		t.Fatal("перечень пуст — утверждать не о чем")
	}
	// Обе стороны названы отдельным числом: перечень, где нет ни одной обёртки
	// контекста, зеленел бы на прежней реализации целиком.
	wrapped := 0
	for _, c := range cases {
		if c.err != nil && strings.Contains(c.err.Error(), "moduleroles: writing the declared role failed") {
			wrapped++
		}
	}
	t.Logf("перепись: из них с контекстом вызывающего впереди %d", wrapped)
	if wrapped == 0 {
		t.Fatal("ни одной обёртки контекста — проба не касается предмета #1889")
	}
}
