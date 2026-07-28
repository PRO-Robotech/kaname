// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Непрерывный fuzzing — вычислитель условий доступа.
//
// Условие висит на выдаче прав и решает, действует ли выдача сейчас: свежесть
// второго фактора, срок, диапазон адресов источника, часы, соответствие
// устройства. Вход — текст выражения (его пишет автор условия), параметры
// условия и контекст запроса; всё три доезжают до вычислителя снаружи.
//
// Цель гоняет НАСТОЯЩИЙ `service.BuiltinEvaluator` — тот, что стоит в
// композиционном корне iam (`wiring.go`) и вызывается на пути `Check` и
// диагностическим RPC. Прежняя редакция звала `parseCELStub`, считавший баланс
// скобок; сравнение скобок и решение о доступе — разные занятия.
//
// Утверждается ровно то, что делает вычислитель опасным:
//
//   - отказ обязан быть отказом: любая ошибка означает «не разрешено». Ошибка,
//     пришедшая вместе с «разрешено», превращается в доступ у любого
//     вызывающего, который проверяет одно из двух;
//   - выражение, которого вычислитель не понимает, не может быть разрешением.
//     Такое выражение делегируется в модель прав — но именно делегируется, а не
//     трактуется как «условие выполнено»;
//   - снятые с употребления виды условий (аварийное окно, окно временной
//     выдачи) обязаны отвергаться. Их номера сохранены ради совместимости
//     формата, но выдача, которая на них ссылается, действовать не должна;
//   - вердикт не зависит от того, вычислялось ли это выражение раньше.
//     Распознавание кэшируется с вытеснением — кэш, меняющий ответ, и есть
//     разрешение, зависящее от истории процесса.
//
// Свободный текст выражения вычисляется движком модели прав, а не здесь: этот
// вычислитель распознаёт известные формы по подстроке. Проверяется поэтому его
// собственный контракт, а не полнота разбора языка.
package fuzz_test

import (
	"strings"
	"testing"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// deprecatedBuiltins — виды условий, снятые с употребления. Номер в формате
// сохранён, действовать не должен.
var deprecatedBuiltins = map[iamv1.BuiltinCondition]bool{
	iamv1.BuiltinCondition_BUILTIN_CONDITION_BREAK_GLASS_WINDOW: true,
	iamv1.BuiltinCondition_BUILTIN_CONDITION_JIT_WINDOW:         true,
}

func FuzzCELExpression(f *testing.F) {
	// Один вычислитель на весь прогон: кэш распознавания в бою живёт столько же,
	// сколько процесс, и его вытеснение — часть предмета проверки. Держится он в
	// замыкании, а не в переменной пакета, чтобы соседние цели не делили с ним
	// состояние.
	evaluator := service.NewBuiltinEvaluator()

	seeds := []struct {
		builtin    int32
		expression string
		param      string
	}{
		{0, `acr_value == "3" && "webauthn" in amr_claims && current_time - mfa_at < 900`, "3"},
		{0, `current_time < valid_until`, "1893456000"},
		{0, `client_ip in allowed_cidrs`, "10.0.0.0/8"},
		{0, `hour_of_day(current_time, tz) >= 9`, "Europe/Moscow"},
		{0, `device_attestation in allowed_attestations`, "tpm2"},
		// Отрицание известной формы: распознавание идёт по подстроке, поэтому
		// текст, означающий обратное, попадает в ту же ветвь.
		{0, `!source_ip_in_range(client_ip, allowed_cidrs)`, "0.0.0.0/0"},
		// Свободный текст — делегируется, но не разрешает.
		{0, `user.role == "admin" || true`, ""},
		{0, `__import__("os").system("rm -rf /")`, ""},
		{0, ``, ""},
		{0, `(`, ""},
		{0, strings.Repeat(`(`, 1000), ""},
		{0, `'\x00\x00'`, "\x00"},
		// Виды условий по номеру, включая снятые и несуществующие.
		{1, "", "3"},
		{2, "", "0"},
		{3, "", "not-a-cidr"},
		{4, "", ""},
		{5, "", ""},
		{6, "", "../../etc/passwd"},
		{6, "", "/etc/localtime"},
		{7, "", "tpm2"},
		{99, "", ""},
		{-1, "", ""},
	}
	for _, s := range seeds {
		f.Add(s.builtin, s.expression, s.param)
	}

	f.Fuzz(func(t *testing.T, builtin int32, expression, param string) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("ПАНИКА на условии builtin=%d expr=%q param=%q: %v",
					builtin, expression, param, r)
			}
		}()

		kind := iamv1.BuiltinCondition(builtin)
		params, ctx := conditionInputs(param)

		allowed, trace, err := evaluator.Evaluate(kind, expression, params, ctx)

		if err != nil && allowed {
			t.Fatalf("вычислитель вернул И ошибку (%v), И разрешение — вызывающий, "+
				"смотрящий на одно из двух, пропустит запрос (builtin=%d expr=%q param=%q, "+
				"trace=%q)", err, builtin, expression, param, trace)
		}
		if deprecatedBuiltins[kind] && (allowed || err == nil) {
			t.Fatalf("снятый с употребления вид условия %v дал allowed=%v err=%v — выдача, "+
				"ссылающаяся на него, продолжает действовать", kind, allowed, err)
		}
		if _, known := iamv1.BuiltinCondition_name[builtin]; !known && (allowed || err == nil) {
			t.Fatalf("неизвестный номер вида условия %d дал allowed=%v err=%v — условие, "+
				"которого нет, не может разрешать", builtin, allowed, err)
		}

		// Повтор через тот же вычислитель: ответ не вправе зависеть от того,
		// лежит ли распознавание в кэше.
		again, _, againErr := evaluator.Evaluate(kind, expression, params, ctx)
		if again != allowed || (againErr == nil) != (err == nil) {
			t.Fatalf("повторное вычисление того же условия дало другой ответ: было "+
				"allowed=%v err=%v, стало allowed=%v err=%v (builtin=%d expr=%q param=%q) — "+
				"вердикт зависит от истории процесса", allowed, err, again, againErr,
				builtin, expression, param)
		}
	})
}

// conditionInputs раскладывает фаззимую строку по всем полям, которые
// вычислитель читает: адрес источника, диапазоны, временная зона, срок,
// подтверждение устройства. Так один вход достаёт и разбор адреса, и разбор
// времени, и загрузку временной зоны по имени, пришедшему снаружи.
func conditionInputs(param string) (params, ctx map[string]any) {
	params = map[string]any{
		"allowed_cidrs":        []any{param},
		"allowed_attestations": []any{param},
		"tz":                   param,
		"valid_until":          param,
		"start_h":              param,
		"end_h":                param,
	}
	ctx = map[string]any{
		"acr_value":          param,
		"amr_claims":         []any{param, "webauthn"},
		"current_time":       param,
		"mfa_at":             param,
		"valid_until":        param,
		"client_ip":          param,
		"device_attestation": param,
		"tz":                 param,
	}
	return params, ctx
}
