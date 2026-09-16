// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package passwordverify — проверяющий пароля, следующий за ХРАНИМЫМ значением
// (фаза Ф2, часть П2, задача `kacho#1268`).
//
// Санкция — приёмка ID-PW-1
// `docs/engineering/acceptance/password-verifier-follows-the-stored-value.md`;
// перечень форматов, потолки и пол объявлены в `internal/domain`
// (`password_hash_format.go`) и здесь не переобъявляются.
//
// # Что этот пакет делает и чего НЕ делает
//
// Делает: выбирает проверяющего по признаку ХРАНИМОГО значения, разбирает тело
// с областью допустимости формата ДО вычисления, сверяет параметры с потолком
// ДО вычисления, считает и сверяет постоянным временем, ограничивает число
// одновременных проверок объявленной ёмкостью и отдаёт исход ТИПОМ.
//
// НЕ делает: не читает настройку «что писать» — «как читать» решает значение, и
// слить эти вопросы значило бы завести два правила об одном поле; не ходит в
// хранилище; не знает ни полосы входа, ни её отказов, ни её частоты; не
// переписывает значений. Подключение ко входу и переписывание — фаза Ф3
// (`kacho#1269`).
package passwordverify

// outcome.go — ЗАКРЫТЫЙ словарь исходов проверки (приёмка §3 Р3).
//
// Исходов семь, и ни один не сводится к «не совпал». Все, кроме первого, ведут
// к отказу — но различать их обязана поддержка: иначе повреждение данных и
// перегрузка читаются как поток неверных паролей, а мёртвый контроль становится
// невидимым. Наружу отказы неразличимы (Р4) — это обязанность полосы входа, и
// значения этого словаря за провод не выходят.

// Outcome — исход одной проверки.
type Outcome string

const (
	// OutcomeMatched — предъявленный пароль сошёлся с хранимым значением.
	OutcomeMatched Outcome = "matched"
	// OutcomeMismatched — не сошёлся. Это вход ЧЕЛОВЕКА, а не наша ошибка.
	OutcomeMismatched Outcome = "mismatched"
	// OutcomeFormatNotInRegistry — признак формата в перечень не входит.
	// Ошибка данных либо настройки: повтор того же запроса не даст иного.
	OutcomeFormatNotInRegistry Outcome = "format-not-in-registry"
	// OutcomeBodyNotParsable — признак известен, тело негодно: разметка
	// повреждена либо параметр лежит за областью допустимости формата.
	OutcomeBodyNotParsable Outcome = "body-not-parsable"
	// OutcomeParamsAboveCeiling — параметры стоимости выше потолка записи.
	// Цену попытки назначал бы чужой источник, поэтому вычисление не
	// начинается вовсе.
	OutcomeParamsAboveCeiling Outcome = "params-above-ceiling"
	// OutcomeMaterialMissing — проверочного материала нет. ЗАКОННОЕ состояние
	// личности, а не повреждение: отсутствие не приводится к пустому значению
	// и не сравнивается с ним.
	OutcomeMaterialMissing Outcome = "material-missing"
	// OutcomeCapacityExhausted — ёмкость проверки занята целиком. Единственный
	// преходящий исход: та же проверка после освобождения обязана пройти.
	OutcomeCapacityExhausted Outcome = "capacity-exhausted"
)

// outcomes — словарь целиком. ВЫВОДИТСЯ отсюда всяким, кому нужен перечень:
// набор счётчиков, проба переписи, текст отказа. Вторая копия разошлась бы
// молча, и разошлась бы она в сторону «исход без счётчика».
var outcomes = []Outcome{
	OutcomeMatched,
	OutcomeMismatched,
	OutcomeFormatNotInRegistry,
	OutcomeBodyNotParsable,
	OutcomeParamsAboveCeiling,
	OutcomeMaterialMissing,
	OutcomeCapacityExhausted,
}

// Outcomes — копия словаря: вызывающий не может его расширить.
func Outcomes() []Outcome {
	out := make([]Outcome, len(outcomes))
	copy(out, outcomes)
	return out
}

// OutcomeNames — имена исходов строками: набор клеток счётчика собирается из
// них, а не из второго перечня.
func OutcomeNames() []string {
	out := make([]string, 0, len(outcomes))
	for _, o := range outcomes {
		out = append(out, string(o))
	}
	return out
}

// IsOurError — исход, названный НАШЕЙ ошибкой: повреждение данных либо
// расхождение настройки с перечнем. Ни «не совпал», ни «материала нет», ни
// исчерпание ёмкости ею не являются — первое есть вход человека, второе
// законное состояние личности, третье нагрузка.
func (o Outcome) IsOurError() bool {
	switch o {
	case OutcomeFormatNotInRegistry, OutcomeBodyNotParsable, OutcomeParamsAboveCeiling:
		return true
	default:
		return false
	}
}

// IsTerminal — повтор того же запроса не может дать иного исхода, поэтому
// политики повтора у него нет. Преходящ ровно один исход — исчерпание ёмкости.
func (o Outcome) IsTerminal() bool { return o != OutcomeCapacityExhausted }
