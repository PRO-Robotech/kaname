// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// password_hash_format.go — ЗАКРЫТЫЙ перечень форматов проверочного значения
// пароля (фаза Ф2, часть П2, задача `kacho#1268`). Санкция — приёмка ID-PW-1
// `docs/engineering/acceptance/password-verifier-follows-the-stored-value.md`,
// §3 Р2 и §5 PWV-13; порядок работ §9 ставит перечень ПЕРВЫМ — до первого
// проверяющего, иначе второй заводится копией первого и перечень рождается в
// двух местах.
//
// # Почему перечень, а не «bcrypt по существующему хешу»
//
// Популяция, которую переносит Ф2, несёт ДВА формата, а не один: замер живой
// базы 2026-08-27 дал 76 значений bcrypt `$2a$` и 7 значений argon2id из 83
// строк способа «пароль», причём производство первого прекратилось, а каждое
// новое значение заводится вторым (приёмка §1.3). План эпика, объявлявший «иных
// форматов 0», опровергнут замером — при одном проверяющем семь человек не
// вошли бы после переноса.
//
// # Что несёт запись и почему каждое поле обязательно
//
//   - ПРИЗНАК формата — первый сегмент разметки самого значения. По нему и
//     только по нему выбирается проверяющий: «что писать» решает настройка,
//     «как читать» — хранимое значение (Р1). Слить их — завести два правила об
//     одном поле, и смена настройки молча сделала бы нечитаемой уже лежащую
//     популяцию;
//   - ПОТОЛОК параметров стоимости — по КАЖДОМУ параметру. Параметры берутся из
//     самого значения, а оно пришло из чужого источника: без потолка чужой
//     источник назначает цену каждой попытки. Потолок лежит ВНУТРИ области
//     допустимости — не ниже нижней границы и НИЖЕ верхней: стоящий на верхней
//     границе спецификации, он не ограничивает ничего сверх неё, и значения
//     «выше потолка» на таком формате не существует;
//   - ОТМЕТКА записываемости. Наследуемый формат продукт не пишет и писать не
//     будет, поэтому настройка «что писать» назвать его не может;
//   - ПОЛ — только у записываемой записи: параметры, ниже которых продукт вновь
//     заводимое значение не пишет. Пола стойкости у ЧТЕНИЯ нет намеренно —
//     значение ниже пола, но в границах допустимости, читается: пол на чтении
//     отказал бы во входе владельцам слабых значений, то есть был бы сбросом,
//     который Ф1 Р1 отвергает.
//
// # Пол и нижняя граница допустимости — РАЗНЫЕ вещи
//
// Граница отвечает на вопрос «это ли значение этого формата»: за ней библиотека
// либо падает, либо молча считает ИНУЮ функцию (argon2id при памяти ниже `8·p`
// берёт `8·p` блоков, а объявленную память кладёт в начальный хеш, — результат
// не равен значению при законной памяти). Пол отвечает на вопрос «достаточно ли
// значение сильное, чтобы его ПИСАТЬ». Одна другую не заменяет.

import (
	"fmt"
	"sort"
)

// PasswordHashFormat — признак формата проверочного значения: первый сегмент
// его разметки, как он лежит в самом значении.
type PasswordHashFormat string

const (
	// PasswordHashFormatBcrypt — НАСЛЕДУЕМЫЙ формат: значения, заведённые
	// прежним поставщиком личности. Продукт их читает и не пишет.
	//
	// Признак — `2a`. Соседние написания bcrypt (`2b`, `2y`) в перечень НЕ
	// внесены: популяция их не несёт, а запись без предмета обещала бы
	// возможность, которой нет. Встретится такое значение — его назовёт
	// перепись переноса, громко и с числом строк, а не примет молча.
	PasswordHashFormatBcrypt PasswordHashFormat = "2a"

	// PasswordHashFormatArgon2id — ОБЪЯВЛЕННЫЙ и растущий формат: им заводится
	// каждое новое значение.
	PasswordHashFormatArgon2id PasswordHashFormat = "argon2id"
)

// PasswordHashCostParam — параметр СТОИМОСТИ формата: тот, что назначает цену
// одной проверки. Соль и длина ключа параметрами стоимости не являются и
// потолка не несут — они не меняют ни времени, ни памяти проверки.
type PasswordHashCostParam string

const (
	// CostParamBcryptCost — показатель стоимости bcrypt: время растёт вдвое на
	// каждую единицу, память от него не зависит вовсе.
	CostParamBcryptCost PasswordHashCostParam = "cost"
	// CostParamArgon2Memory — память argon2id в КиБ: она же и есть память
	// одной проверки, которую страж старта сверяет с пределом процесса.
	CostParamArgon2Memory PasswordHashCostParam = "memory"
	// CostParamArgon2Iterations — число проходов argon2id.
	CostParamArgon2Iterations PasswordHashCostParam = "iterations"
	// CostParamArgon2Parallelism — степень параллельности argon2id.
	CostParamArgon2Parallelism PasswordHashCostParam = "parallelism"
)

// PasswordHashParamRange — область ДОПУСТИМОСТИ параметра: пересечение того,
// что допускает спецификация формата, и того, что читатель исполняет без
// искажения. Обе границы включительны.
type PasswordHashParamRange struct {
	// Min — наименьшее значение, которое читатель считает без искажения.
	Min uint32
	// Max — наибольшее. Где строже спецификация, берётся она; где строже
	// читатель — он.
	Max uint32
	// Why — чем граница обоснована. Запись без причины неотличима от записи
	// без предмета.
	Why string
}

// argon2MaxParam — верхняя граница параметров argon2id по RFC 9106 §3.1.
const argon2MaxParam uint32 = 1<<32 - 1

// costParams — параметры стоимости КАЖДОГО формата. Выводятся отсюда всяким,
// кому нужен их перечень: вторая копия разошлась бы молча, и разошлась бы она в
// сторону «параметр без потолка».
var costParams = map[PasswordHashFormat][]PasswordHashCostParam{
	PasswordHashFormatBcrypt: {CostParamBcryptCost},
	PasswordHashFormatArgon2id: {
		CostParamArgon2Memory,
		CostParamArgon2Iterations,
		CostParamArgon2Parallelism,
	},
}

// admissibility — область допустимости по каждому параметру каждого формата.
var admissibility = map[PasswordHashFormat]map[PasswordHashCostParam]PasswordHashParamRange{
	PasswordHashFormatBcrypt: {
		CostParamBcryptCost: {
			Min: 4, Max: 31,
			Why: "библиотека отвергает стоимость вне 4..31 своим отказом",
		},
	},
	PasswordHashFormatArgon2id: {
		CostParamArgon2Memory: {
			// Нижняя граница ПАРАМЕТРА — 8 КиБ, то есть `8·p` при наименьшей
			// параллельности. Связь с фактической параллельностью значения
			// строже и проверяется РАЗБОРОМ: память ниже `8·p` библиотека не
			// отвергает, а молча считает иную функцию.
			Min: 8, Max: argon2MaxParam,
			Why: "RFC 9106 §3.1: память не меньше `8·p` КиБ; при p=1 это 8",
		},
		CostParamArgon2Iterations: {
			Min: 1, Max: argon2MaxParam,
			Why: "RFC 9106 §3.1: проходов не меньше одного; на нуле библиотека паникует",
		},
		CostParamArgon2Parallelism: {
			// Спецификация допускает до 2²⁴−1, но читатель принимает
			// параллельность ОДНОБАЙТОВОЙ: значение больше 255, приведённое с
			// потерей старших разрядов, стало бы другим числом, а на нуле
			// библиотека паникует. Где строже читатель — берётся он.
			Min: 1, Max: 255,
			Why: "тип читателя однобайтовый: 256 привелось бы к нулю, то есть к панике",
		},
	},
}

// bcryptMemoryPerVerificationBytes — память одной сверки bcrypt. От стоимости
// НЕ зависит: замер приёмки ID-PW-1 §1.6 даёт одно и то же выделение при
// стоимости 4, 10 и 12 — растёт только время.
const bcryptMemoryPerVerificationBytes uint64 = 10328

// PasswordHashFormatRecord — запись перечня.
type PasswordHashFormatRecord struct {
	// Format — признак формата.
	Format PasswordHashFormat
	// Writable — пишет ли продукт значения этого формата.
	Writable bool
	// Ceiling — потолок по каждому параметру стоимости формата.
	Ceiling map[PasswordHashCostParam]uint32
	// Floor — пол; ТОЛЬКО у записываемой записи.
	Floor map[PasswordHashCostParam]uint32
	// Why — чем выбран потолок. Потолок выводится из ЁМКОСТИ, а не из переписи
	// одной установки, и причина обязана стоять рядом с числом.
	Why string
}

// passwordHashFormats — ЗАКРЫТЫЙ перечень. Объявлен ровно здесь; второе
// объявление держит гейт дерева `internal/check`.
var passwordHashFormats = []PasswordHashFormatRecord{
	{
		Format:   PasswordHashFormatBcrypt,
		Writable: false,
		Ceiling: map[PasswordHashCostParam]uint32{
			CostParamBcryptCost: 14,
		},
		Why: "популяция переноса несёт стоимость 12 (одна проверка ≈210 мс, замер приёмки §1.6); " +
			"потолок 14 покрывает установки, где прежний поставщик был настроен строже, и " +
			"остаётся конечным — 31 читалось бы как «без предела»",
	},
	{
		Format:   PasswordHashFormatArgon2id,
		Writable: true,
		Ceiling: map[PasswordHashCostParam]uint32{
			CostParamArgon2Memory:      131072,
			CostParamArgon2Iterations:  10,
			CostParamArgon2Parallelism: 8,
		},
		Floor: map[PasswordHashCostParam]uint32{
			// Строка «хеш нового пароля» Ф1 §4.1: argon2id, память 64 МБ
			// (65536 КиБ), итераций 3, параллельность 4. Пол переносит их
			// дословно — «чтобы не менять стойкость молча».
			CostParamArgon2Memory:      65536,
			CostParamArgon2Iterations:  3,
			CostParamArgon2Parallelism: 4,
		},
		Why: "память на потолке — 128 МиБ на проверку: вдвое выше пола, и ёмкость, умноженная " +
			"на неё, ещё помещается в предел процесса вместе с резервом (PWV-15, 15.7). " +
			"Зазор между полом и потолком есть по каждому параметру, поэтому смена параметров " +
			"настройкой выразима",
	},
}

// PasswordHashFormats — перечень целиком, КОПИЕЙ: вызывающий не может его
// расширить, а расширенный на месте перечень перестал бы быть закрытым.
func PasswordHashFormats() []PasswordHashFormatRecord {
	out := make([]PasswordHashFormatRecord, 0, len(passwordHashFormats))
	for _, r := range passwordHashFormats {
		out = append(out, r.clone())
	}
	return out
}

// PasswordHashFormatByMarker — запись по признаку формата.
//
// Второго исхода, кроме «нашлась» и «такой записи нет», у поиска НЕТ: корзины
// «прочее» перечень не имеет. Признак вне перечня — наша ошибка данных либо
// настройки, а не человека и не временный сбой соседа, и отвечать за него
// обязан отдельный ГРОМКИЙ исход проверяющего, а не запись-заглушка.
func PasswordHashFormatByMarker(marker string) (PasswordHashFormatRecord, bool) {
	for _, r := range passwordHashFormats {
		if string(r.Format) == marker {
			return r.clone(), true
		}
	}
	return PasswordHashFormatRecord{}, false
}

// CostParams — параметры стоимости формата, в устойчивом порядке.
func (f PasswordHashFormat) CostParams() []PasswordHashCostParam {
	src := costParams[f]
	out := make([]PasswordHashCostParam, len(src))
	copy(out, src)
	return out
}

// Admissibility — область допустимости параметра у этого формата.
func (f PasswordHashFormat) Admissibility(p PasswordHashCostParam) (PasswordHashParamRange, bool) {
	byParam, ok := admissibility[f]
	if !ok {
		return PasswordHashParamRange{}, false
	}
	r, ok := byParam[p]
	return r, ok
}

// MemoryPerVerificationAtCeilingBytes — память, которую занимает ОДНА проверка
// значения на потолке этой записи. Это та величина, которую страж старта
// умножает на ёмкость и сверяет с пределом памяти процесса (PWV-15, 15.7).
//
// ВЫВОДИТСЯ из потолка, а не выписывается рядом с ним: выписанная, она стала бы
// вторым местом об одном предмете и разошлась бы с потолком при первой же его
// правке — молча, потому что расхождение не наблюдаемо ничем.
func (r PasswordHashFormatRecord) MemoryPerVerificationAtCeilingBytes() uint64 {
	if memory, ok := r.Ceiling[CostParamArgon2Memory]; ok {
		return uint64(memory) * 1024
	}
	return bcryptMemoryPerVerificationBytes
}

// Validate — запись, годная к объявлению. Зовётся пробой перечня и гейтом
// дерева; самопроверяющаяся запись не даёт перечню разойтись с нормой молча.
func (r PasswordHashFormatRecord) Validate() error {
	if r.Format == "" {
		return fmt.Errorf("Illegal argument password_hash_format.format: required")
	}
	params := r.Format.CostParams()
	if len(params) == 0 {
		return fmt.Errorf("Illegal argument password_hash_format.format %q: параметры стоимости не объявлены", r.Format)
	}

	belowBySome := false
	for _, p := range params {
		ceiling, ok := r.Ceiling[p]
		if !ok {
			return fmt.Errorf("Illegal argument password_hash_format.ceiling %q/%q: required", r.Format, p)
		}
		rng, ok := r.Format.Admissibility(p)
		if !ok {
			return fmt.Errorf("Illegal argument password_hash_format.admissibility %q/%q: required", r.Format, p)
		}
		if ceiling < rng.Min {
			return fmt.Errorf("Illegal argument password_hash_format.ceiling %q/%q = %d: ниже нижней границы допустимости %d — такой потолок не пропускает ничего",
				r.Format, p, ceiling, rng.Min)
		}
		if ceiling >= rng.Max {
			return fmt.Errorf("Illegal argument password_hash_format.ceiling %q/%q = %d: не ниже верхней границы допустимости %d — он не ограничивает ничего сверх спецификации",
				r.Format, p, ceiling, rng.Max)
		}

		floor, hasFloor := r.Floor[p]
		switch {
		case !r.Writable && hasFloor:
			return fmt.Errorf("Illegal argument password_hash_format.floor %q/%q: у только читаемой записи пола не бывает — продукт этот формат не пишет",
				r.Format, p)
		case r.Writable && !hasFloor:
			return fmt.Errorf("Illegal argument password_hash_format.floor %q/%q: required у записываемой записи", r.Format, p)
		case r.Writable && floor > ceiling:
			return fmt.Errorf("Illegal argument password_hash_format.floor %q/%q = %d: выше потолка %d — область настройки «что писать» пуста",
				r.Format, p, floor, ceiling)
		case r.Writable && floor < ceiling:
			belowBySome = true
		}
	}
	if r.Writable && !belowBySome {
		return fmt.Errorf("Illegal argument password_hash_format.floor %q: равен потолку по каждому параметру — область настройки «что писать» из одной точки, и смена параметров невыразима",
			r.Format)
	}

	for p := range r.Ceiling {
		if _, ok := r.Format.Admissibility(p); !ok {
			return fmt.Errorf("Illegal argument password_hash_format.ceiling %q/%q: параметр не принадлежит формату", r.Format, p)
		}
	}
	for p := range r.Floor {
		if _, ok := r.Format.Admissibility(p); !ok {
			return fmt.Errorf("Illegal argument password_hash_format.floor %q/%q: параметр не принадлежит формату", r.Format, p)
		}
	}
	return nil
}

// clone — копия записи вместе с её картами: отданная ссылкой, карта позволила
// бы вызывающему править потолок закрытого перечня.
func (r PasswordHashFormatRecord) clone() PasswordHashFormatRecord {
	out := r
	out.Ceiling = cloneCostMap(r.Ceiling)
	out.Floor = cloneCostMap(r.Floor)
	return out
}

func cloneCostMap(src map[PasswordHashCostParam]uint32) map[PasswordHashCostParam]uint32 {
	if src == nil {
		return nil
	}
	out := make(map[PasswordHashCostParam]uint32, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// PasswordHashFormatMarkers — признаки перечня, отсортированные: перепись и
// тексты отказов печатают их в устойчивом порядке.
func PasswordHashFormatMarkers() []string {
	out := make([]string, 0, len(passwordHashFormats))
	for _, r := range passwordHashFormats {
		out = append(out, string(r.Format))
	}
	sort.Strings(out)
	return out
}
