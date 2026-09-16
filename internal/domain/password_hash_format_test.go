// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// password_hash_format_test.go — перечень форматов проверочного значения
// (фаза Ф2, часть П2, задача `kacho#1268`; приёмка ID-PW-1 §3 Р2, §5 PWV-13).
//
// Предмет проб — свойства, которые держит САМ ПЕРЕЧЕНЬ, а не дисциплина
// вызывающего:
//
//  1. перечень ЗАКРЫТ и корзины «прочее» не имеет: признак вне перечня
//     распознаётся как таковой, а не проваливается на успешный путь;
//  2. у каждой записи потолок задан ПО КАЖДОМУ параметру стоимости её формата и
//     лежит внутри области допустимости — не ниже нижней границы и ниже верхней:
//     потолок на верхней границе спецификации не ограничивает ничего, и значения
//     «выше потолка» на таком формате не существует;
//  3. у записываемой записи есть пол, он ни по одному параметру не выше потолка
//     и хотя бы по одному ниже него: иначе область ручки «что писать» пуста либо
//     из одной точки, и смена параметров невыразима;
//  4. у только читаемой записи пола НЕТ: пол отвечает на вопрос «достаточно ли
//     значение сильное, чтобы его ПИСАТЬ», а такой формат продукт не пишет.
//
// Отличие пола от нижней границы допустимости — несущее, и оно проверяется
// отдельно: граница отвечает «это ли значение этого формата», пол — «писать ли
// такое»; значение ниже пола, но в границах, продукт ЧИТАЕТ (ID-PW-1 Р2).
package domain_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestPasswordHashFormats_RegistryIsClosedAndNonEmpty(t *testing.T) {
	t.Parallel()

	records := domain.PasswordHashFormats()
	require.NotEmpty(t, records,
		"перечень пуст — «закрыт» здесь означало бы «форматов нет», и читать было бы нечем")

	seen := map[domain.PasswordHashFormat]int{}
	writable := 0
	for _, r := range records {
		seen[r.Format]++
		if r.Writable {
			writable++
		}
		require.NoErrorf(t, r.Validate(), "запись %q обязана быть годной", r.Format)
	}
	for f, n := range seen {
		require.Equalf(t, 1, n, "формат %q объявлен %d раза — перечень объявляется ровно одним местом", f, n)
	}
	require.GreaterOrEqual(t, writable, 1,
		"записываемых форматов ноль — настройке «что писать» нечего было бы назвать (PWV-13, 13.2)")

	t.Logf("перепись: записей %d, из них записываемых %d", len(records), writable)

	// Копия, а не сам перечень: вызывающий не может его расширить.
	records[0].Format = "подменено вызывающим"
	again := domain.PasswordHashFormats()
	require.NotEqual(t, domain.PasswordHashFormat("подменено вызывающим"), again[0].Format,
		"перечень отдан ссылкой — вызывающий правит закрытый словарь")
}

func TestPasswordHashFormats_LookupHasNoOtherBranch(t *testing.T) {
	t.Parallel()

	for _, r := range domain.PasswordHashFormats() {
		got, ok := domain.PasswordHashFormatByMarker(string(r.Format))
		require.Truef(t, ok, "формат %q из перечня не находится по своему признаку", r.Format)
		require.Equal(t, r.Format, got.Format)
	}

	// Вне перечня — «нет такой записи», а НЕ запись-заглушка: корзины «прочее»
	// у перечня нет (Р2). Среди отвергаемых — соседние написания bcrypt (`2b`,
	// `2y`): популяция их не несёт, и запись без предмета обещала бы возможность,
	// которой нет.
	for _, bad := range []string{"", "2b", "2y", "argon2i", "argon2d", "scrypt", "pbkdf2", "ARGON2ID", "2A"} {
		_, ok := domain.PasswordHashFormatByMarker(bad)
		require.Falsef(t, ok, "признак %q обязан быть вне перечня — иначе у классификатора есть ветка «прочее»", bad)
	}
}

func TestPasswordHashFormats_CeilingIsSetForEveryCostParamInsideAdmissibility(t *testing.T) {
	t.Parallel()

	checked := 0
	for _, r := range domain.PasswordHashFormats() {
		params := r.Format.CostParams()
		require.NotEmptyf(t, params, "у формата %q не объявлено ни одного параметра стоимости", r.Format)

		for _, p := range params {
			ceiling, ok := r.Ceiling[p]
			require.Truef(t, ok, "у записи %q нет потолка по параметру %q — цену попытки назначал бы чужой источник", r.Format, p)

			rng, ok := r.Format.Admissibility(p)
			require.Truef(t, ok, "у формата %q нет области допустимости по параметру %q", r.Format, p)

			require.GreaterOrEqualf(t, ceiling, rng.Min,
				"потолок %q/%q ниже нижней границы допустимости — такой потолок не пропускает ничего", r.Format, p)
			require.Lessf(t, ceiling, rng.Max,
				"потолок %q/%q стоит на верхней границе спецификации — он не ограничивает ничего сверх неё, "+
					"и значения «выше потолка» на этом формате не существует", r.Format, p)
			checked++
		}
	}
	t.Logf("перепись: пар «запись × параметр стоимости» осмотрено %d", checked)
	require.Positive(t, checked, "осмотрено ноль пар — проверка ничего не измерила")
}

func TestPasswordHashFormats_FloorBelongsToTheWritableRecordOnly(t *testing.T) {
	t.Parallel()

	writable, readOnly := 0, 0
	for _, r := range domain.PasswordHashFormats() {
		if !r.Writable {
			readOnly++
			require.Emptyf(t, r.Floor,
				"у только читаемой записи %q объявлен пол — пол отвечает на вопрос «писать ли такое», "+
					"а продукт этот формат не пишет", r.Format)
			continue
		}
		writable++

		belowBySome := false
		for _, p := range r.Format.CostParams() {
			floor, ok := r.Floor[p]
			require.Truef(t, ok, "у записываемой записи %q нет пола по параметру %q", r.Format, p)
			ceiling := r.Ceiling[p]
			require.LessOrEqualf(t, floor, ceiling,
				"пол %q/%q выше потолка — область ручки «что писать» пуста", r.Format, p)
			if floor < ceiling {
				belowBySome = true
			}
		}
		require.Truef(t, belowBySome,
			"у записи %q пол равен потолку по каждому параметру — область ручки из одной точки, "+
				"и смена параметров (PWV-07) невыразима", r.Format)
	}
	t.Logf("перепись: записей записываемых %d, только читаемых %d", writable, readOnly)
	require.Positive(t, writable, "записываемых ноль")
	require.Positive(t, readOnly, "только читаемых ноль — наследуемый формат не объявлен, и переносить нечего")
}

func TestPasswordHashFormats_MemoryPerVerificationIsDerivedFromTheCeiling(t *testing.T) {
	t.Parallel()

	for _, r := range domain.PasswordHashFormats() {
		got := r.MemoryPerVerificationAtCeilingBytes()
		require.Positivef(t, got,
			"память одной проверки записи %q объявлена нулём — ёмкость, сверенная с нулём, "+
				"обещала бы места, которых нет (PWV-15, 15.7)", r.Format)

		if ceiling, ok := r.Ceiling[domain.CostParamArgon2Memory]; ok {
			require.Equalf(t, uint64(ceiling)*1024, got,
				"память одной проверки записи %q не выведена из её потолка — два места об одном предмете", r.Format)
		}
	}
}

func TestPasswordHashFormats_TheWritableFloorIsNotBelowTheDeclaredHashOfANewPassword(t *testing.T) {
	t.Parallel()

	// Эталон — строка «хеш нового пароля» одобренной Ф1 §4.1: argon2id, память
	// 64 МБ (65536 КиБ), итераций 3, параллельность 4. Он стоит ЗДЕСЬ, а не
	// читается из текста приёмки: код документа не импортирует, и проба,
	// разбирающая чужую прозу, сверялась бы с текстом, а не с нормой.
	reference := map[domain.PasswordHashCostParam]uint32{
		domain.CostParamArgon2Memory:      65536,
		domain.CostParamArgon2Iterations:  3,
		domain.CostParamArgon2Parallelism: 4,
	}

	matched := 0
	for _, r := range domain.PasswordHashFormats() {
		if !r.Writable || r.Format != domain.PasswordHashFormatArgon2id {
			continue
		}
		matched++
		for p, want := range reference {
			require.GreaterOrEqualf(t, r.Floor[p], want,
				"пол %q/%q ниже строки «хеш нового пароля» Ф1 §4.1 — стойкость каждого нового пароля "+
					"падала бы молча", r.Format, p)
		}
	}
	require.Equal(t, 1, matched, "записываемая запись argon2id не найдена — эталону не с чем сверяться")
}
