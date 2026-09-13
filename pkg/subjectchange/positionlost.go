// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

package subjectchange

import (
	"fmt"
	"strconv"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// positionlost.go — СЛОВАРЬ ОТКАЗА «позиция утрачена» для журнала смены субъекта.
//
// # Зачем этот отказ вообще существует
//
// Журнал читается окном `id > since AND id <= settled`. Снятая строка в такое
// окно не попадает: курсор переезжает через неё по последней прочитанной
// позиции, и «строк не было» становится НЕОТЛИЧИМО от «строки убрали». Полоса
// при этом fail-open by design — пропущенная строка означает непогашенный кэш
// вердиктов края, то есть неприменённый отзыв доступа, молча.
//
// Пока такого отказа не существовало, уборка журнала была невозможна не по
// предпочтению, а by construction: любой уборщик молча уносил бы отзывы у
// читателя из-под курсора. Отказ — это и есть недостававший предикат
// обнаружения пропуска.
//
// # Почему производитель и распознаватель — ОДНА пара в ОДНОМ файле
//
// Отказ собирает ВЛАДЕЛЕЦ журнала (iam), а разбирает ЧИТАТЕЛЬ (край). Это две
// стороны одного шва, и класс, которым он ломается, назван в корпусе: два
// механизма об одном предмете, каждый исправен, а вопрос одного — не тот, на
// который отвечает другой. Две похожие сборки одного признака (там «собрал», тут
// «разобрал») разошлись бы МОЛЧА: у обеих непустой токен, обе выглядят полосой,
// а совпасть они перестают навсегда.
//
// Поэтому расхождение сделано НЕВЫРАЗИМЫМ, а не обнаруживаемым: обе стороны
// зовут функции этого файла, и смена канона — правка одной строки здесь.
// Владелец журнала берёт их отсюда же, хотя пакет живёт у читателя: словарь
// принадлежит ПОЛОСЕ, а не тому, кто оказался её первым автором.

// ReasonPositionLost — машинный признак полосы «позиция больше не возобновима».
//
// Клиент ключуется на признак, а не разбирает прозу сообщения: тон сообщения —
// часть контракта, но не его машинная часть.
const ReasonPositionLost = "SUBJECT_CHANGE_POSITION_LOST"

// errorDomain — поверхность, произведшая отказ.
//
// Полосу называет ТОКЕН; домен называет поверхность (`api-conventions.md`
// §By-lane code-split: `<service>.kacho.cloud`). Журнал принадлежит владельцу
// прав, поэтому домен его, а не читательский.
const errorDomain = "iam.kacho.cloud"

// metaEarliestResumable — ключ, под которым едет возобновимая позиция.
const metaEarliestResumable = "earliest_resumable_position"

// PositionLostError — разобранный отказ: с какой позиции читателю СЕСТЬ.
//
// Позиция здесь несущая, а не справочная. Без неё читателю некуда деться:
// принять ноль значило бы проиграть журнал с начала, остаться на месте — получать
// тот же отказ вечно.
type PositionLostError struct {
	// EarliestResumable — нижняя позиция, с которой возобновление ещё ничего не
	// теряет: «самая ранняя удержанная строка минус один», а у вычищенного
	// целиком журнала — сама граница устоявшегося.
	EarliestResumable int64
}

func (e *PositionLostError) Error() string {
	return fmt.Sprintf("subject change position is no longer resumable; earliest resumable position is %d",
		e.EarliestResumable)
}

// PositionLost собирает отказ владельца журнала.
//
// Код `OUT_OF_RANGE` выбран потому, что вызывающий ошибся ПОЗИЦИЕЙ, а не
// временем: повтор того же запроса не пройдёт никогда, сколько бы ни ждать.
// Спутать его с `UNAVAILABLE` («границы ещё нет, переспроси») нельзя — тот
// советует ровно противоположное действие.
//
// Молчаливое начало с ближайшего удержанного места вместо отказа читатель
// записал бы как «изменений не было», а дописать этот исход потом стало бы
// ломающим изменением.
func PositionLost(earliestResumable int64) error {
	st := status.New(codes.OutOfRange,
		"subject change position is no longer resumable; flush the decision cache and resume "+
			"from the earliest resumable position")
	withDetails, err := st.WithDetails(&errdetails.ErrorInfo{
		Reason: ReasonPositionLost,
		Domain: errorDomain,
		Metadata: map[string]string{
			metaEarliestResumable: strconv.FormatInt(earliestResumable, 10),
		},
	})
	if err != nil {
		// Деталь не прикрепилась. Отдаём код и текст как есть: читатель
		// распознавателем такой отказ НЕ признает и уйдёт в общую ветвь — она
		// громкая (жалоба) и безопасная (fail-closed по сроку). Притвориться
		// полосой без позиции хуже: сесть по ней всё равно некуда.
		return st.Err()
	}
	return withDetails.Err()
}

// AsPositionLost разбирает отказ владельца.
//
// # Ключуется на ПРИЗНАК, а не на код
//
// Тот же `OUT_OF_RANGE` производят чужие полосы (в том числе одноимённая полоса
// журналов подписки), и признать их своими значило бы погасить кэш и пересесть
// по чужой позиции. Код и признак разойтись не могут: их ставит один
// конструктор выше.
//
// # Отказ БЕЗ позиции полосой не является
//
// Читателю от него нет пользы: погасить кэш он ещё может, а сесть некуда.
// Поэтому такой ответ уходит в общую ветвь, где он громкий и fail-closed, а не
// притворяется полосой контракта. То же для непарсибельной позиции: значение,
// которое не число, — дефект производителя, и подставлять вместо него ноль
// значило бы проиграть журнал с начала по чужой ошибке.
func AsPositionLost(err error) (*PositionLostError, bool) {
	if err == nil {
		return nil, false
	}
	st, ok := status.FromError(err)
	if !ok {
		return nil, false
	}
	for _, d := range st.Details() {
		info, isInfo := d.(*errdetails.ErrorInfo)
		if !isInfo || info.GetReason() != ReasonPositionLost {
			continue
		}
		raw, named := info.GetMetadata()[metaEarliestResumable]
		if !named {
			return nil, false
		}
		pos, perr := strconv.ParseInt(raw, 10, 64)
		if perr != nil {
			return nil, false
		}
		return &PositionLostError{EarliestResumable: pos}, true
	}
	return nil, false
}
