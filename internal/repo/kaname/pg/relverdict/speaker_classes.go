// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict

// speaker_classes.go — системный класс субъекта в форме вердикта (приёмка
// anonymous-and-authenticated-are-subject-classes.md, kaname#829).
//
// Классы говорящего приходят в каждый из трёх запросов (прямой вопрос, вопрос
// о странице, перечень) ПАРАМЕТРАМИ `$10`, `$11` от одного производителя —
// `domain.SpeakerClasses`. Здесь — второе правило класса, которое обязано
// стоять в КАЖДОЙ ветви выдач, а не в одной: выдача классу раздаёт только
// чтение (Р4, SC-23).

import (
	"strings"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// classVerbFilterSQL — строка выдачи системному классу раздаёт только глаголы
// чтения, какими бы ни были правила её роли сейчас.
//
// Стоит на КАЖДОМ соединении с `role_verb` (вопрос, перечень, развёртка,
// перечень субъектов): правило, поставленное в одну форму, оставило бы
// соседнюю отвечать «пишет» о том же классе. Фильтр — на каждом выпуске
// ответа, а не однажды при выдаче: роль, выданная классу, может получить
// пишущий глагол путём, который правкой роли не является (поставка роли
// модулем, SC-23), и страж правки роли этого пути не видит.
//
// Набор глаголов совпадает с `domain.IsClassReadVerb`; равенство держит
// проба пакета.
const classVerbFilterSQL = `(bs.subject_type <> 'system_class' OR rv.verb = ANY ('{` + classReadVerbsList + `}'::text[]))`

// classReadVerbsList — глаголы чтения, которые выдача системному классу
// раздаёт, через запятую. Источник ОДИН на оба места, где класс сужается: фильтр
// проекции роли (classVerbFilterSQL) и глаголы правила в предикате ветви выдач
// (ruleVerbSQL, kaname#878).
const classReadVerbsList = `get,list`

// classSlot — имя i-го класса говорящего (без вида) либо пустая строка.
//
// Слотов ДВА, потому что классов в словаре два: производитель
// (`domain.SpeakerClasses`) не отдаёт больше, и проба пакета это держит.
// Пустой слот не совпадает ни с одной строкой: у субъекта выдачи и у факта
// пустого имени не бывает.
func classSlot(speaker string, i int) string {
	classes := domain.SpeakerClasses(speaker)
	if i >= len(classes) {
		return ""
	}
	return strings.TrimPrefix(classes[i], string(domain.SubjectTypeSystemClass)+":")
}
