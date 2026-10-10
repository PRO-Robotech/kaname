// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// people_address_lawful_writers.go — ПЕРЕЧЕНЬ законных писателей адреса
// человека в существующую строку в непроверочном Go (задача
// PRO-Robotech/kaname#635; приёмка
// `docs/engineering/acceptance/email-change-is-confirmed-from-the-new-address.md`,
// Р9, сценарий EC-24).
//
// # Предмет
//
// Гейт `TestPeopleAddressHasNoWriterInServiceCode` держал число таких мест
// равным нулю, пока у продукта не было глагола смены адреса, и текст его
// находки (`addressWriterFinding`) называл условия, без которых глагол не
// вносится. Приёмка смены адреса разобрала каждое условие (Р9) и разрешила
// ОДНОГО законного писателя — оператор исхода смены. Перечень называет его
// координатой: файл и функция, в которой стоит оператор, и довод.
//
// # Чем перечень держится
//
//   - запись поглощает РОВНО ОДНО место записи адреса в своём файле и своей
//     функции: второй оператор той же функции, пишущий адрес, — находка, как
//     и любое место вне перечня;
//   - запись без предмета — находка: перечень истекает вместе со своим
//     писателем и не переживает его, оставаясь на вид рабочим;
//   - запись о файле, которого в корпусе нет, считается отдельно (как у
//     ведомости применённых миграций) — инъекция судит синтетику, — а проба
//     дерева требует, чтобы таких было ноль.
//
// Пополняется перечень только одобренной приёмкой, назвавшей писателя, — не
// правкой гейта под покрасневший прогон.
package check

import (
	"fmt"
	"strings"
)

// PeopleLawfulGoWriter — законный писатель адреса в непроверочном Go.
type PeopleLawfulGoWriter struct {
	// Rel — файл; Func — функция, как её называет координата находки
	// (`тип.метод` либо `функция`).
	Rel, Func string
	// Why — почему писатель законен: приёмка и чем выполнены условия гейта.
	Why string
}

// peopleLawfulGoWriters — перечень. Одна запись: оператор исхода смены адреса.
var peopleLawfulGoWriters = []PeopleLawfulGoWriter{
	{
		Rel:  "internal/repo/kaname/pg/email_change_repo.go",
		Func: "humanSessionWriter.ChangeEmail",
		Why: "оператор исхода смены адреса (приёмка email-change-is-confirmed-from-the-new-address.md, " +
			"Р8 п. 1, Р9; kaname#635): пишет адрес только предъявлением кода с нового адреса под живой " +
			"сессией самого человека, в транзакции, которая тем же исходом ставит отметку существующим " +
			"оператором, снимает прочие сессии, ставит письмо на прежний адрес и пишет строку очереди " +
			"смены субъекта; запросу смены предшествует свежесть",
	},
}

// PeopleLawfulGoWriters — перечень копией.
func PeopleLawfulGoWriters() []PeopleLawfulGoWriter {
	out := make([]PeopleLawfulGoWriter, len(peopleLawfulGoWriters))
	copy(out, peopleLawfulGoWriters)
	return out
}

// matchPeopleLawful — места Go против перечня: запись поглощает ровно одно
// место записи адреса в своём файле и своей функции; запись без предмета —
// находка; запись о файле вне корпуса считается отдельно.
func matchPeopleLawful(sites []peopleSite, lawful []PeopleLawfulGoWriter, goCorpus TreeCorpus) (rest []peopleSite, named, stale []string, outside int) {
	used := make([]bool, len(sites))
	for _, e := range lawful {
		if !strings.HasSuffix(e.Rel, ".go") || e.Func == "" {
			stale = append(stale, fmt.Sprintf("%s %s — запись перечня законных писателей адреса называет не функцию "+
				"исходника Go: перечень судит только непроверочный Go", e.Rel, e.Func))
			continue
		}
		if _, ok := goCorpus[e.Rel]; !ok {
			outside++
			continue
		}
		found := false
		for i, s := range sites {
			if used[i] || s.migration || s.kind != siteWriter || s.column != PeopleAddressColumn || s.rel != e.Rel ||
				!strings.HasSuffix(s.where, " в "+e.Func+"()") {
				continue
			}
			used[i], found = true, true
			named = append(named, fmt.Sprintf("%s — законный писатель адреса: %s", s.where, e.Why))
			break
		}
		if !found {
			stale = append(stale, fmt.Sprintf("%s в %s() — запись перечня законных писателей адреса без предмета: "+
				"разбор не находит в этой функции оператора, пишущего адрес человека (%s). Перечень истекает вместе "+
				"со своим писателем — запись снимается тем же изменением, что сняло оператор", e.Rel, e.Func, e.Why))
		}
	}
	for i, s := range sites {
		if !used[i] {
			rest = append(rest, s)
		}
	}
	return rest, named, stale, outside
}
