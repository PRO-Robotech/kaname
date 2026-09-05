// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package clients

// relations.go — ПОРТЫ вопроса о доступе.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ ИЗМЕНИЛОСЬ ПРИ СНЯТИИ ВНЕШНЕГО ДВИЖКА
//
// Эти два порта объявляли поверхность ЧУЖОГО хранилища отношений: вопрос,
// перечисление, чтение кортежей, ЗАПИСЬ кортежей и сведения о хранилище. Записи
// и сведений больше нет — не потому, что их «пока не сделали», а потому, что
// писать больше некуда: состояние, из которого складывается ответ, есть свёртка
// СВОЕГО журнала намерений, и пишет в него тот же коммит, что меняет выдачу.
//
// Остаётся ровно то, что у ответа спрашивают: вердикт об объекте, вердикт о
// странице объектов и перечисление субъектов. Реализация — `internal/authzcascade`
// поверх реляционной формы (`repo/kacho/pg/relverdict`).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПОРТОВ ДВА, А НЕ ОДИН
//
// Разделение переживает движок и остаётся полезным: `RelationStore` — вопрос без
// условий, его держат стражи, которым условный контекст неоткуда взять;
// `RelationQueries` — вопрос С контекстом и страничные формы, их держат читающие
// use-case'ы. Сведение в один порт заставило бы стража объявлять зависимость от
// того, чем он не пользуется, — и первый же дублёр в пробе стал бы шире предмета.

import (
	"context"

	"github.com/PRO-Robotech/kacho-iam/internal/authztypes"
)

// RelationTuple — тройка «субъект, отношение, объект».
//
// ОСТАЁТСЯ ПОСЛЕ СНЯТИЯ ДВИЖКА: это форма полезной нагрузки СТРОКИ ЖУРНАЛА
// намерений (`kacho_iam.fga_outbox`), из которой триггер складывает прямой факт.
// Журнал и триггер — решение Р7 приёмки R7-3: снимается потребитель журнала, а не
// журнал.
type RelationTuple struct {
	User     string
	Relation string
	Object   string
}

type (
	// ConditionalTuple — псевдоним authztypes.ConditionalTuple.
	ConditionalTuple = authztypes.ConditionalTuple
	// TupleConditionRef — псевдоним authztypes.TupleConditionRef.
	TupleConditionRef = authztypes.TupleConditionRef
)

// RelationStore — вопрос о доступе БЕЗ условного контекста.
type RelationStore interface {
	// Check — держит ли субъект это отношение на этом объекте.
	//
	// Ошибка означает «ответа нет», а не «доступа нет»: вызывающий обязан
	// различать их, иначе недоступность базы читалась бы как законный отказ.
	Check(ctx context.Context, subject, relation, object string) (allowed bool, err error)
}

// RelationQueries — вопрос С условным контекстом и страничные формы.
type RelationQueries interface {
	// CheckWithContext — вердикт с условным контекстом запроса.
	CheckWithContext(ctx context.Context, subject, relation, object string, condCtx map[string]any) (allowed bool, err error)

	// BatchCheckWithContext — ОДИН вопрос о МНОГИХ объектах одного типа; по
	// вердикту на объект, позиционно.
	//
	// Объявлен здесь, а не отдельной способностью, НАМЕРЕННО: этот порт — тип
	// поля в каждом читающем use-case, а фильтр страницы (`internal/authzfilter`)
	// выбирает батчевый путь. Провязка, потерявшая способность, продолжала бы
	// возвращать верные строки, платя по обращению за строку, и заметить это было
	// бы нечем. Здесь потеря — ошибка компиляции.
	//
	// Стоимость страницы принадлежит ЗАПРОСУ: ответ собирается одной читающей
	// транзакцией, поэтому все объекты страницы видят один снимок базы.
	BatchCheckWithContext(ctx context.Context, subject, relation string, objects []string,
		condCtx map[string]any) (allowed []bool, err error)

	// ListSubjects — кто держит это отношение на объекте, СТРАНИЦЕЙ С КУРСОРОМ.
	//
	// Курсор обязателен и это не оформление: перечисление без продолжения
	// оставляет остаток недостижимым при живых правах — ровно то, ради чего снято
	// перечисление объектов (решение Р1 приёмки R7-3).
	ListSubjects(ctx context.Context, objectType, objectID, relation string,
		pageSize int, pageToken string) (subjects []string, nextPageToken string, err error)
}
