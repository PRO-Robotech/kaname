// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// switch.go — ПЕРЕКЛЮЧЁННОЕ НАПРАВЛЕНИЕ: по названному типу решает форма, а
// движок спрашивается рядом и только сверяется.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТО ЗДЕСЬ, А НЕ У КАЖДОЙ ДВЕРИ РЕШЕНИЯ
//
// Дверей решения две поверхности: край (`service.AuthorizeService`) и обёртка,
// через которую спрашивают собственные стражи (`authzcascade.Client`). Один и
// тот же сравнитель выдан обеим — это записанное решение композиционного корня,
// принятое ради общего знаменателя. Значит рубильник, положенный СЮДА,
// оказывается один на обе поверхности by construction, а не потому, что две
// стороны договорились.
//
// Обратное — рубильник у каждой двери — дало бы ровно ту беду, ради которой
// сравнение вообще собрано в одну точку: тип, переключённый на одной
// поверхности и не переключённый на другой, отвечает на ОДИН вопрос об ОДНОМ
// объекте двумя действующими источниками.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ОТКАЗ ФОРМЫ — ЭТО ОТКАЗ, А НЕ «СПРОСИ ДВИЖОК»
//
// Запасной путь на движок выглядит осторожным и является противоположностью
// осторожности. Он срабатывает ровно под той нагрузкой, при которой форма и
// начинает не успевать, — то есть возвращает зависимость от движка именно
// тогда, когда её отсутствие только что было объявлено измеренным. Хуже:
// возвращает её НЕВИДИМО, потому что ответ вызывающему при этом правильный.
//
// Поэтому исходов ровно три и они различимы ТИПОМ, а не значением:
//
//	форма ответила          → её вердикт, движок сверяется рядом;
//	форма не ответила       → ошибка вызывающему (недоступность), НЕ отказ;
//	тип не переключён       → прежний путь, движок решает, форма сверяется.
//
// «Не смог спросить» не имеет представления на успешном пути — иначе отказ
// зависимости читался бы как «доступа нет», а это разные миры.

package shadowverdict

import (
	"context"
	"errors"
	"fmt"

	"github.com/PRO-Robotech/kacho/services/iam/internal/verdictsource"
)

// ErrFormNotWired — рубильник называет тип переключённым, а формы нет.
//
// Тихий отказ здесь был бы худшим исходом: тип выглядел бы переключённым, а
// каждое решение по нему становилось бы отказом без единой записи. Ошибка
// сборки обязана звучать как ошибка сборки. Боевая посадка в этом состоянии
// находиться не должна — её проверяет отказ в старте, а не надежда.
var ErrFormNotWired = errors.New("shadow verdict: источник вердикта переключён на форму, но форма не провязана")

// WithSwitchboard провязывает рубильник источника вердикта.
//
// Возвращает тот же сравнитель, чтобы композиционный корень собирал значение
// одним выражением. Пустой рубильник — законный и умалчиваемый вход: не
// переключено ничего, поведение прежнее.
func (c *Comparator) WithSwitchboard(sb verdictsource.Switchboard) *Comparator {
	if c == nil {
		return nil
	}
	c.switchboard = sb
	return c
}

// Decides — принимает ли решение по этому типу ФОРМА.
//
// Отвечает «нет» без формы, и это не осторожность, а тождество: источник,
// которого нет, решать не может. Тот же предикат читают страж старта и
// самоотчёт — «страж прошёл» ⟺ «источник действительно переключён».
func (c *Comparator) Decides(objectType string) bool {
	return c != nil && c.form != nil && c.switchboard.Decides(objectType)
}

// Switchboard отдаёт действующий рубильник — для самоотчёта и метрики.
//
// Читается ТОТ ЖЕ объект, что и путём решения: перечень, собранный отдельно из
// конфигурации, отвечал бы на вопрос «что объявлено», тогда как спрашивают
// «что действует».
func (c *Comparator) Switchboard() verdictsource.Switchboard {
	if c == nil {
		return verdictsource.Switchboard{}
	}
	return c.switchboard
}

// Verdict — вердикт ФОРМЫ по переключённому типу; движок спрашивается РЯДОМ.
//
// # Что здесь на пути запроса, а что нет
//
// На пути запроса — ровно один вопрос форме, и он идёт по контексту ВЫЗЫВАЮЩЕГО
// со сроком вызывающего: это решение, а не наблюдение, и укорачивать ему бюджет
// сроком сверки было бы подменой предмета.
//
// Вне пути запроса — вопрос движку (`askEngine`) и сведение. Ответ вызывающему
// не зависит ни от исхода теневого вызова, ни от недоступности движка, ни от
// того, достался ли теневому пути слот.
//
// # Почему движок спрашивается через переданную функцию
//
// Пакет обязан остаться листом относительно движка: он не знает ни транспорта,
// ни того, из чего складывается окончательный вердикт у вызывающего (у края к
// ответу движка добавляются плоский надзор администратора облака и структурный
// запасной путь). Сравнивать половину ответа значило бы записывать расхождение
// между стадиями одного решения, а не между формами. Поэтому «как спросить
// движок» знает вызывающий, а «что с этим делать» — эта функция.
func (c *Comparator) Verdict(
	ctx context.Context, subject, objectType, objectID, relation string,
	condCtx map[string]any,
	askEngine func(context.Context) (engineAllowed, engineAnswered bool),
) (bool, error) {
	if c == nil || c.form == nil {
		return false, ErrFormNotWired
	}

	c.counts.decisions.Add(1)
	c.counts.verdictsForm.Add(1)

	const question = "прямой вердикт"

	allowed, err := c.form.Allowed(ctx, subject, objectType, objectID, relation, condCtx)
	if err != nil {
		// Форма не ответила. Это НЕ «доступа нет» и НЕ повод спросить движок:
		// исход уезжает вызывающему ошибкой, а здесь честно ложится в корзину
		// «не выполнилось» — иначе доля сравнённого считалась бы от того
		// подмножества, где форма отвечала.
		c.unfinishedAt(question, err.Error(), objectType, relation)
		return false, fmt.Errorf("shadow verdict: форма не ответила: %w", err)
	}

	c.shadowEngine(ctx, question, allowed, subject, objectType, objectID, relation, askEngine)
	return allowed, nil
}

// shadowEngine задаёт вопрос ДВИЖКУ вне пути запроса и сводит исход.
//
// Зеркало `offPath`: там в горутине живёт вопрос форме, здесь — вопрос движку.
// Обе половины делят ОДИН потолок одновременности (`sem`) намеренно: он
// ограничивает всю теневую работу процесса, а не одну её сторону. Слот занят —
// вопрос ОТБРАСЫВАЕТСЯ со своей причиной и остаётся в знаменателе; очередь
// вернула бы неограниченный рост работы, которая ни на что не влияет.
//
// Отдельного ожидания сведения здесь не нужно: ответ формы уже известен к
// моменту запуска, поэтому канала и его гонок нет вовсе.
func (c *Comparator) shadowEngine(
	ctx context.Context, question string, formAllowed bool,
	subject, objectType, objectID, relation string,
	askEngine func(context.Context) (bool, bool),
) {
	if askEngine == nil {
		c.unfinishedAt(question, "движок не спрошен: вызывающий не назвал, как спросить", objectType, relation)
		return
	}
	if !c.acquire() {
		c.unfinishedAt(question, reasonSaturated, objectType, relation)
		return
	}
	// Срок теневого вопроса к движку — свой, и контекст без отмены: обработчик
	// вызывающего вернётся раньше, чем движок ответит, и вопрос, унаследовавший
	// его отмену, попадал бы в «не выполнилось» на КАЖДОМ решении.
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), EngineShadowTimeout)
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer c.release()
		defer cancel()

		engineAllowed, engineAnswered := askEngine(sctx)
		if !engineAnswered {
			c.unfinishedAt(question, "движок вердикта не дал", objectType, relation)
			return
		}
		c.counts.compared.Add(1)
		if formAllowed == engineAllowed {
			c.maybeSummarise()
			return
		}
		c.recordDivergence(question, subject, objectType, objectID, relation, formAllowed, engineAllowed)
	}()
}

// recordDivergence считает расхождение ПО НАПРАВЛЕНИЮ и называет его.
//
// # Почему направления считаются раздельно
//
// «Форма разрешает там, где движок отказывал» — расширение доступа: на
// переключённом типе это уже случившееся событие безопасности, и оно требует
// отката типа, а не разбора. «Форма отказывает там, где движок разрешал» —
// отказ в обслуживании: разбирается без отката, если не задевает аварийный путь
// администратора облака. Один счётчик на оба сделал бы их неотличимыми ровно
// там, где различие и решает, что делать в следующую минуту.
//
// # Почему направление считается и на НЕПЕРЕКЛЮЧЁННОМ пути
//
// Направление — свойство ПАРЫ ответов, а не того, кого спросили первым.
// Считать его только после переключения значило бы завести вторую меру того же
// предмета и «переворачивать полярность» второй реализацией; две меры одного
// предмета расходятся молча. Меняется не счёт, а СРОЧНОСТЬ: до переключения
// расширение блокирует переключение типа, после — требует его отката.
func (c *Comparator) recordDivergence(
	question, subject, objectType, objectID, relation string, formAllowed, engineAllowed bool,
) {
	c.counts.diverged.Add(1)
	wider := formAllowed && !engineAllowed
	if wider {
		c.counts.divergedFormWider.Add(1)
	} else {
		c.counts.divergedFormNarrower.Add(1)
	}

	direction := "форма уже движка — отказ в обслуживании"
	if wider {
		direction = "форма шире движка — расширение доступа"
	}
	decidedByForm := c.switchboard.Decides(objectType)

	// Поимённо — ОДИН РАЗ НА КЛАСС; повторы копятся счётчиком класса и выходят
	// сводкой. Разбирают расхождение всё равно по классу, а не по случаю.
	// КЛЮЧ КЛАССА — контракт с внешним прибором, а не внутренняя строка.
	//
	// Разбор сводки (`deploy/load-tests/iam-shadow-divergence-probe.sh`) читает
	// направление по суффиксу `движок=<bool>`, и в расхождении этого достаточно:
	// ответы противоположны by construction, значит `движок=false` ⟺ разрешила
	// форма ⟺ «форма шире». Второе написание того же значения в ключе не
	// добавляет ничего и ломает разбор — а сломанный разбор объявляет
	// расхождение неразобранным, то есть выдаёт отказ прибора за находку.
	//
	// Направление едет отдельным ПОЛЕМ записи (см. ниже): поле читается
	// человеком, суффикс — прибором, и оба берут его из одной величины `wider`.
	class := fmt.Sprintf("%s|%s|%s|движок=%v", question, objectType, relation, engineAllowed)
	first, seen := c.firstOfClass(class)
	if first {
		fields := []any{
			"question", question, "engine", engineAllowed, "form_e", formAllowed,
			"direction", direction, "decided_by_form", decidedByForm,
			"subject", subject, "object_type", objectType, "object_id", objectID,
			"relation", relation, "class", class, "class_seen", seen,
		}
		if decidedByForm && wider {
			// Тип переключён, и решение приняла форма. Это не наблюдение —
			// это состояние, требующее отката типа рубильником.
			c.logger.Error("shadow verdict: P0 РАСШИРЕНИЕ ДОСТУПА на переключённом типе — откатить тип рубильником",
				append(fields, c.coverage()...)...)
		} else {
			c.logger.Error("shadow verdict: РАСХОЖДЕНИЕ формы E с движком",
				append(fields, c.coverage()...)...)
		}
	}
	c.maybeSummarise()
}

// VerdictMany — вердикт ФОРМЫ о странице объектов ОДНОГО переключённого типа.
//
// Страница стоит одну читающую транзакцию (см. `Asker.AllowedMany`), а движок
// спрашивается о ней РЯДОМ одним батчевым вопросом.
//
// # Почему сверка страницы здесь ПОЛНАЯ, а не по бюджету
//
// Бюджет `BatchCompareBudget` существовал по одной причине: сверять страницу
// поштучно значило открыть по транзакции на объект. После смены направления
// дорогая сторона поменялась местами — форма отвечает о всей странице одной
// транзакцией, а движку батчевый вопрос стоит один вызов. Ограничивать здесь
// нечего, и бюджет не переносится: он остаётся у СВОЕГО предмета — сверки
// страницы, решаемой движком.
//
// Знаменатель растёт на число объектов страницы: одно сообщение — не одно
// решение, и страница из N объектов несёт N решений.
func (c *Comparator) VerdictMany(
	ctx context.Context, subject, objectType string, objectIDs []string, relation string,
	condCtx map[string]any,
	askEngine func(context.Context) (engineVerdicts []bool, engineAnswered bool),
) ([]bool, error) {
	if c == nil || c.form == nil {
		return nil, ErrFormNotWired
	}
	if len(objectIDs) == 0 {
		return nil, nil
	}

	const question = "прямой вердикт страницы"

	c.counts.decisions.Add(int64(len(objectIDs)))
	c.counts.verdictsForm.Add(int64(len(objectIDs)))

	allowed, err := c.form.AllowedMany(ctx, subject, objectType, objectIDs, relation, condCtx)
	if err != nil {
		for range objectIDs {
			c.unfinishedAt(question, err.Error(), objectType, relation)
		}
		return nil, fmt.Errorf("shadow verdict: форма не ответила о странице: %w", err)
	}
	if len(allowed) != len(objectIDs) {
		// Ответ не той длины разложить по позициям нельзя, и подставлять
		// умолчание нечем: «нет» на недостающих объектах отфильтровало бы
		// страницу вердиктом, которого никто не выносил.
		for range objectIDs {
			c.unfinishedAt(question, "форма ответила не о той странице", objectType, relation)
		}
		return nil, fmt.Errorf("shadow verdict: форма ответила о %d объектах из %d",
			len(allowed), len(objectIDs))
	}

	c.shadowEnginePage(ctx, question, allowed, subject, objectType, objectIDs, relation, askEngine)
	return allowed, nil
}

// shadowEnginePage задаёт странице вопрос ДВИЖКУ вне пути запроса и сводит исход
// по каждому объекту.
func (c *Comparator) shadowEnginePage(
	ctx context.Context, question string, formAllowed []bool,
	subject, objectType string, objectIDs []string, relation string,
	askEngine func(context.Context) ([]bool, bool),
) {
	if askEngine == nil {
		for range objectIDs {
			c.unfinishedAt(question, "движок не спрошен: вызывающий не назвал, как спросить", objectType, relation)
		}
		return
	}
	if !c.acquire() {
		for range objectIDs {
			c.unfinishedAt(question, reasonSaturated, objectType, relation)
		}
		return
	}
	sctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), EngineShadowTimeout)
	// Копия ответа формы: срез уехал вызывающему, и читать его из горутины
	// после возврата значило бы сверяться с тем, что вызывающий уже мог
	// переписать под себя.
	formVerdicts := make([]bool, len(formAllowed))
	copy(formVerdicts, formAllowed)
	ids := make([]string, len(objectIDs))
	copy(ids, objectIDs)

	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer c.release()
		defer cancel()

		engineVerdicts, engineAnswered := askEngine(sctx)
		for i, id := range ids {
			if !engineAnswered || i >= len(engineVerdicts) {
				c.unfinishedAt(question, "движок вердикта не дал", objectType, relation)
				continue
			}
			c.counts.compared.Add(1)
			if formVerdicts[i] == engineVerdicts[i] {
				continue
			}
			c.recordDivergence(question, subject, objectType, id, relation,
				formVerdicts[i], engineVerdicts[i])
		}
		c.maybeSummarise()
	}()
}
