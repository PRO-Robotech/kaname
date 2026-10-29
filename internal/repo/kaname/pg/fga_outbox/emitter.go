// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package fga_outbox — atomic emit-in-tx helper for kaname.fga_outbox.
//
// Mirror of the SubjectChangeEmitter pattern
// (internal/repo/kaname/pg/subject_change_emitter.go).
//
// Background
//
//	Раньше каждая мутация отношения шла пост-коммитным синхронным вызовом в
//	чужое хранилище (незаметный Warn на отказе), а часть путей не писала туда
//	вовсе. Совокупный эффект: состояние прав НЕ было надёжным источником истины.
//
//	Все мутации сведены к этому журналу: выдача и отзыв кладут N строк в
//	`kaname.fga_outbox` в ТОЙ ЖЕ pgx.Tx, что и доменное изменение. Откат
//	транзакции вызывающего ⇒ ни одной осиротевшей строки.
//
//	ЧТО ИЗМЕНИЛОСЬ СО СНЯТИЕМ ДВИЖКА (стадия S6, эпик kacho#747). Потребителя у
//	журнала было двое: дренаж, применявший строки к внешнему хранилищу, и
//	триггер, складывающий из них ПРЯМОЙ ФАКТ (`relation_fact`, миграция 0098).
//	Первого больше нет — применять некуда; второй остался и стал единственным.
//
//	Следствие названо прямо, потому что оно меняет срок: строка журнала теперь
//	действует С КОММИТА, а не «когда доедет». Величин доставки у таблицы нет
//	ВОВСЕ — не «их никто не двигает», а их не существует (см. форму ниже);
//	переименование журнала, чьё имя называет снятый движок, — предмет отдельной
//	задачи (§7 приёмки).
//
//	Per ban #10 — within-service refs/invariants live on DB-level: tx-commit is
//	the atomicity primitive, not "INSERT then call the store and hope".
//
// Форма `kaname.fga_outbox` (таблица и триггеры — миграция `0001_initial.sql`).
// ЧЕТЫРЕ колонки, и это вся таблица:
//
//	id            bigserial    PK
//	event_type    text         IN ('fga.tuple.write','fga.tuple.delete')
//	payload       jsonb        {"user":"…","object":"…"} плюс ЛИБО "relation"
//	                           (одно отношение), ЛИБО "relations" (весь набор
//	                           субъекта на этом объекте; см. emitTx); у строки
//	                           ПУБЛИКАЦИИ и у строки иерархии посредника
//	                           регистрации ещё "source_version" — версия
//	                           владельца (см. EmitPublicationTx,
//	                           EmitOwnerOrderedTx)
//	created_at    timestamptz  default now(); строка СНЯТИЯ без версии владельца
//	                           несёт момент своей вставки, clock_timestamp()
//	                           (см. deleteStamp)
//
// Величин доставки (`sent_at`, `last_error`, `attempt_count`) здесь НЕТ, и перечислять
// их было бы не описанием, а обещанием: запрос по ним отвергается базой (42703).
// Они существовали ради клейма дренажа и сняты вместе с ним миграцией 20260822160000
// (kacho#917); ключ упорядочивания `tuple_key` и его триггер — 20260823001000
// (kacho#1033). Класс «журнал спрашивают по признаку доставки, которого у него нет»
// держит гейт `internal/repohygiene`
// `TestJournalWithoutDeliveryMarkerIsNotQueriedByIt` (kacho#1049).
//
// Ключа упорядочивания у строки БОЛЬШЕ НЕТ. Колонку `tuple_key` заполнял триггер
// `BEFORE INSERT`, а читал её клейм дренажа — «только голова партиции». Дренажа
// не стало вместе с внешним движком прав (стадия S6 эпика kacho#747), и писатель
// пережил своего читателя: после снятия колонки он отвергал КАЖДУЮ вставку
// (`record "new" has no field "tuple_key"`, 42703), то есть каждую выдачу и
// каждый отзыв доступа. Триггер, его функция и сторож наличия ключа сняты
// миграцией 20260823001000 (kacho#1033); сама колонка и её индексы — миграцией
// 20260822160000 (kacho#917).
//
// Виды записи объявлены ЗДЕСЬ ЖЕ ([EventTypeWrite] / [EventTypeDelete]). Прежде они
// брались у применителя дренажа, но ни применителя, ни его файла в дереве нет — ссылка
// на них посылала читателя по координате, которой не существует.
package fga_outbox

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// EventTypeWrite / EventTypeDelete — the two event types this table carries.
// Exported so every producer names the row's kind through the package that owns
// the row's shape, instead of repeating the literal at its own INSERT.
const (
	EventTypeWrite  = "fga.tuple.write"
	EventTypeDelete = "fga.tuple.delete"
)

// RelationPredicate renders the SQL predicate «this row carries <arg> as one of its
// relations», matching BOTH row shapes — the single-relation payload and the set.
//
// It exists because a reader that keys on `payload->>'relation'` alone sees only the
// FIRST member of a set, and the direction that fails is the quiet one: a query asking
// "is this tuple queued?" answers NO for a tuple that is queued, so a de-duplication
// enqueues a second time and an assertion that a tuple is ABSENT passes without ever
// looking at the row that holds it.
//
// payloadExpr is the jsonb column expression (`payload`, `o.payload`); arg is the
// placeholder or literal carrying the relation.
func RelationPredicate(payloadExpr, arg string) string {
	return "(" + payloadExpr + "->>'relation' = " + arg +
		" OR " + payloadExpr + "->'relations' @> to_jsonb(" + arg + "::text))"
}

// EmitWriteTx INSERTs N grant rows into `kaname.fga_outbox` (event_type
// `fga.tuple.write`) using the caller-supplied transaction.
//
// MUST run in the same pgx.Tx as the domain state-change (AccessBinding
// insert, JIT auto-grant InsertTx, cluster_admin_grants insert). Tx rollback
// ⇒ outbox rows are not visible to the drainer.
//
// len(tuples)==0 is a no-op (returns nil) — caller decides whether 0 tuples
// is an error.
func EmitWriteTx(ctx context.Context, tx pgx.Tx, tuples []clients.RelationTuple) error {
	return emitTx(ctx, tx, EventTypeWrite, tuples)
}

// EmitDeleteTx INSERTs N revoke rows into `kaname.fga_outbox` (event_type
// `fga.tuple.delete`).
//
// Caller supplies the EXACT tuples that were originally written by EmitWriteTx
// — symmetric revoke. Same atomicity contract as EmitWriteTx.
func EmitDeleteTx(ctx context.Context, tx pgx.Tx, tuples []clients.RelationTuple) error {
	return emitTx(ctx, tx, EventTypeDelete, tuples)
}

// EmitPublicationTx кладёт строку журнала ПУБЛИКАЦИИ объекта для анонимного
// чтения — кортеж `system_class:anonymous #v_get @<object>`, — упорядоченную
// ВЕРСИЕЙ ВЛАДЕЛЬЦА.
//
// Хранимый субъект публикации — системный класс `anonymous`, а не входное слово
// соседа (`user:*` либо `system_class:anonymous`, kaname#893): перевод живёт
// ОДНИМ написанием,
// `domain.PublicationSubject`, и его же называют снятие публикации, разбор
// остаточных фактов и миграция переезда (kaname#829, SC-12, SC-13).
//
// # Чем эта строка отличается от всех остальных, и почему отличие несущее
//
// Полезная нагрузка несёт поле `source_version`. По нему проекция журнала в
// прямой факт (`kaname.relation_fact_from_journal`) узнаёт строку, упорядоченную
// владельцем, и делает с ней две вещи, которых не делает ни с одной другой:
//
//   - сравнивает её по версии владельца, а не по метке `created_at`. Метка —
//     момент НАЧАЛА транзакции службы: снятие, начавшее транзакцию раньше
//     открытия и применённое позже, иначе оказалось бы старше того, что обязано
//     снять, и факт пережил бы своё снятие;
//   - переносит её в прямой факт, хотя отношение — глагол. Глаголы проекция не
//     копирует: форма E выводит их из выдачи. Публикацию не выводит ни одна
//     выдача — её объявляет владелец ресурса, — и без факта её нет нигде.
//
// Поэтому функция принимает ТОЛЬКО объект: субъект и отношение она берёт у
// перевода входного слова (`domain.PublicationSubject` / `PublicationRelation`),
// а не у вызывающего. Строку другой формы с этим полем положить нельзя by construction,
// и глагол, выведенный из выдачи, мимо запрета проекции не проедет.
//
// Тем же полем с kaname#969 упорядочены и строки иерархии посредника регистрации
// (EmitOwnerOrderedTx): первое свойство выше — сравнение по версии владельца — у
// них то же, второго у них нет, потому что глаголов и публикаций среди них нет
// (EmitOwnerOrderedTx отвергает такие строки, а не пропускает).
//
// # Кто зовёт
//
// Только путь публикации (`public_read.ApplyTx`), и только когда намерение
// ПРИМЕНИЛОСЬ — то есть строго новее последнего применённого по этому объекту.
// Устаревшая доставка до журнала не доходит вовсе; порядок строк одного объекта
// в журнале поэтому совпадает с порядком версий владельца.
//
// Версия приходит значением `pgtype.Timestamptz`, а не `time.Time`: намерение без
// маркера хранится как '-infinity', и строка его снятия обязана нести то же
// значение, иначе сравнение в проекции разошлось бы со сравнением в состоянии.
func EmitPublicationTx(ctx context.Context, tx pgx.Tx, published bool, object string, ownerVersion pgtype.Timestamptz) error {
	if tx == nil {
		return fmt.Errorf("fga_outbox: tx must not be nil")
	}
	if object == "" {
		return fmt.Errorf("fga_outbox: publication without an object")
	}
	if !ownerVersion.Valid {
		// Недействительная версия уехала бы в полезную нагрузку как null, и
		// проекция молча упорядочила бы строку меткой журнала — ровно тем
		// порядком, от которого поле защищает.
		return fmt.Errorf("fga_outbox: publication of %s without an owner version", object)
	}
	eventType := EventTypeDelete
	if published {
		eventType = EventTypeWrite
	}
	// Версия кладётся приведением к jsonb в операторе раскладки (lay), а не
	// форматом на стороне Go: так значение в полезной нагрузке и значение в
	// состоянии публикации — одна и та же величина до микросекунды, включая
	// '-infinity'.
	if err := layIntents(ctx, tx, []intent{{
		eventType: eventType,
		tuple:     clients.RelationTuple{User: domain.PublicationSubject, Relation: domain.PublicationRelation, Object: object},
		version:   ownerVersion,
	}}); err != nil {
		return fmt.Errorf("fga_outbox: insert publication %s: %w", eventType, err)
	}
	return nil
}

// EmitOwnerOrderedTx кладёт строки журнала отношений, которые записал посредник
// регистрации объектов (иерархия объекта: указатель области, родитель, владелец),
// упорядоченные ВЕРСИЕЙ РЕГИСТРАЦИИ владельца — по строке на кортеж, с полем
// `source_version` (kaname#969).
//
// # Зачем строке версия регистрации
//
// Без неё свёртка упорядочивает строку меткой журнала, и снятие регистрации,
// дошедшее позже повторной регистрации того же ключа, оказывается НОВЕЕ её
// кортежей: оно снимает и владельца нового объекта, и его указатель области.
// С версией свёртка сравнивает версию снятия с версией КАЖДОГО факта
// (`DELETE … WHERE source_version <= версия снятия`): снятие версии v2 снимает
// владельца регистрации v1 и не трогает кортежи регистрации v3 — тот же порядок,
// которым строка зеркала (`resource_mirror`) уже отличает устаревшее надгробие.
// Запись применяется монотонно (`ON CONFLICT … WHERE хранимая < новой`), поэтому
// запоздавшая доставка старой регистрации не опускает версию факта.
//
// # Чего здесь нет
//
// Глаголов и публикации: глагол выводится из выдачи, а публикация упорядочена
// своим путём (EmitPublicationTx). Вызывающий отдаёт сюда только иерархические
// отношения посредника; проверка ниже отвергает остальное, а не пропускает.
//
// Версия приходит значением `pgtype.Timestamptz` и кладётся приведением в том же
// операторе — как у публикации, до микросекунды, включая '-infinity'.
func EmitOwnerOrderedTx(ctx context.Context, tx pgx.Tx, eventType string, tuples []clients.RelationTuple, ownerVersion pgtype.Timestamptz) error {
	if tx == nil {
		return fmt.Errorf("fga_outbox: tx must not be nil")
	}
	if eventType != EventTypeWrite && eventType != EventTypeDelete {
		return fmt.Errorf("fga_outbox: unknown event type %q", eventType)
	}
	if len(tuples) == 0 {
		return nil
	}
	if !ownerVersion.Valid {
		// Недействительная версия уехала бы в полезную нагрузку как null, и свёртка
		// молча упорядочила бы строку меткой журнала — ровно то, от чего поле защищает.
		return fmt.Errorf("fga_outbox: owner-ordered tuples without an owner version")
	}
	intents := make([]intent, 0, len(tuples))
	seen := make(map[clients.RelationTuple]struct{}, len(tuples))
	for _, t := range tuples {
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		if t.User == "" || t.Relation == "" || t.Object == "" {
			return fmt.Errorf("fga_outbox: owner-ordered tuple without user/relation/object")
		}
		if domain.IsStoredPublication(t.User, t.Relation) || strings.HasPrefix(t.Relation, "v_") {
			return fmt.Errorf("fga_outbox: owner-ordered row of relation %q: verbs and publications are ordered by their own paths", t.Relation)
		}
		intents = append(intents, intent{eventType: eventType, tuple: t, version: ownerVersion})
	}
	if err := layIntents(ctx, tx, intents); err != nil {
		return fmt.Errorf("fga_outbox: insert owner-ordered %s: %w", eventType, err)
	}
	return nil
}

// emitTx enqueues the tuples GROUPED BY (user, object): one row per subject per
// object, carrying that subject's WHOLE relation set on it.
//
// WHY THE ROW IS THE SET AND NOT THE TUPLE. The drainer applies one row per call,
// so the row is the unit that lands atomically. With a row per tuple the
// subject's verb set arrived one relation at a time — and between the first arrival
// and the last, the subject could read its own freshly created resource but not
// change or delete it. Observed on a stand: read allowed at t, update refused 50 ms
// later, both calls resolving against the same object with exactly one relation
// standing on it. A caller that has just been told it may read its own resource is
// entitled to conclude it may act on it; the set is one grant, so it has to move as
// one. (The synchronous writer already applied a whole object at once — the queue,
// which is the at-least-once path and therefore the one that runs whenever the
// synchronous attempt is skipped, cancelled or lost, did not.)
//
// SHAPE. A group of one relation keeps the historical single-tuple payload
// verbatim, so the many emitters that grant one relation at a time (bootstrap, JIT,
// break-glass, the register proxy) produce byte-identical rows and nothing about
// them changes. Only a genuine SET takes the `relations` form, and only a GRANT set
// additionally carries the compatibility echo — see the branch below for why the two
// directions differ.
func emitTx(ctx context.Context, tx pgx.Tx, eventType string, tuples []clients.RelationTuple) error {
	if tx == nil {
		return fmt.Errorf("fga_outbox: tx must not be nil")
	}
	if len(tuples) == 0 {
		return nil
	}
	// ОДИН оператор на все строки вызова (lay): свёртка журнала в прямой факт —
	// операторная (kaname#568), и порядок захвата строк факта внутри оператора
	// задаёт она сама. Между вызовами порядок захвата — порядок вызовов, поэтому
	// транзакция, которой нужно больше одного набора, кладёт их одним вызовом
	// EmitJournalTx либо копит на отложенной транзакции (Defer) и кладёт одним
	// Flush (kaname#617).
	intents := make([]intent, 0, len(tuples))
	for _, t := range tuples {
		intents = append(intents, intent{eventType: eventType, tuple: t})
	}
	if err := layIntents(ctx, tx, intents); err != nil {
		return fmt.Errorf("fga_outbox: insert %s: %w", eventType, err)
	}
	return nil
}

// groupPayload — полезная нагрузка строки одного набора: одиночное отношение либо
// набор (у выдачи — с эхом первого отношения, см. ниже).
func groupPayload(eventType string, g grantGroup) (string, error) {
	fields := map[string]any{"user": g.user, "object": g.object}
	if len(g.relations) == 1 {
		fields["relation"] = g.relations[0]
	} else {
		fields["relations"] = g.relations
		if eventType == EventTypeWrite {
			// ЭХО СОВМЕСТИМОСТИ — ТОЛЬКО У ВЫДАЧИ, и асимметрия несущая.
			//
			// Введено ради выкатки, на которой под выпуска до формы набора ещё забирал
			// эти строки дренажем. С эхом он применял ОДНО отношение и отмечал строку
			// доставленной; без эха не мог её разобрать и отравлял.
			//
			// Для ВЫДАЧИ первый исход лучше: у субъекта меньше доступа, чем ему
			// положено (отказ закрытый), строка поглощена, и следующий проход сверки
			// её дополняет.
			//
			// Для СНЯТИЯ он строго хуже и необратим: строка отмечена доставленной, а
			// большая часть набора ПЕРЕЖИВАЕТ СВОЁ СНЯТИЕ — лишний доступ, невидимый
			// ни ведомости отравленных, ни предупреждению о заторе, ни повторной
			// доставке, потому что для очереди работа сделана. Отравленное снятие,
			// напротив, видно во всех трёх и доставляется заново при первом
			// наблюдении модели после старта пода — а его гарантирует конец выкатки.
			// Поэтому у снятия эха нет: лучше застрять громко, чем примениться
			// частично и молча.
			fields["relation"] = g.relations[0]
		}
	}
	payload, err := json.Marshal(fields)
	if err != nil {
		return "", fmt.Errorf("fga_outbox: marshal payload: %w", err)
	}
	return string(payload), nil
}

// EmitJournalTx кладёт выдачи И снятия транзакции ОДНИМ оператором (kaname#617).
//
// # Зачем один оператор
//
// Свёртка журнала в прямой факт берёт замки строк факта в общем порядке
// (объект, субъект) — но лишь в границах ОДНОГО оператора (kaname#568). Транзакция,
// писавшая журнал несколькими операторами, брала замки в порядке своих вызовов:
// проход реконсайлера писал выдачи по члену в цикле сверки, а снятия — в конце
// прохода. Проход выдачи B, у которой объект «a» выпал из отбора, а «b» вошёл, брал
// «b» раньше «a»; проход соседней выдачи A того же субъекта, в чей отбор входят
// оба, — «a» раньше «b». Встречные замки, и база снимает одну из транзакций
// отказом 40P01 (проба `TestReconcilePassesOfOneSubjectCommitWhenOneRevokesWhatTheOtherWrites`).
// Один оператор на транзакцию — и порядок захвата общий для всех писателей журнала.
//
// # Ключ, у которого есть и выдача, и снятие
//
// Строки одного ключа (субъект, объект) свёртка берёт в порядке id, отношения
// набора — побайтно. Набор выдачи и набор снятия одного ключа — две строки, и
// порядок замков внутри ключа был бы порядком строк, а не отношений: выдача
// `viewer` со снятием `editor` в одной транзакции и выдача `editor` со снятием
// `viewer` в другой брали бы их встречно. Поэтому у такого ключа строка — на
// ОТНОШЕНИЕ, и строки идут по отношению: id внутри ключа повторяет побайтный
// порядок отношений, тот же, что у набора (раскладка — journalRows).
//
// Кортеж, названный и выдачей, и снятием одного вызова, — отказ: исход такой пары
// зависел бы от порядка строк, а не от намерения вызывающего.
//
// Метки строк — прежние: выдача несёт начало транзакции, снятие — момент вставки
// (writeStamp / deleteStamp).
func EmitJournalTx(ctx context.Context, tx pgx.Tx, writes, deletes []clients.RelationTuple) error {
	if tx == nil {
		return fmt.Errorf("fga_outbox: tx must not be nil")
	}
	if len(writes) == 0 && len(deletes) == 0 {
		return nil
	}
	written := make(map[clients.RelationTuple]struct{}, len(writes))
	for _, t := range writes {
		written[t] = struct{}{}
	}
	for _, t := range deletes {
		if _, both := written[t]; both {
			return fmt.Errorf("fga_outbox: tuple %s#%s@%s is both written and deleted in one call", t.Object, t.Relation, t.User)
		}
	}
	intents := make([]intent, 0, len(writes)+len(deletes))
	for _, t := range writes {
		intents = append(intents, intent{eventType: EventTypeWrite, tuple: t})
	}
	for _, t := range deletes {
		intents = append(intents, intent{eventType: EventTypeDelete, tuple: t})
	}
	if err := layIntents(ctx, tx, intents); err != nil {
		return fmt.Errorf("fga_outbox: insert journal: %w", err)
	}
	return nil
}

// intent — строка журнала ДО раскладки: кортеж, вид строки и — у строки,
// упорядоченной владельцем (публикация, иерархия посредника регистрации), —
// версия владельца. Недействительная версия — строка без `source_version`.
type intent struct {
	eventType string
	tuple     clients.RelationTuple
	version   pgtype.Timestamptz
}

// layIntents — единственная точка, где намерения писателей становятся строками
// журнала. На отложенной транзакции (Deferred) строки копятся до Flush; на
// обычной ложатся сразу, одним оператором.
func layIntents(ctx context.Context, tx pgx.Tx, intents []intent) error {
	if d, ok := tx.(*Deferred); ok {
		return d.add(intents)
	}
	return lay(ctx, tx, intents)
}

// lay кладёт намерения ОДНИМ оператором в порядке journalRows.
//
// Метка строки — та же, что у каждого писателя по отдельности: строка, упорядоченная
// владельцем, несёт начало транзакции (её порядок задаёт версия, а не метка),
// снятие без версии — момент вставки (deleteStamp), выдача — начало транзакции
// (writeStamp). Версия владельца кладётся приведением в этом же операторе — до
// микросекунды, включая '-infinity', как в состоянии публикации и в зеркале.
func lay(ctx context.Context, tx pgx.Tx, intents []intent) error {
	rows, err := journalRows(intents)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		return nil
	}
	eventTypes := make([]string, 0, len(rows))
	payloads := make([]string, 0, len(rows))
	versions := make([]pgtype.Timestamptz, 0, len(rows))
	for _, r := range rows {
		eventTypes = append(eventTypes, r.eventType)
		payloads = append(payloads, r.payload)
		versions = append(versions, r.version)
	}
	_, err = tx.Exec(ctx,
		`INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
		 SELECT e,
		        CASE WHEN v IS NULL THEN p::jsonb
		             ELSE p::jsonb || jsonb_build_object('source_version', v) END,
		        CASE WHEN v IS NULL AND e = $4 THEN `+deleteStamp+` ELSE `+writeStamp+` END
		   FROM unnest($1::text[], $2::text[], $3::timestamptz[]) WITH ORDINALITY AS t(e, p, v, n)
		  ORDER BY n`,
		eventTypes, payloads, versions, EventTypeDelete,
	)
	return err
}

// journalRow — строка журнала после раскладки, в порядке id.
type journalRow struct {
	object, user, relation string
	eventType, payload     string
	version                pgtype.Timestamptz
}

// journalRows раскладывает намерения в строки в ОБЩЕМ порядке захвата замков:
// (объект, субъект, отношение) побайтно, как сравнивает свёртка (COLLATE "C").
//
// Ключ (субъект, объект), у которого все намерения — выдачи без версии либо все —
// снятия без версии, ложится ОДНОЙ строкой-набором (groupByGrant, groupPayload):
// набор — одна выдача, и двигаться ему одним куском. Ключ, у которого есть и
// выдача, и снятие либо строка с версией владельца, ложится строкой на КАЖДОЕ
// намерение: порядок замков внутри ключа — порядок отношений, а не порядок
// писателей. Намерения одного кортежа внутри такого ключа идут в порядке их
// записи (сортировка устойчива): «выдать, снять, выдать» одного кортежа в одной
// транзакции — не то же, что «выдать, снять». Подряд идущий повтор того же
// намерения того же кортежа схлопывается.
func journalRows(intents []intent) ([]journalRow, error) {
	type key struct{ user, object string }
	const (
		plainWrite = 1 << iota
		plainDelete
		ordered
	)
	kinds := make(map[key]int, len(intents))
	for _, it := range intents {
		k := key{it.tuple.User, it.tuple.Object}
		switch {
		case it.version.Valid:
			kinds[k] |= ordered
		case it.eventType == EventTypeDelete:
			kinds[k] |= plainDelete
		default:
			kinds[k] |= plainWrite
		}
	}
	single := func(k key) bool { s := kinds[k]; return s == plainWrite || s == plainDelete }

	rows := make([]journalRow, 0, len(intents))
	sets := map[string][]clients.RelationTuple{}
	type last struct {
		eventType string
		version   pgtype.Timestamptz
	}
	previous := make(map[clients.RelationTuple]last)
	for _, it := range intents {
		if single(key{it.tuple.User, it.tuple.Object}) {
			sets[it.eventType] = append(sets[it.eventType], it.tuple)
			continue
		}
		if p, seen := previous[it.tuple]; seen && p.eventType == it.eventType && p.version == it.version {
			continue
		}
		previous[it.tuple] = last{it.eventType, it.version}
		payload, err := groupPayload(it.eventType, grantGroup{user: it.tuple.User, object: it.tuple.Object, relations: []string{it.tuple.Relation}})
		if err != nil {
			return nil, err
		}
		rows = append(rows, journalRow{
			object: it.tuple.Object, user: it.tuple.User, relation: it.tuple.Relation,
			eventType: it.eventType, payload: payload, version: it.version,
		})
	}
	for _, eventType := range []string{EventTypeWrite, EventTypeDelete} {
		for _, g := range groupByGrant(sets[eventType]) {
			payload, err := groupPayload(eventType, g)
			if err != nil {
				return nil, err
			}
			rows = append(rows, journalRow{
				object: g.object, user: g.user, relation: g.relations[0],
				eventType: eventType, payload: payload,
			})
		}
	}
	slices.SortStableFunc(rows, func(a, b journalRow) int {
		return cmp.Or(cmp.Compare(a.object, b.object), cmp.Compare(a.user, b.user), cmp.Compare(a.relation, b.relation))
	})
	return rows, nil
}

// Deferred — транзакция, на которой строки журнала КОПЯТСЯ и ложатся одним
// оператором (Flush), сколько бы писателей и вызовов их ни назвали (kaname#617).
//
// # Зачем
//
// Порядок захвата строк факта общий лишь внутри одного оператора журнала. Транзакция,
// которая пишет журнал несколькими вызовами — снятие регистрации с потомками,
// отзывом выдач и публикацией, применение манифеста модуля, — брала замки фактов
// порядком своих вызовов и сходилась в кольцо с любым писателем, бравшим те же
// факты в общем порядке (40P01). Отложенная транзакция сводит все вызовы к одному
// оператору, и все замки фактов берутся после замков строк предметной области,
// взятых по ходу транзакции, — тот же порядок родов, что у прохода материализации.
//
// # Чем она отличается от обычной
//
// Свёртка строки видит состояние транзакции на момент Flush, а не на момент
// вызова писателя: реестр выпущенного и статус выдач — конечные. Читатель
// прямого факта той же транзакции видит строки журнала лишь после Flush, поэтому
// вопрос «стоит ли факт» после записи задаётся после Flush.
//
// Flush — один раз: строка журнала после него — отказ, а не второй оператор.
// Фиксация с неуложенными строками — отказ, а не молчаливая потеря; точка
// сохранения внутри — отказ: строки внутри неё легли бы мимо раскладки.
type Deferred struct {
	pgx.Tx
	pending []intent
	laid    bool
}

// Defer оборачивает транзакцию; уже отложенную возвращает как есть.
func Defer(tx pgx.Tx) *Deferred {
	if d, ok := tx.(*Deferred); ok {
		return d
	}
	return &Deferred{Tx: tx}
}

func (d *Deferred) add(intents []intent) error {
	if d.laid {
		return errors.New("fga_outbox: the journal of this transaction is already laid — a second statement would take fact locks out of the common order")
	}
	d.pending = append(d.pending, intents...)
	return nil
}

// Flush кладёт накопленное одним оператором. Второй вызов — отказ.
func (d *Deferred) Flush(ctx context.Context) error {
	if d.laid {
		return errors.New("fga_outbox: the journal of this transaction is already laid")
	}
	d.laid = true
	if err := lay(ctx, d.Tx, d.pending); err != nil {
		return fmt.Errorf("fga_outbox: insert journal: %w", err)
	}
	d.pending = nil
	return nil
}

// Commit фиксирует транзакцию; неуложенные строки журнала — отказ.
func (d *Deferred) Commit(ctx context.Context) error {
	if len(d.pending) > 0 {
		return fmt.Errorf("fga_outbox: commit with %d journal intents not laid — Flush is missing", len(d.pending))
	}
	return d.Tx.Commit(ctx)
}

// Begin — точка сохранения внутри отложенной транзакции: отказ.
func (d *Deferred) Begin(context.Context) (pgx.Tx, error) {
	return nil, errors.New("fga_outbox: savepoint inside a transaction whose journal is deferred")
}

// writeStamp / deleteStamp — метка created_at строки журнала, она же ВЕРСИЯ строки
// для свёртки в прямой факт (kaname.relation_fact_fold_row: версия — поле владельца,
// а без него — эта метка). Снятие применяется к факту, только если версия факта не
// новее версии строки снятия.
//
// ПОЧЕМУ У СНЯТИЯ — МОМЕНТ ВСТАВКИ, А НЕ НАЧАЛО ТРАНЗАКЦИИ (kaname#919, kaname#923).
// now() — момент НАЧАЛА транзакции. Снятие выдачи открывает транзакцию, ждёт на
// своих замках (advisory выдачи, строка выдачи `FOR UPDATE`) и лишь потом читает
// ведомость; аддитивный форвард, начавший транзакцию ПОЗЖЕ и зафиксированный до
// того, как снятие получило строку, пишет факт с версией новее метки снятия.
// Снятие видит его в ведомости и пишет строку снятия — а свёртка её отбрасывает
// как устаревшую, и факт переживает снятие: доступ без выдачи. Замок строки
// упорядочивал транзакции, но версия, которая решает исход, о замке не знала.
//
// clock_timestamp() — момент самой вставки строки снятия, то есть момент ПОСЛЕ
// всех замков, под которыми снятие решило, что снимать. Любой факт, который
// снятие увидело, зафиксирован раньше этого момента, и версия его — начало
// зафиксированной транзакции — не новее. Строка снятия поэтому снимает всё, что
// увидела, на любом порядке начала транзакций и на каждом пути снятия (отзыв,
// удаление, истечение срока, снос области, полный проход), — все они пишут
// снятие этой функцией. Это и порядок id журнала: строка, вставленная позже,
// и упорядочена позже.
//
// Выдача остаётся на now(), и правки ей не нужно: начало её транзакции не позже
// момента её вставки, поэтому снятие, свёрнутое после выдачи, снимает её при
// любой из двух меток, а свёрнутое раньше ничего не находит — выдача ложится
// заново. Правка меняет ровно одно — версию строки снятия. Строки,
// упорядоченные владельцем (EmitPublicationTx, EmitOwnerOrderedTx), меткой не
// упорядочиваются вовсе.
const (
	writeStamp  = "now()"
	deleteStamp = "clock_timestamp()"
)

// grantGroup — one subject's relation set on one object: the unit a row carries and
// the unit the drainer's ordering partition covers.
type grantGroup struct {
	user      string
	object    string
	relations []string
}

// groupByGrant buckets tuples by (user, object), drops a relation repeated within
// one group, and returns the groups in ONE canonical order — by object, then user,
// with the relations inside a group sorted too.
//
// WHO HOLDS THE LOCK ORDER — AND HOW FAR IT REACHES. The journal trigger locks one
// fact row per tuple. Two transactions folding overlapping tuples of one subject in
// different orders take the same locks crosswise, and the database breaks the cycle
// by failing one of them with 40P01. Observed on a stand: a binding delete that ran
// while a sibling binding of the same subject was being materialized ended ABORTED,
// and the binding the caller removed stayed alive.
//
// The order is held by the DATABASE, not by this function: the fold is a statement
// trigger (`kaname.relation_fact_from_journal`, migration 20261005040457) that walks
// the rows of one statement by (object, user) byte-wise, same-key rows by id, and
// the relations of a set byte-wise — whoever wrote them: this emitter, the boot
// backfill's `INSERT … SELECT`, the module seed, raw migration SQL.
//
// Досягаемость порядка — ОДИН оператор: между операторами одной транзакции замки
// берутся порядком писателя, и база этого не держит — второй оператор журнала в
// транзакции она не отвергает. Держат писатели: транзакция кладёт журнал одним
// вызовом (EmitJournalTx либо одиночный писатель) либо копит его на отложенной
// транзакции и кладёт одним Flush (Deferred). Перепись писателей по этому
// свойству — kaname#617.
//
// Сортировка здесь оставлена ради канонического журнала (одна строка на набор,
// отношения в одном порядке), а не ради замков. Переставлять безопасно: строки
// наборов — разные ключи (субъект, объект), а строки разных ключей коммутируют.
// Выдача и снятие ОДНОГО ключа не коммутируют — такой ключ ложится строкой на
// намерение в порядке записи (journalRows), а не набором отсюда.
//
// De-duplication matters because the store rejected a request naming the same tuple
// twice (cannot_allow_duplicate_tuples_in_one_request), and a caller that
// legitimately derives one tuple from two rules would otherwise turn a whole grant
// into a permanent poison.
func groupByGrant(tuples []clients.RelationTuple) []grantGroup {
	type key struct{ user, object string }
	idx := make(map[key]int, len(tuples))
	seen := make(map[clients.RelationTuple]struct{}, len(tuples))
	groups := make([]grantGroup, 0, len(tuples))
	for _, t := range tuples {
		if _, dup := seen[t]; dup {
			continue
		}
		seen[t] = struct{}{}
		k := key{user: t.User, object: t.Object}
		if i, ok := idx[k]; ok {
			groups[i].relations = append(groups[i].relations, t.Relation)
			continue
		}
		idx[k] = len(groups)
		groups = append(groups, grantGroup{user: t.User, object: t.Object, relations: []string{t.Relation}})
	}
	for i := range groups {
		slices.Sort(groups[i].relations)
	}
	slices.SortFunc(groups, func(a, b grantGroup) int {
		return cmp.Or(cmp.Compare(a.object, b.object), cmp.Compare(a.user, b.user))
	})
	return groups
}
