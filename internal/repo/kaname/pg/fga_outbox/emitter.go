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
	// Версия кладётся В ТОМ ЖЕ ОПЕРАТОРЕ приведением к jsonb, а не форматом на
	// стороне Go: так значение в полезной нагрузке и значение в состоянии
	// публикации — одна и та же величина до микросекунды, включая '-infinity'.
	if _, err := tx.Exec(ctx,
		`INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
		 VALUES ($1, jsonb_build_object('user', $2::text, 'relation', $3::text,
		                                'object', $4::text, 'source_version', $5::timestamptz),
		         now())`,
		eventType, domain.PublicationSubject, domain.PublicationRelation, object, ownerVersion,
	); err != nil {
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
	users := make([]string, 0, len(tuples))
	relations := make([]string, 0, len(tuples))
	objects := make([]string, 0, len(tuples))
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
		users, relations, objects = append(users, t.User), append(relations, t.Relation), append(objects, t.Object)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
		 SELECT $1, jsonb_build_object('user', u, 'relation', r, 'object', o, 'source_version', $5::timestamptz), now()
		   FROM unnest($2::text[], $3::text[], $4::text[]) AS t(u, r, o)
		  ORDER BY o, u, r`,
		eventType, users, relations, objects, ownerVersion,
	); err != nil {
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
	groups := groupByGrant(tuples)
	payloads := make([]string, 0, len(groups))
	for _, g := range groups {
		payload, err := groupPayload(eventType, g)
		if err != nil {
			return err
		}
		payloads = append(payloads, payload)
	}
	// ОДИН стейтмент на все строки вместо одного на строку: свёртка журнала в
	// прямой факт — операторная (kaname#568), и порядок захвата строк факта
	// внутри оператора задаёт она сама — по (объект, субъект), строки одного ключа
	// по id. МЕЖДУ вызовами порядок захвата — порядок вызовов: транзакция, которой
	// нужны и выдачи, и снятия, кладёт их одним вызовом EmitJournalTx (kaname#617).
	// Выдача и отзыв одного ключа НЕ коммутативны, и id второго вызова всегда
	// больше id первого.
	stamp := writeStamp
	if eventType == EventTypeDelete {
		stamp = deleteStamp
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
		 SELECT $1, p::jsonb, `+stamp+` FROM unnest($2::text[]) AS p`,
		eventType, payloads,
	); err != nil {
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
			// COMPATIBILITY ECHO — GRANTS ONLY, and the asymmetry is the point.
			//
			// During a rolling upgrade a pod that predates the set form still claims
			// these rows. Given an echo it applies ONE relation and marks the row
			// delivered; given none it cannot decode the row and poisons it.
			//
			// For a GRANT the first outcome is better: the subject ends up with less
			// access than it is owed (fail-closed), the row is consumed, and the next
			// reconcile pass completes it.
			//
			// For a REVOKE it is strictly worse, and irrecoverably so: the row is
			// marked delivered while most of the set SURVIVES ITS OWN REMOVAL — an
			// over-grant that is invisible to the poison ledger, to the wedge warning
			// and to the redrive, because as far as the queue is concerned the work
			// is done. A poisoned revoke, by contrast, is visible in all three and is
			// re-driven on the first model observation after a pod starts — which the
			// end of the rollout guarantees. So revokes carry no echo: better stuck
			// and loud than applied in part and silent.
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
// порядок отношений, тот же, что у набора.
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
	type key struct{ user, object string }
	type row struct {
		object, user, relation, eventType, payload string
	}
	writeGroups, deleteGroups := groupByGrant(writes), groupByGrant(deletes)
	inWrites := make(map[key]struct{}, len(writeGroups))
	for _, g := range writeGroups {
		inWrites[key{g.user, g.object}] = struct{}{}
	}
	mixed := make(map[key]struct{})
	for _, g := range deleteGroups {
		if _, ok := inWrites[key{g.user, g.object}]; ok {
			mixed[key{g.user, g.object}] = struct{}{}
		}
	}
	rows := make([]row, 0, len(writeGroups)+len(deleteGroups))
	add := func(eventType string, groups []grantGroup) error {
		for _, g := range groups {
			parts := []grantGroup{g}
			if _, ok := mixed[key{g.user, g.object}]; ok {
				parts = parts[:0]
				for _, rel := range g.relations {
					parts = append(parts, grantGroup{user: g.user, object: g.object, relations: []string{rel}})
				}
			}
			for _, p := range parts {
				payload, err := groupPayload(eventType, p)
				if err != nil {
					return err
				}
				rows = append(rows, row{object: p.object, user: p.user, relation: p.relations[0], eventType: eventType, payload: payload})
			}
		}
		return nil
	}
	if err := add(EventTypeWrite, writeGroups); err != nil {
		return err
	}
	if err := add(EventTypeDelete, deleteGroups); err != nil {
		return err
	}
	// Порядок строк — порядок id: (объект, субъект, первое отношение строки),
	// побайтно, как сравнивает свёртка (COLLATE "C").
	slices.SortFunc(rows, func(a, b row) int {
		return cmp.Or(cmp.Compare(a.object, b.object), cmp.Compare(a.user, b.user), cmp.Compare(a.relation, b.relation))
	})
	eventTypes := make([]string, 0, len(rows))
	payloads := make([]string, 0, len(rows))
	for _, r := range rows {
		eventTypes = append(eventTypes, r.eventType)
		payloads = append(payloads, r.payload)
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
		 SELECT e, p::jsonb, CASE WHEN e = $3 THEN `+deleteStamp+` ELSE `+writeStamp+` END
		   FROM unnest($1::text[], $2::text[]) WITH ORDINALITY AS t(e, p, n)
		  ORDER BY n`,
		eventTypes, payloads, EventTypeDelete,
	); err != nil {
		return fmt.Errorf("fga_outbox: insert journal: %w", err)
	}
	return nil
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
// backfill's `INSERT … SELECT`, the module seed, raw migration SQL. Its reach is ONE
// STATEMENT: across the statements of one transaction the order is the writer's — поэтому
// транзакция, которой нужны и выдачи, и снятия, кладёт их одним вызовом EmitJournalTx
// (проход реконсайлера, kaname#617).
// The sort here is kept because it makes the journal itself canonical (one row per
// set, relations in one order) — not because the locks depend on it.
//
// Reordering is safe because nothing inside one call depends on the caller's order:
// the rows of one set are always different (user, object) keys, and rows of different
// keys commute. The order that does matter — a grant and a revoke of the SAME key —
// lies across calls, and the INSERT below keeps it (later call, larger id).
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
