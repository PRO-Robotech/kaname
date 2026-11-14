// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package fga_outbox — помощник атомарной отправки внутри транзакции в kaname.fga_outbox.
//
// Повторяет образец SubjectChangeEmitter
// (internal/repo/kaname/pg/subject_change_emitter.go).
//
// Предыстория
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
// По запрету #10 внутрисервисные ссылки и инварианты живут на уровне БД: коммит транзакции —
// примитив атомарности, а не «INSERT, затем вызвать хранилище и надеяться».
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
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// EventTypeWrite / EventTypeDelete — два типа событий этой таблицы.
// Экспортируются, чтобы каждый производитель называл вид строки через пакет, владеющий
// её формой, а не повторял литерал в собственном INSERT.
const (
	EventTypeWrite  = "fga.tuple.write"
	EventTypeDelete = "fga.tuple.delete"
)

// RelationPredicate строит предикат SQL «эта строка несёт <arg> среди своих
// отношений», совпадающий с ОБОИМИ формами строки — одним отношением и набором.
//
// Он нужен, поскольку читатель только по `payload->>'relation'` видит лишь
// ПЕРВЫЙ элемент набора, а сбой происходит незаметно: запрос
// «этот кортеж в очереди?» отвечает НЕТ для имеющегося кортежа, поэтому устранение дублей
// ставит его повторно, а утверждение об ОТСУТСТВИИ кортежа проходит, даже не
// посмотрев строку, где тот лежит.
//
// payloadExpr — выражение колонки jsonb (`payload`, `o.payload`); arg —
// плейсхолдер или литерал с отношением.
func RelationPredicate(payloadExpr, arg string) string {
	return "(" + payloadExpr + "->>'relation' = " + arg +
		" OR " + payloadExpr + "->'relations' @> to_jsonb(" + arg + "::text))"
}

// EmitWriteTx вставляет N строк выдачи в `kaname.fga_outbox` (event_type
// `fga.tuple.write`), используя транзакцию вызывающего.
//
// ОБЯЗАН исполняться в той же pgx.Tx, что изменение доменного состояния (вставка AccessBinding,
// автовыдача InsertTx JIT, вставка cluster_admin_grants). Откат транзакции
// ⇒ строки outbox не видны выгрузчику.
//
// len(tuples)==0 ничего не меняет (возвращает nil); вызывающий решает, являются ли 0 кортежей
// ошибкой.
func EmitWriteTx(ctx context.Context, tx pgx.Tx, tuples []clients.RelationTuple) error {
	return emitTx(ctx, tx, EventTypeWrite, tuples)
}

// EmitDeleteTx вставляет N строк отзыва в `kaname.fga_outbox` (event_type
// `fga.tuple.delete`).
//
// Вызывающий передаёт ТОЧНЫЕ кортежи, изначально записанные EmitWriteTx,
// для симметричного отзыва. Контракт атомарности тот же, что у EmitWriteTx.
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
// а не у вызывающего. Строку другой формы с этим полем положить нельзя по устройству,
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
	if eventType == EventTypeWrite {
		// Настоящая отправка владельца начинает новую жизнь точного кортежа, включая ноль.
		// Устаревший Register сюда не доходит; обычный AB EmitWriteTx не сбрасывает доказательство.
		if err := invalidateRetirementTx(ctx, tx, users, relations, objects); err != nil {
			return err
		}
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

// emitTx ставит кортежи С ГРУППИРОВКОЙ ПО (user, object): одна строка на субъекта
// на объекте, несущая ВЕСЬ его набор отношений к объекту.
//
// ПОЧЕМУ СТРОКА — НАБОР, А НЕ КОРТЕЖ. Выгрузчик применяет одну строку за вызов,
// поэтому строка — единица атомарного применения. При строке на кортеж набор
// глаголов субъекта прибывал по отношению, и между первым
// и последним субъект мог читать собственный только что созданный ресурс, но не
// менять или удалять его. На стенде: чтение разрешено в момент t, обновление отвергнуто через 50 мс,
// оба вызова решались для одного объекта ровно с одним действующим
// отношением. Только что получивший доступ на чтение своего ресурса вправе
// заключить, что может действовать с ним; набор — одна выдача, поэтому должен перемещаться
// целиком. (Синхронный писатель уже применял весь объект разом, а очередь,
// которая обеспечивает доставку хотя бы раз и поэтому исполняется, когда
// синхронная попытка пропущена, отменена или потеряна, — нет.)
//
// ФОРМА. Группа из одного отношения сохраняет историческую нагрузку одного кортежа
// дословно, поэтому многие отправители одного отношения (начальная загрузка, JIT,
// аварийный доступ, прокси регистрации) производят побайтно одинаковые строки, и для
// них ничего не меняется. Лишь настоящий НАБОР принимает форму `relations`, и только набор ВЫДАЧИ
// дополнительно несёт эхо совместимости — ниже объяснено, почему два
// направления различаются.
// EmitDecisionTx связывает обычный tuple payload с защищённым final decision.
// Метка приходит от coordinated writer, а не из запроса. Ordered registration
// использует свои отдельные отправители и через этот путь не проходит.
func EmitDecisionTx(ctx context.Context, tx pgx.Tx, eventType string, tuples []clients.RelationTuple, at time.Time) error {
	if at.IsZero() || (eventType != EventTypeWrite && eventType != EventTypeDelete) {
		return fmt.Errorf("fga_outbox: invalid decision coordinate")
	}
	return emitStampedTx(ctx, tx, eventType, tuples, at)
}

func emitTx(ctx context.Context, tx pgx.Tx, eventType string, tuples []clients.RelationTuple) error {
	return emitStampedTx(ctx, tx, eventType, tuples, time.Time{})
}

func emitStampedTx(ctx context.Context, tx pgx.Tx, eventType string, tuples []clients.RelationTuple, at time.Time) error {
	if tx == nil {
		return fmt.Errorf("fga_outbox: tx must not be nil")
	}
	if len(tuples) == 0 {
		return nil
	}
	groups := groupByGrant(tuples)
	payloads := make([]string, 0, len(groups))
	for _, g := range groups {
		fields := map[string]any{"user": g.user, "object": g.object}
		if len(g.relations) == 1 {
			fields["relation"] = g.relations[0]
		} else {
			fields["relations"] = g.relations
			if eventType == EventTypeWrite {
				// ЭХО СОВМЕСТИМОСТИ — ТОЛЬКО ВЫДАЧИ, и асимметрия намеренна.
				//
				// При постепенном обновлении pod, предшествующий форме набора, всё ещё захватывает
				// эти строки. При наличии эха он применяет ОДНО отношение и отмечает строку
				// доставленной; без эха не декодирует строку и объявляет её неисправимой.
				//
				// Для ВЫДАЧИ первый исход лучше: субъект получает меньше
				// доступа, чем положено (безопасный отказ), строка потреблена, а следующий
				// проход сверки дополняет её.
				//
				// Для ОТЗЫВА это строго хуже и невосстановимо: строка
				// отмечена доставленной, хотя большая часть набора ПЕРЕЖИВАЕТ СОБСТВЕННОЕ УДАЛЕНИЕ —
				// избыточная выдача невидима реестру неисправимых записей, предупреждению о застревании
				// и повторному запуску, поскольку с точки зрения очереди работа
				// завершена. Неисправимый отзыв, напротив, виден всем трём и
				// перезапускается при первом наблюдении модели после старта pod, что
				// гарантирует завершение обновления. Поэтому отзывы не несут эха: лучше застрять
				// заметно, чем частично примениться молча.
				fields["relation"] = g.relations[0]
			}
		}
		payload, err := json.Marshal(fields)
		if err != nil {
			return fmt.Errorf("fga_outbox: marshal payload: %w", err)
		}
		payloads = append(payloads, string(payload))
	}
	// ОДИН стейтмент на все строки вместо одного на строку: свёртка журнала в
	// прямой факт — операторная (kaname#568), и порядок захвата строк факта
	// внутри оператора задаёт она сама — по (объект, субъект), строки одного ключа
	// по id. Порядок МЕЖДУ вызовами сохраняется: выдача и отзыв одного ключа НЕ
	// коммутативны, и id второго вызова всегда больше id первого.
	stamp := writeStamp
	if eventType == EventTypeDelete {
		stamp = deleteStamp
	}
	args := []any{eventType, payloads}
	if !at.IsZero() {
		stamp = "$3::timestamptz"
		args = append(args, at.UTC())
	}
	if _, err := tx.Exec(ctx,
		`INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
   SELECT $1, p::jsonb, `+stamp+` FROM unnest($2::text[]) AS p`, args...,
	); err != nil {
		return fmt.Errorf("fga_outbox: insert %s: %w", eventType, err)
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

// grantGroup — набор отношений одного субъекта к одному объекту: единица строки
// и единица раздела упорядочения выгрузчика.
type grantGroup struct {
	user      string
	object    string
	relations []string
}

// groupByGrant группирует кортежи по (user, object), удаляет повтор отношения внутри
// группы и возвращает группы в ОДНОМ каноническом порядке — объект, затем пользователь;
// отношения внутри группы также отсортированы.
//
// КТО ДЕРЖИТ ПОРЯДОК БЛОКИРОВОК И КАК ДАЛЕКО ОН ДЕЙСТВУЕТ. Триггер журнала блокирует одну
// строку факта на кортеж. Две транзакции, сворачивающие пересекающиеся кортежи субъекта
// в разном порядке, берут одни блокировки перекрёстно, и база разрывает цикл,
// завершая одну ошибкой 40P01. Наблюдалось на стенде: удаление привязки,
// запущенное во время материализации соседней привязки того же субъекта, завершалось ABORTED,
// а удаляемая вызывающим привязка оставалась жива.
//
// Порядок держит БАЗА ДАННЫХ, а не эта функция: свёртка — операторный
// триггер (`kaname.relation_fact_from_journal`, миграция 20261005040457), обходящий
// строки одного оператора побайтно по (object, user), строки одного ключа по id, а
// отношения набора побайтно, кто бы их ни записал: этот отправитель, стартовое
// заполнение `INSERT … SELECT`, начальное заполнение модуля, сырой SQL миграции. Предел — ОДИН
// ОПЕРАТОР: между операторами транзакции порядок принадлежит писателю.
// Сортировка здесь сохранена ради каноничности самого журнала (одна строка на
// набор, один порядок отношений), а не зависимости блокировок от неё.
//
// Перестановка безопасна: внутри вызова ничто не зависит от порядка вызывающего;
// строки одного набора всегда имеют разные ключи (user, object), а строки разных
// ключей коммутируют. Значимый порядок — выдача и отзыв ОДНОГО ключа —
// лежит между вызовами, и INSERT ниже сохраняет его (поздний вызов, больший id).
//
// Устранение дублей важно: хранилище отвергало запрос, называющий один кортеж
// дважды (cannot_allow_duplicate_tuples_in_one_request), и вызывающий, законно
// выводящий кортеж из двух правил, иначе превращал бы всю выдачу
// в постоянно неисправимую запись.
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
