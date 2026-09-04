// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package resource_mirror — atomic emit-in-tx helper for kacho_iam.resource_mirror.
//
// The table is an OUTPUT-ONLY, cross-domain denormalised mirror (the source of
// truth stays with the owning service) of the labels +
// parent-scope of resources owned by OTHER services (such as compute and vpc).
// It is fed PUSH-style over the existing `compute→iam` FGA-proxy edge — IAM never
// pulls from compute, so the cross-domain graph stays acyclic.
//
// UpsertTx / DeleteTx MUST run in the SAME pgx.Tx as the owner-tuple fga_outbox
// emit (RegisterResource / UnregisterResource), so a rolled-back caller-tx
// leaves NEITHER the mirror row NOR the tuple intent (atomic co-commit, ban #10).
// Tx-commit is the atomicity primitive — never "UPSERT then call a second store".
//
// Schema (migration 0019 `kacho_iam.resource_mirror`):
//
//	object_type       text         PK ч.1   (closed-ish dotted key, e.g. "compute.instance")
//	object_id         text         PK ч.2   (opaque cross-DB soft-ref, no FK)
//	parent_project_id text                  (parent-scope for selector containment)
//	parent_account_id text                  (parent-scope for selector containment)
//	labels            jsonb        '{}'      (owner labels copy; GIN-indexed — selector matches @>)
//	updated_at        timestamptz  now()     (last-write marker)
//
// The write-path FILLS the mirror; the selector READS it (containment). Idempotency under
// the at-least-once drainer is by-construction: PK (object_type,object_id)
// makes UPSERT/DELETE a no-op-equivalent on repeat and serializes concurrent
// writers of the same object on the row-lock (deterministic last-write).
package resource_mirror

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// Row — the tenant-facing projection mirrored for one owner object. Labels nil
// is normalized to an empty JSONB object ('{}').
type Row struct {
	// ObjectType — тип в словаре КАТАЛОГА ресурсов (`vpc.network`,
	// `iam.account`): им названа колонка зеркала, и им же зовёт регистрация.
	//
	// Цепь предков этой же строки ложится словарём МОДЕЛИ ПРАВ — перевод делает
	// писатель (см. upsertParentEdges). Разница не косметическая: по цепи ходит
	// вопрос о доступе, а он приходит словарём модели.
	ObjectType      string
	ObjectID        string
	ParentProjectID string
	ParentAccountID string
	Labels          map[string]string
	// SourceVersion — monotonic per-object marker from the SOURCE (compute),
	// stamped when it emitted the register intent inside its writer-tx. The
	// conditional UPSERT applies this register ONLY when it is strictly newer than
	// the stored one (last-source-state-wins). Zero value (legacy /
	// empty producer) is normalized to '-infinity' so the register still applies
	// unconditionally (back-compat).
	SourceVersion time.Time

	// ParentChain — цепь предков от БЛИЖАЙШЕГО к дальнему, каждый элемент в форме
	// `"<type>:<id>"`.
	//
	// Пусто означает «предков нет», и набор рёбер объекта тогда опустошается.
	// Здесь стояло, что предки в этом случае «читаются из двух колонок выше, как
	// раньше», — читаются они только отсюда: вопрос о доступе поднимается по
	// рёбрам, а не по колонкам зеркала. Вывод цепи из области — обязанность
	// ВЛАДЕЛЬЦА (pkg/ownerregister.ParentChain), и держится она гейтом по дереву
	// (internal/repohygiene), а не этим комментарием.
	//
	// Пишется В ТОЙ ЖЕ транзакции, что и строка зеркала: объект и его цепь —
	// один факт, и разъехаться на сбое они не вправе. Объект без цепи молча
	// выпадает из области выдачи и из каскада, то есть отказ по нему неотличим
	// от честного.
	ParentChain []string
}

// negInfinity — the sentinel a zero/legacy SourceVersion maps to ('-infinity'),
// so an older producer's empty version still applies (back-compat with a
// producer that emits no version).
func versionOr(t time.Time) any {
	if t.IsZero() {
		return "-infinity"
	}
	return t.UTC()
}

// Outcome — the verdict of one conditional mirror write. Two INDEPENDENT facts, both
// decided by the database, neither taken on the caller's word:
//
//   - Applied — a row was written. False means the monotonic guard rejected the write
//     as not-newer (a redelivery of a registration already stored).
//   - ProjectionUnchanged — the write advanced ONLY source_version: the stored
//     parent-scope and labels were already byte-identical to the incoming ones. This is
//     the fact the register path needs, and it is NOT the same question as Applied: the
//     duplicate delivery that arrives SECOND may still carry the NEWER version (the
//     synchronous registrar stamps wall-clock after the commit, the drainer replays the
//     version the DB stamped inside the writer-tx), so it applies — while changing
//     nothing about the object. Only a registration that REPLACED a different projection
//     can have invalidated an earlier materialization.
type Outcome struct {
	Applied             bool
	ProjectionUnchanged bool
}

// UpsertTx INSERTs-or-conditionally-UPDATEs the mirror row for (ObjectType,
// ObjectID) using the caller-supplied transaction. UPSERT-on-PK ⇒ idempotent on
// drainer retry; the UPDATE branch is gated `WHERE source_version <
// EXCLUDED.source_version`, making the mirror LAST-SOURCE-STATE-WINS:
// a stale register-intent (older source_version,
// reordered by the HA drainer) updates 0 rows and is a no-op — NOT an error
// (at-least-once OK) and NOT an overwrite with older labels. A repeat with the
// SAME source_version is likewise a no-op (`<` is strict). Equal/newer in-order
// register applies and advances source_version.
//
// TWO STATEMENTS, ONE TRANSACTION, NO CHECK-THEN-ACT. The version-only bump is tried
// FIRST as a conditional UPDATE whose WHERE also demands that every selector-relevant
// column already equal the incoming value. Postgres re-evaluates that WHERE after
// waiting on a concurrent writer's row lock (READ COMMITTED), so the comparison is made
// against the row as actually committed — not against a snapshot read earlier and acted
// on later (ban #10). Only when it matches nothing does the ordinary UPSERT run. Both
// statements are atomic in themselves and commit with the caller's tx.
//
// The two cannot be folded into one statement: two data-modifying CTEs over the same
// table would either see a pre-UPDATE snapshot or touch the same row twice.
//
// A concurrent delivery that inserts the row between the two statements makes the second
// take its UPSERT branch and report ProjectionUnchanged = false — a CONSERVATIVE answer
// (the caller then keeps its delete-stale-capable path), never a permissive one.
//
// MUST run in the same pgx.Tx as the owner-tuple fga_outbox emit; tx rollback ⇒
// the row is not visible (atomic co-commit, ban #10).
func UpsertTx(ctx context.Context, tx pgx.Tx, row Row) (Outcome, error) {
	if tx == nil {
		return Outcome{}, fmt.Errorf("resource_mirror: tx must not be nil")
	}
	labels := row.Labels
	if labels == nil {
		labels = map[string]string{}
	}
	payload, err := json.Marshal(labels)
	if err != nil {
		return Outcome{}, fmt.Errorf("resource_mirror: marshal labels: %w", err)
	}
	version := versionOr(row.SourceVersion)
	// (1) VERSION-ONLY BUMP. Matches exactly when a row already exists, the incoming
	// version is strictly newer, AND nothing a selector reads has changed. `labels =
	// $5::jsonb` is jsonb equality — key order and whitespace do not make a projection
	// "different". An unversioned producer ('-infinity') never satisfies `< $6` and so
	// never reaches this branch: it supplies no proof and gets no exemption.
	//
	// УСЛОВИЕ ПРИЁМА СТОИТ И ЗДЕСЬ. Полоса срабатывает на СУЩЕСТВУЮЩЕЙ строке и
	// вставки не делает, поэтому без своего `EXISTS` она давала бы обход: тип
	// снят с платформы, а регистрация им проходит — только потому, что строка
	// уже лежит. Ноль затронутых строк здесь ничего не скрывает: вердикт о
	// каталоге выносит оператор (2), и он различает «не принято» и «не новее».
	tag, err := tx.Exec(ctx,
		`UPDATE kacho_iam.resource_mirror
		    SET source_version = $6, updated_at = now()
		  WHERE object_type       = $1
		    AND object_id         = $2
		    AND parent_project_id = $3
		    AND parent_account_id = $4
		    AND labels            = $5::jsonb
		    AND source_version    < $6
		    AND EXISTS (SELECT 1 FROM kacho_iam.catalog_resource cr
		                 WHERE cr.dotted = $1 AND cr.live)`,
		row.ObjectType, row.ObjectID, row.ParentProjectID, row.ParentAccountID, payload, version,
	)
	if err != nil {
		return Outcome{}, fmt.Errorf("resource_mirror: bump source version: %w", err)
	}
	if tag.RowsAffected() > 0 {
		return Outcome{Applied: true, ProjectionUnchanged: true}, nil
	}
	// (2) INSERT-OR-SUPERSEDE ПОД УСЛОВИЕМ ПРИЁМА. Either the row is new, or the
	// incoming projection differs from the stored one, or the version is not newer
	// (0 rows — a redelivery the monotonic guard already recognised).
	//
	// # ДВА ВЕРДИКТА ОДНИМ ОПЕРАТОРОМ, И ВТОРОЙ НУЖЕН ИМЕННО ЗДЕСЬ
	//
	// «Тип не принят» и «редоставка не новее» дают ОДИНАКОВЫЙ ноль затронутых
	// строк. Вызывающий читает этот ноль как «делать нечего» и возвращает УСПЕХ —
	// то есть голое `WHERE EXISTS` превратило бы отказ в тихое согласие, ровно на
	// том входе, ради которого условие и заводится. Поэтому оператор возвращает
	// ОБА факта: принадлежность типа живому каталогу и число применённых строк.
	//
	// # ПОЧЕМУ ЭТО НЕ ЧТЕНИЕ-И-ДЕЙСТВИЕ (запрет #10)
	//
	// Сверка и запись — ОДИН оператор в одном снимке: между «спросил» и «вставил»
	// нет окна, в которое поместилось бы снятие типа. Читающая ветвь общая для
	// обоих вердиктов, поэтому разойтись они не могут by construction.
	//
	// # ПОЧЕМУ НЕ ВНЕШНИЙ КЛЮЧ
	//
	// Ключ на `(dotted, live)` выражал бы ту же сверку постоянным инвариантом — и
	// тем самым запретил бы СНЯТИЕ типа, пока у арендатора есть хоть один ресурс
	// этого типа (`ON UPDATE NO ACTION` отверг бы перевод строки каталога в
	// неживую), а каскад унёс бы чужие данные. Условие приёма и постоянный
	// инвариант здесь — разные утверждения: регистрировать новым типом нельзя,
	// а уже зарегистрированное обязано пережить снятие (зеркало терпит висячую
	// ссылку by design). Проба:
	// TestResourceMirror_RetiredTypeKeepsItsAlreadyRegisteredRows.
	//
	// Явные приведения у параметров обязательны: в списке `SELECT` тип параметра
	// не выводится из колонки назначения, как он выводился в форме `VALUES`.
	// ИМЯ ТИПА МОДЕЛИ ПРИЕЗЖАЕТ ИЗ ТОЙ ЖЕ СТРОКИ, ЧЬЮ ЛИВНОСТЬ ЗДЕСЬ СПРАШИВАЮТ.
	//
	// Цепь предков этой регистрации названа словарём МОДЕЛИ, и раньше перевод
	// брался у словаря, ПОРОЖДЁННОГО СБОРКОЙ: тип, заведённый применением
	// манифеста в работающем процессе, тот словарь возвращал точечным именем, и
	// вставка ребра отвергалась проверкой схемы — то есть регистрация не
	// проходила ВОВСЕ (kacho#1982). Читать имя вторым запросом не надо: строка,
	// дающая право на запись, и строка, дающая имя, — ОДНА, и берутся они одним
	// оператором в одном снимке.
	var typeLive bool
	var modelType *string
	var appliedRows int64
	if err = tx.QueryRow(ctx,
		`WITH live_type AS (
		     SELECT object_type
		       FROM kacho_iam.catalog_resource
		      WHERE dotted = $1 AND live
		 ), applied AS (
		     INSERT INTO kacho_iam.resource_mirror
		       (object_type, object_id, parent_project_id, parent_account_id, labels, source_version, updated_at)
		     SELECT $1::text, $2::text, $3::text, $4::text, $5::jsonb, $6::timestamptz, now()
		      WHERE EXISTS (SELECT 1 FROM live_type)
		     ON CONFLICT (object_type, object_id) DO UPDATE
		        SET parent_project_id = EXCLUDED.parent_project_id,
		            parent_account_id = EXCLUDED.parent_account_id,
		            labels            = EXCLUDED.labels,
		            source_version    = EXCLUDED.source_version,
		            updated_at        = now()
		      WHERE resource_mirror.source_version < EXCLUDED.source_version
		     RETURNING 1
		 )
		 SELECT EXISTS (SELECT 1 FROM live_type),
		        (SELECT object_type FROM live_type),
		        (SELECT count(*) FROM applied)`,
		row.ObjectType, row.ObjectID, row.ParentProjectID, row.ParentAccountID, payload, version,
	).Scan(&typeLive, &modelType, &appliedRows); err != nil {
		return Outcome{}, fmt.Errorf("resource_mirror: upsert: %w", err)
	}
	if !typeLive {
		// Отказ НАЗЫВАЕТ поле и правило: без имени типа вызывающий не знает, что
		// чинить, а «invalid object» одинаково звучало бы и на грамматике.
		// Наименование каталога здесь не является оракулом: перечень грантуемых
		// типов платформа отдаёт арендатору сама (PermissionCatalogService), то
		// есть отказ не сообщает ничего, чего вызывающий не мог бы прочесть. Чей
		// это тип — вопрос ДРУГОЙ полосы (правило приёма), и она по-прежнему
		// отвечает отказом без причины.
		return Outcome{}, iamerr.Wrapf(iamerr.ErrUnknownResourceType,
			"resource type %q is not a live entry of the platform resource catalog",
			row.ObjectType)
	}
	applied := appliedRows > 0
	if applied {
		// `modelType` непуст by construction: сюда доходит только живая строка
		// (ветвь `!typeLive` выше), а колонка объявлена `NOT NULL` под проверкой
		// грамматики. Ветви «имени нет» здесь не заводится — она объявляла бы
		// состояние, которого не бывает, и первый же читатель принял бы её за
		// свидетельство, что бывает.
		if err := upsertParentEdges(ctx, tx, row, *modelType, version); err != nil {
			return Outcome{}, err
		}
	}
	return Outcome{Applied: applied}, nil
}

// upsertParentEdges записывает цепь предков объекта рёбрами, в ТОЙ ЖЕ транзакции.
//
// Полная замена, а не досыпка: цепь — это состояние, а не приращение. Владелец
// прислал ту цепь, которая верна сейчас; ребро, которого в ней нет, обязано
// исчезнуть, иначе объект останется под областью, из которой его вынесли, — то
// есть право переживёт перенос.
//
// Зовётся ТОЛЬКО когда зеркало реально применилось: устаревшая доставка не
// проходит монотонную защиту строки и не должна переписывать цепь свежей.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЦЕПЬ ПИШЕТСЯ В СЛОВАРЕ МОДЕЛИ ПРАВ — И ЭТО НЕ ТО ЖЕ, ЧЕМ НАЗВАНА СТРОКА ЗЕРКАЛА
//
// Зеркало — проекция КАТАЛОГА ресурсов, и его `object_type` назван словарём
// каталога (`vpc.network`). Цепь читается вопросом о доступе, а он приходит
// словарём МОДЕЛИ (`vpc_network`) — им же названы три из четырёх колонок, с
// которыми цепь соединяется: прямой факт, область выдачи и собственная
// родительская сторона рёбер. Цепь в словаре каталога не совпала бы с ними
// НИКОГДА и молча: исход выглядел бы как «права нет», а не как ошибка.
//
// Обратное направление невозможно by construction, а не по вкусу: вершина
// иерархии `cluster` в каталоге ресурсов отсутствует — кластер не ресурс, — и
// цепь, названная словарём каталога, не смогла бы дойти до строки администратора
// облака вовсе.
//
// Перевод берётся ЕДИНСТВЕННЫЙ (`modelTypeName`, model_dictionary.go) и читает
// ЖИВУЮ строку каталога, а не словарь, порождённый сборкой: иначе тип,
// заведённый применением манифеста в работающем процессе, приезжал бы сюда
// точечным именем и вся регистрация отвергалась бы проверкой схемы (kacho#1982).
// Родительская сторона приезжает от владельца ресурса уже модельными именами
// (`project`, `account`, `registry_registry`) — их перевод не трогает, потому что
// сужение идёт по СВОЙСТВУ имени, а не по перечню имён.
//
// Имя САМОГО объекта переводить здесь нечем и не надо: оно приезжает уже
// разрешённым из строки, чью ливность спросил вызывающий тем же оператором. Свой
// запрос тут завёл бы второе место об одном предмете — и второй снимок.
//
// Держится это не здесь, а проверками схемы `*_type NOT LIKE '%.%'`: регрессия
// писателя отвергается строкой, а не перестаёт совпадать тихо.
func upsertParentEdges(ctx context.Context, tx pgx.Tx, row Row, objectType string, version any) error {
	if _, err := tx.Exec(ctx,
		`DELETE FROM kacho_iam.resource_parent_edge
		  WHERE object_type = $1 AND object_id = $2`,
		objectType, row.ObjectID,
	); err != nil {
		return fmt.Errorf("resource_parent_edge: clear: %w", err)
	}
	for i, ancestor := range row.ParentChain {
		typ, id, ok := splitObjectRef(ancestor)
		if !ok {
			// Непонятая форма — ОТКАЗ, а не пропуск: пропущенное звено делает цепь
			// короче настоящей, и объект оказывается под тем предком, под которым
			// он не находится. Молчаливое проглатывание здесь дало бы область
			// выдачи, «совпавшую» с ожиданием ровно потому, что про звено не
			// спросили.
			return fmt.Errorf("resource_parent_edge: непонятая форма предка %q "+
				"(ожидается \"<type>:<id>\")", ancestor)
		}
		parentType, err := modelTypeName(ctx, tx, typ)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx,
			`INSERT INTO kacho_iam.resource_parent_edge
			   (object_type, object_id, parent_type, parent_id, depth, source_version, updated_at)
			 VALUES ($1, $2, $3, $4, $5, $6, now())`,
			objectType, row.ObjectID, parentType, id, i+1, version,
		); err != nil {
			return fmt.Errorf("resource_parent_edge: insert depth %d: %w", i+1, err)
		}
	}
	return nil
}

// splitObjectRef разбирает `"<type>:<id>"`. Разделитель — ПЕРВОЕ двоеточие:
// идентификаторы продукта его не содержат, а тип — тем более, поэтому разбор
// однозначен; при этом форма проверяется, а не предполагается.
func splitObjectRef(ref string) (typ, id string, ok bool) {
	i := strings.IndexByte(ref, ':')
	if i <= 0 || i == len(ref)-1 {
		return "", "", false
	}
	return ref[:i], ref[i+1:], true
}

// DeleteTx conditionally removes BOTH halves of a registration for
// (objectType, objectID): the mirror row and the object's chain of parent edges.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЦЕПЬ СНИМАЕТСЯ ЗДЕСЬ, А НЕ ОСТАВЛЯЕТСЯ БАЗЕ
//
// Регистрация пишет обе половины одной транзакцией (`UpsertTx` →
// `upsertParentEdges`), а снятие убирало только первую. Досняться цепи неоткуда:
// внешнего ключа с зеркала на ребро НЕТ и быть не может — стороны названы
// РАЗНЫМИ словарями (зеркало — словарём каталога, `vpc.securityGroup`; ребро —
// словарём модели прав, `vpc_security_group`), поэтому каскад тут невыразим by
// construction. Значит либо снимает этот код, либо не снимает никто.
//
// Не снимал никто, и следствие ровно обратно тому, ради чего цепь заведена:
// обход ВНИЗ («что лежит под этой областью») продолжает числить снятый объект
// под областью выдачи. Право переживает свой предмет — тот же класс, что
// уцелевший `owner` после снятия регистрации (см. пробу
// `unregister_resource_residual_owner_test.go`). Замер стенда 2026-08-20: рёбер
// 14 707, из них 14 527 без строки зеркала — 98.8 % таблицы.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОДИН ПРЕДИКАТ НА ОБЕ ПОЛОВИНЫ — ИНАЧЕ ОНИ РАЗОЙДУТСЯ ИМЕННО НА ПЕРЕСТАНОВКЕ
//
// Цепь снимается ПОД ТЕМ ЖЕ условием `source_version <= $tombstone`, что и строка
// зеркала, а не безусловно. Безусловное снятие выглядело бы исправным на всяком
// прямом порядке доставки и теряло бы объект ровно на переупорядоченной паре
// «правка → снятие»: надгробие, опоздавшее к свежей регистрации, ноль строк
// зеркала не трогает — и не вправе трогать цепь. Держит это парная проба
// `TestParentEdges_StaleUnregisterKeepsTheChain`.
//
// ─────────────────────────────────────────────────────────────────────────────
// The mirror half: the
// DELETE is gated `WHERE source_version <= $tombstone` so a STALE unregister
// tombstone (older than the stored register — a Delete-after-Update reorder)
// updates 0 rows and is a no-op, leaving the fresher row intact.
// An absent row → no-op (idempotent). A zero tombstone (legacy /
// empty producer) maps to '-infinity' and only matches a stored legacy
// '-infinity' register (`-infinity <= -infinity`) — i.e. when BOTH producer
// edges are legacy the old unconditional delete is preserved (back-compat). The
// producer (compute) is upgraded atomically (register & unregister carry the
// version together), so a mixed versioned-register / legacy-delete window exists only
// transiently during rollout and degrades gracefully. Same atomicity contract
// as UpsertTx.
//
// # СНЯТИЕ КАТАЛОГ НЕ СПРАШИВАЕТ, И ЭТО РЕШЕНИЕ, А НЕ ПРОПУСК
//
// UpsertTx требует у типа живую строку каталога; здесь такого условия нет
// намеренно. Условие приёма связывает ВХОД, а снятие входом не является: оно
// убирает то, что уже лежит. Спроси мы каталог и здесь — ресурс, чей тип сняли
// с платформы после его регистрации, стал бы НЕудаляемым: снять его было бы
// нечем, а строка зеркала продолжала бы участвовать в подборе по признакам.
// Отказ на снятии дороже отказа на приёме и в очереди потребителя: невыполнимое
// снятие означает право, которое не отзывается.
func DeleteTx(ctx context.Context, tx pgx.Tx, objectType, objectID string, tombstone time.Time) error {
	if tx == nil {
		return fmt.Errorf("resource_mirror: tx must not be nil")
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM kacho_iam.resource_mirror
		  WHERE object_type = $1 AND object_id = $2
		    AND source_version <= $3`,
		objectType, objectID, versionOr(tombstone),
	); err != nil {
		return fmt.Errorf("resource_mirror: delete: %w", err)
	}
	// Цепь предков — вторая половина той же регистрации. Перевод словаря берётся
	// ЕДИНСТВЕННЫЙ и тот же, которым цепь писалась (`modelTypeName` в
	// `upsertParentEdges`): назови её здесь словарём каталога — снятие не совпало
	// бы ни с одним ребром и промолчало бы, то есть выглядело бы исполненным.
	//
	// Перевод ливность НЕ спрашивает (см. model_dictionary.go): условие приёма
	// связывает вход, а снятие входом не является. Ресурс, чей тип сняли с
	// платформы после его регистрации, обязан оставаться удаляемым — снятие типа
	// мягкое, строка каталога остаётся, и имя по ней резолвится по-прежнему.
	modelType, err := modelTypeName(ctx, tx, objectType)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM kacho_iam.resource_parent_edge
		  WHERE object_type = $1 AND object_id = $2
		    AND source_version <= $3`,
		modelType, objectID, versionOr(tombstone),
	); err != nil {
		return fmt.Errorf("resource_parent_edge: delete: %w", err)
	}
	return nil
}
