// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package resource_mirror — atomic emit-in-tx helper for kaname.resource_mirror.
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
// Schema (migration 0019 `kaname.resource_mirror`):
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

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// Row — the tenant-facing projection mirrored for one owner object. Labels nil
// is normalized to an empty JSONB object ('{}').
type Row struct {
	// ObjectType — тип в словаре КАТАЛОГА ресурсов (`vpc.network`,
	// `iam.account`): им названа колонка зеркала, и им же зовёт регистрация.
	//
	// Цепь предков этой же строки ложится словарём МОДЕЛИ ПРАВ — перевод делает
	// DB command. Разница не косметическая: по цепи ходит
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

// StmtRegistrationCommand is shared with scalegrid so measurement exercises the
// complete production writer, including nested validation and edge projection.
// The VOLATILE command trigger takes the mirror lock in a separate SPI statement
// before comparing the chain (kaname#874); one local binding judges the whole payload.
const StmtRegistrationCommand = `INSERT INTO kaname.resource_registration_command
    (dotted_type, object_id, parent_project_id, parent_account_id, labels, source_version, parent_chain)
    VALUES ($1, $2, $3, $4, $5::jsonb, $6::timestamptz, $7::text[])
    RETURNING type_live, model_type, applied, projection_unchanged`

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
// The DB command owns the full payload and both physical projections. Its
// refusal rolls back the complete statement; the caller still owns commit of
// mirror, tuple, audit and reconcile effects in the same transaction.
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
	var typeLive bool
	var modelType *string
	var outcome Outcome
	if err = tx.QueryRow(ctx, StmtRegistrationCommand,
		row.ObjectType, row.ObjectID, row.ParentProjectID, row.ParentAccountID,
		payload, versionOr(row.SourceVersion), row.ParentChain,
	).Scan(&typeLive, &modelType, &outcome.Applied, &outcome.ProjectionUnchanged); err != nil {
		return Outcome{}, fmt.Errorf("resource_mirror: registration command: %w", err)
	}
	if !typeLive {
		return Outcome{}, iamerr.Wrapf(iamerr.ErrUnknownResourceType,
			"resource type %q is not a live entry of the platform resource catalog", row.ObjectType)
	}
	return outcome, nil
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
// registration command), а снятие убирало только первую. Досняться цепи неоткуда:
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
func DeleteTx(ctx context.Context, tx pgx.Tx, objectType, objectID string, tombstone time.Time) (bool, error) {
	if tx == nil {
		return false, fmt.Errorf("resource_mirror: tx must not be nil")
	}
	tag, err := tx.Exec(ctx,
		`DELETE FROM kaname.resource_mirror
		  WHERE object_type = $1 AND object_id = $2
		    AND source_version <= $3`,
		objectType, objectID, versionOr(tombstone),
	)
	if err != nil {
		return false, fmt.Errorf("resource_mirror: delete: %w", err)
	}
	deleted := tag.RowsAffected() > 0
	// Цепь предков — вторая половина той же регистрации. Перевод словаря берётся
	// ЕДИНСТВЕННЫЙ и тот же, которым цепь писалась (`modelTypeName` в
	// registration command): назови её здесь словарём каталога — снятие не совпало
	// бы ни с одним ребром и промолчало бы, то есть выглядело бы исполненным.
	//
	// Перевод ливность НЕ спрашивает (см. model_dictionary.go): условие приёма
	// связывает вход, а снятие входом не является. Ресурс, чей тип сняли с
	// платформы после его регистрации, обязан оставаться удаляемым — снятие типа
	// мягкое, строка каталога остаётся, и имя по ней резолвится по-прежнему.
	modelType, err := modelTypeName(ctx, tx, objectType)
	if err != nil {
		return false, err
	}
	if _, err := tx.Exec(ctx,
		`DELETE FROM kaname.resource_parent_edge
		  WHERE object_type = $1 AND object_id = $2
		    AND source_version <= $3`,
		modelType, objectID, versionOr(tombstone),
	); err != nil {
		return false, fmt.Errorf("resource_parent_edge: delete: %w", err)
	}
	return deleted, nil
}
