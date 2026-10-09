// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// governance_ports.go — narrow port-iface definitions for the writer-tx outbox
// emitters. TxBeginner opens the transaction; RelationOutboxEmitter (fga_outbox),
// ResourceMirrorEmitter (resource_mirror) and AuditOutboxEmitter (audit_outbox)
// emit their rows inside that same caller-owned transaction, so each side-effect
// commits atomically with the mutation that produced it.
//
// Service layer defines these ports; adapters in repo/kaname/pg and clients/
// implement them. Composition root (cmd/kaname/main.go) injects concrete
// implementations.
package service

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// TxBeginner opens a transaction. The returned handle is the opaque service.Tx
// (see tx.go) — the concrete pgx.Tx is materialized only inside repo adapters.
type TxBeginner interface {
	Begin(ctx context.Context) (Tx, error)
}

// RelationTuple — {User, Relation, Object} triple for fga_outbox writes.
// Neutral value type owned by internal/outboxtypes so the repo-ports package
// (internal/repo/kaname) can reference it without importing this use-case package
// (dependency-rule fix); the alias keeps the ergonomic service.RelationTuple name.
type RelationTuple = outboxtypes.RelationTuple

// RelationOutboxEmitter — port for emitting kaname.fga_outbox grant/revoke
// rows from writer-tx-owning code paths. Atomic with the surrounding
// mutation; the drainer applies tuples to the relation backend asynchronously.
type RelationOutboxEmitter interface {
	EmitWriteTx(ctx context.Context, tx Tx, tuples []RelationTuple) error
	EmitDeleteTx(ctx context.Context, tx Tx, tuples []RelationTuple) error
}

// ResourceMirrorRow — service-layer payload for one kaname.resource_mirror
// row. OUTPUT-ONLY mirror of the labels + parent-scope of a
// resource owned by another service (source of truth = owner). Labels nil →
// persisted as JSONB '{}'.
type ResourceMirrorRow struct {
	ObjectType      string
	ObjectID        string
	ParentProjectID string
	ParentAccountID string
	// ParentChain — цепь предков от ближайшего к дальнему, каждый элемент
	// `"<type>:<id>"`. Двух колонок выше хватает не всякому объекту: модель
	// требует цепи произвольной формы, а объект без предка молча выпадает из
	// области выдачи и из каскада.
	ParentChain []string
	Labels      map[string]string
	// Generation — поколение объекта у владельца (строго растущее целое на
	// каждое изменение объекта). Обязательно: приёма без поколения нет.
	// Регистрация применяется, только если оно строго новее головы объекта
	// (`kaname.object_head`, включая надгробие снятия); иначе REJECTED_STALE.
	Generation int64
}

// ResourceMirrorEmitter — порт приёма регистрации и снятия объекта в проекцию
// (зеркало, цепь предков, голова объекта) в транзакции вызывающего: атомарно с
// намерением кортежа владельца в `fga_outbox`. Проекцию пишет ОДИН
// производитель — триггер `resource_event` базы службы доступа; порт кладёт
// намерение и возвращает исход приёма, решённый базой.
//
//   - `applied` — поколение строго новее головы, проекция записана. Ложь —
//     REJECTED_STALE: запоздалая или повторная доставка, не изменившая ничего
//     (ни зеркала, ни надгробия, ни цепи).
//   - `projectionUnchanged` (только регистрация) — применённая регистрация
//     сдвинула ТОЛЬКО поколение: родитель и метки уже были теми же, ничто
//     материализованное по прежним фактам устареть не могло.
type ResourceMirrorEmitter interface {
	UpsertTx(ctx context.Context, tx Tx, row ResourceMirrorRow) (applied, projectionUnchanged bool, err error)
	DeleteTx(ctx context.Context, tx Tx, objectType, objectID string, generation int64) (applied bool, err error)
}

// PublicReadIntent — намерение владельца о публикации одного объекта для
// анонимного чтения (`user:* #v_get`).
type PublicReadIntent struct {
	// ObjectType / ObjectID — объект в словаре МОДЕЛИ прав, как в кортеже
	// публикации.
	ObjectType string
	ObjectID   string
	// HeadType — тип того же объекта в словаре КАТАЛОГА: ключ головы объекта
	// (`kaname.object_head`), по которой судится воплощение.
	HeadType string
	// Published — открывает (true) или закрывает (false).
	Published bool
	// Version — версия владельца намерения публикации; обязательна.
	Version time.Time
	// ObjectGeneration — поколение воплощения объекта у владельца; обязательно.
	ObjectGeneration int64
}

// PublicReadPublisher — публикация объекта для анонимного чтения в транзакции
// вызывающего (kaname#107; приёмка NTF-3, Р30 «Публикация для анонимного
// чтения»). Реализация — *repo/kaname/pg.PublicReadPublisher.
//
//   - ApplyTx — применяет намерение ПОРЯДКОМ ВЕРСИЙ ВЛАДЕЛЬЦА и только к
//     ТЕКУЩЕМУ воплощению объекта; иначе REJECTED_STALE (`applied == false`),
//     ничего не меняя и строки журнала не кладя.
//   - WithdrawTx — снятие объекта уносит его публикацию (строку и прямой факт).
//   - DropStaleIncarnationTx — регистрация, начавшая воплощение, снимает
//     публикацию прежнего воплощения.
type PublicReadPublisher interface {
	ApplyTx(ctx context.Context, tx Tx, in PublicReadIntent) (applied bool, err error)
	WithdrawTx(ctx context.Context, tx Tx, objectType, objectID string) error
	DropStaleIncarnationTx(ctx context.Context, tx Tx, objectType, objectID, headType string) error
}

// AuditEvent — service-layer payload for a durable kaname.audit_outbox
// compliance row. The repo adapter generates the id (evt_<22-char> — bug #126
// regression-guard), marshals Payload to the event_payload jsonb, and inserts
// it with status='pending'. EventType must satisfy the audit_outbox_event_type
// CHECK (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`).
//
// Payload carries the compliance dimensions (actor / subject / resource / key
// domain fields). It MUST NOT contain secret material (no tokens, no key PEM,
// no client_secret) — see acceptance 5.2-36.
//
// Neutral value type owned by internal/outboxtypes so the repo-ports package can
// reference it without importing this use-case package (dependency-rule fix);
// the alias keeps the ergonomic service.AuditEvent name.
type AuditEvent = outboxtypes.AuditEvent

// AuditOutboxEmitter — port for emitting one durable kaname.audit_outbox row
// inside a caller-owned writer-tx. Atomic with the surrounding security-relevant
// mutation (запрет #10): the audit row commits iff the mutation commits, so a
// rolled-back mutation leaves no orphan compliance row and a committed mutation
// always leaves its trail.
//
// Mirrors RelationOutboxEmitter's emit-in-tx shape: the concrete pgx.Tx is
// recovered from the opaque service.Tx inside the repo adapter (txAsPgx).
type AuditOutboxEmitter interface {
	EmitTx(ctx context.Context, tx Tx, ev AuditEvent) error
}
