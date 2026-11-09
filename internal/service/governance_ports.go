// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// governance_ports.go — определения узких портов-интерфейсов отправителей
// outbox внутри транзакции писателя. TxBeginner открывает транзакцию; RelationOutboxEmitter (fga_outbox),
// ResourceMirrorEmitter (resource_mirror) и AuditOutboxEmitter (audit_outbox)
// пишут строки в той же транзакции вызывающего, поэтому каждый побочный эффект
// коммитится атомарно с породившей его мутацией.
//
// Слой служб определяет порты; адаптеры repo/kaname/pg и clients/
// реализуют их. Корень композиции (cmd/kaname/main.go) внедряет конкретные
// реализации.
package service

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// TxBeginner открывает транзакцию. Возвращаемый дескриптор — непрозрачный service.Tx
// (см. tx.go); конкретный pgx.Tx материализуется лишь внутри адаптеров репозитория.
type TxBeginner interface {
	Begin(ctx context.Context) (Tx, error)
}

// RelationTuple — тройка {User, Relation, Object} для записи fga_outbox.
// Нейтральный тип значения принадлежит internal/outboxtypes, чтобы пакет портов репозитория
// (internal/repo/kaname) ссылался на него без импорта пакета сценариев
// (исправление правила зависимостей); псевдоним сохраняет удобное имя service.RelationTuple.
type RelationTuple = outboxtypes.RelationTuple

// VersionedRelationTuple — строка атомарного снятия с собственной версией.
type VersionedRelationTuple = outboxtypes.VersionedRelationTuple

// RelationOutboxEmitter — порт отправки строк выдачи/отзыва kaname.fga_outbox
// из путей, владеющих транзакцией писателя. Атомарен с окружающей
// мутацией; выгрузчик асинхронно применяет кортежи к хранилищу отношений.
type RelationOutboxEmitter interface {
	EmitWriteTx(ctx context.Context, tx Tx, tuples []RelationTuple) error
	EmitDeleteTx(ctx context.Context, tx Tx, tuples []RelationTuple) error
}

// ResourceMirrorRow — нагрузка слоя служб для одной строки kaname.resource_mirror.
// Зеркало ТОЛЬКО ВЫХОДА: метки и родительская область
// ресурса другой службы (источник истины — владелец). Метки nil →
// сохраняются как JSONB '{}'.
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
	// SourceVersion — монотонный маркер объекта от владельца.
	// UPSERT зеркала применяет регистрацию лишь при строго большем значении,
	// чем сохранённая версия (побеждает последнее состояние источника). Ноль → '-infinity' (старый формат).
	SourceVersion time.Time
}

// ResourceMirrorEmitter — порт вставки/обновления и удаления строки kaname.resource_mirror
// в транзакции писателя вызывающего. Атомарен с отправкой
// кортежа владельца в fga_outbox (одна транзакция): откат транзакции вызывающего не оставляет
// ни строки зеркала, ни намерения кортежа. Путь заполнения зеркала лишь ЗАПОЛНЯЕТ
// зеркало; читает его сверщик. UPSERT по первичному ключу даёт идемпотентность при
// выгрузке с доставкой хотя бы раз.
// UpsertTx сообщает ДВА независимых факта записи, решённых БД, поскольку
// двойную доставку каждого потребителя нельзя распознать лишь по одному из них.
//
//   - `applied` — оператор ИЗМЕНИЛ строку. Монотонный страж означает, что регистрация
//     с SourceVersion не строго новее сохранённой обновляет НОЛЬ строк —
//     повторная доставка уже выполненной работы, поэтому вторая доставка пропускает её.
//   - `projectionUnchanged` — запись продвинула ТОЛЬКО SourceVersion: родительская область и
//     метки уже побайтно совпадали. Этого случая `applied` НЕ ВИДИТ.
//     Две доставки регистрации несут РАЗНЫЕ версии (синхронный
//     регистратор ставит настенные часы после коммита; выгрузчик повторяет версию,
//     поставленную БД внутри транзакции писателя, то есть раньше), а их порядок прибытия не
//     фиксирован; когда выгрузчик первый, синхронный вызов применяется с
//     БОЛЕЕ НОВОЙ версией, ничего не меняя в объекте. Лишь регистрация,
//     ЗАМЕНИВШАЯ отличающуюся проекцию, могла сделать прежнюю материализацию устаревшей,
//     и лишь ей нужен проход сверки, способный удалять устаревшее.
//
// Сообщение обоих фактов ничего не стоит: операторы уже вычисляют условия.
type ResourceMirrorEmitter interface {
	UpsertTx(ctx context.Context, tx Tx, row ResourceMirrorRow) (applied, projectionUnchanged bool, err error)
	// DeleteTx снимает строку зеркала, если надгробие не старше хранимой
	// регистрации. deleted — строка была и снята: только такое снятие есть снятие
	// регистрации объекта (kaname#963, Д1), и только оно отзывает его выдачи.
	DeleteTx(ctx context.Context, tx Tx, objectType, objectID string, tombstone time.Time) (deleted bool, err error)
	// DescendantsTx — каждый объект, в цепи предков которого на любой глубине стоит
	// (parentType, parentID), с отношениями, стоящими на нём, — в снимке транзакции
	// вызывающего (kaname#1002).
	DescendantsTx(ctx context.Context, tx Tx, parentType, parentID string) ([]RegisteredDescendant, error)
	// DropRegistrationTx снимает регистрацию потомка безусловно: строку зеркала
	// (`catalogType`) и всю цепь предков (`modelType`). deleted — строка зеркала была;
	// version — версия снятой регистрации, нулевая без версии (kaname#969).
	DropRegistrationTx(ctx context.Context, tx Tx, catalogType, modelType, objectID string) (deleted bool, version time.Time, err error)
}

// RegisteredDescendant — потомок снимаемого объекта по цепи предков и отношения,
// стоящие на нём в момент чтения (kaname#1002). `ModelType` — словарь модели прав.
type RegisteredDescendant struct {
	ModelType string
	ID        string
	Standing  []RelationTuple
}

// PublicReadPublisher — применяет намерение владельца о публикации объекта для
// анонимного чтения (`user:*` либо `system_class:anonymous`, `#v_get`) в
// транзакции вызывающего, ПОРЯДКОМ ВЕРСИЙ
// ВЛАДЕЛЬЦА: намерение, не новее последнего применённого по объекту, не меняет
// ничего и строки журнала не кладёт. `objectType` — словарь модели прав.
// Нулевая `version` — доставка без маркера (см. public_read.ApplyTx).
// Реализация — *repo/kaname/pg.PublicReadPublisher (kaname#107).
type PublicReadPublisher interface {
	ApplyTx(ctx context.Context, tx Tx, objectType, objectID string, published bool, version time.Time) (applied bool, err error)
}

// AuditEvent — нагрузка слоя служб для надёжной строки соответствия kaname.audit_outbox.
// Адаптер репозитория создаёт id (evt_<22-char> — защита от регрессии ошибки kacho-iam#126),
// сериализует Payload в event_payload jsonb и вставляет
// со status='pending'. EventType должен удовлетворять ограничению audit_outbox_event_type
// CHECK (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`).
//
// Payload несёт измерения соответствия (доменные поля действующего лица, субъекта, ресурса,
// ключа). Он НЕ ДОЛЖЕН содержать секретный материал (токены, PEM ключа,
// client_secret) — см. приёмку 5.2-36.
//
// Нейтральный тип значения принадлежит internal/outboxtypes, чтобы пакет портов репозитория
// ссылался на него без импорта пакета сценариев (исправление правила зависимостей);
// псевдоним сохраняет удобное имя service.AuditEvent.
type AuditEvent = outboxtypes.AuditEvent

// AuditOutboxEmitter — порт отправки одной надёжной строки kaname.audit_outbox
// в транзакции писателя вызывающего. Атомарен с окружающей значимой для безопасности
// мутацией (запрет #10): строка аудита коммитится тогда и только тогда, когда коммитится мутация, поэтому
// откат не оставляет осиротевшей строки соответствия, а коммит
// всегда оставляет след.
//
// Повторяет форму отправки внутри транзакции RelationOutboxEmitter: конкретный pgx.Tx
// восстанавливается из непрозрачного service.Tx внутри адаптера репозитория (txAsPgx).
type AuditOutboxEmitter interface {
	EmitTx(ctx context.Context, tx Tx, ev AuditEvent) error
}
