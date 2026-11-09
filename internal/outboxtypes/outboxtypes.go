// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Пакет outboxtypes содержит НЕЙТРАЛЬНЫЕ типы значений данных очереди транзакции записи,
// общие для границы чистой архитектуры между слоем сценариев
// (internal/service, определяет порты выпуска) и агрегатором портов Repository
// CQRS (internal/repo/kaname, чья поверхность Writer также их выпускает).
//
// Зачем отдельный листовой пакет: internal/repo/kaname/iface.go (порты
// Repository/Reader/Writer) предоставляет EmitAuditEvent / EmitFGARelationWrite
// / EmitFGARelationDelete через эти данные. Если бы данные жили в
// internal/service (слой сценариев), пакет портов репозитория импортировал бы
// пакет сценариев, ЗАВИСЯЩИЙ от него: перевёрнутое ребро слоёв, от которого «один
// рефакторинг до цикла импортов» (repo/kaname → service → repo/kaname).
// Вынос данных в этот листовой пакет только на стандартной библиотеке позволяет ОБЕИМ сторонам
// ссылаться на нейтральный тип без взаимного импорта.
//
// Пакет импортирует ТОЛЬКО стандартную библиотеку.
package outboxtypes

import "time"

// RelationTuple — тройка {User, Relation, Object} для записи выдачи/отзыва
// в kaname.fga_outbox.
type RelationTuple struct {
	User     string
	Relation string
	Object   string
}

// VersionedRelationTuple задаёт собственную версию строки единого снятия.
// Нулевая версия означает прежний неупорядоченный intent, а не часы владельца.
type VersionedRelationTuple struct {
	Tuple         RelationTuple
	SourceVersion time.Time
	// CurrentRemoval удостоверяет фактически снятое зеркало явным нулевым намерением.
	// Только такой план может снять точную конечную границу без версии запроса.
	CurrentRemoval bool
}

// AuditEvent — данные постоянной строки аудита kaname.audit_outbox.
// Адаптер репозитория создаёт id (evt_<22-char>), кодирует Payload в
// event_payload jsonb и вставляет со status='pending'. EventType обязан
// удовлетворять CHECK audit_outbox_event_type
// (`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+$`).
//
// Payload несёт измерения аудита (actor / subject / resource / key —
// доменные поля). Секретных данных быть НЕ ДОЛЖНО (ни токенов, ни PEM ключей,
// ни client_secret) — см. приёмку 5.2-36.
type AuditEvent struct {
	// EventType — каноническое значение таксономии `iam.<resource>.<action>`.
	EventType string
	// TenantAccountID — область Account для аудиторских запросов по аккаунту; "" → NULL.
	TenantAccountID string
	// Payload — тело event_payload jsonb (имена ключей выбирает сценарий:
	// actor / subject_id / reason / token_jti / …).
	Payload map[string]any
}

// InviteMailRateLimit — ограничение частоты писем НА АДРЕС за окно (приёмка
// ID-MAIL-1, Р14/Р22, MAIL-25): не больше MaxPerWindow писем одному адресу за
// Window. Обе величины положительны; значения, означающего «без ограничения»,
// у ограничения нет — писатель отвергает непозитивные, а не читает их как
// «сколько угодно».
type InviteMailRateLimit struct {
	MaxPerWindow int
	Window       time.Duration
}

// InviteMailIntent — намерение отправить письмо приглашения, ставящееся в
// очередь `kaname.invite_mail_outbox` ТОЙ ЖЕ транзакцией, что и мутация,
// его породившая. Несёт ограничение частоты: писатель списывает окно адресата
// ПЕРЕД постановкой в очередь, и сверхнормативное намерение в очередь не
// попадает — это и есть единственный путь письма, и ограничитель стоит на
// нём по построению, а не по дисциплине вызывающего.
type InviteMailIntent struct {
	// UserID — строка приглашения; ключ партиции порядка очереди.
	UserID string
	// AccountID — аккаунт, куда приглашён человек (атрибуция письма).
	AccountID string
	// To — адрес получателя.
	To string
	// LoginURL — адрес страницы входа; пусто ⇒ подставит отправитель из
	// своей настройки.
	LoginURL string
	// Limit — ограничение частоты на адрес.
	Limit InviteMailRateLimit
}
