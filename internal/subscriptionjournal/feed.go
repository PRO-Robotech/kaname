// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package subscriptionjournal

// feed.go — порт журнала ленты извещений kaname (замысел issue-2917 З2, З17;
// приёмка NTF-2 Р1, CX2-27).
//
// # Что здесь, и чего здесь нет
//
// Строку сигнала `notification_feed:kaname` пишет писатель фундамента
// (`feed.JournalSignal` → `subscription.Journal.Emit`) в транзакции постановки
// письма — той же, что строка ленты (`feed.PutID`, шаг 6). Своего писателя у
// службы нет: два писателя одной строки разошлись бы молча, а форму строки
// (`resource_id = 'kaname'`, без якоря, без областей, `UPDATED`) держит база
// (`20261010031946_resource_journal_admits_the_feed_signal.sql`). Служба
// приносит ОБЪЯВЛЕНИЕ — вид ключа ленты в своём журнале — и имя ленты.
//
// Журнал — ресурсный журнал подписки службы (`kaname.resource_journal`), а не
// журнал изменений субъектов (`kaname.subject_change_outbox`): последний —
// сигнал пересчёта вердиктов прав, потока подписки у него нет, и строка ленты
// в нём никого бы не разбудила.
//
// # Ключ объявляется по флагу почты
//
// При выключенном флаге ключ ленты в словаре видов НЕ объявляется (З2, NTF-1
// Р9): журнал собирается [Journal] без него. [FeedJournal] — то же объявление
// плюс ключ ленты, и ничего сверх; выбирает между ними корень по тому же
// значению флага, что получают `mail.Enqueuer` и источник ленты.

import (
	"maps"

	"github.com/PRO-Robotech/corelib/notify/feed"
	"github.com/PRO-Robotech/corelib/subscription"

	"github.com/PRO-Robotech/kaname/internal/manifest"
)

// KindFeed — вид строки сигнала ленты словом журнала: ключ ленты фундамента.
const KindFeed = feed.JournalKey

// feedObjectType — тип объекта модели прав, которым судится видимость строки
// сигнала: `notification_feed` (право `reader` выдано только `service:notify`).
const feedObjectType = "notification_feed"

// actionSubscribe — действие, ради которого задаётся вопрос о видимости строки
// сигнала: подписка на поток изменений (разрешение глагола `Subscribe`). Строка
// сигнала не принадлежит ни одной выборке списка — списочного действия у неё нет.
const actionSubscribe = "platform.subscription.subscribe"

// FeedJournal — объявление журнала при включённом флаге почты: [Journal] и вид
// ключа ленты уровня кластера без имени — та форма, которую требует писатель
// фундамента и держит ограничение базы.
func FeedJournal() subscription.Journal {
	j := Journal()
	kinds := maps.Clone(j.Mapping.Kinds)
	kinds[KindFeed] = subscription.Kind{
		ObjectType: feedObjectType,
		Action:     actionSubscribe,
		NameForm:   subscription.NameFormNone,
		Scope:      subscription.ScopeCluster,
	}
	j.Mapping.Kinds = kinds
	return j
}

// FeedSignal — порт журнала ленты (`feed.Signal`) для источника ленты kaname:
// строка вида [KindFeed] об объекте `notification_feed:kaname` с родом
// `UPDATED` — «в ленте появилось»; лента существует, пока существует служба, и
// снятием сигнал не бывает. Объявление судится здесь, при сборке корня: отказ —
// отказ старта, а не отказ первой постановки.
func FeedSignal() (feed.Signal, error) {
	return feed.JournalSignal(FeedJournal(), manifest.AccessServiceFeed, changeUpdated)
}
