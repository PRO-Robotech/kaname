// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

// notifications.go — строка `notifications` манифеста (приёмка NTF-1, Р3 и Р5;
// замысел З17).
//
// # Что строка объявляет
//
// Модуль объявляет ОДНОЙ строкой, что у него есть пространство уведомлений и
// кто читает его ленту: `notifications: {namespace: <модуль>, readers: [notify]}`.
// Применитель посева переводит её в кортеж `service:notify reader
// notification_feed:<модуль>`. Кортеж `sender` кортежный путь применителя НЕ
// пишет: по замыслу (З18) он — проекция записи выдачи, а записи выдачи в этом
// дереве нет, поэтому сегодня строка даёт право читать ленту и не даёт права
// отправлять.
//
// # Почему форма закрыта именно так
//
//   - `namespace` равен `module` ЭТОГО манифеста: иначе модуль объявлял бы право
//     отправлять от имени чужого (О3: «сервис А не отправляет от имени сервиса Б»);
//   - `readers` ровно `[notify]`: `reader` ленты даёт право забрать тело письма, и
//     выдаётся оно только шлюзу. Лишний читатель рядом с законным — такая же
//     находка, как чужой вместо него: половину строки применитель не применяет.
//
// # Разрядов у строки ДВА, и различает их вызывающий, а не документ
//
// У службы доступа служебного принципала нет (MRW-1 Р1), поэтому её собственный
// манифест несёт только `readers: [notify]` без `namespace` — это выдаёт
// `service:notify reader notification_feed:kaname`, и ничего сверх (Р3). Лента
// службы называется литералом [AccessServiceFeed], а не выводится из её `module`.
//
// Какой разряд судится, говорит ВЫЗЫВАЮЩИЙ ([AsAccessService] у загрузчика,
// позиция своего манифеста у применителя), а не сам документ: форма, по которой
// документ «опознавал бы себя» службой, была бы формой, которую может написать
// любой модуль.

import (
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// NotificationReader — единственный читатель ленты уведомлений: шлюз notify.
const NotificationReader = "notify"

// AccessServiceFeed — лента службы доступа. Литерал, а не `module` её манифеста
// (Р3): пространство службы называется `kaname`, а модуль её манифеста — иначе.
const AccessServiceFeed = "kaname"

// Notifications — строка `notifications` манифеста.
type Notifications struct {
	// Namespace — пространство уведомлений модуля; равно `module` манифеста. У
	// манифеста службы доступа не пишется вовсе.
	Namespace string `yaml:"namespace"`
	// Readers — читатели ленты; законно ровно `[notify]`.
	Readers []string `yaml:"readers"`
}

// String — строка в той форме, в какой её пишет автор манифеста. Находка
// называет строку ею, чтобы автор узнал свой текст.
func (n *Notifications) String() string {
	parts := make([]string, 0, 2)
	if n.Namespace != "" {
		parts = append(parts, "namespace: "+n.Namespace)
	}
	parts = append(parts, "readers: ["+strings.Join(n.Readers, ", ")+"]")
	return "notifications: {" + strings.Join(parts, ", ") + "}"
}

// NotificationsHolder — чей манифест судится.
type NotificationsHolder int

const (
	// HolderModule — манифест модуля платформы.
	HolderModule NotificationsHolder = iota
	// HolderAccessService — собственный манифест службы доступа (Р3).
	HolderAccessService
)

var (
	// ErrNotificationNamespaceForeign — пространство не своего модуля либо не
	// названо в манифесте модуля (NTF1-F02).
	ErrNotificationNamespaceForeign = errors.New("manifest: notifications namespace is not the module's own")
	// ErrNotificationReaderNotNotify — читатель ленты не ровно `[notify]` (NTF1-F03).
	ErrNotificationReaderNotNotify = errors.New("manifest: notifications reader is not notify alone")
	// ErrAccessServiceHasNoServicePrincipal — манифест службы доступа назвал
	// пространство, то есть объявил служебного принципала службы (NTF1-F21 (б)).
	ErrAccessServiceHasNoServicePrincipal = errors.New("manifest: the access service declares no service principal")
	// ErrNotificationsDeclaredNull — ключ `notifications` без значения. Отдельный
	// отказ по тому же доводу, что у `seed:`: разобранный указатель nil не
	// отличил бы «строки нет» от «строку написали пустой».
	ErrNotificationsDeclaredNull = errors.New("manifest: notifications is declared with no value")
)

// JudgeNotifications судит строку `notifications` манифеста m как строку
// разряда holder. Манифест без строки находок не даёт. Находки собираются все.
//
// Предикат ОДИН на загрузчик и применитель: разойдясь, они дали бы оснастке и
// посеву разные ответы об одной строке — и разошлись бы молча, потому что на
// законной строке оба отвечают одинаково.
func JudgeNotifications(m *Manifest, holder NotificationsHolder) error {
	return judgeNotifications(m, holder, 0)
}

// NotificationFeed — лента, на которую строка манифеста m разряда holder выдаёт
// `reader`. Вызывающий судит строку [JudgeNotifications] раньше.
func NotificationFeed(m *Manifest, holder NotificationsHolder) string {
	if holder == HolderAccessService {
		return AccessServiceFeed
	}
	return m.Notifications.Namespace
}

// judgeNotifications — суд с номером строки документа (0 — номер неизвестен:
// у применителя документа уже нет).
func judgeNotifications(m *Manifest, holder NotificationsHolder, line int) error {
	n := m.Notifications
	if n == nil {
		return nil
	}
	where := fmt.Sprintf("модуль %q, строка манифеста `%s`", m.Module, n)
	if line > 0 {
		where += fmt.Sprintf(" (line %d)", line)
	}

	var faults []error
	switch holder {
	case HolderAccessService:
		if n.Namespace != "" {
			faults = append(faults, fmt.Errorf("%w: %s: у службы доступа служебного принципала нет (MRW-1 Р1) — "+
				"её строка несёт только `readers: [%s]`, лента службы — %q",
				ErrAccessServiceHasNoServicePrincipal, where, NotificationReader, AccessServiceFeed))
		}
	default:
		if n.Namespace != m.Module {
			faults = append(faults, fmt.Errorf("%w: %s: пространство не своего модуля — у модуля %q "+
				"пространство только %q", ErrNotificationNamespaceForeign, where, m.Module, m.Module))
		}
	}
	if len(n.Readers) != 1 || n.Readers[0] != NotificationReader {
		faults = append(faults, fmt.Errorf("%w: %s: reader ленты — только %s, законно ровно `readers: [%s]`",
			ErrNotificationReaderNotNotify, where, NotificationReader, NotificationReader))
	}
	return errors.Join(faults...)
}

// refuseNullNotifications — `notifications:` без значения.
func refuseNullNotifications(doc *yaml.Node) error {
	for i := 0; i+1 < len(doc.Content); i += 2 {
		key, value := doc.Content[i], doc.Content[i+1]
		if key.Value != "notifications" || value.Tag != "!!null" {
			continue
		}
		return fmt.Errorf("%w: line %d: write the line in full or omit the key entirely",
			ErrNotificationsDeclaredNull, key.Line)
	}
	return nil
}

// notificationsLine — номер строки ключа `notifications` в документе; 0 — ключа нет.
func notificationsLine(doc *yaml.Node) int {
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value == "notifications" {
			return doc.Content[i].Line
		}
	}
	return 0
}

// AsAccessService — судить документ как СОБСТВЕННЫЙ манифест службы доступа
// (Р3). Вносит его носитель встроенного манифеста; оснастка дерева и доставка
// судят манифесты модулей.
func AsAccessService() LoadOption {
	return func(opts *loadOptions) { opts.notificationsHolder = HolderAccessService }
}
