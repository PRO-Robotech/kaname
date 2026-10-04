// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

// recipient_directory.go — строка `recipientDirectory` манифеста (приёмка
// NTF-3, kacho#2918: Р28, NTF3-50; замысел З27, CX3B-15, УК3-08).
//
// # Что строка объявляет
//
// Модуль `notify` объявляет ОДНОЙ строкой, что он читает справочник адресов
// службы доступа: `recipientDirectory: {readers: [notify]}`. Применитель посева
// переводит её в кортеж `service:notify reader
// notification_recipient_directory:root`, и только он даёт `notify` право на
// методы справочника.
//
// # Почему форма закрыта именно так
//
// Справочник отдаёт адреса ВСЕХ пользователей установки, поэтому читатель у
// него один на установку — шлюз писем:
//
//   - строку пишет только манифест модуля `notify`: строка в чужом манифесте
//     объявляла бы право читать адреса от имени того, кто их не рассылает;
//   - `readers` ровно `[notify]`: лишний читатель рядом с законным — такая же
//     находка, как чужой вместо него, половину строки применитель не применяет;
//   - документ, назвавший себя `notify`, обязан ПРИЕХАТЬ ключом доставки
//     `notify` (правило происхождения, [RecipientDirectoryProvenance]): иначе
//     любой модуль, положивший в доставку документ с чужим `module`, выписал бы
//     себе справочник, а настоящего манифеста `notify` в доставке могло не быть
//     вовсе.
//
// Находка одна на все три случая — «читатель справочника — только notify» — и
// называет модуль и строку (а у правила происхождения — ключ доставки).

import (
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/corelib/modulemanifest"
)

// RecipientDirectoryReader — единственный читатель справочника адресов и
// единственный модуль, чей манифест вправе нести строку.
const RecipientDirectoryReader = "notify"

// recipientDirectoryKey — ключ строки в документе.
const recipientDirectoryKey = "recipientDirectory"

// RecipientDirectory — строка `recipientDirectory` манифеста.
type RecipientDirectory struct {
	// Readers — читатели справочника; законно ровно `[notify]`.
	Readers []string `yaml:"readers"`
}

// String — строка в той форме, в какой её пишет автор манифеста.
func (d *RecipientDirectory) String() string {
	return recipientDirectoryKey + ": {readers: [" + strings.Join(d.Readers, ", ") + "]}"
}

var (
	// ErrRecipientDirectoryReader — строка не в манифесте `notify`, читатель не
	// ровно `[notify]`, либо документ приехал не своим ключом доставки.
	ErrRecipientDirectoryReader = errors.New("manifest: читатель справочника — только notify")
	// ErrRecipientDirectoryDeclaredNull — ключ `recipientDirectory` без
	// значения: разобранный указатель nil не отличил бы «строки нет» от «строку
	// написали пустой».
	ErrRecipientDirectoryDeclaredNull = errors.New("manifest: recipientDirectory is declared with no value")
)

// JudgeRecipientDirectory судит строку `recipientDirectory` манифеста m.
// Манифест без строки находок не даёт.
//
// Предикат ОДИН на загрузчик и применитель посева: разойдясь, они дали бы
// оснастке и посеву разные ответы об одной строке.
func JudgeRecipientDirectory(m *Manifest) error { return judgeRecipientDirectory(m, 0) }

// judgeRecipientDirectory — суд строки манифеста m с номером строки документа
// (0 — номер неизвестен). Манифест без строки находок не даёт.
func judgeRecipientDirectory(m *Manifest, line int) error {
	d := m.RecipientDirectory
	if d == nil {
		return nil
	}
	var faults []string
	if m.Module != RecipientDirectoryReader {
		faults = append(faults, fmt.Sprintf("строку несёт только манифест модуля %q", RecipientDirectoryReader))
	}
	if len(d.Readers) != 1 || d.Readers[0] != RecipientDirectoryReader {
		faults = append(faults, fmt.Sprintf("законно ровно `readers: [%s]`", RecipientDirectoryReader))
	}
	if len(faults) == 0 {
		return nil
	}
	where := fmt.Sprintf("модуль %q, строка манифеста `%s`", m.Module, d)
	if line > 0 {
		where += fmt.Sprintf(" (line %d)", line)
	}
	return fmt.Errorf("%w: %s: %s", ErrRecipientDirectoryReader, where, strings.Join(faults, "; "))
}

// RecipientDirectoryProvenance — правило происхождения (УК3-08, CX3B-15):
// строка документа, доставленного ключом key, применима, только когда ключ —
// ключ доставки модуля, которым документ себя назвал. Манифест без строки
// находок не даёт.
//
// Судит ДОСТАВКУ, а не документ: имя ключа документу не видно, поэтому
// правило зовёт обход каталога доставки, у которого ключ есть.
func RecipientDirectoryProvenance(key string, m *Manifest) error {
	if m == nil || m.RecipientDirectory == nil {
		return nil
	}
	if want := modulemanifest.DeliveryKey(m.Module); key != want {
		return fmt.Errorf("%w: модуль %q, строка манифеста `%s`: документ доставлен ключом %s, "+
			"а не своим %s — строка не применяется",
			ErrRecipientDirectoryReader, m.Module, m.RecipientDirectory, key, want)
	}
	return nil
}

// refuseNullRecipientDirectory — `recipientDirectory:` без значения.
func refuseNullRecipientDirectory(doc *yaml.Node) error {
	for i := 0; i+1 < len(doc.Content); i += 2 {
		key, value := doc.Content[i], doc.Content[i+1]
		if key.Value != recipientDirectoryKey || value.Tag != "!!null" {
			continue
		}
		return fmt.Errorf("%w: line %d: write the line in full or omit the key entirely",
			ErrRecipientDirectoryDeclaredNull, key.Line)
	}
	return nil
}

// recipientDirectoryLine — номер строки ключа в документе; 0 — ключа нет.
func recipientDirectoryLine(doc *yaml.Node) int {
	for i := 0; i+1 < len(doc.Content); i += 2 {
		if doc.Content[i].Value == recipientDirectoryKey {
			return doc.Content[i].Line
		}
	}
	return 0
}
