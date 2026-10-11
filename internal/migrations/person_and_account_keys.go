// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// person_and_account_keys.go — каждый внешний ключ на `users` и `accounts`
// записан в ведомости вместе с действием и доводом (задача kaname#664,
// приёмка `own-account-and-identity-are-removed-in-order.md`, Р9, KN664-60/61).
//
// # Предмет
//
// Арендатор не мог уйти, потому что два ключа на `users` и `accounts` образовали
// цикл `RESTRICT`, а ещё три `RESTRICT` на `users` стояли на том же пути. Ни
// один из них не был ошибкой по отдельности — каждый заводился своей задачей
// без вопроса «как это снимается». Цикл вырос молча и молча вырастет снова,
// если новый ключ на эти таблицы не обязан называть своё действие.
//
// # Почему судится НАКАТАННАЯ схема, а не текст миграций
//
// Текстовая перепись не видит снятия таблицы вместе с её ключом и не различает
// ключ, объявленный в `CREATE TABLE`, и ключ `ADD CONSTRAINT` иначе, как
// разбором SQL. Каталог базы отвечает на сам вопрос: какие ключи на эти
// таблицы существуют после наката всей цепи. Поэтому держатель —
// интеграционная проба этого пакета, а судья ниже — чистая функция над тем,
// что она прочла.
//
// # Ведомость истекает сама
//
// Строка ведомости без ключа — находка, а не молчание: снятый ключ, о котором
// ведомость продолжает говорить, есть то же «два места об одном предмете».
package migrations

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// PersonAndAccountKeysLedger — ведомость ключей на `users` и `accounts`.
//
//go:embed person_and_account_keys.json
var PersonAndAccountKeysLedger []byte

// ForeignKeyOnPersonOrAccount — внешний ключ, прочитанный из каталога
// накатанной схемы.
type ForeignKeyOnPersonOrAccount struct {
	Name       string `json:"name"`
	Table      string `json:"table"`
	References string `json:"references"`
	// OnDelete — действие словом каталога: CASCADE, RESTRICT, SET NULL,
	// NO ACTION, SET DEFAULT.
	OnDelete string `json:"on_delete"`
}

// KeyLedgerRow — строка ведомости: ключ, его действие и довод.
type KeyLedgerRow struct {
	ForeignKeyOnPersonOrAccount
	Reason string `json:"reason"`
}

// ParseKeyLedger разбирает ведомость. Неизвестное поле — отказ: строка с
// опечаткой в имени поля иначе читалась бы как строка без довода.
func ParseKeyLedger(raw []byte) ([]KeyLedgerRow, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var doc struct {
		Keys []KeyLedgerRow `json:"keys"`
	}
	if err := dec.Decode(&doc); err != nil {
		return nil, fmt.Errorf("ведомость ключей на users и accounts: %w", err)
	}
	return doc.Keys, nil
}

// OnDeleteWord — слово действия по коду каталога (`pg_constraint.confdeltype`).
// Неизвестный код — отказ, а не пустое слово: пустое совпало бы с пустым
// полем ведомости.
func OnDeleteWord(code string) (string, error) {
	switch code {
	case "a":
		return "NO ACTION", nil
	case "r":
		return "RESTRICT", nil
	case "c":
		return "CASCADE", nil
	case "n":
		return "SET NULL", nil
	case "d":
		return "SET DEFAULT", nil
	}
	return "", fmt.Errorf("неизвестный код действия внешнего ключа %q", code)
}

// ErrNoKeysWalked — обход каталога не нашёл ни одного ключа: вердикта нет.
var ErrNoKeysWalked = fmt.Errorf("обход накатанной схемы не нашёл ни одного внешнего ключа на users и accounts — " +
	"вердикт беспредметен: «ноль находок» неотличимо от «ноль прочитанного»")

// JudgePersonAndAccountKeys сверяет ключи каталога с ведомостью. Находки —
// по одной строке на нарушение, отсортированы; пустой обход — ошибка.
func JudgePersonAndAccountKeys(found []ForeignKeyOnPersonOrAccount, ledger []KeyLedgerRow) ([]string, error) {
	if len(found) == 0 {
		return nil, ErrNoKeysWalked
	}
	byName := map[string]KeyLedgerRow{}
	var findings []string
	for _, row := range ledger {
		if _, dup := byName[row.Name]; dup {
			findings = append(findings, fmt.Sprintf("строка ведомости %s записана дважды", row.Name))
		}
		byName[row.Name] = row
		if strings.TrimSpace(row.Reason) == "" {
			findings = append(findings, fmt.Sprintf("строка ведомости %s без довода", row.Name))
		}
	}
	seen := map[string]bool{}
	for _, k := range found {
		seen[k.Name] = true
		row, ok := byName[k.Name]
		if !ok {
			findings = append(findings, fmt.Sprintf("ключ %s (%s → %s ON DELETE %s) без строки ведомости: "+
				"запиши действие и довод — как ключ снимается вместе с тем, на что ссылается",
				k.Name, k.Table, k.References, k.OnDelete))
			continue
		}
		if row.Table != k.Table || row.References != k.References || row.OnDelete != k.OnDelete {
			findings = append(findings, fmt.Sprintf("ключ %s: в схеме %s → %s ON DELETE %s, в ведомости %s → %s ON DELETE %s",
				k.Name, k.Table, k.References, k.OnDelete, row.Table, row.References, row.OnDelete))
		}
	}
	for _, row := range ledger {
		if !seen[row.Name] {
			findings = append(findings, fmt.Sprintf("строка ведомости %s без ключа в схеме — ведомость истекла, сними строку", row.Name))
		}
	}
	sort.Strings(findings)
	return findings, nil
}
