// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"syscall"
)

// Замкнутая привязанная к фазе ведомость участников/непрозрачных секретов. Байты утверждений — секреты,
// а не токены предъявителя; оба используют неизменный анонимный двухстрочный протокол FD5.
func ridNewmanClientSecrets(stem, caseID string, variables map[string]any) ([]string, error) {
	if !strings.HasPrefix(caseID, stem+"-") || len(caseID) == len(stem)+1 {
		return nil, errors.New("invalid Newman case identity")
	}
	names := []string{"jwtRIDOperator"}
	if stem == "registry-installation-rid10" {
		names = append(names, "jwtRIDCreator")
	}
	if stem == "registry-installation-rid01" {
		if !rid01PublicCase(caseID) {
			return nil, errors.New("invalid Newman case identity")
		}
		switch caseID {
		case rid01ExpiredAccessCase:
			names = append(names, "jwtRIDExpiredCreator")
		case rid01RenewedAccessCase:
			names = append(names, "jwtRIDCreator")
		case rid01ExpiredKeyCase:
			names = append(names, "rid01ClientAssertion")
		}
	}
	if stem == "registry-installation-rid03" {
		actor, ok := rid03NewmanActor(caseID)
		if !ok {
			return nil, errors.New("invalid Newman case identity")
		}
		if actor == "I" {
			names = append(names, "jwtRIDIssuer")
		}
		if actor == "C" {
			names = append(names, "jwtRIDCreator")
		}
	}
	if stem == "registry-installation-rid04" {
		actor, ok := rid04NewmanActor(caseID)
		if !ok {
			return nil, errors.New("invalid Newman case identity")
		}
		if actor == "I" {
			names = append(names, "jwtRIDIssuer")
		}
	}
	if stem == "registry-installation-rid05" {
		actor, ok := rid05NewmanActor(caseID)
		if !ok {
			return nil, errors.New("invalid Newman case identity")
		}
		if actor == "I" {
			names = append(names, "jwtRIDIssuer")
		}
		if actor == "A" {
			names = append(names, "rid05ClientAssertion")
		}
	}
	if stem == "registry-installation-rid06" {
		actor, ok := rid06PublicActor(caseID)
		if !ok {
			return nil, errors.New("invalid Newman case identity")
		}
		if actor == "I" {
			names = append(names, "jwtRIDIssuer")
		}
		if actor == "C" {
			names = append(names, "jwtRIDCreator")
		}
	}
	if stem == "registry-installation-rid11" {
		rule, ok := rid11PublicRules[caseID]
		if !ok {
			return nil, errors.New("invalid Newman case identity")
		}
		if rule.Token401 {
			names = append(names, "rid11ClientAssertion")
		}
	}
	allowed := map[string]bool{}
	for _, name := range names {
		allowed[name] = true
	}
	for name := range variables {
		if (strings.HasPrefix(name, "jwtRID") || name == "rid01ClientAssertion" || name == "rid05ClientAssertion" || name == "rid11ClientAssertion") && !allowed[name] {
			return nil, errors.New("undeclared Newman client secret")
		}
		if name == "rid11IssuanceOrigin" && !rid11TokenCase(caseID) {
			return nil, errors.New("undeclared Newman issuance origin")
		}
		if name == "rid05IssuanceOrigin" && !rid05TokenCase(caseID) {
			return nil, errors.New("undeclared Newman issuance origin")
		}
		if name == "rid01IssuanceOrigin" && caseID != rid01ExpiredKeyCase {
			return nil, errors.New("undeclared Newman issuance origin")
		}
	}
	secrets := make([]string, 0, len(names))
	for _, name := range names {
		value, ok := variables[name].(string)
		if !ok || value == "" || len(value) > 16<<10 {
			return nil, errors.New("required Newman client secret is absent or invalid")
		}
		secrets = append(secrets, value)
	}
	return secrets, nil
}

// Каждый допущенный токен/утверждение получает существующую двухстрочную запись FD5. Захватываем все секреты
// до чтения ключа TLS или любой другой способной отказать работы допуска.
func ridNewmanRecordBearers(inventory io.Writer, bearers []string) error {
	for _, bearer := range bearers {
		if err := json.NewEncoder(inventory).Encode([]string{"", bearer}); err != nil {
			return errors.New("anonymous Newman bearer capture failed")
		}
	}
	return nil
}

// Читаем лишь сам анонимный FD5, а не объединение секретов мира, используемое
// для проверки потоков. Известный фикстуре токен не доказывает захват FD5.
// ReadAt через SectionReader сохраняет смещение общего открытого файлового описания.
func ridNewmanAuditAnonymousInventory(inventory *os.File, required []string) error {
	info, err := inventory.Stat()
	if err != nil {
		return errors.New("anonymous Newman inventory metadata unavailable")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() > 1<<20 {
		return errors.New("anonymous Newman inventory is not private and bounded")
	}
	seen := make(map[string]bool)
	decoder := json.NewDecoder(io.NewSectionReader(inventory, 0, info.Size()))
	for {
		var record []string
		err := decoder.Decode(&record)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil || len(record) != 2 || record[1] == "" {
			return errors.New("anonymous Newman inventory record is invalid")
		}
		for _, value := range record {
			if value != "" {
				seen[value] = true
			}
		}
	}
	for _, value := range required {
		if value == "" || !seen[value] {
			return errors.New("anonymous Newman inventory lacks actual admitted secret")
		}
	}
	return nil
}
