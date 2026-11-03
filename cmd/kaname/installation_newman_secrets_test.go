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

// Closed phase-bound actor/opaque-secret inventory. Assertion bytes are secrets,
// not bearer tokens; both use the unchanged anonymous two-string FD5 protocol.
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
	allowed := map[string]bool{}
	for _, name := range names {
		allowed[name] = true
	}
	for name := range variables {
		if (strings.HasPrefix(name, "jwtRID") || name == "rid01ClientAssertion") && !allowed[name] {
			return nil, errors.New("undeclared Newman client secret")
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

// Every admitted bearer/assertion gets its existing two-string FD5 record. Capture all secrets
// before reading the TLS key or doing any other fallible admission work.
func ridNewmanRecordBearers(inventory io.Writer, bearers []string) error {
	for _, bearer := range bearers {
		if err := json.NewEncoder(inventory).Encode([]string{"", bearer}); err != nil {
			return errors.New("anonymous Newman bearer capture failed")
		}
	}
	return nil
}

// Read only the anonymous FD5 itself, never the world-secret union used for
// stream scanning. A token known to the fixture is not proof of FD5 capture.
// ReadAt through SectionReader preserves the shared file description offset.
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
