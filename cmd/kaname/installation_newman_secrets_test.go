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

// These are the only bearer variables admitted by the reviewed public cases.
// Keep the same closed set in run-rid-native.cjs. Error text never includes a
// variable value: a malformed producer must not turn validation into a leak.
func ridNewmanClientBearers(stem string, variables map[string]any) ([]string, error) {
	names := []string{"jwtRIDOperator"}
	if stem == "registry-installation-rid10" {
		names = append(names, "jwtRIDCreator")
	}
	for name := range variables {
		if strings.HasPrefix(name, "jwtRID") && name != names[0] && !(len(names) == 2 && name == names[1]) {
			return nil, errors.New("undeclared Newman bearer variable")
		}
	}
	bearers := make([]string, 0, len(names))
	for _, name := range names {
		value, ok := variables[name].(string)
		if !ok || value == "" || len(value) > 16<<10 {
			return nil, errors.New("required Newman bearer is absent or invalid")
		}
		bearers = append(bearers, value)
	}
	return bearers, nil
}

// Every bearer gets its own existing two-string FD5 record. Capture all tokens
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
