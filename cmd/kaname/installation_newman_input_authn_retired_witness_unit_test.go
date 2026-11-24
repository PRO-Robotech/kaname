// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRID11RetiredPrivateWitness_OriginalSQLBytesAndNoAlias(t *testing.T) {
	// Пробелы, порядок ключей и escape являются частью исходного SQL hash.
	sql := "{ \"name\": \"a\\\"b\\\\c\", \"id\": \"cluster_fixture\" }"
	var row rid09PrimaryRow
	require.NoError(t, json.Unmarshal([]byte(sql), &row))
	s := rid03NewmanSnapshot{Raw: map[string][]rid09PrimaryRow{"clusters": {row}}}
	plain, err := json.Marshal(s.Whole)
	require.NoError(t, err)
	s.Whole.retiredSQLRows = map[string][]string{"clusters": {sql}, "audit_outbox": {"PRIVATE-MUST-NOT-EXPORT"}}
	s.Raw["audit_outbox"] = []rid09PrimaryRow{{"payload": json.RawMessage(`"PRIVATE-MUST-NOT-EXPORT"`)}}
	withPrivate, err := json.Marshal(s.Whole)
	require.NoError(t, err)
	require.Equal(t, plain, withPrivate, "старый Whole JSON и его hash не меняются")
	witness := rid11RetiredPrivateWitness(s, s)
	s.Whole.retiredSQLRows["clusters"][0] = "changed"
	s.Raw["clusters"][0]["id"] = json.RawMessage(`"changed"`)
	wire, err := json.Marshal(witness)
	require.NoError(t, err)
	require.NotContains(t, string(wire), "PRIVATE-MUST-NOT-EXPORT")
	var decoded struct {
		Before struct {
			Tables map[string]struct {
				SQLRows     []string `json:"sqlRows"`
				RawRowsJSON string   `json:"rawRowsJSON"`
			} `json:"tables"`
		} `json:"before"`
	}
	require.NoError(t, json.Unmarshal(wire, &decoded))
	require.Len(t, decoded.Before.Tables, 10)
	require.Equal(t, []string{sql}, decoded.Before.Tables["clusters"].SQLRows)
	require.Contains(t, decoded.Before.Tables["clusters"].RawRowsJSON, "cluster_fixture")
	require.NotContains(t, decoded.Before.Tables["clusters"].RawRowsJSON, "changed")
}

func TestRID11RetiredPrivateWitness_MissingAndOversizeRemainRejectedObservations(t *testing.T) {
	s := rid03NewmanSnapshot{Raw: map[string][]rid09PrimaryRow{}}
	witness := rid11RetiredPrivateWitness(s, s)
	table := witness["before"].(map[string]any)["tables"].(map[string]any)["clusters"].(map[string]any)
	require.Equal(t, false, table["rawPresent"])
	require.Equal(t, false, table["sqlPresent"])
	require.Equal(t, "null", table["rawRowsJSON"])
	s.Whole.retiredSQLRows = map[string][]string{"clusters": {strings.Repeat("x", 8*1024*1024+1)}}
	require.Equal(t, false, rid11RetiredPrivateWitness(s, s)["bounded"])
	require.False(t, rid11RetiredPrivateTable("operations"))
	require.False(t, rid11RetiredPrivateTable("access_tokens"))
	require.False(t, rid11RetiredPrivateTable("fga_outbox"))
}
