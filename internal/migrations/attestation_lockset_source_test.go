// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package migrations_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/stretchr/testify/require"
)

func TestAttestationLocksetOneScanAndExactDown(t *testing.T) {
	old, err := migrations.FS.ReadFile("20261113190000_authority_bundle_lifecycle_drains_before_activation.sql")
	require.NoError(t, err)
	next, err := migrations.FS.ReadFile("20261114080000_attestation_reads_lockset_once.sql")
	require.NoError(t, err)
	body := func(s string) string {
		t.Helper()
		const start = "CREATE OR REPLACE FUNCTION kaname.authority_protocol_attestation() RETURNS jsonb"
		i := strings.Index(s, start)
		require.NotEqual(t, -1, i)
		s = s[i:]
		end := strings.Index(s, "END $$;")
		require.NotEqual(t, -1, end)
		return s[:end+len("END $$;")]
	}
	parts := strings.Split(string(next), "-- +goose Down")
	require.Len(t, parts, 2)
	before, up, down := body(string(old)), body(parts[0]), body(parts[1])
	require.Equal(t, before, down, "Down возвращает точную прежнюю trust/lock функцию")
	require.Equal(t, 1, strings.Count(up, "FROM pg_catalog.pg_locks"))
	require.Contains(t, up, "WITH held AS MATERIALIZED (")
	require.NotContains(t, up, "FOR k IN")
	for _, fragment := range []string{"l.pid=pg_backend_pid()", "d.datname=current_database()", "l.locktype='advisory' AND l.objsubid=2 AND l.granted", "h.classid=1262569283::oid AND h.objid=0::oid AND h.mode=expected_mode", "h.classid=1262569281::oid", "SELECT h.objid FROM held h WHERE h.classid=1262569281::oid AND h.mode='ExclusiveLock'", "SELECT DISTINCT (hashtext(value)::bigint & 4294967295)::oid", "EXCEPT", "CASE WHEN r.present AND proof->>'mode'='accounts'"} {
		require.Contains(t, up, fragment)
	}
	// Вся security-prefix часть до проверки locks, кроме неиспользуемой loop
	// переменной, сохраняется byte-for-byte; никакого кэша или trusted caller flag.
	prefix := func(s string) string { return strings.Split(s, " expected_mode:=")[0] }
	normalized := strings.Replace(before, "strict_mode boolean; k integer; expected_mode text;", "strict_mode boolean; expected_mode text; root_present boolean; accounts_present boolean;", 1)
	require.Equal(t, prefix(normalized), prefix(up))
	for _, part := range parts {
		require.NotEqual(t, -1, strings.Index(part, "PERFORM kaname.authority_protocol_drain()"))
		require.Less(t, strings.Index(part, "PERFORM kaname.authority_protocol_drain()"), strings.Index(part, "CREATE OR REPLACE FUNCTION"))
		require.Contains(t, part, "REVOKE ALL ON FUNCTION kaname.authority_protocol_attestation() FROM PUBLIC")
	}
}
