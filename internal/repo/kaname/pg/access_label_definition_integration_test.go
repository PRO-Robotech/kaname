// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestAccessLabelDefinitionsAreScopedAndOwnerPrivate(t *testing.T) {
	r := writerProtocolRig(t)
	const create = `INSERT INTO kaname.authority_access_label_definition
		(scope_kind, scope_id, module, resource, label_key)
		VALUES ('account', $1, 'iam', 'project', 'team') RETURNING id::text`
	var first, second string
	require.NoError(t, r.admin.QueryRow(r.ctx, create, r.a).Scan(&first))
	require.NoError(t, r.admin.QueryRow(r.ctx, create, r.b).Scan(&second))
	require.NotEqual(t, first, second, "одинаковый ключ в разных аккаунтах имеет разные идентификаторы")

	var duplicate *pgconn.PgError
	err := r.admin.QueryRow(r.ctx, create, r.a).Scan(new(string))
	require.ErrorAs(t, err, &duplicate)
	require.Equal(t, "23505", duplicate.Code)

	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_value
		(definition_id, label_value) VALUES ($1::text::uuid, 'a'), ($2::text::uuid, 'b')`, first, second)
	require.NoError(t, err)

	for _, table := range []string{"kaname.authority_access_label_definition", "kaname.authority_access_label_value"} {
		var allowed bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_table_privilege(current_user, $1::text,
			'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')`, table).Scan(&allowed))
		require.False(t, allowed, "штатная выдача runtime не раскрывает %s", table)
	}
}
