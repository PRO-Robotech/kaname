// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// Все десять проверок истории регистрации судят запись службы после допуска.
// Законная вставка и настоящий отказ UPDATE отличают дефект писателя от
// отсутствующей таблицы, неверного имени ограничения и отказа соседнего CHECK.
func TestIntegration_RegistrationHistoryChecksAreServiceDefects(t *testing.T) {
	pool := cvPool(t)
	ctx := context.Background()
	logBuf := cvCaptureLog(t)
	for _, table := range []struct {
		name      string
		insert    string
		mutations []struct{ column, set string }
	}{
		{
			name: "resource_registration_pointer",
			insert: `INSERT INTO kaname.resource_registration_pointer
 (module,object_type,object_id,relation,subject,source_version)
 VALUES ('registry','registry_registry','history-probe','reader','user:history-owner',now())`,
			mutations: []struct{ column, set string }{
				{"module", "module=''"},
				{"object_type", "object_type='invalid:type'"},
				{"object_id", "object_id='invalid:id'"},
				{"relation", "relation='owner'"},
				{"subject", "subject='user:*'"},
			},
		},
		{
			name: "resource_registration_retirement",
			insert: `INSERT INTO kaname.resource_registration_retirement
 (object_type,object_id,relation,subject,delete_through)
 VALUES ('registry_registry','history-probe','project','project:history-parent',now())`,
			mutations: []struct{ column, set string }{
				{"object_type", "object_type='invalid:type'"},
				{"object_id", "object_id='invalid:id'"},
				{"relation", "relation='reader'"},
				{"subject", "subject=''"},
				{"delete_through", "delete_through='infinity'"},
			},
		},
	} {
		for _, mutation := range table.mutations {
			constraint := table.name + "_" + mutation.column + "_check"
			t.Run(constraint, func(t *testing.T) {
				tx, err := pool.Begin(ctx)
				require.NoError(t, err)
				defer func() { _ = tx.Rollback(ctx) }()
				tag, err := tx.Exec(ctx, table.insert)
				require.NoError(t, err)
				require.EqualValues(t, 1, tag.RowsAffected())
				_, err = tx.Exec(ctx, "UPDATE kaname."+table.name+" SET "+mutation.set+" WHERE object_id='history-probe'")
				var refusal *pgconn.PgError
				require.ErrorAs(t, err, &refusal)
				require.Equal(t, "23514", refusal.Code)
				require.Equal(t, table.name, refusal.TableName)
				require.Equal(t, constraint, refusal.ConstraintName)
				logBuf.Reset()
				mapped := wrapPgErr(refusal, "RegistrationHistory", "history-probe")
				require.ErrorIs(t, mapped, iamerr.ErrInternal)
				require.Equal(t, iamerr.ErrInternal.Error(), mapped.Error())
				require.Contains(t, logBuf.String(), "constraint="+constraint)
				require.Contains(t, logBuf.String(), "table="+table.name)
				require.NotEmpty(t, refusal.Detail)
				require.NotContains(t, logBuf.String(), refusal.Detail)
				require.NotContains(t, logBuf.String(), refusal.Message)
			})
		}
	}
}
