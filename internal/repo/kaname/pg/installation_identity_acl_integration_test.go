// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"
	"time"

	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/authorityprotocol"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestInstallationEntryPreservesInvokerIdentityReadACL(t *testing.T) {
	for _, strict := range []bool{false, true} {
		name := "prepared"
		if strict {
			name = "strict"
		}
		t.Run(name, func(t *testing.T) {
			r := identityLifecycleSingle(t, writerProtocolRig(t))
			if strict {
				require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
			}
			positive := func() {
				tx, err := authorityprotocol.OpenParticipant(r.ctx, r.runtime, kaname.AuthorityCatalog)
				require.NoError(t, err)
				require.NotNil(t, tx)
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), 5*time.Second)
				defer cancel()
				require.NoError(t, tx.Rollback(cleanup))
			}
			positive()
			quoted := pgx.Identifier{r.role}.Sanitize()
			_, err := r.admin.Exec(r.ctx, "REVOKE SELECT ON kaname.authority_semantic_identity FROM "+quoted)
			require.NoError(t, err)
			var readable, executable bool
			require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_table_privilege(current_user,'kaname.authority_semantic_identity','SELECT'),has_function_privilege(current_user,'kaname.authority_installation_enter_v2(text)','EXECUTE')`).Scan(&readable, &executable))
			require.False(t, readable)
			require.True(t, executable, "отказ проверяет SELECT, не потерю EXECUTE")
			// ACCESS EXCLUSIVE заставил бы любой owner SELECT ждать. Отказ 42501
			// обязан возникнуть до такого чтения и до row/coordinator locks.
			holder, err := r.admin.Begin(r.ctx)
			require.NoError(t, err)
			defer func() {
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), 5*time.Second)
				defer cancel()
				_ = holder.Rollback(cleanup)
			}()
			_, err = holder.Exec(r.ctx, `LOCK TABLE kaname.authority_semantic_identity IN ACCESS EXCLUSIVE MODE`)
			require.NoError(t, err)
			bounded, cancel := context.WithTimeout(r.ctx, 2*time.Second)
			denied, err := authorityprotocol.OpenParticipant(bounded, r.runtime, kaname.AuthorityCatalog)
			cancel()
			require.Nil(t, denied)
			var pgerr *pgconn.PgError
			require.ErrorAs(t, err, &pgerr)
			require.Equal(t, "42501", pgerr.Code)
			require.NoError(t, holder.Rollback(r.ctx))
			_, err = r.admin.Exec(r.ctx, "GRANT SELECT ON kaname.authority_semantic_identity TO "+quoted)
			require.NoError(t, err)
			positive()
		})
	}
}
