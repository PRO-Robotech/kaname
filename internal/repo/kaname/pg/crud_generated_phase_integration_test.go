// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

// Actual FK SET NULL с полным AFTER-образом выполняет AccountDeletePublic.
// Здесь owner напрямую проверяет отрицательные ветви private codec: это не
// runtime authority и не способ выдать caller manifest. EXECUTE не выдаётся.
func TestSevenCRUDUsersGeneratedPhaseRejectsBeforeAndAfterMismatch(t *testing.T) {
	r := writerProtocolRig(t)
	before := sevenCRUDCommandSnapshot(t, r)
	for _, probe := range []string{"before-missing", "before-stored-value", "before-other-field", "after-null", "after-other-value", "after-applied-null", "after-applied-other-value"} {
		t.Run(probe, func(t *testing.T) {
			tx, err := r.admin.Begin(r.ctx)
			require.NoError(t, err)
			defer func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_ = tx.Rollback(cleanup)
			}()
			_, err = tx.Exec(r.ctx, strings.ReplaceAll(`DO $probe$
DECLARE old_row jsonb:='{"id":"usr_phase","account_id":"acc_phase","invite_status":"ACTIVE","recovery_path_opened_at":null,"expected_login_kind":"password"}';
 new_row jsonb;actual_row jsonb;manifest jsonb;probe text:='PROBE_LITERAL';
BEGIN
 new_row:=old_row||jsonb_build_object('account_id',NULL);
 manifest:=jsonb_build_object('object_command',1,'writes',jsonb_build_array(jsonb_build_object(
  'command',1,'table','users','operation','UPDATE','old',old_row,'new',new_row)));
 actual_row:=new_row||jsonb_build_object('expected_login_kind',NULL);
 IF probe='before-missing' THEN actual_row:=actual_row-'expected_login_kind';
 ELSIF probe='before-stored-value' THEN actual_row:=new_row;
 ELSIF probe='before-other-field' THEN actual_row:=actual_row||jsonb_build_object('invite_status','BLOCKED');
 ELSIF probe IN ('after-other-value','after-applied-other-value') THEN actual_row:=actual_row||jsonb_build_object('expected_login_kind','invalid');
 END IF;
 IF probe LIKE 'before-%' THEN PERFORM kaname._authority_resource_before_write_v3(manifest,'users','UPDATE',old_row,actual_row);
 ELSIF probe LIKE 'after-applied-%' THEN PERFORM kaname._authority_resource_write_v2(manifest,'users','UPDATE',old_row,actual_row);
 ELSE PERFORM kaname._authority_resource_side_v2(manifest,'users','UPDATE','new',actual_row);END IF;
END $probe$;`, "PROBE_LITERAL", probe))
			var pe *pgconn.PgError
			require.ErrorAs(t, err, &pe)
			require.Equal(t, "42501", pe.Code)
			expectedMessage := "resource transition absent from private manifest"
			if probe == "before-missing" || probe == "before-stored-value" {
				expectedMessage = "unexpected users generated column BEFORE phase"
			}
			if probe == "before-other-field" || strings.HasPrefix(probe, "after-applied-") {
				expectedMessage = "resource row absent from private manifest"
			}
			require.Equal(t, expectedMessage, pe.Message)
			require.NoError(t, tx.Rollback(r.ctx))
			require.Equal(t, before, sevenCRUDCommandSnapshot(t, r))
		})
	}
}
