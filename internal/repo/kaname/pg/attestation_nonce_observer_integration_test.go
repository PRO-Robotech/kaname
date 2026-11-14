// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Observer устанавливает только test owner. Это не runtime API и не решение
// об авторизации: перед чтением caller обязан пройти настоящий statement guard.
// Observer ничего не пишет, не вызывает private verifier и показывает только
// nonce текущих backend и транзакции. ACL verifier и temp proof не меняются.
func attestationNonceObserver(t *testing.T, r protocolRig) {
	t.Helper()
	assertPrivate := func() {
		t.Helper()
		var executable bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,'kaname.authority_protocol_attestation()','EXECUTE')`).Scan(&executable))
		require.False(t, executable, "canonical verifier остаётся private для runtime LOGIN")
	}
	assertPrivate()
	_, err := r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_attestation_nonce() RETURNS text
 LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
 DECLARE observed text;
 BEGIN
  SELECT nonce::text INTO STRICT observed
  FROM pg_temp.kaname_authority_attestation
  WHERE backend=pg_backend_pid() AND transaction_id=pg_current_xact_id_if_assigned();
  RETURN observed;
 END $$;
 REVOKE ALL ON FUNCTION kaname.test_attestation_nonce() FROM PUBLIC`)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := r.admin.Exec(ctx, `DROP FUNCTION IF EXISTS kaname.test_attestation_nonce()`)
		require.NoError(t, err)
	})
	_, err = r.admin.Exec(r.ctx, "GRANT EXECUTE ON FUNCTION kaname.test_attestation_nonce() TO "+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	assertPrivate()
}
