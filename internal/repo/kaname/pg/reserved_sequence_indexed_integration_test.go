// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestPreparedSequenceIndexedStoresRejectRuntimeTamper(t *testing.T) {
	for _, probe := range []string{"private-program-write", "private-effects-write"} {
		t.Run(probe, func(t *testing.T) {
			w := metadataFixture(t, false)
			before := metadataSnapshot(t, w)
			changed := w.project
			changed.Description = "private sequence ACL probe"
			writer, err := w.factory.ProjectMetadataWriter(w.r.ctx, changed, []string{"description"}, w.subject(w.actor))
			require.NoError(t, err)
			defer policyFixtureRollback(writer)
			err = kanamepg.MetadataSequenceProbeForTest(w.r.ctx, writer, probe)
			var pe *pgconn.PgError
			require.ErrorAs(t, err, &pe)
			require.Equal(t, "42501", pe.Code)
			require.NoError(t, writer.Rollback(w.r.ctx))
			require.Equal(t, before, metadataSnapshot(t, w))
		})
	}
}

// Owner GIVEN повреждает только private metadata действительного prepared TX.
// Такой injector отсутствует в delivery SQL. Он не выдаёт proof/IDs наружу и
// нужен для независимого отрицательного контроля exact equality после digest.
func TestPreparedSequenceIndexedEffectsRejectCorruptionWithoutHashAuthority(t *testing.T) {
	for _, mode := range []string{"header-nonce", "header-backend", "header-xid", "header-invoker", "pair-oid", "effects-nonce", "digest-only", "duplicate-exact", "unselected", "consumed"} {
		t.Run(mode, func(t *testing.T) {
			w := metadataFixture(t, false)
			_, err := w.r.admin.Exec(w.r.ctx, `CREATE FUNCTION kaname.test_sequence_effect_corrupt_v3(p_mode text) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $fault$
BEGIN
 CASE p_mode
 WHEN 'header-nonce' THEN UPDATE pg_temp.kaname_authority_sequence_program SET nonce='00000000-0000-0000-0000-000000000000'::uuid;
 WHEN 'header-backend' THEN UPDATE pg_temp.kaname_authority_sequence_program SET backend=0;
 WHEN 'header-xid' THEN UPDATE pg_temp.kaname_authority_sequence_program SET transaction_id='0';
 WHEN 'header-invoker' THEN UPDATE pg_temp.kaname_authority_sequence_program SET invoker_oid=0;
 WHEN 'pair-oid' THEN UPDATE pg_temp.kaname_authority_sequence_program SET effects_oid='pg_temp.kaname_authority_sequence_program'::regclass;
 WHEN 'effects-nonce' THEN UPDATE pg_temp.kaname_authority_sequence_effects SET nonce='00000000-0000-0000-0000-000000000000'::uuid;
 WHEN 'digest-only' THEN UPDATE pg_temp.kaname_authority_sequence_effects SET origin=origin||jsonb_build_object('operation','INSERT') WHERE selected;
 WHEN 'duplicate-exact' THEN
  INSERT INTO pg_temp.kaname_authority_sequence_effects(ordinal,nonce,table_name,reserved_id,origin,row_value,origin_digest,row_digest,selected)
  SELECT 100001,e.nonce,e.table_name,9223372036854775807,e.origin,e.row_value,e.origin_digest,e.row_digest,true
   FROM pg_temp.kaname_authority_sequence_effects e WHERE e.selected ORDER BY e.ordinal LIMIT 1;
 WHEN 'unselected' THEN UPDATE pg_temp.kaname_authority_sequence_effects SET selected=false WHERE selected;
 WHEN 'consumed' THEN UPDATE pg_temp.kaname_authority_sequence_effects SET consumed=true WHERE selected;
 ELSE RAISE EXCEPTION 'unknown test corruption';END CASE;
END $fault$;REVOKE ALL ON FUNCTION kaname.test_sequence_effect_corrupt_v3(text) FROM PUBLIC`)
			require.NoError(t, err)
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				_, e := w.r.admin.Exec(cleanup, `DROP FUNCTION kaname.test_sequence_effect_corrupt_v3(text)`)
				require.NoError(t, e)
			})
			_, err = w.r.admin.Exec(w.r.ctx, fmt.Sprintf(`GRANT EXECUTE ON FUNCTION kaname.test_sequence_effect_corrupt_v3(text) TO %s`, pgx.Identifier{w.r.runtime.Config().ConnConfig.User}.Sanitize()))
			require.NoError(t, err)
			full, observed := sequenceObservedFullRepo(t, w.r)
			w.factory, err = kanamepg.NewMetadataMutationWriters(w.r.ctx, full, w.r.bundle)
			require.NoError(t, err)
			before := metadataSnapshot(t, w)
			changed := w.project
			changed.Description = "indexed exact sequence fault"
			writer, err := w.factory.ProjectMetadataWriter(w.r.ctx, changed, []string{"description"}, w.subject(w.actor))
			require.NoError(t, err)
			defer policyFixtureRollback(writer)
			require.NoError(t, kanamepg.MetadataSequenceCorruptForTest(w.r.ctx, writer, mode))
			_, err = writer.ProjectsW().Update(w.r.ctx, changed, []string{"description"})
			require.Error(t, err)
			var pe *pgconn.PgError
			require.ErrorAs(t, observed.last(), &pe)
			require.Equal(t, "42501", pe.Code)
			if mode == "duplicate-exact" {
				require.Equal(t, "ambiguous journal source ordinal", pe.Message)
			}
			if mode == "header-nonce" || mode == "header-backend" || mode == "header-xid" || mode == "header-invoker" || mode == "pair-oid" {
				require.Equal(t, "sequence program transaction changed", pe.Message)
			}
			require.NoError(t, writer.Rollback(w.r.ctx))
			require.Equal(t, before, metadataSnapshot(t, w), "подмена metadata не фиксирует business/audit/journal/fold")
		})
	}
}

// Test owner наблюдает только форму результата, не выдавая private proof/header.
// Spoofed storage при compatibility NULL намеренно не имеет настоящей схемы:
// раннее чтение или проверка storage вместо трёхветочной семантики вызовет отказ.
func TestSequenceFreshProbePreservesNullMissingAndInvalidProof(t *testing.T) {
	r := writerProtocolRig(t)
	_, err := r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_sequence_probe_shape_v3() RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $observer$
DECLARE p jsonb;h jsonb;
BEGIN
 SELECT q.proof,q.header INTO STRICT p,h FROM kaname._authority_sequence_probe_v3() q;
 IF p IS NULL AND h IS NULL THEN RETURN 'null-proof';END IF;
 IF p IS NOT NULL AND h IS NULL THEN RETURN 'no-program';END IF;
 IF p IS NOT NULL AND h IS NOT NULL THEN RETURN 'program';END IF;
 RAISE EXCEPTION 'invalid probe result shape';
END $observer$;REVOKE ALL ON FUNCTION kaname.test_sequence_probe_shape_v3() FROM PUBLIC`)
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, e := r.admin.Exec(cleanup, `DROP FUNCTION kaname.test_sequence_probe_shape_v3()`)
		require.NoError(t, e)
	})
	_, err = r.admin.Exec(r.ctx, "GRANT EXECUTE ON FUNCTION kaname.test_sequence_probe_shape_v3() TO "+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
	// Production helper остаётся закрыт для настоящего LOGIN.
	_, err = r.runtime.Exec(r.ctx, `SELECT * FROM kaname._authority_sequence_probe_v3()`)
	var pe *pgconn.PgError
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "42501", pe.Code)
	var shape string
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.test_sequence_probe_shape_v3()`).Scan(&shape))
	require.Equal(t, "null-proof", shape)
	tx, err := r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(tx)
	_, err = tx.Exec(r.ctx, `CREATE TEMP TABLE kaname_authority_sequence_program(junk integer) ON COMMIT DROP;
 CREATE TEMP TABLE kaname_authority_sequence_effects(junk integer) ON COMMIT DROP`)
	require.NoError(t, err)
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.test_sequence_probe_shape_v3()`).Scan(&shape))
	require.Equal(t, "null-proof", shape)
	require.NoError(t, tx.Rollback(r.ctx))
	attestationLocksetInjector(t, r)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	_, err = r.runtime.Exec(r.ctx, `SELECT kaname.test_sequence_probe_shape_v3()`)
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "42501", pe.Code)
	tx, err = r.runtime.Begin(r.ctx)
	require.NoError(t, err)
	defer attestationLocksetRollback(tx)
	r.enter(t, tx, r.intent(r.a), "decision")
	require.NoError(t, tx.QueryRow(r.ctx, `SELECT kaname.test_sequence_probe_shape_v3()`).Scan(&shape))
	require.Equal(t, "no-program", shape)
	// Предыдущий положительный результат не заменяет следующую fresh attestation.
	_, err = tx.Exec(r.ctx, `SELECT kaname.test_attestation_accounts(ARRAY[$1,$2]::text[],'accounts')`, r.a, "sequence_probe_missing_account")
	require.NoError(t, err)
	_, err = tx.Exec(r.ctx, `SELECT kaname.test_sequence_probe_shape_v3()`)
	require.ErrorAs(t, err, &pe)
	require.Equal(t, "42501", pe.Code)
	require.Equal(t, "authority account barrier missing", pe.Message)
	require.NoError(t, tx.Rollback(r.ctx))
	authorityWaitReleased(t, r.runtime)
}
