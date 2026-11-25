// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestExternalAccessLabelPendingKeepsCompositeRootWithoutMirror(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	const id = "external-generation/opaque%2Fid"

	// Владелец фикстуры оставляет открытое поколение без строки ресурса и
	// выходных фактов. Наблюдение должно находить именно составной корень.
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_dirty_root
 (root_type,root_id,generation,new_labels) VALUES ('vpc.network',$1,gen_random_uuid(),'{}')`, id)
	require.NoError(t, err)

	read := func(model string, rowsLimit, readsLimit int) (bool, int, int, error) {
		t.Helper()
		tx, err := r.runtime.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		require.NoError(t, err)
		defer tx.Rollback(r.ctx)
		var pending bool
		var rows, reads int
		err = tx.QueryRow(r.ctx, `SELECT pending,logical_rows,logical_reads
 FROM kaname.authority_resource_reconcile_pending_v1($1,$2,$3,$4)`, model, id, rowsLimit, readsLimit).
			Scan(&pending, &rows, &reads)
		return pending, rows, reads, err
	}

	pending, rows, reads, err := read("vpc_network", 3, 3)
	require.NoError(t, err)
	require.True(t, pending)
	require.Equal(t, 3, rows)
	require.Equal(t, 3, reads)

	pending, rows, reads, err = read("compute_instance", 2, 4)
	require.NoError(t, err)
	require.False(t, pending)
	require.Equal(t, 2, rows)
	require.Equal(t, 4, reads)

	_, _, _, err = read("vpc_network", 3, 2)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "54000", pgErr.Code)
}

func TestExternalAccessLabelProjectionKeepsRetiredAliasAndDependentOutput(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	const rootType, id, dependent = "vpc.oldNetworkForGeneration", "generation/net%2F", "generation-output"
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.catalog_resource
 (module,resource,dotted,object_type,live,retired_at)
 VALUES ('vpc','oldNetworkForGeneration',$1,'vpc_network',false,'2000-01-01T00:00:00Z')`, rootType)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_dirty_root
 (root_type,root_id,generation,new_labels) VALUES ($1,$2,gen_random_uuid(),'{}')`, rootType, id)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.authority_access_label_dirty_fact
 (root_type,root_id,generation,object_type,object_id,relation,subject)
 SELECT root_type,root_id,generation,'project',$3,'viewer','user:external-generation'
 FROM kaname.authority_access_label_dirty_root WHERE root_type=$1 AND root_id=$2`, rootType, id, dependent)
	require.NoError(t, err)

	observe := func(model, object string, wantRows, wantReads int) string {
		t.Helper()
		tx, err := r.runtime.BeginTx(r.ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
		require.NoError(t, err)
		defer tx.Rollback(r.ctx)
		var fingerprint string
		var roots, outputs [][]string
		var rows, reads int
		require.NoError(t, tx.QueryRow(r.ctx, `SELECT fingerprint,roots,outputs,logical_rows,logical_reads
 FROM kaname.authority_resource_generation_observe_v1($1,$2,$3,$4)`, model, object, wantRows, wantReads).
			Scan(&fingerprint, &roots, &outputs, &rows, &reads))
		require.Len(t, fingerprint, 64)
		require.Equal(t, [][]string{{rootType, id}}, roots)
		require.Equal(t, [][]string{{"project", dependent}}, outputs)
		require.Equal(t, wantRows, rows)
		require.Equal(t, wantReads, reads)
		return fingerprint
	}

	// Живой тип разрешается, но ожидающее поколение относится к снятому
	// имени. Оно видно и от исходного ресурса, и от затронутого проекта.
	fingerprint := observe("vpc_network", id, 8, 9)
	observe("project", dependent, 4, 6)
	_, err = r.admin.Exec(r.ctx, `UPDATE kaname.catalog_resource SET retired_reason='fixture'
 WHERE dotted=$1 AND NOT live`, rootType)
	require.NoError(t, err)
	require.NotEqual(t, fingerprint, observe("vpc_network", id, 8, 9),
		"изменение физической версии снятого элемента каталога меняет снимок")
}
