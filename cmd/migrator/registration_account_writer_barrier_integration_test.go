// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// Исторические Down остаются исполнимы на прежнем префиксе; после следующего
// настоящего Up тот же CLI обязан сохранить историю и отказать в откате.
func TestRegistrationMigrator_AccountWriterHistoryIsIrreversible(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: PostgreSQL")
	}
	for _, history := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty", true: "retired-assignment"}[history], func(t *testing.T) {
			dsn, db := registrationOriginDBTo(t, "fresh", "20261102130000")
			if history {
				_, err := db.Exec(`INSERT INTO kaname.registration_account_writer_assignment
 (assignment_id,account_id,module,binding_id,removed_at)
 VALUES ('cli-down-history','acc1a18042d81fb438d6','registry','cli-down-binding',clock_timestamp());
 INSERT INTO kaname.registration_account_writer_switch(singleton,cluster_writer_retired_at)
 VALUES(true,clock_timestamp())`)
				require.NoError(t, err)
			}
			snapshot := func() string {
				return registrationScalar(t, db, `SELECT jsonb_build_array(
 (SELECT jsonb_agg(to_jsonb(v) ORDER BY id) FROM goose_db_version v),
 (SELECT jsonb_agg(to_jsonb(a) ORDER BY assignment_id) FROM kaname.registration_account_writer_assignment a),
 (SELECT jsonb_agg(to_jsonb(s) ORDER BY singleton) FROM kaname.registration_account_writer_switch s),
 (SELECT jsonb_agg(to_jsonb(i) ORDER BY singleton) FROM kaname.registration_legacy_cluster_writer_identity i))::text`)
			}
			before := snapshot()
			if history {
				require.Contains(t, before, "cli-down-history")
			}
			for _, args := range [][]string{
				{"down", "--dsn", dsn},
				{"down", "--target", registrationReversibleTip, "--dsn", dsn},
			} {
				_, _, err := runCommandFS(t, migrations.FS, args, nil)
				require.ErrorContains(t, err, "registration account writer history is irreversible")
				var refusal *pgconn.PgError
				require.ErrorAs(t, err, &refusal)
				require.Equal(t, "P0001", refusal.Code)
				require.Equal(t, before, snapshot(), "отказ не меняет данные и журнал миграций")
				if history {
					_, err = db.Exec(`UPDATE kaname.groups SET name=name WHERE id='grp258e6bbe9bbe45568'`)
					require.ErrorAs(t, err, &refusal)
					require.Equal(t, "registration_legacy_seed_namespace_retired", refusal.ConstraintName)
				}
			}
		})
	}
}
