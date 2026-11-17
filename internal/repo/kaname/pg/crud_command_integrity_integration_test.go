// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"testing"
)

func sevenCRUDCommandSnapshot(t *testing.T, r protocolRig) string {
	t.Helper()
	var snapshot string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT jsonb_build_object(
 'projects',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY id),'[]'::jsonb) FROM kaname.projects v),
 'audit',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY id),'[]'::jsonb) FROM kaname.audit_outbox v),
 'fga',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY id),'[]'::jsonb) FROM kaname.fga_outbox v),
 'facts',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY to_jsonb(v)::text),'[]'::jsonb) FROM kaname.relation_fact v),
 'journal',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY sequence_no),'[]'::jsonb) FROM kaname.resource_journal v),
 'reconcile',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY id),'[]'::jsonb) FROM kaname.resource_reconcile_outbox v),
 'bindings',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY id),'[]'::jsonb) FROM kaname.access_bindings v),
 'ledger',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY to_jsonb(v)::text),'[]'::jsonb) FROM kaname.access_binding_emitted_tuples v),
 'quota',(SELECT coalesce(jsonb_agg(to_jsonb(v) ORDER BY to_jsonb(v)::text),'[]'::jsonb) FROM kaname.project_resource_quotas v)
 )::text`).Scan(&snapshot))
	return snapshot
}

func TestSevenCRUDPrivateCommandCannotCommitOmittedPartialReplayedOrWrongEffects(t *testing.T) {
	for _, probe := range []string{"omitted", "partial", "replay", "wrong-request", "out-of-order", "claim-again", "wrong-origin", "unplanned-journal"} {
		t.Run(probe, func(t *testing.T) {
			f := sevenCRUDPublicFixture(t, "project.create", "")
			before := sevenCRUDCommandSnapshot(t, f.r)
			writer, err := f.factory.ProjectCreateWriter(f.ctx, f.project, domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(f.actor)})
			require.NoError(t, err)
			defer writer.Rollback(f.ctx)
			switch probe {
			case "omitted":
				err = kanamepg.CRUDCommandProbeForTest(f.ctx, writer, "commit")
			case "partial", "replay":
				_, err = writer.ProjectsW().Insert(f.ctx, f.project)
				require.NoError(t, err)
				if probe == "partial" {
					err = kanamepg.CRUDCommandProbeForTest(f.ctx, writer, "commit")
				} else {
					_, err = writer.ProjectsW().Insert(f.ctx, f.project)
				}
			case "wrong-request":
				changed := f.project
				changed.Name += "_different"
				_, err = writer.ProjectsW().Insert(f.ctx, changed)
			case "out-of-order":
				err = writer.EmitFGARelationWrite(f.ctx, []service.RelationTuple{})
			default:
				err = kanamepg.CRUDCommandProbeForTest(f.ctx, writer, probe)
			}
			var pe *pgconn.PgError
			require.ErrorAs(t, err, &pe)
			require.Equal(t, "42501", pe.Code)
			// Ошибка statement оставляет TX aborted; явный rollback обязателен перед
			// внешним снимком. Deferred commit уже откатил TX, повторный rollback harmless.
			_ = writer.Rollback(f.ctx)
			require.Equal(t, before, sevenCRUDCommandSnapshot(t, f.r), "ни доменный, ни journal/audit/fold эффект не переживает отказ")
		})
	}
}
