// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/authorityprotocol"
	"github.com/stretchr/testify/require"
)

func fullContractActivate(t *testing.T, r protocolRig) (*kanamepg.Repository, *kanamepg.FullWriterContract) {
	t.Helper()
	require.NoError(t, lifecycleOwner(r).StageFullAuthorityBundle(r.ctx, r.bundle))
	require.NoError(t, lifecycleOwner(r).ActivateFullAuthorityBundle(r.ctx, r.bundle))
	contract, err := kanamepg.NewFullWriterContract(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	full, err := r.repo.WithFullWriterContract(contract)
	require.NoError(t, err)
	return full, contract
}

func TestFullWriterContractSameBundleExcludesAlreadyRunningStagedRepo(t *testing.T) {
	r := writerProtocolRig(t)
	// The old object remains alive across real owner activation; no projector bump.
	staged := r.repo
	require.NoError(t, staged.ValidateStagedWriterContract(r.ctx))
	old, err := staged.ParticipantAuthorityWriter(r.ctx, r.intent(r.a))
	require.NoError(t, err)
	require.NoError(t, old.Rollback(r.ctx))
	before := r.bundle.Identity()
	full, contract := fullContractActivate(t, r)
	require.Equal(t, before, r.bundle.Identity())
	require.Error(t, staged.ValidateStagedWriterContract(r.ctx))
	old, err = staged.ParticipantAuthorityWriter(r.ctx, r.intent(r.a))
	require.Error(t, err)
	require.Nil(t, old)
	// The new binary's default repository also remains on generation1.
	old, err = kanamepg.New(r.runtime, nil).ParticipantAuthorityWriter(contract.Context(r.ctx), r.intent(r.a))
	require.Error(t, err, "installation context must not upgrade an ordinary repository")
	require.Nil(t, old)
	current, err := full.ParticipantAuthorityWriter(r.ctx, r.intent(r.a))
	require.NoError(t, err)
	lifecycleWriterCleanup(t, current)
	group := domain.Group{ID: "grp-full-contract", AccountID: domain.AccountID(r.a), Name: "full-contract"}
	_, err = current.GroupsW().Insert(r.ctx, group)
	require.NoError(t, err)
	require.NoError(t, current.Commit(r.ctx))
	var exists bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.groups WHERE id=$1)`, string(group.ID)).Scan(&exists))
	require.True(t, exists)
	require.NoError(t, lifecycleOwner(r).CloseAuthorityBundle(r.ctx))
	denied, err := full.ParticipantAuthorityWriter(r.ctx, r.intent(r.a))
	require.Error(t, err)
	require.Nil(t, denied)
	require.Error(t, lifecycleOwner(r).StageAuthorityBundle(r.ctx, r.bundle), "cannot downgrade full contract")
}

func TestFullWriterContractOldEntryFamiliesRefuseWithoutEffects(t *testing.T) {
	r := writerProtocolRig(t)
	_, contract := fullContractActivate(t, r)
	id := r.bundle.Identity()
	cases := []struct {
		name, query string
		args        []any
	}{
		{"typed", `SELECT kaname.authority_protocol_enter_typed_v2('global',ARRAY[]::text[],'[]'::jsonb,'group',$1,$2,$3,'participant')`, []any{id.ModelID, id.CatalogID, id.ProjectorVersion}},
		{"full", `SELECT kaname.authority_protocol_enter_full_v2('global',ARRAY[]::text[],'[]'::jsonb,'binding',$1,$2,$3,'decision','{"generation":"1","count":1,"revision":"0"}'::jsonb)`, []any{id.ModelID, id.CatalogID, id.ProjectorVersion}},
		{"resource", `SELECT kaname.authority_resource_enter_v2('global',ARRAY[]::text[],'[]'::jsonb,$1,$2,$3)`, []any{id.ModelID, id.CatalogID, id.ProjectorVersion}},
		{"resource-source", `SELECT kaname.authority_resource_source_enter_v2('global',ARRAY[]::text[],'[]'::jsonb,$1,$2,$3)`, []any{id.ModelID, id.CatalogID, id.ProjectorVersion}},
		{"installation-auto-identity", `SELECT kaname.authority_installation_enter_v2('cluster')`, nil},
	}
	var before string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT description FROM kaname.accounts WHERE id=$1`, r.a).Scan(&before))
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tx, err := r.runtime.Begin(r.ctx)
			require.NoError(t, err)
			lifecycleRollback(t, tx)
			_, err = tx.Exec(r.ctx, c.query, c.args...)
			require.Error(t, err)
			_, err = tx.Exec(r.ctx, `UPDATE kaname.accounts SET description='forbidden old writer' WHERE id=$1`, r.a)
			require.Error(t, err)
			require.NoError(t, tx.Rollback(r.ctx))
		})
	}
	var after string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT description FROM kaname.accounts WHERE id=$1`, r.a).Scan(&after))
	require.Equal(t, before, after)
	old, err := authorityprotocol.OpenParticipant(r.ctx, r.runtime, kaname.AuthorityCluster)
	require.Error(t, err)
	require.Nil(t, old)
	current, err := authorityprotocol.OpenParticipant(contract.Context(r.ctx), r.runtime, kaname.AuthorityCluster)
	require.NoError(t, err)
	lifecycleRollback(t, current)
	_, err = current.Exec(r.ctx, `UPDATE kaname.accounts SET description='full maintenance' WHERE id=$1`, r.a)
	require.NoError(t, err)
	require.NoError(t, current.Commit(r.ctx))
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT description FROM kaname.accounts WHERE id=$1`, r.a).Scan(&after))
	require.Equal(t, "full maintenance", after)
}

func TestFullWriterContractAllNewEntryProfilesStayOperational(t *testing.T) {
	r := writerProtocolRig(t)
	full, _ := fullContractActivate(t, r)
	id := r.bundle.Identity()
	// This probes admission only; Resource body/final-clock proofs remain covered
	// by the existing real producer suites and are never replaced by these entries.
	queries := []string{
		`SELECT kaname.authority_protocol_enter_typed_v3('global',ARRAY[]::text[],'[]'::jsonb,'group',$1,$2,$3,'participant')`,
		`SELECT kaname.authority_protocol_enter_full_v3('global',ARRAY[]::text[],'[]'::jsonb,'binding',$1,$2,$3,'decision','{"generation":"1","count":1,"revision":"0"}'::jsonb)`,
		`SELECT kaname.authority_resource_enter_v3('global',ARRAY[]::text[],'[]'::jsonb,$1,$2,$3)`,
		`SELECT kaname.authority_resource_source_enter_v3('global',ARRAY[]::text[],'[]'::jsonb,$1,$2,$3)`,
	}
	for _, query := range queries {
		tx, err := r.runtime.Begin(r.ctx)
		require.NoError(t, err)
		lifecycleRollback(t, tx)
		_, err = tx.Exec(r.ctx, query, id.ModelID, id.CatalogID, id.ProjectorVersion)
		require.NoError(t, err)
		require.NoError(t, tx.Rollback(r.ctx))
	}
	// Shared full repository reaches each existing factory without changing its API.
	_, err := kanamepg.NewGrantPolicyWriters(r.ctx, full, r.bundle)
	require.NoError(t, err)
	groups, err := kanamepg.NewGroupMembershipParticipant(r.ctx, full, r.bundle)
	require.NoError(t, err)
	require.NotNil(t, groups)
	_, err = kanamepg.NewHumanAdmissionParticipant(r.ctx, full, r.bundle)
	require.NoError(t, err)
	_, err = kanamepg.NewClusterAdminParticipant(r.ctx, full, r.bundle)
	require.NoError(t, err)
	_, err = kanamepg.NewResourceObjectParticipant(r.ctx, full, r.bundle)
	require.NoError(t, err)
	_, err = kanamepg.NewGrantDelegationParticipant(r.ctx, full, r.bundle)
	require.NoError(t, err)
	_, err = kanamepg.NewInviteDecisionRunner(r.ctx, full, r.bundle)
	require.NoError(t, err)
}

func TestFullWriterContractQueuedOldWriterRechecksAfterActivation(t *testing.T) {
	r := writerProtocolRig(t)
	require.NoError(t, lifecycleOwner(r).StageFullAuthorityBundle(r.ctx, r.bundle))
	// Owner holds the actual activation barrier; the old process queues behind it.
	owner, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, owner)
	_, err = owner.Exec(r.ctx, `SELECT kaname.authority_protocol_drain()`)
	require.NoError(t, err)
	done := lifecycleAsync(t, r.ctx, func(ctx context.Context) error {
		w, e := r.repo.ParticipantAuthorityWriter(ctx, r.intent(r.a))
		if w != nil {
			_ = w.Rollback(ctx)
		}
		return e
	})
	receiptWaitForBlocker(t, r.ctx, r.admin, int(owner.Conn().PgConn().PID()))
	id := r.bundle.Identity()
	_, err = owner.Exec(r.ctx, `SELECT kaname.authority_protocol_activate_full_v3($1,$2,$3)`, id.ModelID, id.CatalogID, id.ProjectorVersion)
	require.NoError(t, err)
	require.NoError(t, owner.Commit(r.ctx))
	require.Error(t, lifecycleResult(t, r.ctx, done))
	require.NoError(t, lifecycleOwner(r).ValidateFullAuthorityBundle(r.ctx, r.bundle))
}

func TestFullWriterContractActivationDrainsAlreadySignedOldTransaction(t *testing.T) {
	r := writerProtocolRig(t)
	require.NoError(t, lifecycleOwner(r).StageFullAuthorityBundle(r.ctx, r.bundle))
	old, err := r.repo.ParticipantAuthorityWriter(r.ctx, r.intent(r.a))
	require.NoError(t, err)
	lifecycleWriterCleanup(t, old)
	done := lifecycleAsync(t, r.ctx, func(ctx context.Context) error { return lifecycleOwner(r).ActivateFullAuthorityBundle(ctx, r.bundle) })
	var oldPID int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT pid FROM pg_locks WHERE locktype='advisory' AND classid=1262569281::oid AND objid=(hashtext($1)::bigint & 4294967295)::oid AND objsubid=2 AND granted AND mode='ExclusiveLock'`, r.a).Scan(&oldPID))
	receiptWaitForBlocker(t, r.ctx, r.admin, oldPID)
	require.NoError(t, old.Rollback(r.ctx))
	require.NoError(t, lifecycleResult(t, r.ctx, done))
	denied, err := r.repo.ParticipantAuthorityWriter(r.ctx, r.intent(r.a))
	require.Error(t, err)
	require.Nil(t, denied)
}

func TestFullWriterContractReadinessFailsOnExactBodyMutation(t *testing.T) {
	r := writerProtocolRig(t)
	_, _ = fullContractActivate(t, r)
	var body string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT prosrc FROM pg_proc WHERE oid='kaname.authority_installation_enter_v3(text,text,text,text)'::regprocedure`).Scan(&body))
	changed := strings.Replace(body, "RETURN 3;", "RETURN 2;", 1)
	require.NotEqual(t, body, changed)
	_, err := r.admin.Exec(r.ctx, `CREATE OR REPLACE FUNCTION kaname.authority_installation_enter_v3(p_kind text,p_model text,p_catalog text,p_projector text) RETURNS integer LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $contract$`+changed+`$contract$`)
	require.NoError(t, err)
	_, err = kanamepg.NewFullWriterContract(r.ctx, r.repo, r.bundle)
	require.Error(t, err)
	// No actor payload or free GUC can repair the pinned function graph.
	_, err = r.runtime.Exec(r.ctx, `SELECT set_config('kaname.full_writer_contract','2',false)`)
	require.NoError(t, err)
	_, err = kanamepg.NewFullWriterContract(r.ctx, r.repo, r.bundle)
	require.Error(t, err)
}

func TestFullWriterContractExplicitSelectionPreparedAndGenerationOne(t *testing.T) {
	r := writerProtocolRig(t)
	_, err := kanamepg.NewFullWriterContract(r.ctx, r.repo, r.bundle)
	require.Error(t, err, "prepared is not full active")
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	_, err = kanamepg.NewFullWriterContract(r.ctx, r.repo, r.bundle)
	require.Error(t, err, "generation1 active is not generation2")
	w, err := r.repo.ParticipantAuthorityWriter(r.ctx, r.intent(r.a))
	require.NoError(t, err)
	require.NoError(t, w.Rollback(r.ctx))
	require.NoError(t, lifecycleOwner(r).CloseAuthorityBundle(r.ctx))
	require.NoError(t, lifecycleOwner(r).StageFullAuthorityBundle(r.ctx, r.bundle))
	require.Error(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle), "ordinary activate cannot activate a full stage")
	require.NoError(t, lifecycleOwner(r).ActivateFullAuthorityBundle(r.ctx, r.bundle))
	_, err = kanamepg.NewFullWriterContract(r.ctx, lifecycleOwner(r), r.bundle)
	require.Error(t, err, "owner is never an ordinary runtime LOGIN")
	var allowed bool
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT kaname.authority_full_contract_validate_v3($1,$2,$3)`, r.bundle.Identity().ModelID+"wrong", r.bundle.Identity().CatalogID, r.bundle.Identity().ProjectorVersion).Scan(&allowed))
	require.False(t, allowed)
	for _, signature := range []string{
		"_authority_protocol_enter_contract_v3(text,text[],jsonb,text,text,text,text,integer,text,integer)",
		"_authority_consumer_enter_contract_v3(text,text[],jsonb,text,text,text,text,text,text,jsonb,integer)",
		"_authority_full_contract_storage_v3()",
		"authority_protocol_activate_full_v3(text,text,text)",
	} {
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_function_privilege(current_user,$1,'EXECUTE')`, "kaname."+signature).Scan(&allowed))
		require.False(t, allowed, signature)
	}
	require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT has_table_privilege(current_user,'kaname.authority_writer_contract','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')`).Scan(&allowed))
	require.False(t, allowed)
}

func TestFullWriterContractReadinessRequiresActualStatementAndRowGuards(t *testing.T) {
	for _, guard := range []string{"authority_protocol_statement", "authority_protocol_row"} {
		t.Run(guard, func(t *testing.T) {
			r := writerProtocolRig(t)
			_, _ = fullContractActivate(t, r)
			_, err := r.admin.Exec(r.ctx, `ALTER TABLE kaname.group_members DISABLE TRIGGER `+guard)
			require.NoError(t, err)
			_, err = kanamepg.NewFullWriterContract(r.ctx, r.repo, r.bundle)
			require.Error(t, err)
		})
	}
}
