// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"testing"

	bindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Ordinary D1/D3 Create не получает разрешение от исправления D5 статуса.
// Последний recipient имеет существующий SA ID, но отсутствующий user тип;
// первый правильный recipient не скрывает отказ полного Subjects набора.
func TestBindingCreateMissingTypedRecipientDenied(t *testing.T) {
	w := delegationUCFixture(t)
	seed := stageBinding(t, w.r, w.r.a, false)
	template := bindingRow(t, w.r, seed)
	w.grantAdmin(t)
	var serviceAccounts, users int
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT (SELECT count(*) FROM kaname.service_accounts WHERE id=$1),(SELECT count(*) FROM kaname.users WHERE id=$1)`, w.input.DelegateID).Scan(&serviceAccounts, &users))
	require.Equal(t, 1, serviceAccounts)
	require.Zero(t, users)
	// Настоящий typed epoch key отсутствует: без RR negative этот exact
	// metadata запрос даёт 40001 ещё до позднего recipient preflight.
	var token []byte
	missingGuard := w.r.runtime.QueryRow(w.r.ctx, `SELECT kaname.authority_policy_epoch_read($1::text[])`, []string{"*", "user:" + w.input.DelegateID}).Scan(&token)
	var pgerr *pgconn.PgError
	require.ErrorAs(t, missingGuard, &pgerr)
	require.Equal(t, "40001", pgerr.Code)
	require.Equal(t, "policy guard missing", pgerr.Message)
	writers, err := kanamepg.NewGrantPolicyWriters(w.r.ctx, w.r.repo, w.r.bundle)
	require.NoError(t, err)
	require.NoError(t, lifecycleOwner(w.r).ActivateAuthorityBundle(w.r.ctx, w.r.bundle))
	uc := bindingapp.NewCreateAccessBindingUseCase(w.r.repo, w.ops, w.source).WithBindingDecisions(writers)
	valid := domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(w.input.DelegateID)}
	input := domain.AccessBinding{RoleID: template.RoleID, ResourceType: "account", ResourceID: w.r.a, Scope: domain.ScopeAccount, Subjects: []domain.Subject{valid, {Type: domain.SubjectTypeUser, ID: valid.ID}}, Target: domain.AccessTarget{AllInScope: true}}
	op, err := uc.Execute(declarerCtx(w.r.ctx, w.member), input)
	require.Nil(t, op)
	require.Equal(t, codes.PermissionDenied, status.Code(err), "отсутствующий typed recipient не является исчерпанием classification retries")
	var created int
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.access_bindings WHERE role_id=$1 AND subject_id=$2`, template.RoleID, valid.ID).Scan(&created))
	require.Zero(t, created)
	authorityWaitReleased(t, w.r.runtime)
	// Тот же существующий principal с правильным типом проходит настоящий UC.
	input.Subjects = []domain.Subject{valid}
	op, err = uc.Execute(declarerCtx(w.r.ctx, w.member), input)
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, w.r.ctx, w.ops, op.ID).Error)
	var version int
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*),max(grant_capability_version) FROM kaname.access_bindings WHERE role_id=$1 AND subject_type='service_account' AND subject_id=$2`, template.RoleID, valid.ID).Scan(&created, &version))
	require.Equal(t, 1, created)
	require.Equal(t, 1, version)
	authorityWaitReleased(t, w.r.runtime)
}
