// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/stretchr/testify/require"
)

// Настоящий public UC получает те же full repository и context, что startup.
// Успех конструктора не заменяет исполнения InviteUser и CreateMembership.
func inviteFullContractFixture(t *testing.T, membership, optional bool) (inviteDecisionFixture, domain.Email, string) {
	t.Helper()
	f := newInviteDecisionFixture(t)
	email := domain.Email("full-invite-" + ids.NewID("tst") + "@example.invalid")
	var foreign string
	if membership {
		foreign = seedMemberUser(t, f.r.ctx, f.r.admin, f.r.b, "full-invite-foreign")
		require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT email FROM kaname.users WHERE id=$1`, foreign).Scan(&email))
	}
	var capability domain.RoleID
	if optional {
		capability = inviteCoverageHolder(t, f)
	}
	full, contract := fullContractActivate(t, f.r)
	f.r.repo = full
	f.r.ctx = contract.Context(f.r.ctx)
	var version, writerVersion, requiredContract, stagedContract int
	var phase, enforcement string
	require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT a.protocol_version,p.protocol_version,a.phase,p.enforcement,c.required_contract,c.staged_contract FROM kaname.authority_semantic_identity a JOIN kaname.authority_writer_protocol p USING(singleton) JOIN kaname.authority_writer_contract c USING(singleton) WHERE a.singleton`).Scan(&version, &writerVersion, &phase, &enforcement, &requiredContract, &stagedContract))
	// Полный контракт меняет поколение writer, сохраняя версию протокола.
	require.Equal(t, 1, version)
	require.Equal(t, 1, writerVersion)
	require.Equal(t, 2, requiredContract)
	require.Equal(t, 2, stagedContract)
	require.Equal(t, "active", phase)
	require.Equal(t, "strict", enforcement)
	var err error
	f.runner, err = kanamepg.NewInviteDecisionRunner(f.r.ctx, full, f.r.bundle)
	require.NoError(t, err)
	resources, err := kanamepg.NewResourceObjectParticipant(f.r.ctx, full, f.r.bundle)
	require.NoError(t, err)
	objects, err := resources.NewObjectReconciler(slog.Default())
	require.NoError(t, err)
	require.NoError(t, objects.WithStagedBindingReconciler(withdrawalParticipant(t, f.r, nil)))
	native := delegationNativeDoor{r: f.r}
	f.uc = userapp.NewInviteUserUseCase(full, f.ops, native).WithInviteDecisions(f.runner).WithInviteTTL(time.Hour).WithInviteMailRateLimit(outboxtypes.InviteMailRateLimit{MaxPerWindow: 5, Window: time.Hour}, nil).WithObjectReconciler(objects)
	if optional {
		invitePromoteCoverage(t, f, capability)
	}
	return f, email, foreign
}

func TestInviteDecisionFullContractPublicDoors(t *testing.T) {
	for _, membership := range []bool{false, true} {
		for _, optional := range []bool{false, true} {
			t.Run(fmt.Sprintf("membership_%v_optional_%v", membership, optional), func(t *testing.T) {
				f, email, foreign := inviteFullContractFixture(t, membership, optional)
				op := f.execute(t, email, membership, optional)
				require.Nil(t, awaitDelegatedOperation(t, f.r.ctx, f.ops, op.ID).Error)
				var uid, state, home string
				var queued int
				require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT u.id,m.state,u.account_id,(SELECT count(*) FROM kaname.invite_mail_outbox WHERE payload->>'user_id'=u.id) FROM kaname.users u JOIN kaname.memberships m ON m.user_id=u.id AND m.account_id=$2 WHERE lower(u.email)=lower($1)`, string(email), f.r.a).Scan(&uid, &state, &home, &queued))
				require.NotEmpty(t, uid)
				if membership {
					require.Equal(t, foreign, uid)
					require.Equal(t, "ACTIVE", state)
					require.Equal(t, f.r.b, home)
					require.Zero(t, queued)
				} else {
					require.Equal(t, "PENDING", state)
					require.Equal(t, f.r.a, home)
					require.Equal(t, 1, queued)
					var journal, fga, reconcileCount int
					require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT (SELECT count(*) FROM kaname.resource_journal WHERE resource_id=$1),(SELECT count(*) FROM kaname.fga_outbox WHERE payload->>'object'='iam_user:'||$1),(SELECT count(*) FROM kaname.resource_reconcile_outbox WHERE object_type='iam.user' AND object_id=$1)`, uid).Scan(&journal, &fga, &reconcileCount))
					require.Positive(t, journal)
					require.Positive(t, fga)
					require.Positive(t, reconcileCount)
				}
				if optional {
					var count int
					require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT count(*) FROM kaname.access_bindings WHERE subject_type='user' AND subject_id=$1 AND role_id=$2 AND resource_id=$3 AND status='ACTIVE' AND grant_capability_version=1`, uid, f.role, f.project).Scan(&count))
					require.Equal(t, 1, count)
				}
				authorityWaitReleased(t, f.r.runtime)
			})
		}
	}
}
