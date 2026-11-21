// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grant_delegation

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	repogd "github.com/PRO-Robotech/kaname/internal/repo/kaname/grant_delegation"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type delegationFactoryProbe struct {
	w        *delegationProbeWriter
	err      error
	kinds    []kaname.GrantDelegationMutation
	proposed []domain.GrantDelegation
}

func (p *delegationFactoryProbe) GrantDelegationWriter(_ context.Context, k kaname.GrantDelegationMutation, d domain.GrantDelegation) (kaname.Writer, error) {
	p.kinds = append(p.kinds, k)
	p.proposed = append(p.proposed, d)
	return p.w, p.err
}

type delegationProbeWriter struct {
	kaname.Writer
	commits, rollbacks, inserts, audits int
	auditErr                            error
}

func (w *delegationProbeWriter) AccessBindingsW() repoab.WriterIface { return delegationProbeAB{w: w} }
func (w *delegationProbeWriter) EmitAuditEvent(context.Context, outboxtypes.AuditEvent) error {
	w.audits++
	return w.auditErr
}
func (w *delegationProbeWriter) Commit(context.Context) error   { w.commits++; return nil }
func (w *delegationProbeWriter) Rollback(context.Context) error { w.rollbacks++; return nil }

type delegationProbeAB struct {
	repoab.WriterIface
	w *delegationProbeWriter
}

func (w delegationProbeAB) GrantDelegationsW() repogd.WriterIface { return delegationProbeGD{w: w.w} }

type delegationProbeGD struct {
	repogd.WriterIface
	w *delegationProbeWriter
}

func (w delegationProbeGD) Insert(_ context.Context, d domain.GrantDelegation) (domain.GrantDelegation, error) {
	w.w.inserts++
	d.Status = domain.GrantDelegationActive
	return d, nil
}

// Проверяется настоящий doCreate, включая mutation+audit+commit/rollback,
// и запрет случайно открыть старый writer при подключённом participant.
func TestDelegationCreateWorkerUsesParticipantAndAuditRollback(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "commit", true: "audit-failure"}[fail], func(t *testing.T) {
			w := &delegationProbeWriter{}
			if fail {
				w.auditErr = errors.New("audit unavailable")
			}
			f := &delegationFactoryProbe{w: w}
			u := NewCreateGrantDelegationUseCase(nil, nil, nil).WithAuthorityWriter(f)
			d := retryDelegation(retryID, domain.GrantDelegationActive)
			_, err := u.doCreate(operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: retryUser}), d, retryUser, false, "")
			require.Equal(t, []kaname.GrantDelegationMutation{kaname.GrantDelegationCreate}, f.kinds)
			require.Equal(t, d.ID, f.proposed[0].ID)
			require.Equal(t, d.RoleIDs, f.proposed[0].RoleIDs)
			require.Equal(t, 1, w.inserts)
			require.Equal(t, 1, w.audits)
			if fail {
				require.Error(t, err)
				require.Zero(t, w.commits)
				require.Equal(t, 1, w.rollbacks)
			} else {
				require.NoError(t, err)
				require.Equal(t, 1, w.commits)
				require.Zero(t, w.rollbacks)
			}
		})
	}
}

// Unit fixture проверяет TX scaffolding; native policy проверяется отдельно
// настоящими PostgreSQL public-UC сценариями.
func (w *delegationProbeWriter) LockGrantDelegationCreate(context.Context, domain.GrantDelegation) error {
	return nil
}

type delegationUnitAdminChecker struct{}

func (delegationUnitAdminChecker) Check(context.Context, string, string, string) (bool, error) {
	return true, nil
}
func (w *delegationProbeWriter) TransactionRelationChecker(*authzmodel.Plans) (kaname.RelationChecker, error) {
	return delegationUnitAdminChecker{}, nil
}
func TestDelegationExplicitNilParticipantDoesNotFallBack(t *testing.T) {
	var typedNil *delegationFactoryProbe
	for _, factory := range []delegationWriterFactory{nil, typedNil} {
		create := NewCreateGrantDelegationUseCase(nil, nil, nil).WithAuthorityWriter(factory)
		_, err := create.doCreate(context.Background(), retryDelegation(retryID, domain.GrantDelegationActive), retryUser, false, "")
		require.Equal(t, codes.Unavailable, status.Code(err))
		update := NewUpdateGrantDelegationUseCase(nil, nil, nil).WithAuthorityWriter(factory)
		_, err = update.doUpdate(context.Background(), updatePatch{id: retryID}, nil)
		require.Equal(t, codes.Unavailable, status.Code(err))
	}
}
