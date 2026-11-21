// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	ab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	"github.com/stretchr/testify/require"
)

type bindingDecisionFailure struct {
	called  int
	create  bool
	actor   domain.Subject
	binding domain.AccessBinding
	err     error
}

var _ kaname.BindingAuthorizationDecisionRunner = (*bindingDecisionFailure)(nil)
var _ kaname.BindingMetadataDecisionRunner = (*bindingDecisionFailure)(nil)

func (f *bindingDecisionFailure) RunBindingAuthorizationDecision(ctx context.Context, actor domain.Subject, b domain.AccessBinding, create, delegated bool, tuples func(domain.AccessBinding, domain.Role) []ab.RelationTuple, apply func(context.Context, kaname.SemanticAuthorityWriter, domain.AccessBinding, domain.Role) error) error {
	if delegated {
		return errors.New("неожиданная делегированная проверка")
	}
	return f.RunBindingDecision(ctx, actor, b, create, tuples, apply)
}

func (f *bindingDecisionFailure) RunBindingMetadataDecision(ctx context.Context, actor domain.Subject, request kaname.BindingMetadataDecision, _ func(context.Context, kaname.SemanticAuthorityWriter, domain.AccessBinding, domain.Role) error) error {
	return f.RunBindingDecision(ctx, actor, domain.AccessBinding{ID: request.ID}, false, nil, nil)
}

func (f *bindingDecisionFailure) RunBindingDecision(ctx context.Context, actor domain.Subject, b domain.AccessBinding, create bool, _ func(domain.AccessBinding, domain.Role) []ab.RelationTuple, _ func(context.Context, kaname.SemanticAuthorityWriter, domain.AccessBinding, domain.Role) error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	f.called++
	f.create = create
	f.actor = actor
	f.binding = b
	return f.err
}
func TestBindingDecisionActualWorkersDoNotFallbackAndKeepTypedSubjects(t *testing.T) {
	ctx := operations.WithPrincipal(context.Background(), operations.Principal{Type: "service_account", ID: "sva00000000000000001"})
	failure := &bindingDecisionFailure{err: errors.New("native source unavailable")}
	create := &CreateAccessBindingUseCase{}
	handler := (&Handler{create: create, update: &UpdateAccessBindingUseCase{}}).WithBindingDecisions(failure)
	b := domain.AccessBinding{ID: "acb00000000000000001", Subjects: []domain.Subject{{Type: domain.SubjectTypeUser, ID: "usr00000000000000001"}, {Type: domain.SubjectTypeGroup, ID: "grp00000000000000001"}}}
	_, err := create.doCreate(ctx, b, "sva00000000000000001")
	require.Error(t, err)
	require.Equal(t, 1, failure.called)
	require.True(t, failure.create)
	require.Equal(t, domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: "sva00000000000000001"}, failure.actor)
	require.Equal(t, b.Subjects, failure.binding.Subjects)
	// Нулевой repo намеренно не пригоден: silent legacy fallback дал бы panic.
	update := handler.update
	_, err = update.doUpdate(ctx, "acb00000000000000001", true, false, true, domain.Labels{"purpose": "metadata"})
	require.Error(t, err)
	require.Equal(t, 2, failure.called)
	require.False(t, failure.create)
}
func TestBindingDecisionAnonymousAndCancellationNeverReachMutation(t *testing.T) {
	f := &bindingDecisionFailure{err: errors.New("must not mutate")}
	u := (&CreateAccessBindingUseCase{}).WithBindingDecisions(f)
	_, err := u.doCreate(context.Background(), domain.AccessBinding{ID: "acb00000000000000001"}, "forged")
	require.Error(t, err)
	require.Zero(t, f.called)
	ctx, cancel := context.WithCancel(operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: "usr00000000000000001"}))
	cancel()
	_, err = u.doCreate(ctx, domain.AccessBinding{ID: "acb00000000000000001"}, "usr00000000000000001")
	require.Error(t, err)
	require.Zero(t, f.called)
}

type bindingWithdrawalFailure struct {
	called int
	kind   kaname.BindingWithdrawalKind
}

func (f *bindingWithdrawalFailure) WithdrawBinding(_ context.Context, _ domain.AccessBindingID, k kaname.BindingWithdrawalKind, _ string, _ func(context.Context, kaname.Writer, clients.RelationStore, domain.AccessBinding) error, _ func(context.Context, kaname.Writer, domain.AccessBinding) error) (domain.AccessBinding, error) {
	f.called++
	f.kind = k
	return domain.AccessBinding{}, errors.New("stage failed")
}
func TestBindingWithdrawalActualDeleteAndRevokeWorkersRouteClosed(t *testing.T) {
	f := &bindingWithdrawalFailure{}
	handler := (&Handler{delete: &DeleteAccessBindingUseCase{}, revoke: &RevokeAccessBindingUseCase{}}).WithBindingWithdrawal(f)
	remove := handler.delete
	require.Error(t, remove.deleteOnce(context.Background(), "acb00000000000000001", "usr00000000000000001"))
	require.Equal(t, kaname.BindingWithdrawalDelete, f.kind)
	revoke := handler.revoke
	_, err := revoke.doRevoke(context.Background(), "acb00000000000000001", "usr00000000000000001")
	require.Error(t, err)
	require.Equal(t, kaname.BindingWithdrawalRevoke, f.kind)
	require.Equal(t, 2, f.called)
}
