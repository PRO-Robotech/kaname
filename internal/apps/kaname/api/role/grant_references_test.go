// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package role

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	rolerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
)

type metaReferenceWriter struct {
	Writer
	refs    *metaReferenceRows
	checker kaname.RelationChecker
}

func (w metaReferenceWriter) RolesW() rolerepo.WriterIface { return w.refs }
func (w metaReferenceWriter) TransactionRelationChecker(*authzmodel.Plans) (kaname.RelationChecker, error) {
	return w.checker, nil
}

type metaReferenceRows struct {
	rolerepo.WriterIface
	reads     int
	reference rolerepo.GrantReference
	err       error
}

func (r *metaReferenceRows) LockGrantOwnerAccount(context.Context, domain.Role) (domain.AccountID, error) {
	r.reads++
	return "acc_owner", nil
}
func (r *metaReferenceRows) LockGrantReference(context.Context, domain.RoleID) (rolerepo.GrantReference, error) {
	r.reads++
	return r.reference, r.err
}

type metaReferenceCheck func(context.Context, string, string, string) (bool, error)

func (f metaReferenceCheck) Check(ctx context.Context, s, r, o string) (bool, error) {
	return f(ctx, s, r, o)
}
func TestGrantReferencesMethodBeforeExistenceVisibilityBeforeLifecycle(t *testing.T) {
	plans, e := authzmodel.New(authzmodel.DSL)
	require.NoError(t, e)
	ctx := operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: "usr_owner"})
	owner := domain.Role{AccountID: "acc_owner"}
	caps := []domain.GrantCapabilityRule{{Kind: domain.GrantCapabilityBindRole, BoundRoleID: "rol_target"}}
	refs := &metaReferenceRows{reference: rolerepo.GrantReference{Role: domain.Role{ID: "rol_target", ProjectID: "prj_owner"}, AccountID: "acc_owner", Live: true}}
	w := metaReferenceWriter{refs: refs, checker: metaReferenceCheck(func(context.Context, string, string, string) (bool, error) { return false, nil })}
	require.ErrorIs(t, checkGrantReferences(ctx, w, owner, caps, true, plans), iamerr.ErrPermissionDenied)
	require.Zero(t, refs.reads)
	w.checker = metaReferenceCheck(func(_ context.Context, _ string, relation, _ string) (bool, error) { return relation == "editor", nil })
	require.ErrorIs(t, checkGrantReferences(ctx, w, owner, caps, true, plans), iamerr.ErrNotFound)
	refs.reference.Live = false
	require.ErrorIs(t, checkGrantReferences(ctx, w, owner, caps, true, plans), iamerr.ErrNotFound)
	w.checker = metaReferenceCheck(func(context.Context, string, string, string) (bool, error) { return true, nil })
	require.ErrorIs(t, checkGrantReferences(ctx, w, owner, caps, true, plans), iamerr.ErrNotFound)
	refs.reference.Live = true
	require.NoError(t, checkGrantReferences(ctx, w, owner, caps, true, plans))
	refs.reference.AccountID = "acc_other"
	require.ErrorIs(t, checkGrantReferences(ctx, w, owner, caps, true, plans), iamerr.ErrFailedPrecondition)
	refs.reference.Role.IsSystem = true
	require.NoError(t, checkGrantReferences(ctx, w, owner, caps, true, plans))
	require.ErrorIs(t, checkGrantReferences(ctx, w, owner, caps, true, nil), iamerr.ErrUnavailable)
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	w.checker = metaReferenceCheck(func(ctx context.Context, _, _, _ string) (bool, error) { return false, ctx.Err() })
	require.ErrorIs(t, checkGrantReferences(canceled, w, owner, caps, true, plans), context.Canceled)
	refs.err = errors.New("hidden backend detail")
	w.checker = metaReferenceCheck(func(context.Context, string, string, string) (bool, error) { return true, nil })
	err := checkGrantReferences(ctx, w, owner, caps, true, plans)
	require.ErrorIs(t, err, iamerr.ErrUnavailable)
	require.NotContains(t, err.Error(), "hidden backend detail")
}
func TestGrantReferenceCommonAnchorAllowsNestedAccountButNotSiblingProject(t *testing.T) {
	a := domain.Role{AccountID: "acc_a"}
	p := domain.Role{ProjectID: "prj_a"}
	q := domain.Role{ProjectID: "prj_b"}
	require.True(t, rolerepo.CommonGrantAnchor(a, "acc_a", p, "acc_a"))
	require.True(t, rolerepo.CommonGrantAnchor(p, "acc_a", a, "acc_a"))
	require.False(t, rolerepo.CommonGrantAnchor(p, "acc_a", q, "acc_a"))
	require.False(t, rolerepo.CommonGrantAnchor(a, "acc_a", p, "acc_b"))
}

type metaHeldKeys struct{ seen []domain.ResourceRef }

func (k *metaHeldKeys) RegisteredOf(_ context.Context, refs []domain.ResourceRef) ([]domain.ResourceRef, error) {
	k.seen = append(k.seen, refs...)
	return refs, nil
}
func TestGrantReferenceHoldsKeepAuthoredRuleIndices(t *testing.T) {
	keys := &metaHeldKeys{}
	rules := domain.Rules{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{"rol_reference"}}, {Module: "iam", Resources: []string{"role"}, Verbs: []string{"get", "bind"}, ResourceNames: []string{"rol_mixed"}}, {Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}, ResourceNames: []string{"acc_named"}}}
	held, e := heldNamesOf(context.Background(), keys, rules)
	require.NoError(t, e)
	require.Len(t, held, 2)
	require.Equal(t, 1, held[0].Rule)
	require.Equal(t, 2, held[1].Rule)
	require.NotContains(t, keys.seen, domain.ResourceRef{Type: "iam.role", ID: "rol_reference"})
}

func (r *metaReferenceRows) LockGrantAuthoringAxes(context.Context, []domain.GrantCapabilityRule) error {
	return nil
}
