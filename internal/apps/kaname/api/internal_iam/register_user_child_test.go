// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

type userChildRegistrationTxStub struct {
	steps    []string
	input    UserChildRegistrationInput
	policy   domain.UserChildPathPolicy
	target   domain.UserChildRegistrationTarget
	question [3]string
	actor    operations.Principal
	version  time.Time
	allowed  bool
	applyErr error
}

func (s *userChildRegistrationTxStub) RunUserChildRegistration(
	ctx context.Context, run func(context.Context, UserChildRegistrationTx) (time.Time, error),
) (time.Time, error) {
	return run(ctx, s)
}

func (s *userChildRegistrationTxStub) ResolveUserChildRegistration(
	_ context.Context, input UserChildRegistrationInput,
) (domain.UserChildRegistrationTarget, error) {
	s.steps = append(s.steps, "resolve")
	s.input = input
	target, err := s.policy.Resolve(input.ResourceID)
	s.target = target
	return target, err
}

func (s *userChildRegistrationTxStub) Check(_ context.Context, subject, relation, object string) (bool, error) {
	s.steps = append(s.steps, "check")
	s.question = [3]string{subject, relation, object}
	return s.allowed, nil
}

func (s *userChildRegistrationTxStub) ApplyUserChildRegistration(
	_ context.Context, target domain.UserChildRegistrationTarget, actor operations.Principal,
) (time.Time, error) {
	s.steps = append(s.steps, "apply")
	s.actor = actor
	if target != s.target {
		return time.Time{}, domain.ErrUserChildRegistrationRefused
	}
	return s.version, s.applyErr
}

func TestUserChildRegistrationAuthorizesServerParentBeforeApplying(t *testing.T) {
	p := operations.Principal{Type: "user", ID: "usr-actor"}
	ctx := operations.WithPrincipal(t.Context(), p)
	input := UserChildRegistrationInput{ResourceType: "registry.repositories", ResourceID: "container/namespace/child"}
	fixture := &userChildRegistrationTxStub{
		policy:  domain.UserChildPathPolicy{ChildType: "registry_repository", ParentType: "registry_registry", ParentAction: "v_create", ParentSegments: 1},
		version: time.Unix(100, 0),
		allowed: true,
	}
	uc := NewUserChildRegistration(fixture)
	version, err := uc.Register(ctx, input)
	require.NoError(t, err)
	require.Equal(t, fixture.version, version)
	require.Equal(t, []string{"resolve", "check", "apply"}, fixture.steps)
	require.Equal(t, input, fixture.input)
	require.Equal(t, [3]string{"user:usr-actor", "v_create", "registry_registry:container"}, fixture.question)
	require.Equal(t, p, fixture.actor)
}

func TestUserChildRegistrationUsesOnePublicRefusal(t *testing.T) {
	ctx := operations.WithPrincipal(t.Context(), operations.Principal{Type: "user", ID: "usr-actor"})
	input := UserChildRegistrationInput{ResourceType: "registry.repositories", ResourceID: "parent/child"}
	fixture := &userChildRegistrationTxStub{
		policy:   domain.UserChildPathPolicy{ChildType: "registry_repository", ParentType: "registry_registry", ParentAction: "v_create", ParentSegments: 1},
		applyErr: domain.ErrUserChildRegistrationRefused,
	}
	uc := NewUserChildRegistration(fixture)
	want := status.Convert(authzguard.PermissionDenied()).Proto()

	version, err := uc.Register(ctx, input)
	require.True(t, version.IsZero())
	require.Equal(t, want, status.Convert(err).Proto())
	require.Equal(t, []string{"resolve", "check"}, fixture.steps)

	fixture.allowed, fixture.steps = true, nil
	version, err = uc.Register(ctx, input)
	require.True(t, version.IsZero())
	require.Equal(t, want, status.Convert(err).Proto())
	require.Equal(t, []string{"resolve", "check", "apply"}, fixture.steps)

	fixture.steps = nil
	service := operations.WithPrincipal(t.Context(), operations.Principal{Type: "service_account", ID: "sa-caller"})
	version, err = uc.Register(service, input)
	require.True(t, version.IsZero())
	require.Equal(t, want, status.Convert(err).Proto())
	require.Empty(t, fixture.steps)
}

func TestUserChildRegistrationPathUsesDeclaredParentBoundary(t *testing.T) {
	policy := domain.UserChildPathPolicy{
		ChildType: "example_item", ParentType: "example_container", ParentAction: "v_create", ParentSegments: 2,
	}
	target, err := policy.Resolve("tenant/container/repo/sub-item")
	require.NoError(t, err)
	require.Equal(t, "example_container:tenant/container", target.ParentObject)
	require.Equal(t, "example_item:tenant/container/repo/sub-item", target.ChildObject)

	for _, malformed := range []string{
		"tenant/container", "tenant//container/repo", "tenant/container/", "/container/repo",
		"tenant/container/../repo", "tenant/container/a%2fb", "tenant/container/other:repo", "tenant/container/a#member",
	} {
		_, err := policy.Resolve(malformed)
		require.ErrorIs(t, err, domain.ErrUserChildRegistrationRefused, malformed)
	}
}
