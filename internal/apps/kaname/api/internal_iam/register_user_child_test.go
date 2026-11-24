// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

type userChildRegistrationRunnerStub struct {
	input   kaname.UserChildRegistrationInput
	caller  operations.Principal
	version time.Time
	err     error
	calls   int
}

func (s *userChildRegistrationRunnerStub) RunUserChildRegistration(_ context.Context, input kaname.UserChildRegistrationInput, caller operations.Principal) (time.Time, error) {
	s.input, s.caller = input, caller
	s.calls++
	return s.version, s.err
}

func TestUserChildRegistrationPassesOnlyImmutableIntentAndVerifiedHuman(t *testing.T) {
	p := operations.Principal{Type: "user", ID: "usr-actor"}
	ctx := operations.WithPrincipal(t.Context(), p)
	input := kaname.UserChildRegistrationInput{ResourceType: "registry.repositories", ResourceID: "container/namespace/child"}
	fixture := &userChildRegistrationRunnerStub{version: time.Unix(100, 0)}
	version, err := NewUserChildRegistration(fixture).Register(ctx, input)
	require.NoError(t, err)
	require.Equal(t, fixture.version, version)
	require.Equal(t, input, fixture.input)
	require.Equal(t, p, fixture.caller)
	require.Equal(t, 1, fixture.calls)
}

func TestUserChildRegistrationUsesOnePublicRefusal(t *testing.T) {
	ctx := operations.WithPrincipal(t.Context(), operations.Principal{Type: "user", ID: "usr-actor"})
	input := kaname.UserChildRegistrationInput{ResourceType: "registry.repositories", ResourceID: "parent/child"}
	fixture := &userChildRegistrationRunnerStub{version: time.Unix(100, 0), err: domain.ErrUserChildRegistrationRefused}
	uc := NewUserChildRegistration(fixture)
	want := status.Convert(authzguard.PermissionDenied()).Proto()
	version, err := uc.Register(ctx, input)
	require.True(t, version.IsZero())
	require.Equal(t, want, status.Convert(err).Proto())
	require.Equal(t, 1, fixture.calls)

	for _, principal := range []operations.Principal{{}, {Type: "service_account", ID: "sa-caller"}} {
		version, err = uc.Register(operations.WithPrincipal(t.Context(), principal), input)
		require.True(t, version.IsZero())
		require.Equal(t, want, status.Convert(err).Proto())
	}
	require.Equal(t, 1, fixture.calls, "непроверенный человек не открывает runner")
}

func TestUserChildRegistrationMissingCommittedVersionIsUnavailable(t *testing.T) {
	ctx := operations.WithPrincipal(t.Context(), operations.Principal{Type: "user", ID: "usr-actor"})
	fixture := &userChildRegistrationRunnerStub{}
	version, err := NewUserChildRegistration(fixture).Register(ctx, kaname.UserChildRegistrationInput{ResourceType: "registry.repositories", ResourceID: "parent/child"})
	require.True(t, version.IsZero())
	require.Equal(t, status.Convert(authzguard.AuthzBackendUnavailable()).Proto(), status.Convert(err).Proto())
	require.Equal(t, 1, fixture.calls)
}

func TestUserChildRegistrationPreservesBackendAndContextFailures(t *testing.T) {
	ctx := operations.WithPrincipal(t.Context(), operations.Principal{Type: "user", ID: "usr-actor"})
	input := kaname.UserChildRegistrationInput{ResourceType: "registry.repositories", ResourceID: "parent/child"}
	backend := errors.New("backend failed")
	for _, cause := range []error{backend, iamerr.ErrAborted,
		errors.Join(iamerr.ErrUnavailable, domain.ErrUserChildRegistrationRefused, backend),
		errors.Join(context.Canceled, domain.ErrUserChildRegistrationRefused),
	} {
		fixture := &userChildRegistrationRunnerStub{version: time.Unix(100, 0), err: cause}
		version, err := NewUserChildRegistration(fixture).Register(ctx, input)
		require.True(t, version.IsZero())
		require.ErrorIs(t, err, cause)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	fixture := &userChildRegistrationRunnerStub{}
	version, err := NewUserChildRegistration(fixture).Register(canceled, input)
	require.True(t, version.IsZero())
	require.ErrorIs(t, err, context.Canceled)
	require.Zero(t, fixture.calls)
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

	prefix := "tenant/container/"
	id := prefix + strings.Repeat("a", domain.MaxUserChildObjectKeyBytes-len(policy.ChildType)-1-len(prefix))
	target, err = policy.Resolve(id)
	require.NoError(t, err)
	require.Len(t, target.ChildObject, domain.MaxUserChildObjectKeyBytes)
	_, err = policy.Resolve(id + "a")
	require.ErrorIs(t, err, domain.ErrUserChildRegistrationRefused)
}
