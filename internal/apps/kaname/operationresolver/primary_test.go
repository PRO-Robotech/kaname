// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package operationresolver

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/corelib/operations"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type primaryRouteProbe struct {
	kanamerepo.Repository
	primary, ordinary int
	cause             error
}

func (r *primaryRouteProbe) Reader(context.Context) (kanamerepo.Reader, error) {
	r.ordinary++
	return nil, r.cause
}
func (r *primaryRouteProbe) ReaderFromPrimary(context.Context) (kanamerepo.Reader, error) {
	r.primary++
	return nil, r.cause
}

func TestGrantDelegationRecoverySelectsPrimaryOnly(t *testing.T) {
	for _, tc := range []struct {
		name     string
		metadata proto.Message
		primary  int
	}{
		{"create delegation", &iamv1.CreateGrantDelegationMetadata{}, 1},
		{"revoke delegation", &iamv1.RevokeGrantDelegationMetadata{}, 1},
		{"ordinary account", &iamv1.CreateAccountMetadata{}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cause := errors.New("reader boundary")
			repo := &primaryRouteProbe{cause: cause}
			metadata, err := anypb.New(tc.metadata)
			require.NoError(t, err)
			_, err = New(repo, nil, nil).Resolve(context.Background(), operations.Operation{Metadata: metadata})
			require.ErrorIs(t, err, cause)
			require.Equal(t, tc.primary, repo.primary)
			require.Equal(t, 1-tc.primary, repo.ordinary)
		})
	}
}
