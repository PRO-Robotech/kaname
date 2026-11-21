// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"fmt"
	"testing"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestResourceFinalAuthorityErrorPreservesNonAuthorityFailures(t *testing.T) {
	stage := &resourceRegistrationStage{}
	for name, input := range map[string]error{
		"nil":            nil,
		"ordinary ACL":   &pgconn.PgError{Code: "42501", Message: "permission denied for table relation_fact"},
		"source proof":   &pgconn.PgError{Code: "42501", Message: "registration final owner evidence omitted"},
		"backend":        &pgconn.PgError{Code: "08006"},
		"wrong SQLSTATE": &pgconn.PgError{Code: "XX000", ConstraintName: "resource_registration_authority_denied"},
		"cancel":         context.Canceled,
		"unknown":        errors.New("private SQL detail"),
	} {
		t.Run(name, func(t *testing.T) {
			got := stage.finalAuthorityError(input)
			if input == nil {
				require.NoError(t, got)
				return
			}
			require.Same(t, input, got)
		})
	}
}

func TestResourceFinalAuthorityErrorRequiresRegistrationStageAndExactMarker(t *testing.T) {
	raw := &pgconn.PgError{Code: "42501", ConstraintName: "resource_registration_authority_denied", Message: "private diagnostic"}
	var missing *resourceRegistrationStage
	require.Same(t, raw, missing.finalAuthorityError(raw))
	err := (&resourceRegistrationStage{}).finalAuthorityError(fmt.Errorf("driver: %w", raw))
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Equal(t, "permission denied", status.Convert(err).Message())
}

func TestResourceFinalAuthorityErrorPreservesPermanentBindingRefusalOnlyForDenial(t *testing.T) {
	c, tx, module, in := resourceRegistrationPrepareFixture(t)
	tx.refuses = true
	prepared, err := prepareResourceRegistration(context.Background(), c, module, in)
	require.NoError(t, err)
	stage := &resourceRegistrationStage{registration: prepared}
	denial := &pgconn.PgError{Code: "42501", ConstraintName: "resource_registration_authority_denied"}
	require.ErrorIs(t, stage.finalAuthorityError(denial), iamerr.ErrObjectBoundToOtherProject)
	backend := &pgconn.PgError{Code: "08006"}
	require.Same(t, backend, stage.finalAuthorityError(backend))
}
