// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// subject_naming_reaches_the_edge_test.go — the SEAM between iam's invalidation
// producer and the edge's decision cache.
//
// The edge keys every cached verdict by the FGA-shaped subject it resolved from
// the token: `<fga-type>:<id>` (gateway/internal/middleware/subject_extractor.go
// builds it from the principal TYPE claim), and InvalidateSubject matches that
// string against the key PREFIX. So an invalidation whose subject string differs
// by one character drops nothing — and the edge answers NotFound, which the
// applier classifies as idempotent success and marks the row sent. The failure
// is silent by construction: no error, no retry, no dropped entry.
//
// Therefore the assertion here is the OBSERVABLE one — "the string iam sends is
// the string the edge keys by" — measured against ids THE PRODUCT ACTUALLY MINTS
// (`ids.NewID` → 3-char prefix + 17 crockford-base32, no separator), not against
// hand-written fixtures. Every pre-existing fixture in this package spells
// subjects `usr_alice` / `usr_w1_2_15`; that form has no producer anywhere in the
// product, and it is exactly what made a mapper keyed on `usr_` look correct.
package clients_test

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/outbox/drainer"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

// Test_SubjectNameMatchesWhatTheEdgeKeysBy — for an id of the form the product
// mints, the applier must send exactly `<fga-type>:<id>`.
func Test_SubjectNameMatchesWhatTheEdgeKeysBy(t *testing.T) {
	for _, tc := range []struct {
		name        string
		idPrefix    string
		wantFGAType string
	}{
		{"user", "usr", "user"},
		{"service account", "sva", "service_account"},
		{"group", "grp", "group"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			id := ids.NewID(tc.idPrefix) // real minted form, e.g. "svatt493t8mxrgjzjh8n"
			require.NotContains(t, id, "_",
				"guard on the fixture itself: minted ids carry NO separator; a fixture "+
					"that has one is not what the product produces")

			mock := &recordingAuthzCacheClient{}
			apply := clients.NewSubjectChangeApplier(mock)

			err := apply(context.Background(), "group_member_change", clients.SubjectChangeEvent{
				SubjectID: id,
				EventType: "group_member_change",
			})
			require.NoError(t, err)

			calls := mock.snapshot()
			require.Len(t, calls, 1)
			assert.Equal(t, tc.wantFGAType+":"+id, calls[0].Subject,
				"the edge keys its cache by `<fga-type>:<id>` and matches on that prefix; "+
					"anything else drops zero entries and the revoke never lands")
		})
	}
}

// Test_LegacySeparatorSubjectStillNames — paired POSITIVE control for the test
// above. Without it, a mapper that named nothing at all would look like the
// same finding: this pins that the hand-written legacy spelling keeps working,
// so a red above means "minted ids are not named", not "naming is broken".
func Test_LegacySeparatorSubjectStillNames(t *testing.T) {
	mock := &recordingAuthzCacheClient{}
	apply := clients.NewSubjectChangeApplier(mock)

	err := apply(context.Background(), "binding_revoke", clients.SubjectChangeEvent{
		SubjectID: "usr_alice",
		EventType: "binding_revoke",
	})
	require.NoError(t, err)

	calls := mock.snapshot()
	require.Len(t, calls, 1)
	assert.Equal(t, "user:usr_alice", calls[0].Subject)
}

// Test_UnnameableSubjectIsNeverReportedAsApplied — a subject the applier cannot
// name must NOT be marked delivered.
//
// Today an unknown prefix falls through as-is, the edge answers NotFound ("no
// cache entries"), and the applier maps NotFound → ErrAlreadyApplied → the row
// is stamped sent. That is the whole defect in one line: the failure to name a
// subject is indistinguishable from having successfully invalidated it.
func Test_UnnameableSubjectIsNeverReportedAsApplied(t *testing.T) {
	mock := &recordingAuthzCacheClient{
		errs: []error{status.Error(codes.NotFound, "no cache entries for subject")},
	}
	apply := clients.NewSubjectChangeApplier(mock)

	err := apply(context.Background(), "binding_revoke", clients.SubjectChangeEvent{
		SubjectID: "zzz0000000000000000", // no such subject family in the product
		EventType: "binding_revoke",
	})

	require.Error(t, err, "a subject we cannot name is not an invalidation we performed")
	assert.False(t, stderrors.Is(err, drainer.ErrAlreadyApplied),
		"must never be reported as idempotent success — that stamps the row sent and "+
			"the revoke is lost with no error anywhere")
	assert.True(t, stderrors.Is(err, drainer.ErrPermanent),
		"unnameable subject cannot become nameable on retry: terminal, loud, never transient")
}
