// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// force_logout_session_test.go — force-logout must END the session at the
// provider, not merely record that it should no longer be honoured.
//
// Recording the cutoff stops tokens from being issued. It does not stop the
// browser from holding a live session, and a session that survives keeps its
// ORIGINAL authentication instant when it asks again — so the cutoff refuses it
// forever and nothing ever prompts the re-authentication that would clear it.
// The person is wedged rather than logged out. The self-service logout path at
// the edge has always ended the session for the caller's own subject; this is
// the same lever, for the subject an administrator names.
package internal_iam

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

// recordingSessions — the provider's login-session surface.
type recordingSessions struct {
	subjects []string
	err      error
}

func (r *recordingSessions) DeleteLoginSessions(_ context.Context, subject string) error {
	r.subjects = append(r.subjects, subject)
	return r.err
}

// staticExternalIDs resolves users.id → the external identity the provider
// knows. Force-logout names a kacho user; the provider keys sessions on its own
// subject, so the two are not interchangeable and the resolution is real work.
type staticExternalIDs struct {
	byID map[domain.UserID]string
	err  error
}

func (s *staticExternalIDs) ExternalIDOf(_ context.Context, id domain.UserID) (string, error) {
	if s.err != nil {
		return "", s.err
	}
	ext, ok := s.byID[id]
	if !ok {
		return "", errors.New("no such user")
	}
	return ext, nil
}

func sessionAwareHandler(rec sessionRevoker, sess *recordingSessions, ext *staticExternalIDs) (*Handler, *recordingForceLogoutOps) {
	ops := &recordingForceLogoutOps{}
	h := NewHandler(NewLookupSubjectUseCase(nil), nil).
		WithSessionRevoker(rec).
		WithAdminChecker(&fakeForceLogoutChecker{allow: true}).
		WithOperations(ops).
		WithProviderSessions(sess, ext)
	return h, ops
}

// TestForceLogout_EndsTheProviderSession — the session is ended, for the
// EXTERNAL subject of the named user.
func TestForceLogout_EndsTheProviderSession(t *testing.T) {
	sess := &recordingSessions{}
	ext := &staticExternalIDs{byID: map[domain.UserID]string{"usr_victim": "kratos-uuid-victim"}}
	h, _ := sessionAwareHandler(&fakeForceLogoutRecorder{}, sess, ext)

	op, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
	require.NoError(t, err)
	require.True(t, op.GetDone())

	require.Equal(t, []string{"kratos-uuid-victim"}, sess.subjects,
		"the session must be ended for the identity the provider knows, not the kacho user id")
}

// TestForceLogout_ProviderUnreachable_FailsTheMutation — the administrator must
// not be told the person was logged out when the session is still standing.
//
// The cutoff stays committed on purpose: it is protective on its own, it is
// idempotent, and retrying the whole call re-applies it and re-attempts the
// teardown. What must not happen is a success report.
func TestForceLogout_ProviderUnreachable_FailsTheMutation(t *testing.T) {
	sess := &recordingSessions{err: errors.New("provider unreachable")}
	ext := &staticExternalIDs{byID: map[domain.UserID]string{"usr_victim": "kratos-uuid-victim"}}
	rec := &fakeForceLogoutRecorder{}
	h, ops := sessionAwareHandler(rec, sess, ext)

	_, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
	require.Error(t, err, "an un-torn-down session must not be reported as a completed logout")
	assert.Equal(t, codes.Unavailable, status.Code(err))

	assert.Equal(t, 1, rec.allCnt, "the cutoff stays committed — it is protective and idempotent")
	assert.Contains(t, ops.calls, "markerror",
		"a poll of the operation must see the failure, not a success")
}

// TestForceLogout_SessionsNotWired_StillRecordsTheCutoff — a deployment without
// the provider-admin surface configured keeps the behaviour it had. The cutoff
// is the authoritative half and is now enforced at issuance; the teardown is
// what makes the refusal recoverable.
func TestForceLogout_SessionsNotWired_StillRecordsTheCutoff(t *testing.T) {
	rec := &fakeForceLogoutRecorder{}
	h := forceLogoutHandler(rec)

	op, err := h.ForceLogout(adminCtx(), &iamv1.ForceLogoutRequest{UserId: "usr_victim"})
	require.NoError(t, err)
	require.True(t, op.GetDone())
	assert.Equal(t, 1, rec.allCnt)
}
