// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package session_revocations

// list_by_user_authz_test.go — ListByUser answers about the subject the CALLER
// NAMED, so the caller has to be allowed to read that subject.
//
// The whole response is the logout/revocation history of one named user: when
// each of their sessions was torn down and why. There is exactly one object the
// question can be asked about (`iam_user:<user_id>`), so this is the per-object
// shape, not the page-filtered one — and the object is named by the request, not
// derived from the caller.
//
// Every assertion below is on the OBSERVABLE answer — what the caller gets back,
// and whether the store was read at all — never on an internal call count alone.
// The refusals are stated together with the admissions they are supposed to
// leave intact: a lone "it was refused" is at its greenest when everything is
// broken and nothing is served to anyone.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

const (
	victimID    = "usr_victim"
	neighbourID = "usr_neighbour"
)

// countingReader records whether the revocation store was read at all. A refusal
// that still reads the rows has already paid for the answer it claims to
// withhold, and the next handler edit hands them over.
type countingReader struct {
	rows  []domain.SessionRevocation
	reads int
}

func (r *countingReader) IsRevoked(context.Context, string) (bool, error) { return false, nil }
func (r *countingReader) GetByJTI(context.Context, string) (domain.SessionRevocation, error) {
	return domain.SessionRevocation{}, nil
}

func (r *countingReader) ListByUser(_ context.Context, _ string, _ int32, _ string) ([]domain.SessionRevocation, string, error) {
	r.reads++
	return r.rows, "", nil
}

func victimHistory() *countingReader {
	now := time.Now().UTC().Truncate(time.Second)
	return &countingReader{rows: []domain.SessionRevocation{{
		TokenJTI: "jti-victim-1", UserID: victimID, Reason: "force-logout",
		RevokedAt: now, TTLExpiresAt: now.Add(time.Hour),
	}}}
}

// scriptedChecker answers a fixed set of (subject, relation, object) questions.
// Anything not scripted answers "no" — the model's own posture, so a test that
// forgets to grant something sees a refusal rather than an accident.
type scriptedChecker struct {
	allow map[string]bool
	err   error
	asked []string
}

func (c *scriptedChecker) Check(_ context.Context, subject, relation, object string) (bool, error) {
	key := subject + "|" + relation + "|" + object
	c.asked = append(c.asked, key)
	if c.err != nil {
		return false, c.err
	}
	return c.allow[key], nil
}

func grants(keys ...string) *scriptedChecker {
	m := map[string]bool{}
	for _, k := range keys {
		m[k] = true
	}
	return &scriptedChecker{allow: m}
}

// asUser puts a real end-user principal on the context — the forwarded identity
// the gateway relays, which is the only thing that names WHO is asking.
func asUser(id string) context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: id})
}

func listByUser(t *testing.T, h *Handler, ctx context.Context, target string) (*iamv1.ListByUserResponse, error) {
	t.Helper()
	return h.ListByUser(ctx, &iamv1.ListByUserRequest{UserId: target})
}

// ── the refusal ─────────────────────────────────────────────────────────────

// A caller who may not read the named user must not receive that user's session
// history — and must not be told whether the user exists either, so the answer
// is the owner's own miss, verbatim.
func TestListByUser_ForeignSubject_IsRefusedAndStoreIsNotRead(t *testing.T) {
	store := victimHistory()
	h := newHandler(&fakeRevoker{}, store).WithRelationStore(grants())

	resp, err := listByUser(t, h, asUser(neighbourID), victimID)

	require.Error(t, err, "a neighbour asked for another user's session history and was served")
	assert.Nil(t, resp.GetRevocations())
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Equal(t, "User "+victimID+" not found", status.Convert(err).Message(),
		"the refusal must read exactly like the owner's own miss — a distinguishable text is an existence oracle")
	assert.Zero(t, store.reads,
		"the revocation store was read for a caller who may not read it")
}

// ── the admissions it must leave intact ─────────────────────────────────────

// A user reads their own logout history. This is an identity fact, not a model
// question, so it holds even where the model cannot be reached.
func TestListByUser_Self_IsServed(t *testing.T) {
	store := victimHistory()
	h := newHandler(&fakeRevoker{}, store).WithRelationStore(grants())

	resp, err := listByUser(t, h, asUser(victimID), victimID)

	require.NoError(t, err)
	require.Len(t, resp.GetRevocations(), 1)
	assert.Equal(t, "jti-victim-1", resp.GetRevocations()[0].GetTokenJti())
}

// …and it holds where the model is absent entirely. Asserted rather than merely
// stated in a comment: the ordering that makes it true — self decided before the
// port is looked at — is invisible at the call site and one reordering away from
// being false.
func TestListByUser_Self_IsServedWithNoRelationPortAtAll(t *testing.T) {
	store := victimHistory()
	h := newHandler(&fakeRevoker{}, store) // deliberately no WithRelationStore

	resp, err := listByUser(t, h, asUser(victimID), victimID)

	require.NoError(t, err, "a user could not read their own session history")
	require.Len(t, resp.GetRevocations(), 1)
}

// A delegate explicitly granted the read on that user is served. Without this the
// refusal above would be satisfied by a gate that denies everyone.
func TestListByUser_GrantedDelegate_IsServed(t *testing.T) {
	store := victimHistory()
	h := newHandler(&fakeRevoker{}, store).WithRelationStore(
		grants("user:" + neighbourID + "|viewer|iam_user:" + victimID))

	resp, err := listByUser(t, h, asUser(neighbourID), victimID)

	require.NoError(t, err)
	require.Len(t, resp.GetRevocations(), 1)
}

// The cloud administrator reads anything — the emergency path must not depend on
// a per-object grant having been materialised.
func TestListByUser_ClusterAdmin_IsServed(t *testing.T) {
	store := victimHistory()
	h := newHandler(&fakeRevoker{}, store).WithRelationStore(
		grants("user:" + neighbourID + "|system_admin|cluster:" + domain.ClusterSingletonID))

	resp, err := listByUser(t, h, asUser(neighbourID), victimID)

	require.NoError(t, err)
	require.Len(t, resp.GetRevocations(), 1)
}

// ── the unconditional cut ───────────────────────────────────────────────────

// An unnamed caller is refused whether or not the model is wired. There is no
// per-RPC check behind this RPC to fall back on, so tying the cut to the port
// being present would hand the history to anyone the day the port is absent.
func TestListByUser_Anonymous_IsRefusedWithAndWithoutRelationPort(t *testing.T) {
	for name, wire := range map[string]bool{"port wired": true, "port absent": false} {
		t.Run(name, func(t *testing.T) {
			store := victimHistory()
			h := newHandler(&fakeRevoker{}, store)
			if wire {
				h = h.WithRelationStore(grants())
			}

			_, err := listByUser(t, h, context.Background(), victimID)

			require.Error(t, err, "an unidentified caller was served another user's session history")
			assert.Equal(t, codes.NotFound, status.Code(err))
			assert.Zero(t, store.reads)
		})
	}
}

// ── fail-closed on a model that cannot answer ───────────────────────────────

// "The model did not answer" is not "the model said no", and neither is it "yes".
// It is reported as an outage the caller may retry — never as a 404, which is a
// claim the caller acts on.
func TestListByUser_RelationStoreError_IsUnavailableNotADenialAndNotTheRows(t *testing.T) {
	store := victimHistory()
	h := newHandler(&fakeRevoker{}, store).WithRelationStore(
		&scriptedChecker{err: errors.New("dial tcp: connection refused")})

	resp, err := listByUser(t, h, asUser(neighbourID), victimID)

	require.Error(t, err)
	assert.Nil(t, resp.GetRevocations())
	assert.Equal(t, codes.Unavailable, status.Code(err))
	assert.NotContains(t, status.Convert(err).Message(), "connection refused",
		"the transport detail must not leak through the status message")
	assert.Zero(t, store.reads)
}

// A deployment with no rights model wired is a POSTURE fact, not an answer. It is
// refused loudly and named, so that "nobody has access" cannot be mistaken for a
// correct model and quietly repaired by removing this gate.
func TestListByUser_RelationPortUnwired_RefusesAndNamesThePosture(t *testing.T) {
	store := victimHistory()
	h := newHandler(&fakeRevoker{}, store) // no WithRelationStore

	_, err := listByUser(t, h, asUser(neighbourID), victimID)

	require.Error(t, err, "with no rights model wired the history was served anyway")
	assert.Equal(t, codes.PermissionDenied, status.Code(err))
	assert.Contains(t, status.Convert(err).Message(), "not configured",
		"an unconfigured rights model must be distinguishable from a model that said no")
	assert.Zero(t, store.reads)
}

// ── ordering: the caller's own errors still come first ──────────────────────

// A malformed page is the caller's error and stays reportable as such: the
// authorization decision must not swallow it into a 404, or a caller who IS
// allowed can never learn why their page was rejected.
func TestListByUser_PageValidationStillPrecedesAuthorization(t *testing.T) {
	h := newHandler(&fakeRevoker{}, victimHistory()).WithRelationStore(grants())

	_, err := h.ListByUser(asUser(neighbourID), &iamv1.ListByUserRequest{
		UserId:   victimID,
		PageSize: 100_000,
	})

	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}
