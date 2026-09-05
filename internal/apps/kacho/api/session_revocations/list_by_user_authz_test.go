// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
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
	checker := grants()
	h := newHandler(&fakeRevoker{}, store).WithRelationStore(checker)

	resp, err := listByUser(t, h, asUser(neighbourID), victimID)

	require.Error(t, err, "a neighbour asked for another user's session history and was served")
	assert.Nil(t, resp.GetRevocations())
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Equal(t, "User "+victimID+" not found", status.Convert(err).Message(),
		"the refusal must read exactly like the owner's own miss — a distinguishable text is an existence oracle")
	assert.Zero(t, store.reads,
		"the revocation store was read for a caller who may not read it")

	// The question that was actually put to the model — not merely that SOME
	// question was. A gate asking about the wrong object refuses just as
	// convincingly and narrows nothing: the object has to be the user the
	// request named, and the subject the caller who asked.
	assert.Contains(t, checker.asked,
		"user:"+neighbourID+"|"+listByUserRelation+"|iam_user:"+victimID,
		"the model was never asked whether this caller may read THIS user")
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

// Holding the READ TIER on that user no longer opens the session history.
//
// This assertion is INVERTED, not removed. It used to read "a delegate granted
// the read on that user is served", and under #797 that was correct: this RPC
// was gated by `iam_user.viewer`, so the tier was the grant. #1140 narrowed the
// gate to `session_reader` — a session history is information ABOUT A PERSON,
// not a right over their account, and identity is global here, so a tier held
// inside one account disclosed the person's history across all of them. From
// that moment the old assertion pinned behaviour the owner's decision had
// overturned: it went green on the wrong answer and red on the right one.
//
// Removing it would have guarded nothing — putting the tier back is one line of
// the model, and it would pass in silence. So it now states the opposite, with
// both controls that keep the refusal from being vacuous:
//
//   - the model WAS consulted, and about the narrowed relation — so the refusal
//     is a decision, not a request cut short somewhere earlier;
//   - the tier this caller genuinely holds is never even ASKED about, which is
//     what "the gate moved off the tier" means observably.
//
// That the gate is not simply "deny everyone" is held by its neighbours:
// TestListByUser_ClusterAdmin_IsServed goes through the model and is served,
// TestListByUser_Self_IsServed is served ahead of it.
func TestListByUser_ReadTierHolderOnThatUser_IsRefused(t *testing.T) {
	store := victimHistory()
	// Exactly what a delegated account steward ends up holding on a member's
	// identity row, and exactly what used to gate this RPC.
	checker := grants("user:" + neighbourID + "|viewer|iam_user:" + victimID)
	h := newHandler(&fakeRevoker{}, store).WithRelationStore(checker)

	resp, err := listByUser(t, h, asUser(neighbourID), victimID)

	require.Error(t, err,
		"the read tier on a user still hands over that user's session history: "+
			"whoever administers one of their accounts reads sessions from all of them")
	assert.Nil(t, resp.GetRevocations())
	assert.Equal(t, codes.NotFound, status.Code(err))
	assert.Equal(t, "User "+victimID+" not found", status.Convert(err).Message(),
		"the refusal must read exactly like the owner's own miss")
	assert.Zero(t, store.reads,
		"the revocation store was read for a caller who may not read it")

	assert.Contains(t, checker.asked,
		"user:"+neighbourID+"|"+listByUserRelation+"|iam_user:"+victimID,
		"the model was not asked about the narrowed relation — then the refusal above is "+
			"not a decision and this probe is vacuous")
	assert.NotContains(t, checker.asked, "user:"+neighbourID+"|viewer|iam_user:"+victimID,
		"the read tier was still put to the model: the gate has not actually moved off it")
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
