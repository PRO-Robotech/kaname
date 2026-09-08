// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package cluster_test

// machine_subject_revoke_test.go — cluster-admin grants held by a MACHINE
// principal (ServiceAccount) must be revocable through the RPC surface.
//
// Background (security.md "Авторизация живёт в МОДЕЛИ"): the relation model
// permits `cluster:…#system_admin@service_account:<id>` and migration 0058
// SEEDS exactly such a permanent grant for the bootstrap-admin ServiceAccount.
// Every write path of the cluster-grant writer, however, was pinned to
// `subject_type = 'user'`, and both use-cases rejected SERVICE_ACCOUNT with
// InvalidArgument — so the one grant the platform issues to a machine could
// never be taken back through the interface. Granted authority that cannot be
// revoked is the worst failure mode of an access-control surface.
//
// These are use-case-level unit tests (no Postgres): they drive Execute with
// fake ports and assert the OBSERVABLE contract — the subject type reaches the
// writer, and the emitted relation tuple names the machine subject
// (`service_account:<id>`, not `user:<id>`, which would be a tuple that never
// matches and therefore a revoke that silently does nothing).
//
// The SQL side is locked by the handler integration test
// (TestCluster_6_20_RevokeAdmin_BootstrapServiceAccountGrant).

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	clusterapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/cluster"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// validServiceAccount — a well-formed `sva…` id (3-char prefix + 17 Crockford
// base32 chars), the same shape migration 0058 seeds.
const validServiceAccount = "sva0000000000000000a"

// ── fake ports ───────────────────────────────────────────────────────────────

// fakeTx — no-op service.Tx.
type fakeTx struct{ committed bool }

func (f *fakeTx) Commit(context.Context) error   { f.committed = true; return nil }
func (f *fakeTx) Rollback(context.Context) error { return nil }

// fakeTxBeginner — hands out a single fakeTx.
type fakeTxBeginner struct{ tx *fakeTx }

func (f *fakeTxBeginner) Begin(context.Context) (service.Tx, error) {
	if f.tx == nil {
		f.tx = &fakeTx{}
	}
	return f.tx, nil
}

// recordingGrantWriter — records the arguments each write port receives so the
// test can assert the subject TYPE actually crosses the port boundary.
type recordingGrantWriter struct {
	revokeSubjectType domain.GrantSubjectType
	revokeSubjectID   domain.SubjectID
	revokeCalled      bool

	grantSubjectType domain.GrantSubjectType
	grantSubjectID   domain.SubjectID
	grantCalled      bool
}

func (r *recordingGrantWriter) Grant(
	_ context.Context, _ service.Tx,
	subjectType domain.GrantSubjectType, subject domain.SubjectID, grantedBy string,
) (domain.ClusterAdminGrant, bool, error) {
	r.grantCalled = true
	r.grantSubjectType = subjectType
	r.grantSubjectID = subject
	return domain.ClusterAdminGrant{
		ID:          "cag_test",
		SubjectType: subjectType,
		SubjectID:   subject,
		GrantedBy:   grantedBy,
	}, true, nil
}

func (r *recordingGrantWriter) Revoke(
	_ context.Context, _ service.Tx,
	subjectType domain.GrantSubjectType, subject domain.SubjectID, _ string,
) (domain.ClusterAdminGrant, error) {
	r.revokeCalled = true
	r.revokeSubjectType = subjectType
	r.revokeSubjectID = subject
	return domain.ClusterAdminGrant{
		ID:          "cag_test",
		SubjectType: subjectType,
		SubjectID:   subject,
	}, nil
}

func (r *recordingGrantWriter) Reactivate(
	_ context.Context, _ service.Tx,
	subjectType domain.GrantSubjectType, subject domain.SubjectID, grantedBy string,
) (domain.ClusterAdminGrant, error) {
	return domain.ClusterAdminGrant{
		ID:          "cag_test",
		SubjectType: subjectType,
		SubjectID:   subject,
		GrantedBy:   grantedBy,
	}, nil
}

// recordingRelationEmitter — captures the tuples emitted into fga_outbox.
type recordingRelationEmitter struct {
	written []service.RelationTuple
	deleted []service.RelationTuple
}

func (r *recordingRelationEmitter) EmitWriteTx(_ context.Context, _ service.Tx, tuples []service.RelationTuple) error {
	r.written = append(r.written, tuples...)
	return nil
}

func (r *recordingRelationEmitter) EmitDeleteTx(_ context.Context, _ service.Tx, tuples []service.RelationTuple) error {
	r.deleted = append(r.deleted, tuples...)
	return nil
}

// noopOpsRepo — operations.Repo stub. The cluster use-cases touch Create /
// MarkDone / MarkDoneWithMetadata / MarkError; every one is stubbed explicitly
// (embedding the interface and overriding only some methods leaves the rest as
// a nil-panic waiting to happen).
type noopOpsRepo struct{ operations.Repo }

func (noopOpsRepo) Create(context.Context, operations.Operation) error { return nil }
func (noopOpsRepo) MarkDone(context.Context, string, *anypb.Any) error { return nil }
func (noopOpsRepo) MarkDoneWithMetadata(context.Context, string, *anypb.Any, *anypb.Any) error {
	return nil
}
func (noopOpsRepo) MarkError(context.Context, string, *statuspb.Status) error {
	return nil
}

// ── RevokeAdmin: machine subject ─────────────────────────────────────────────

// TestRevokeAdmin_ServiceAccountSubject_IsRevocable — a cluster-admin grant
// held by a ServiceAccount must be revocable. Before the fix the use-case
// rejected SERVICE_ACCOUNT outright with InvalidArgument
// ("only 'user' supported in this version"), which made the migration-seeded
// bootstrap grant permanent and unrevocable through the interface.
func TestRevokeAdmin_ServiceAccountSubject_IsRevocable(t *testing.T) {
	chk := &fakeAdminChecker{allow: true}
	w := &recordingGrantWriter{}
	rel := &recordingRelationEmitter{}

	uc := clusterapp.NewRevokeAdminUseCase(w, rel, &fakeTxBeginner{}, noopOpsRepo{}).
		WithAdminChecker(chk)

	op, err := uc.Execute(ctxUser(validUserA),
		iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT, validServiceAccount)

	require.NoError(t, err,
		"a cluster-admin grant held by a ServiceAccount must be revocable through the RPC")
	require.NotNil(t, op)
	require.True(t, op.GetDone())

	require.True(t, w.revokeCalled, "the revoke must reach the writer")
	require.Equal(t, domain.GrantSubjectTypeServiceAccount, w.revokeSubjectType,
		"the machine subject type must cross the port boundary — a writer pinned to "+
			"'user' silently matches no row and revokes nothing")
	require.EqualValues(t, validServiceAccount, w.revokeSubjectID)
}

// TestRevokeAdmin_ServiceAccountSubject_EmitsMachineTuple — the relation tuple
// removed on revoke must name the MACHINE subject. Emitting `user:<sva…>`
// would delete a tuple that never existed: the DB row would flip to revoked
// while the relation backend kept granting cluster-admin — a revoke that
// reports success and takes nothing away.
func TestRevokeAdmin_ServiceAccountSubject_EmitsMachineTuple(t *testing.T) {
	chk := &fakeAdminChecker{allow: true}
	rel := &recordingRelationEmitter{}

	uc := clusterapp.NewRevokeAdminUseCase(&recordingGrantWriter{}, rel, &fakeTxBeginner{}, noopOpsRepo{}).
		WithAdminChecker(chk)

	_, err := uc.Execute(ctxUser(validUserA),
		iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT, validServiceAccount)
	require.NoError(t, err)

	require.Len(t, rel.deleted, 1, "exactly one system_admin tuple must be removed")
	require.Equal(t, "service_account:"+validServiceAccount, rel.deleted[0].User,
		"the removed tuple must name the machine subject, not user:<sva…>")
	require.Equal(t, "system_admin", rel.deleted[0].Relation)
	require.Equal(t, "cluster:"+domain.ClusterSingletonID, rel.deleted[0].Object)
}

// TestGrantAdmin_ServiceAccountSubject_EmitsMachineTuple — symmetry: granting
// to a machine subject writes `service_account:<id>`. Asymmetric grant/revoke
// (grant writes one tuple shape, revoke deletes another) is how an
// unrevocable grant is manufactured, so both directions are locked.
func TestGrantAdmin_ServiceAccountSubject_EmitsMachineTuple(t *testing.T) {
	chk := &fakeAdminChecker{allow: true}
	w := &recordingGrantWriter{}
	rel := &recordingRelationEmitter{}

	// Состояние субъекта названо явно: проверка состояния — не «необязательная»,
	// непровязанная она отказывает, поэтому фикстура обязана его нести.
	uc := clusterapp.NewGrantAdminUseCase(w, nil, rel, &fakeTxBeginner{}, noopOpsRepo{}).
		WithAdminChecker(chk).
		WithSubjectStateReader(&fakeSubjectState{saEnabled: true})

	_, err := uc.Execute(ctxUser(validUserA),
		iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT, validServiceAccount)
	require.NoError(t, err)

	require.True(t, w.grantCalled)
	require.Equal(t, domain.GrantSubjectTypeServiceAccount, w.grantSubjectType)
	require.Len(t, rel.written, 1)
	require.Equal(t, "service_account:"+validServiceAccount, rel.written[0].User)
}

// ── format validation stays per-type ─────────────────────────────────────────

// TestRevokeAdmin_ServiceAccountSubject_RejectsUserShapedID — accepting the
// machine subject type must not turn the id check into a rubber stamp: a
// `usr…` id under SERVICE_ACCOUNT is still malformed.
func TestRevokeAdmin_ServiceAccountSubject_RejectsUserShapedID(t *testing.T) {
	chk := &fakeAdminChecker{allow: true}
	w := &recordingGrantWriter{}

	uc := clusterapp.NewRevokeAdminUseCase(w, &recordingRelationEmitter{}, &fakeTxBeginner{}, noopOpsRepo{}).
		WithAdminChecker(chk)

	_, err := uc.Execute(ctxUser(validUserA),
		iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT, validUserA)
	require.Equal(t, codes.InvalidArgument, status.Code(err),
		"a user-shaped id under SERVICE_ACCOUNT must still be rejected")
	require.False(t, w.revokeCalled, "malformed id must not reach the writer")
}

// TestRevokeAdmin_UserSubject_RejectsServiceAccountShapedID — the mirror case.
func TestRevokeAdmin_UserSubject_RejectsServiceAccountShapedID(t *testing.T) {
	chk := &fakeAdminChecker{allow: true}
	w := &recordingGrantWriter{}

	uc := clusterapp.NewRevokeAdminUseCase(w, &recordingRelationEmitter{}, &fakeTxBeginner{}, noopOpsRepo{}).
		WithAdminChecker(chk)

	_, err := uc.Execute(ctxUser(validUserA),
		iamv1.ClusterGrantSubjectType_USER, validServiceAccount)
	require.Equal(t, codes.InvalidArgument, status.Code(err),
		"a machine-shaped id under USER must still be rejected")
	require.False(t, w.revokeCalled)
}

// TestRevokeAdmin_UnspecifiedSubjectType_Rejected — UNSPECIFIED never reaches
// the use-case from the handler (it defaults to USER there), but the use-case
// must not treat an unset enum as a valid type on its own.
func TestRevokeAdmin_UnspecifiedSubjectType_Rejected(t *testing.T) {
	chk := &fakeAdminChecker{allow: true}
	w := &recordingGrantWriter{}

	uc := clusterapp.NewRevokeAdminUseCase(w, &recordingRelationEmitter{}, &fakeTxBeginner{}, noopOpsRepo{}).
		WithAdminChecker(chk)

	_, err := uc.Execute(ctxUser(validUserA),
		iamv1.ClusterGrantSubjectType_CLUSTER_GRANT_SUBJECT_TYPE_UNSPECIFIED, validUserB)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.False(t, w.revokeCalled)
}

// ── regression: the human path is unchanged ──────────────────────────────────

// TestRevokeAdmin_UserSubject_StillEmitsUserTuple — the pre-existing human
// path must be untouched by the machine-subject work.
func TestRevokeAdmin_UserSubject_StillEmitsUserTuple(t *testing.T) {
	chk := &fakeAdminChecker{allow: true}
	w := &recordingGrantWriter{}
	rel := &recordingRelationEmitter{}

	uc := clusterapp.NewRevokeAdminUseCase(w, rel, &fakeTxBeginner{}, noopOpsRepo{}).
		WithAdminChecker(chk)

	_, err := uc.Execute(ctxUser(validUserA), iamv1.ClusterGrantSubjectType_USER, validUserB)
	require.NoError(t, err)

	require.Equal(t, domain.GrantSubjectTypeUser, w.revokeSubjectType)
	require.Len(t, rel.deleted, 1)
	require.Equal(t, "user:"+validUserB, rel.deleted[0].User)
	require.Equal(t, "system_admin", rel.deleted[0].Relation)
	require.Equal(t, "cluster:"+domain.ClusterSingletonID, rel.deleted[0].Object)
}
