// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"strings"
	"testing"
	"time"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/authzplan"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/fga_outbox"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func TestUserTokenIssueAuthorityRejectsChangedDecisionModel(t *testing.T) {
	for _, tc := range []struct{ declaration, changed string }{
		{"define token_issuer: subject", "define token_issuer: subject or admin"},
		{"define subject: [user]", "define subject: [user, service_account]"},
		{"define system_admin: [user, service_account]", "define system_admin: [user]"},
	} {
		model, err := authzplan.ParseModel(strings.ReplaceAll(authzmodel.DSL, tc.declaration, tc.changed))
		require.NoError(t, err)
		require.ErrorIs(t, validateUserTokenIssueModel(model), kaname.ErrSourceUnconfirmed)
	}
}

func TestUserTokenIssueAuthorityBindsBothQuestionsAndCanonicalSelf(t *testing.T) {
	owner := domain.UserID(ids.NewID(domain.PrefixUser))
	bundle := nativeBoundaryBundle(t)
	for _, typ := range []string{"user", "service_account"} {
		actor := domain.Subject{Type: domain.SubjectType(typ), ID: domain.SubjectID(owner)}
		ctx := operations.WithPrincipal(context.Background(), operations.Principal{Type: typ, ID: string(owner)})
		questions := newNativePolicyQuestions()
		_, err := prepareUserTokenIssueAuthority(context.Background(), bundle, actor, owner, questions)
		require.ErrorIs(t, err, iamerr.ErrPermissionDenied)
		require.Empty(t, questions.roots)
		a, err := prepareUserTokenIssueAuthority(ctx, bundle, actor, owner, questions)
		require.NoError(t, err)
		subject := typ + ":" + string(owner)
		require.Len(t, questions.roots, 2)
		require.Contains(t, questions.roots, nativePolicyQuestion{subject, "token_issuer", "iam_user", string(owner)})
		require.Contains(t, questions.roots, nativePolicyQuestion{subject, "system_admin", "cluster", domain.ClusterSingletonID})
		f := relverdict.AdministrativeFact{ObjectType: "iam_user", ObjectID: string(owner), Relation: "subject", Subject: subject, QuestionRelation: "token_issuer", QuestionSubject: subject, QuestionObjectType: "iam_user", QuestionObjectID: string(owner)}
		allowed, err := a.verify(nil, ctx, f, nil)
		require.NoError(t, err)
		require.Equal(t, typ == "user", allowed)
		f.QuestionObjectID = ids.NewID(domain.PrefixUser)
		allowed, err = a.verify(nil, ctx, f, nil)
		require.False(t, allowed)
		require.ErrorIs(t, err, relverdict.ErrAdministrativeSourceUnconfirmed)
		f = relverdict.AdministrativeFact{QuestionSubject: subject, QuestionRelation: "system_admin", QuestionObjectType: "cluster", QuestionObjectID: domain.ClusterSingletonID, ObjectType: "cluster", ObjectID: domain.ClusterSingletonID, Relation: "system_admin", Subject: "group:grp_fixture#member"}
		allowed, err = a.verify(nil, ctx, f, nil)
		require.NoError(t, err)
		require.False(t, allowed)

		require.ErrorIs(t, a.evaluate(ctx, &authorityWriteTx{}), kaname.ErrSourceUnconfirmed)
	}
}

func TestUserTokenIssueAuthorityRequiresHeldQuestionsAndOneBudget(t *testing.T) {
	bundle := nativeBoundaryBundle(t)
	id := ids.NewID(domain.PrefixUser)
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(id)}
	ctx := operations.WithPrincipal(context.Background(), operations.Principal{Type: "user", ID: id})
	q := newNativePolicyQuestions()
	a, err := prepareUserTokenIssueAuthority(ctx, bundle, actor, domain.UserID(id), q)
	require.NoError(t, err)
	capture, err := captureNativeReadBoundary(ctx, bundle, q, nativeBoundaryGraph(), &nativeReadBudget{})
	require.NoError(t, err)
	type noSQL struct{ pgx.Tx }
	budget := &relverdict.AdministrativeReadBudget{}
	w := &authorityWriteTx{
		writeTx:        &writeTx{readTx: readTx{tx: noSQL{}}},
		fence:          authorityFence{mode: kaname.AuthorityFenceGlobal, decisionAt: time.Unix(1, 0)},
		producerBudget: budget, nativeRead: &protectedNativeRead{boundary: capture, global: true, budget: budget},
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	require.ErrorIs(t, a.evaluate(canceled, w), context.Canceled)
	require.ErrorIs(t, a.evaluate(context.Background(), w), iamerr.ErrPermissionDenied)
	other := operations.WithPrincipal(context.Background(), operations.Principal{Type: "service_account", ID: id})
	require.ErrorIs(t, a.evaluate(other, w), iamerr.ErrPermissionDenied)
	w.closed = true
	require.ErrorIs(t, a.evaluate(ctx, w), kaname.ErrSourceUnconfirmed)
	w.closed = false
	w.producerBudget = &relverdict.AdministrativeReadBudget{}
	require.ErrorIs(t, a.evaluate(ctx, w), kaname.ErrSourceUnconfirmed)
	w.producerBudget = budget
	capture.bundle = nativeBoundaryBundle(t)
	require.ErrorIs(t, a.evaluate(ctx, w), kaname.ErrSourceUnconfirmed)
	capture.bundle = bundle
	delete(capture.questions, nativePolicyQuestion{"user:" + id, "system_admin", "cluster", domain.ClusterSingletonID})
	require.ErrorIs(t, a.evaluate(ctx, w), kaname.ErrSourceUnconfirmed)
}

// Проверяем только слой решения: физическая TX и native readers настоящие.
// Часы и границу двух вопросов задаёт проба; блокировки writer проверяются
// при отдельном подключении token-specific preflight к commitMapping.
func TestUserTokenIssueAuthorityCurrentSources(t *testing.T) {
	if testing.Short() {
		t.Skip("requires PostgreSQL")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pgtest.NewDB(t))
	require.NoError(t, err)
	defer pool.Close()
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	target, human := ids.NewID(domain.PrefixUser), ids.NewID(domain.PrefixUser)
	for _, id := range []string{target, human} {
		_, err = tx.Exec(ctx, `INSERT INTO kaname.users(id,account_id,external_id,email,display_name,invite_status,email_verified_at)
SELECT $1,id,$1,$1||'@example.invalid',$1,'ACTIVE',clock_timestamp() FROM kaname.accounts ORDER BY id LIMIT 1`, id)
		require.NoError(t, err)
	}
	require.NoError(t, fga_outbox.EmitWriteTx(ctx, tx, []clients.RelationTuple{
		{User: "user:" + target, Relation: "subject", Object: "iam_user:" + target},
	}))
	bundle := nativeBoundaryBundle(t)
	var at time.Time
	require.NoError(t, tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at))
	evaluate := func(typ, id string, at time.Time, exhausted bool) error {
		call := operations.WithPrincipal(ctx, operations.Principal{Type: typ, ID: id})
		questions := newNativePolicyQuestions()
		a, e := prepareUserTokenIssueAuthority(call, bundle, domain.Subject{Type: domain.SubjectType(typ), ID: domain.SubjectID(id)}, domain.UserID(target), questions)
		require.NoError(t, e)
		budget := &relverdict.AdministrativeReadBudget{}
		capture, e := captureNativeReadBoundary(call, bundle, questions, nativePolicyReadSnapshot{tx}, &nativeReadBudget{shared: budget})
		require.NoError(t, e)
		w := &authorityWriteTx{writeTx: &writeTx{readTx: readTx{tx: tx}}, fence: authorityFence{mode: kaname.AuthorityFenceGlobal, decisionAt: at}, producerBudget: budget, nativeRead: &protectedNativeRead{boundary: capture, global: true, budget: budget}}
		if exhausted {
			require.NoError(t, budget.Charge(0, budget.RemainingReads()))
		}
		return a.evaluate(call, w)
	}
	require.NoError(t, evaluate("user", target, at, false))
	require.ErrorIs(t, evaluate("user", human, at, false), iamerr.ErrPermissionDenied)
	require.ErrorIs(t, evaluate("user", target, at, true), kaname.ErrSourceReadLimit)
	var machine string
	// У посеянной служебной учётки два действительных источника одной выдачи.
	require.NoError(t, tx.QueryRow(ctx, `SELECT b.subject_id FROM kaname.access_bindings b JOIN kaname.cluster_admin_grants g
ON g.subject_type=b.subject_type AND g.subject_id=b.subject_id AND g.cluster_id=b.resource_id
WHERE b.resource_type='cluster' AND b.resource_id=$1 AND b.is_system AND b.role_id IS NULL AND b.granted_relation='system_admin'
AND b.subject_type='service_account' AND b.status='ACTIVE' AND g.granted_until IS NULL LIMIT 1`, domain.ClusterSingletonID).Scan(&machine))
	// Сначала заканчивается прямая выдача, потом независимый roleless holder.
	directEnd, bindingEnd := at.Add(time.Minute), at.Add(2*time.Minute)
	tag, err := tx.Exec(ctx, `UPDATE kaname.cluster_admin_grants SET granted_until=$2 WHERE subject_type='service_account' AND subject_id=$1 AND granted_until IS NULL`, machine, directEnd)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
	tag, err = tx.Exec(ctx, `UPDATE kaname.access_bindings SET expires_at=$2 WHERE subject_type='service_account' AND subject_id=$1 AND granted_relation='system_admin' AND is_system`, machine, bindingEnd)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
	require.NoError(t, evaluate("service_account", machine, directEnd, false))
	require.ErrorIs(t, evaluate("service_account", machine, bindingEnd, false), iamerr.ErrPermissionDenied)

	_, err = tx.Exec(ctx, `INSERT INTO kaname.cluster_admin_grants(id,cluster_id,subject_type,subject_id,granted_by,granted_at,granted_until)
VALUES($1,$2,'user',$3,$3,$4,$5)`, ids.NewID(domain.PrefixClusterAdminGrant), domain.ClusterSingletonID, human, at, directEnd)
	require.NoError(t, err)
	require.NoError(t, fga_outbox.EmitWriteTx(ctx, tx, []clients.RelationTuple{{User: "user:" + human, Relation: "system_admin", Object: authzguard.ClusterObject()}}))
	require.NoError(t, evaluate("user", human, at, false))
	require.ErrorIs(t, evaluate("user", human, directEnd, false), iamerr.ErrPermissionDenied)
}
