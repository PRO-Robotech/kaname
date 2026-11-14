// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"errors"
	"fmt"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/stretchr/testify/require"
)

func TestInviteDecisionIntentIsBoundToAuthenticatedActor(t *testing.T) {
	for _, typ := range []string{"user", "service_account"} {
		t.Run(typ, func(t *testing.T) {
			id := "usr_actor"
			if typ == "service_account" {
				id = "sva_actor"
			}
			ctx := operations.WithPrincipal(context.Background(), operations.Principal{Type: typ, ID: id})
			in := kaname.InviteDecisionIntent{Actor: domain.Subject{Type: domain.SubjectType(typ), ID: domain.SubjectID(id)}, CandidateUserID: "usr_candidate", AccountID: "acc_account", Email: "new@example.invalid", GrantedBy: domain.UserID(id)}
			if typ == "user" {
				in.InvitedBy = domain.UserID(id)
			}
			require.NoError(t, validateInviteIntent(ctx, in))
			forged := in
			forged.Actor.ID = "usr_other"
			require.ErrorIs(t, validateInviteIntent(ctx, forged), iamerr.ErrPermissionDenied)
			forged = in
			forged.GrantedBy = "usr_other"
			require.ErrorIs(t, validateInviteIntent(ctx, forged), iamerr.ErrPermissionDenied)
			forged = in
			forged.ProjectID = "prj_project"
			require.ErrorIs(t, validateInviteIntent(ctx, forged), kaname.ErrInvalidAuthorityFencePlan)
			forged = in
			forged.CandidateUserID = "sva_wrong_kind"
			require.ErrorIs(t, validateInviteIntent(ctx, forged), kaname.ErrInvalidAuthorityFencePlan)
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			require.ErrorIs(t, validateInviteIntent(canceled, in), context.Canceled)
		})
	}
}
func TestInviteDecisionRootsDeclareOptionalCapabilityBeforeDiscovery(t *testing.T) {
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_actor"}
	q := newNativePolicyQuestions()
	require.NoError(t, q.invite(actor, "acc_account", "prj_project", "rol_role"))
	roots, err := q.ordered(context.Background())
	require.NoError(t, err)
	require.Len(t, roots, 7)
	for _, rel := range []string{"editor", "admin", "owner"} {
		_, found := q.roots[nativePolicyQuestion{"user:usr_actor", rel, "account", "acc_account"}]
		require.True(t, found)
	}
	_, found := q.roots[nativePolicyQuestion{"user:usr_actor", "admin", "project", "prj_project"}]
	require.True(t, found)
	base := newNativePolicyQuestions()
	require.NoError(t, base.invite(actor, "acc_account", "", ""))
	require.Len(t, base.roots, 4)
}
func TestInviteEditorUnknownProvenanceDoesNotBecomeOrdinaryAllow(t *testing.T) {
	s := &inviteAccountSources{}
	for _, fact := range []relverdict.AdministrativeFact{{QuestionRelation: "editor"}, {ObjectType: "account", ObjectID: "a", Relation: "editor", Subject: "user:u", ConditionName: "time_between"}, {ObjectType: "account", ObjectID: "a", Relation: "editor", Subject: "user:u", ConditionParameters: map[string]any{"unknown": true}}, {ObjectType: "account", ObjectID: "a", Relation: "editor", Subject: "group:g"}, {ObjectType: "project", ObjectID: "p", Relation: "editor", Subject: "user:u"}, {ObjectType: "account", ObjectID: "a", Relation: "viewer", Subject: "user:u"}} {
		ok, err := s.verify(context.Background(), fact, &relverdict.AdministrativeReadBudget{})
		require.False(t, ok)
		require.ErrorIs(t, err, relverdict.ErrAdministrativeSourceUnconfirmed)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ok, err := s.verify(ctx, relverdict.AdministrativeFact{}, nil)
	require.False(t, ok)
	require.ErrorIs(t, err, context.Canceled)
}
func TestInviteDecisionMissingRunnerAndPrivateBindingCopy(t *testing.T) {
	var runner *InviteDecisions
	called := false
	err := runner.RunInviteDecision(context.Background(), kaname.InviteDecisionIntent{}, func(context.Context, kaname.InviteMutationWriter, kaname.PreparedInvite) error {
		called = true
		return nil
	})
	require.Error(t, err)
	require.False(t, called)
	p := &preparedInvite{binding: domain.AccessBinding{Subjects: []domain.Subject{{Type: domain.SubjectTypeUser, ID: "usr_recipient"}}}}
	copy := p.Binding()
	copy.Subjects[0].ID = "usr_actor"
	require.Equal(t, domain.SubjectID("usr_recipient"), p.Binding().Subjects[0].ID)
	err = &inviteCleanupError{context.Canceled}
	require.ErrorIs(t, err, context.Canceled)
}

// Подмена ограничена ошибкой физического entry/cleanup, разрешения не подменяются.
type inviteEntryFaultTx struct {
	pgx.Tx
	rollback func(context.Context) error
}

func (t inviteEntryFaultTx) Rollback(ctx context.Context) error { return t.rollback(ctx) }

func TestInviteDecisionEntryCleanupIsTerminal(t *testing.T) {
	for _, code := range []string{"P1034", "40001"} {
		for _, canceled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s_cancel_%v", code, canceled), func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				cleanupErr := errors.New("rollback transport failure")
				sqlErr := &pgconn.PgError{Code: code}
				begins, entries, rollbacks := 0, 0, 0
				err := runInviteAttempts(ctx, func() error {
					_, e := enterInviteWriter(ctx, func(_ context.Context, opts pgx.TxOptions) (pgx.Tx, error) {
						begins++
						require.Equal(t, pgx.ReadCommitted, opts.IsoLevel)
						return inviteEntryFaultTx{rollback: func(cleanup context.Context) error {
							rollbacks++
							require.NoError(t, cleanup.Err())
							deadline, ok := cleanup.Deadline()
							require.True(t, ok)
							require.LessOrEqual(t, time.Until(deadline), 5*time.Second)
							return cleanupErr
						}}, nil
					}, func(context.Context, pgx.Tx) (*authorityWriteTx, error) {
						entries++
						if canceled {
							cancel()
						}
						return nil, sqlErr
					})
					return e
				})
				var cleanup *inviteCleanupError
				require.ErrorAs(t, err, &cleanup)
				require.ErrorIs(t, err, cleanupErr)
				require.ErrorIs(t, err, sqlErr)
				if canceled {
					require.ErrorIs(t, err, context.Canceled)
				}
				require.Equal(t, 1, begins)
				require.Equal(t, 1, entries)
				require.Equal(t, 1, rollbacks)
			})
		}
	}
}
func TestInviteDecisionEntryRollbackSuccessRestagesAndExhausts(t *testing.T) {
	for _, eventual := range []bool{false, true} {
		t.Run(fmt.Sprint(eventual), func(t *testing.T) {
			calls := 0
			err := runInviteAttempts(context.Background(), func() error {
				calls++
				if eventual && calls == 2 {
					return nil
				}
				_, e := enterInviteWriter(context.Background(), func(context.Context, pgx.TxOptions) (pgx.Tx, error) {
					return inviteEntryFaultTx{rollback: func(context.Context) error { return nil }}, nil
				}, func(context.Context, pgx.Tx) (*authorityWriteTx, error) { return nil, &pgconn.PgError{Code: "P1034"} })
				return e
			})
			if eventual {
				require.NoError(t, err)
				require.Equal(t, 2, calls)
			} else {
				require.ErrorIs(t, err, iamerr.ErrAborted)
				require.Equal(t, authorityEntryAttempts, calls)
			}
		})
	}
}
func TestInviteDecisionUnknownCommitIsNotRetried(t *testing.T) {
	calls := 0
	unknown := errors.New("commit outcome unknown")
	err := runInviteAttempts(context.Background(), func() error { calls++; return unknown })
	require.ErrorIs(t, err, unknown)
	require.Equal(t, 1, calls)
}

type inviteSourceRow func(...any) error

func (r inviteSourceRow) Scan(dest ...any) error { return r(dest...) }

type inviteSourceRows struct {
	pgx.Rows
	keys     [][3]string
	at       int
	subjects bool
}

func (r *inviteSourceRows) Next() bool { r.at++; return r.at <= len(r.keys) }
func (r *inviteSourceRows) Scan(dest ...any) error {
	if r.subjects {
		*dest[0].(*domain.SubjectType) = domain.SubjectTypeUser
		*dest[1].(*domain.SubjectID) = "usr_actor"
		return nil
	}
	for i := range dest {
		*dest[i].(*string) = r.keys[r.at-1][i]
	}
	return nil
}
func (*inviteSourceRows) Close()     {}
func (*inviteSourceRows) Err() error { return nil }

// SQL fixture проверяет весь реальный bindingProduces(system) и обход страниц;
// разрешения интеграционного runner проверяются отдельно на настоящем PostgreSQL.
type inviteSourceTx struct {
	pgx.Tx
	queries, pages int
	tail           error
	cancel         context.CancelFunc
}

func (tx *inviteSourceTx) QueryRow(_ context.Context, query string, args ...any) pgx.Row {
	tx.queries++
	if strings.Contains(query, "SELECT EXISTS") {
		return inviteSourceRow(func(dest ...any) error { *dest[0].(*bool) = true; return nil })
	}
	return inviteSourceRow(func(dest ...any) error {
		for _, d := range dest {
			v := reflect.ValueOf(d).Elem()
			v.Set(reflect.Zero(v.Type()))
		}
		*dest[0].(*string) = string(args[0].(domain.AccessBindingID))
		*dest[1].(*string) = "user"
		*dest[2].(*string) = "usr_actor"
		*dest[4].(*string) = "account"
		*dest[5].(*string) = "acc_account"
		*dest[6].(*string) = "ACTIVE"
		*dest[14].(*[]byte) = []byte(`{}`)
		*dest[15].(*[]byte) = []byte(`{"allInScope":true}`)
		*dest[16].(*string) = "editor"
		*dest[17].(*bool) = true
		return nil
	})
}
func (tx *inviteSourceTx) Query(_ context.Context, query string, _ ...any) (pgx.Rows, error) {
	tx.queries++
	if strings.Contains(query, "access_binding_subjects") {
		return &inviteSourceRows{keys: make([][3]string, 1), subjects: true}, nil
	}
	tx.pages++
	if tx.pages == 2 {
		if tx.cancel != nil {
			tx.cancel()
		}
		return &inviteSourceRows{}, tx.tail
	}
	keys := make([][3]string, 256)
	for i := range keys {
		keys[i] = [3]string{fmt.Sprintf("acb_%04d", i), "account", "acc_account"}
	}
	return &inviteSourceRows{keys: keys}, nil
}
func TestInviteAccountEditorCompleteTailAndSharedBudget(t *testing.T) {
	for _, mode := range []string{"complete", "tail_error", "tail_cancel", "shared_exhausted", "already_exhausted"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			tail := errors.New("ledger tail unavailable")
			tx := &inviteSourceTx{}
			if mode == "tail_error" {
				tx.tail = tail
			}
			if mode == "tail_cancel" {
				tx.cancel = cancel
			}
			s := &inviteAccountSources{nativeAdministrativeSources: nativeAdministrativeSources{w: &authorityWriteTx{writeTx: &writeTx{readTx: readTx{tx: tx}}, fence: authorityFence{mode: kaname.AuthorityFenceGlobal, decisionAt: time.Now()}}}, actor: domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_actor"}}
			budget := &relverdict.AdministrativeReadBudget{}
			if mode == "shared_exhausted" {
				require.NoError(t, budget.Charge(0, 4096-514))
			}
			if mode == "already_exhausted" {
				require.NoError(t, budget.Charge(0, 4096))
			}
			allowed, err := s.verify(ctx, relverdict.AdministrativeFact{ObjectType: "account", ObjectID: "acc_account", Relation: "editor", Subject: "user:usr_actor"}, budget)
			switch mode {
			case "complete":
				require.NoError(t, err)
				require.True(t, allowed)
				require.Equal(t, 2, tx.pages)
			case "tail_error":
				require.ErrorIs(t, err, tail)
				require.False(t, allowed)
				require.Equal(t, 2, tx.pages)
			case "tail_cancel":
				require.ErrorIs(t, err, context.Canceled)
				require.False(t, allowed)
				require.Equal(t, 2, tx.pages)
			case "shared_exhausted":
				require.ErrorIs(t, err, relverdict.ErrAdministrativeSourceLimit)
				require.False(t, allowed)
				require.Equal(t, 1, tx.pages)
				require.Equal(t, 514, tx.queries)
			case "already_exhausted":
				require.ErrorIs(t, err, relverdict.ErrAdministrativeSourceLimit)
				require.False(t, allowed)
				require.Zero(t, tx.queries)
			}
		})
	}
}

func TestInviteDecisionPreparedBindingCannotChangeAxes(t *testing.T) {
	in := kaname.InviteDecisionIntent{AccountID: "acc_account", ProjectID: "prj_project", RoleID: "rol_role", BindingID: "acb_binding", GrantedBy: "usr_actor"}
	p := &preparedInvite{recipient: "usr_recipient", binding: inviteBinding(in, "usr_recipient")}
	writer := &inviteBindingWriter{prepared: p}
	for _, axis := range []string{"binding", "role", "project", "subject", "target", "audit"} {
		t.Run(axis, func(t *testing.T) {
			b := p.Binding()
			switch axis {
			case "binding":
				b.ID = "acb_other"
			case "role":
				b.RoleID = "rol_other"
			case "project":
				b.ResourceID = "prj_other"
			case "subject":
				b.Subjects[0].ID = "usr_other"
			case "target":
				b.Target.AllInScope = false
			case "audit":
				b.GrantedByUserID = "usr_other"
			}
			_, err := writer.Insert(context.Background(), b)
			require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
		})
	}
}
