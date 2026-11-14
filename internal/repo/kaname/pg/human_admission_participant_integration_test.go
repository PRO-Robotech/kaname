// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
)

// Эти adapters совпадают с фактическими ports loginlane: callback bootstrap
// не заменён тестовым allow и получает тот же MirrorWriter.
type admissionVerificationStore struct {
	sessions *kanamepg.HumanSessionRepo
	inner    *kanamepg.RegistrationStore
}

func (s admissionVerificationStore) Resolve(ctx context.Context, d domain.BearerDigest, now time.Time) (humansession.Resolved, humansession.NoSessionReason, error) {
	return s.sessions.Resolve(ctx, d, now)
}
func (s admissionVerificationStore) VerificationWriter(ctx context.Context, id domain.UserID) (humansession.VerificationWriter, error) {
	w, e := s.inner.VerificationWriter(ctx, id)
	if e != nil {
		return nil, e
	}
	return admissionVerificationWriter{w}, nil
}

type admissionVerificationWriter struct{ *kanamepg.RegistrationWriter }

func (w admissionVerificationWriter) ActivateInviteOnVerification(ctx context.Context, u domain.User) (humansession.InviteActivation, error) {
	return userapp.ActivateInviteForLane(ctx, w.MirrorWriter(), u)
}

type admissionEmailStore struct{ admissionVerificationStore }

func (s admissionEmailStore) EmailChangeWriter(ctx context.Context, id domain.UserID) (humansession.EmailChangeWriter, error) {
	return s.inner.EmailChangeWriter(ctx, id)
}
func admissionPace() humansession.VerificationPace {
	return humansession.VerificationPace{CodeTTL: 30 * time.Minute, Attempts: 5, Interval: time.Minute, Limit: 5, Window: 24 * time.Hour}
}
func admissionLetter(t *testing.T, r protocolRig, uid domain.UserID, kind string) string {
	t.Helper()
	var code string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT payload->>'code' FROM kaname.invite_mail_outbox WHERE event_type=$1 AND payload->>'user_id'=$2 ORDER BY id DESC LIMIT 1`, kind, string(uid)).Scan(&code))
	require.NotEmpty(t, code)
	return code
}
func admissionRegistrar(t *testing.T, r protocolRig, s registration.Store) (*registration.RegisterUseCase, *passwordverify.Hasher, *humansession.PasswordRule) {
	t.Helper()
	hasher, err := passwordverify.NewHasher(passwordverify.Declared{Format: domain.PasswordHashFormatArgon2id, Params: map[domain.PasswordHashCostParam]uint32{domain.CostParamArgon2Memory: 65536, domain.CostParamArgon2Iterations: 3, domain.CostParamArgon2Parallelism: 4}})
	require.NoError(t, err)
	rule, err := humansession.NewPasswordRule(12, nil, humansession.NopObserver{}, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	lane, ok := registration.LaneByName(registration.LanePassword)
	require.True(t, ok)
	uc, err := registration.NewRegisterUseCase(registration.Deps{Store: s, Rule: rule, Hasher: hasher, Lane: lane, TTL: 24 * time.Hour, Now: time.Now, Logger: slog.New(slog.DiscardHandler), CutoffClock: momentclock.Func(time.Now), Letter: admissionPace(), Sources: kanamepg.NewHumanSessionRepo(r.runtime), SourcePace: humansession.SourcePace{Limit: 10000, Window: time.Hour}})
	require.NoError(t, err)
	return uc, hasher, rule
}
func admissionAssertBootstrap(t *testing.T, r protocolRig, id domain.UserID) {
	t.Helper()
	var accounts, bindings, subjects, ledger, intents int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT (SELECT count(*) FROM kaname.accounts WHERE owner_user_id=$1),(SELECT count(*) FROM kaname.access_bindings WHERE subject_type='user' AND subject_id=$1 AND role_id=$2),(SELECT count(*) FROM kaname.access_binding_subjects WHERE subject_type='user' AND subject_id=$1),(SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE fga_user='user:'||$1),(SELECT count(*) FROM kaname.fga_outbox WHERE payload->>'user'='user:'||$1)`, string(id), domain.OwnerRoleID).Scan(&accounts, &bindings, &subjects, &ledger, &intents))
	require.Equal(t, 1, accounts)
	require.Positive(t, bindings)
	require.Positive(t, subjects)
	require.Positive(t, ledger)
	require.Positive(t, intents)
}
func TestHumanAdmissionActualRegistrationVerificationEmailAndRecovery(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(map[bool]string{false: "prepared", true: "strict"}[strict], func(t *testing.T) {
			r := writerProtocolRig(t)
			// Все четыре исхода работают при единственном доступном соединении.
			config := r.runtime.Config()
			config.MaxConns = 1
			single, err := pgxpool.NewWithConfig(r.ctx, config)
			require.NoError(t, err)
			t.Cleanup(single.Close)
			r.runtime = single
			r.repo = kanamepg.New(single, nil)
			p, err := kanamepg.NewHumanAdmissionParticipant(r.ctx, r.repo, r.bundle)
			require.NoError(t, err)
			if strict {
				require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
			}
			store := kanamepg.NewRegistrationStore(r.runtime).WithHumanAdmissionParticipant(p)
			uc, hasher, rule := admissionRegistrar(t, r, regStore{inner: store})
			email := "admission-" + ids.NewID("tst") + "@example.invalid"
			out, err := uc.Execute(r.ctx, registration.Input{Email: email, Password: "correct-horse-battery-staple-9"})
			require.NoError(t, err)
			require.False(t, out.View.EmailVerified)
			admissionAssertBootstrap(t, r, out.View.User.ID)
			sessions := kanamepg.NewHumanSessionRepo(r.runtime)
			verify, err := humansession.NewConfirmVerificationUseCase(humansession.VerificationDeps{Store: admissionVerificationStore{sessions, store}, Pace: admissionPace()})
			require.NoError(t, err)
			code := admissionLetter(t, r, out.View.User.ID, "mail.verification.send")
			bad := "0" + code[1:]
			if bad == code {
				bad = "1" + code[1:]
			}
			_, err = verify.Execute(r.ctx, humansession.ConfirmVerificationInput{Bearer: out.Bearer, Code: bad})
			require.ErrorIs(t, err, humansession.ErrAuthenticationFailed)
			var mark bool
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT email_verified_at IS NOT NULL FROM kaname.users WHERE id=$1`, string(out.View.User.ID)).Scan(&mark))
			require.False(t, mark)
			verified, err := verify.Execute(r.ctx, humansession.ConfirmVerificationInput{Bearer: out.Bearer, Code: code})
			require.NoError(t, err)
			require.True(t, verified.View.EmailVerified)
			deps := humansession.EmailChangeDeps{Store: admissionEmailStore{admissionVerificationStore{sessions, store}}, Methods: kanamepg.NewLoginMethodRepo(r.runtime), Pace: admissionPace(), Freshness: time.Hour, MailLimit: outboxtypes.InviteMailRateLimit{MaxPerWindow: 20, Window: time.Hour}}
			request, err := humansession.NewRequestEmailChangeUseCase(deps)
			require.NoError(t, err)
			newEmail := "changed-" + email
			_, err = request.Execute(r.ctx, humansession.RequestEmailChangeInput{Bearer: verified.Bearer, NewEmail: newEmail})
			require.NoError(t, err)
			confirm, err := humansession.NewConfirmEmailChangeUseCase(deps)
			require.NoError(t, err)
			changed, err := confirm.Execute(r.ctx, humansession.ConfirmEmailChangeInput{Bearer: verified.Bearer, Code: admissionLetter(t, r, out.View.User.ID, "mail.email-change.send")})
			require.NoError(t, err)
			require.Equal(t, domain.Email(newEmail), changed.View.User.Email)
			// Recovery другого неподтверждённого человека исполняет MarkEmailVerified,
			// смену password/session и bootstrap provenance на настоящем четвёртом port.
			secondEmail := "recovery-" + email
			second, err := uc.Execute(r.ctx, registration.Input{Email: secondEmail, Password: "correct-horse-battery-staple-9"})
			require.NoError(t, err)
			require.False(t, second.View.EmailVerified)
			recoveryRequest, err := humansession.NewRequestRecoveryUseCase(humansession.RequestRecoveryDeps{Store: sessions, CodeTTL: 30 * time.Minute, Dispatcher: humansession.SyncDispatcher{}, Sources: sessions, SourcePace: humansession.SourcePace{Limit: 10000, Window: time.Hour}, MailLimit: outboxtypes.InviteMailRateLimit{MaxPerWindow: 20, Window: time.Hour}})
			require.NoError(t, err)
			require.NoError(t, recoveryRequest.Execute(r.ctx, humansession.RequestRecoveryInput{Email: secondEmail}))
			completion, err := kanamepg.NewRecoveryCompletionStore(r.runtime, userapp.ActivateInviteForLane)
			require.NoError(t, err)
			completion = completion.WithHumanAdmissionParticipant(p)
			complete, err := humansession.NewCompleteRecoveryUseCase(humansession.CompleteRecoveryDeps{Store: sessions, Completion: completion, Hasher: hasher, Rule: rule, Limits: humansession.Limits{AddressAttempts: 50, AddressWindow: time.Hour, SourceAttempts: 500, SourceWindow: time.Hour}, TTL: 24 * time.Hour, CutoffClock: momentclock.Func(time.Now)})
			require.NoError(t, err)
			recovered, err := complete.Execute(r.ctx, humansession.CompleteRecoveryInput{Email: secondEmail, Code: admissionLetter(t, r, second.View.User.ID, "mail.recovery.send"), NewPassword: "different-correct-horse-battery-7"})
			require.NoError(t, err)
			require.True(t, recovered.View.EmailVerified)
			admissionAssertBootstrap(t, r, second.View.User.ID)
			authorityWaitReleased(t, r.runtime)
		})
	}
}

func TestHumanAdmissionRecoveryInviteSameTransactionRollback(t *testing.T) {
	r := writerProtocolRig(t)
	owner := bindingPublicOwner(t, r)
	seed, err := lifecycleOwner(r).Writer(r.ctx)
	require.NoError(t, err)
	defer policyFixtureRollback(seed)
	pending, _, err := seed.UsersW().InsertPending(r.ctx, domain.User{ID: domain.UserID(ids.NewID(domain.PrefixUser)), AccountID: domain.AccountID(r.a), Email: "admission-pending@example.invalid", InviteStatus: domain.InviteStatusPending, InvitedBy: domain.UserID(owner)}, time.Now().Add(time.Hour))
	require.NoError(t, err)
	require.NoError(t, seed.Commit(r.ctx))
	p, err := kanamepg.NewHumanAdmissionParticipant(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	store, err := kanamepg.NewRecoveryCompletionStore(r.runtime, userapp.ActivateInviteForLane)
	require.NoError(t, err)
	store = store.WithHumanAdmissionParticipant(p)
	for _, commit := range []bool{false, true} {
		w, err := store.RecoveryCompletionWriter(r.ctx, pending.ID)
		require.NoError(t, err)
		defer policyFixtureRollback(w)
		v, err := domain.NewLoginVerifier("admission-fixture-password-verifier")
		require.NoError(t, err)
		created, err := w.PutLoginVerifier(r.ctx, domain.LoginMethod{UserID: pending.ID, Kind: domain.LoginMethodPassword, Verifier: v, State: domain.LoginMethodStateActive})
		require.NoError(t, err)
		require.True(t, created)
		marked, err := w.MarkEmailVerified(r.ctx, pending.ID, pending.Email, time.Now())
		require.NoError(t, err)
		require.True(t, marked)
		activated, err := w.ActivateInviteOnVerification(r.ctx, pending)
		require.NoError(t, err)
		require.Equal(t, pending.ID, activated.User.ID)
		require.NotEmpty(t, activated.OwnerBindingID)
		if commit {
			require.NoError(t, w.Commit(r.ctx))
			admissionAssertBootstrap(t, r, pending.ID)
		} else {
			// Отказ ПОСЛЕ callback не публикует его owner grant или admission mark.
			require.NoError(t, w.Rollback(r.ctx))
			var status string
			var verified bool
			var owners int
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT invite_status,email_verified_at IS NOT NULL,(SELECT count(*) FROM kaname.accounts WHERE owner_user_id=$1) FROM kaname.users WHERE id=$1`, string(pending.ID)).Scan(&status, &verified, &owners))
			require.Equal(t, "PENDING", status)
			require.False(t, verified)
			require.Zero(t, owners)
		}
	}
	authorityWaitReleased(t, r.runtime)
}

func TestHumanAdmissionGlobalBeforePersonWaitCancellationAndClosedIdentity(t *testing.T) {
	r := writerProtocolRig(t)
	uid := domain.UserID(bindingPublicOwner(t, r))
	p, err := kanamepg.NewHumanAdmissionParticipant(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	store := kanamepg.NewRegistrationStore(r.runtime).WithHumanAdmissionParticipant(p)
	for _, cancelWait := range []bool{true, false} {
		held, err := r.repo.ParticipantAuthorityWriter(r.ctx, r.intent(r.a))
		require.NoError(t, err)
		defer policyFixtureRollback(held)
		account, err := held.Accounts().Get(r.ctx, domain.AccountID(r.a))
		require.NoError(t, err)
		account.Description = "admission-after-wait"
		_, err = held.AccountsW().Update(r.ctx, account, []string{"description"})
		require.NoError(t, err)
		ctx, cancel := context.WithCancel(r.ctx)
		done := make(chan error, 1)
		taken := false
		t.Cleanup(func() {
			cancel()
			if !taken {
				select {
				case <-done:
				case <-time.After(6 * time.Second):
					t.Error("admission waiter не завершился после отмены")
				}
			}
		})
		go func() {
			w, e := store.VerificationWriter(ctx, uid)
			if e == nil {
				defer policyFixtureRollback(w)
				var got domain.Account
				got, e = w.MirrorWriter().Accounts().Get(ctx, domain.AccountID(r.a))
				if e == nil && got.Description != account.Description {
					e = errors.New("post-wait source mismatch")
				}
				if e == nil {
					e = w.Commit(ctx)
				}
			}
			done <- e
		}()
		authorityWaitLock(t, r.ctx, r.admin)
		if cancelWait {
			cancel()
			e := <-done
			taken = true
			require.Error(t, e)
			require.NoError(t, held.Rollback(r.ctx))
		} else {
			require.NoError(t, held.Commit(r.ctx))
			e := <-done
			taken = true
			require.NoError(t, e)
			cancel()
		}
	}
	// Второй вид отмены: entry уже взял GLOBAL, но старая транзакция держит
	// строку личности. Ошибка holdPersonOf освобождает и TX, и GLOBAL.
	blocker, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	defer policyFixtureRollback(blocker)
	var heldID, xid string
	require.NoError(t, blocker.QueryRow(r.ctx, `SELECT id FROM kaname.users WHERE id=$1 FOR UPDATE`, string(uid)).Scan(&heldID))
	require.NoError(t, blocker.QueryRow(r.ctx, `SELECT pg_current_xact_id()::text`).Scan(&xid))
	waiting, cancel := context.WithCancel(r.ctx)
	done := make(chan error, 1)
	taken := false
	t.Cleanup(func() {
		cancel()
		if !taken {
			select {
			case <-done:
			case <-time.After(6 * time.Second):
				t.Error("person waiter не завершился")
			}
		}
	})
	go func() {
		w, e := store.VerificationWriter(waiting, uid)
		if e == nil {
			policyFixtureRollback(w)
		}
		done <- e
	}()
	semanticWaitIdentity(t, r.ctx, r.admin, xid)
	cancel()
	e := <-done
	taken = true
	require.ErrorIs(t, e, context.Canceled)
	require.NoError(t, blocker.Rollback(r.ctx))
	authorityWaitReleased(t, r.runtime)
	// Владелец схемы меняет только persisted identity: runtime store не может
	// самостоятельно согласовать или обойти чужой handoff. Затем положительный twin.
	_, err = r.admin.Exec(r.ctx, `UPDATE kaname.authority_semantic_identity SET model_id=repeat('f',64)`)
	require.NoError(t, err)
	_, err = store.Writer(r.ctx)
	require.Error(t, err)
	_, err = r.admin.Exec(r.ctx, `UPDATE kaname.authority_semantic_identity SET model_id=$1`, r.bundle.Identity().ModelID)
	require.NoError(t, err)
	twin, err := store.Writer(r.ctx)
	require.NoError(t, err)
	require.NoError(t, twin.Rollback(r.ctx))
	require.NoError(t, lifecycleOwner(r).CloseAuthorityBundle(r.ctx))
	_, err = store.Writer(r.ctx)
	require.Error(t, err, "closed identity не становится legacy")
	_, err = store.VerificationWriter(r.ctx, uid)
	require.Error(t, err)
	_, err = store.EmailChangeWriter(r.ctx, uid)
	require.Error(t, err)
	recovery, err := kanamepg.NewRecoveryCompletionStore(r.runtime, userapp.ActivateInviteForLane)
	require.NoError(t, err)
	_, err = recovery.WithHumanAdmissionParticipant(p).RecoveryCompletionWriter(r.ctx, uid)
	require.Error(t, err)
	authorityWaitReleased(t, r.runtime)
}

// Отказ фиксации вставлен ПОСЛЕ настоящего тела регистрации, а не вместо него.
type admissionCommitFailureStore struct {
	registration.Store
	reached *bool
}

func (s admissionCommitFailureStore) Writer(ctx context.Context) (registration.Writer, error) {
	w, err := s.Store.Writer(ctx)
	if err != nil {
		return nil, err
	}
	return admissionCommitFailureWriter{Writer: w, reached: s.reached}, nil
}

type admissionCommitFailureWriter struct {
	registration.Writer
	reached *bool
}

func (w admissionCommitFailureWriter) Commit(context.Context) error {
	*w.reached = true
	return errors.New("контролируемый поздний отказ фиксации")
}
func TestHumanAdmissionRegistrationLateFailureRollsBackWholeOutcome(t *testing.T) {
	r := writerProtocolRig(t)
	p, err := kanamepg.NewHumanAdmissionParticipant(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	require.NoError(t, lifecycleOwner(r).ActivateAuthorityBundle(r.ctx, r.bundle))
	store := kanamepg.NewRegistrationStore(r.runtime).WithHumanAdmissionParticipant(p)
	// Снимок конечных таблиц исхода; счётчики входного pacing сюда не включены.
	snapshot := func() []int64 {
		var users, accounts, bindings, subjects, ledger, outbox, sessions, methods int64
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT (SELECT count(*) FROM kaname.users),(SELECT count(*) FROM kaname.accounts),(SELECT count(*) FROM kaname.access_bindings),(SELECT count(*) FROM kaname.access_binding_subjects),(SELECT count(*) FROM kaname.access_binding_emitted_tuples),(SELECT count(*) FROM kaname.fga_outbox),(SELECT count(*) FROM kaname.human_sessions),(SELECT count(*) FROM kaname.user_login_methods)`).Scan(&users, &accounts, &bindings, &subjects, &ledger, &outbox, &sessions, &methods))
		return []int64{users, accounts, bindings, subjects, ledger, outbox, sessions, methods}
	}
	before := snapshot()
	reached := false
	failing, _, _ := admissionRegistrar(t, r, admissionCommitFailureStore{Store: regStore{inner: store}, reached: &reached})
	input := registration.Input{Email: "admission-rollback@example.invalid", Password: "correct-horse-battery-staple-9"}
	_, err = failing.Execute(r.ctx, input)
	require.ErrorIs(t, err, humansession.ErrStoreUnavailable)
	require.True(t, reached)
	require.Equal(t, before, snapshot())
	authorityWaitReleased(t, r.runtime)
	success, _, _ := admissionRegistrar(t, r, regStore{inner: store})
	out, err := success.Execute(r.ctx, input)
	require.NoError(t, err)
	admissionAssertBootstrap(t, r, out.View.User.ID)
	authorityWaitReleased(t, r.runtime)
}
