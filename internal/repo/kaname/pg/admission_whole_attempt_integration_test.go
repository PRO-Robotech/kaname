// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
	"github.com/stretchr/testify/require"
)

// Реальная отложенная ошибка PostgreSQL возникает только после полного тела.
// Счётчик не откатывается вместе с исходом и пропускает вторую фиксацию.
func wholeAttemptCommitFault(t *testing.T, r protocolRig, table, event string) func() {
	t.Helper()
	require.Contains(t, []string{"audit_outbox", "invite_mail_outbox"}, table)
	var before int
	require.NoError(t, r.admin.QueryRow(r.ctx, "SELECT count(*) FROM kaname."+table+" WHERE event_type=$1", event).Scan(&before))
	_, err := r.admin.Exec(r.ctx, fmt.Sprintf(`CREATE SEQUENCE kaname.whole_attempt_commit_count;
CREATE FUNCTION kaname.whole_attempt_commit_fault() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
BEGIN
 IF NEW.event_type=%s AND lower(trim(current_query())) IN ('commit', 'commit;') AND nextval('kaname.whole_attempt_commit_count')=1 THEN
  RAISE EXCEPTION 'fixture deferred commit failure' USING ERRCODE='40001';
 END IF;
 RETURN NULL;
END $$;
CREATE CONSTRAINT TRIGGER whole_attempt_commit_fault AFTER INSERT ON kaname.%s DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION kaname.whole_attempt_commit_fault();`, "'"+event+"'", table))
	require.NoError(t, err)
	var deferrable, deferred bool
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT tgdeferrable,tginitdeferred FROM pg_trigger WHERE tgname='whole_attempt_commit_fault'`).Scan(&deferrable, &deferred))
	require.True(t, deferrable)
	require.True(t, deferred)
	t.Cleanup(func() {
		var attempts int
		var called bool
		err := r.admin.QueryRow(r.ctx, `SELECT last_value,is_called FROM kaname.whole_attempt_commit_count`).Scan(&attempts, &called)
		t.Logf("actual deferred COMMIT fault: attempts=%d called=%t deferrable=%t initially_deferred=%t readback=%v", attempts, called, deferrable, deferred, err)
		if err != nil {
			t.Error(err)
		}
		var durable int
		err = r.admin.QueryRow(r.ctx, "SELECT count(*) FROM kaname."+table+" WHERE event_type=$1", event).Scan(&durable)
		t.Logf("durable event rows after operation: before=%d after=%d readback=%v", before, durable, err)
		if err != nil {
			t.Error(err)
		}
	})
	return func() {
		var attempts int
		require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT last_value FROM kaname.whole_attempt_commit_count`).Scan(&attempts))
		require.Equal(t, 2, attempts, "повторяется вся попытка после реального COMMIT 40001")
		var durable int
		require.NoError(t, r.admin.QueryRow(r.ctx, "SELECT count(*) FROM kaname."+table+" WHERE event_type=$1", event).Scan(&durable))
		require.Equal(t, before+1, durable, "ровно один исход опубликован после повторной попытки")
		authorityWaitReleased(t, r.runtime)
	}
}

func TestHumanAdmissionWholeAttemptCommitRetry(t *testing.T) {
	for _, name := range []string{"registration", "request-verification", "confirm-verification", "request-email-change", "confirm-email-change", "recovery-completion"} {
		t.Run(name, func(t *testing.T) {
			r := writerProtocolRig(t)
			repo, _ := fullContractActivate(t, r)
			participant, err := kanamepg.NewHumanAdmissionParticipant(r.ctx, repo, r.bundle)
			require.NoError(t, err)
			store := kanamepg.NewRegistrationStore(r.runtime).WithHumanAdmissionParticipant(participant)
			registrar, hasher, rule := admissionRegistrar(t, r, regStore{inner: store})
			email := "whole-attempt-" + ids.NewID("tst") + "@example.invalid"
			input := registration.Input{Email: email, Password: "correct-horse-battery-staple-9"}
			if name == "registration" {
				check := wholeAttemptCommitFault(t, r, "audit_outbox", registration.AuditUserRegistered)
				out, err := registrar.Execute(r.ctx, input)
				require.NoError(t, err)
				check()
				admissionAssertBootstrap(t, r, out.View.User.ID)
				var count int
				require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE event_type=$1 AND event_payload->>'user_id'=$2`, registration.AuditUserRegistered, string(out.View.User.ID)).Scan(&count))
				require.Equal(t, 1, count)
				return
			}
			out, err := registrar.Execute(r.ctx, input)
			require.NoError(t, err)
			sessions := kanamepg.NewHumanSessionRepo(r.runtime)
			verification := humansession.VerificationDeps{RequirePreparedWrite: true, Store: admissionVerificationStore{sessions, store}, Pace: admissionPace()}
			if name == "request-verification" {
				verification.Now = func() time.Time { return time.Now().Add(2 * time.Minute) }
				request, err := humansession.NewRequestVerificationUseCase(verification)
				require.NoError(t, err)
				check := wholeAttemptCommitFault(t, r, "invite_mail_outbox", "mail.verification.send")
				_, err = request.Execute(r.ctx, out.Bearer)
				require.NoError(t, err)
				check()
				return
			}
			if name == "recovery-completion" {
				request, err := humansession.NewRequestRecoveryUseCase(humansession.RequestRecoveryDeps{Store: sessions, CodeTTL: 30 * time.Minute, Dispatcher: humansession.SyncDispatcher{}, Sources: sessions, SourcePace: humansession.SourcePace{Limit: 10000, Window: time.Hour}, MailLimit: outboxtypes.InviteMailRateLimit{MaxPerWindow: 20, Window: time.Hour}})
				require.NoError(t, err)
				require.NoError(t, request.Execute(r.ctx, humansession.RequestRecoveryInput{Email: email}))
				completion, err := kanamepg.NewRecoveryCompletionStore(r.runtime, userapp.ActivateInviteForLane)
				require.NoError(t, err)
				completion = completion.WithHumanAdmissionParticipant(participant)
				complete, err := humansession.NewCompleteRecoveryUseCase(humansession.CompleteRecoveryDeps{RequirePreparedWrite: true, Store: sessions, Completion: completion, Hasher: hasher, Rule: rule, Limits: humansession.Limits{AddressAttempts: 50, AddressWindow: time.Hour, SourceAttempts: 500, SourceWindow: time.Hour}, TTL: 24 * time.Hour, CutoffClock: momentclock.Func(time.Now)})
				require.NoError(t, err)
				code := admissionLetter(t, r, out.View.User.ID, "mail.recovery.send")
				check := wholeAttemptCommitFault(t, r, "audit_outbox", humansession.AuditRecoveryCompleted)
				recovered, err := complete.Execute(r.ctx, humansession.CompleteRecoveryInput{Email: email, Code: code, NewPassword: "different-correct-horse-battery-7"})
				require.NoError(t, err)
				require.True(t, recovered.View.EmailVerified)
				check()
				return
			}
			confirm, err := humansession.NewConfirmVerificationUseCase(verification)
			require.NoError(t, err)
			code := admissionLetter(t, r, out.View.User.ID, "mail.verification.send")
			if name == "confirm-verification" {
				check := wholeAttemptCommitFault(t, r, "audit_outbox", humansession.AuditEmailVerified)
				verified, err := confirm.Execute(r.ctx, humansession.ConfirmVerificationInput{Bearer: out.Bearer, Code: code})
				require.NoError(t, err)
				require.True(t, verified.View.EmailVerified)
				check()
				return
			}
			verified, err := confirm.Execute(r.ctx, humansession.ConfirmVerificationInput{Bearer: out.Bearer, Code: code})
			require.NoError(t, err)
			deps := humansession.EmailChangeDeps{RequirePreparedWrite: true, Store: admissionEmailStore{admissionVerificationStore{sessions, store}}, Methods: kanamepg.NewLoginMethodRepo(r.runtime), Pace: admissionPace(), Freshness: time.Hour, MailLimit: outboxtypes.InviteMailRateLimit{MaxPerWindow: 20, Window: time.Hour}}
			request, err := humansession.NewRequestEmailChangeUseCase(deps)
			require.NoError(t, err)
			if name == "request-email-change" {
				check := wholeAttemptCommitFault(t, r, "invite_mail_outbox", "mail.email-change.send")
				_, err = request.Execute(r.ctx, humansession.RequestEmailChangeInput{Bearer: verified.Bearer, NewEmail: "changed-" + email})
				require.NoError(t, err)
				check()
				return
			}
			_, err = request.Execute(r.ctx, humansession.RequestEmailChangeInput{Bearer: verified.Bearer, NewEmail: "changed-" + email})
			require.NoError(t, err)
			change, err := humansession.NewConfirmEmailChangeUseCase(deps)
			require.NoError(t, err)
			code = admissionLetter(t, r, out.View.User.ID, "mail.email-change.send")
			check := wholeAttemptCommitFault(t, r, "audit_outbox", humansession.AuditEmailChanged)
			changed, err := change.Execute(r.ctx, humansession.ConfirmEmailChangeInput{Bearer: verified.Bearer, Code: code})
			require.NoError(t, err)
			require.Equal(t, "changed-"+email, string(changed.View.User.Email))
			check()
		})
	}
}
