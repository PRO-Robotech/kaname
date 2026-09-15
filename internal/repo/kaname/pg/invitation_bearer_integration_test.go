// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// invitation_bearer_integration_test.go — предъявитель приглашения как НАША
// сущность: срок, однократность, отзыв (приёмка ID-MAIL-1, Р21а, Р24; §10 пп. 16,
// 17, 22; сценарии MAIL-22, MAIL-23, MAIL-24, MAIL-46 — уровень I).
//
// # Что утверждается, и почему здесь, а не в use-case
//
// Предъявитель приглашения — СТРОКА ожидания (Р24), а её выкуп — один оператор
// базы. Срок, однократность и отзыв живут в ТОМ ЖЕ операторе, что активирует:
// проверка перед записью разошлась бы с записью ровно под конкуренцией (ban #10).
// Поэтому свойство утверждается настоящим Postgres, а не дублёром, — дублёр не
// способен воспроизвести ни часы базы, ни замки строк.
//
// # Часы управляются ДАННЫМИ, а не ожиданием
//
// «Срок вышел» воспроизводится сдвигом записанного срока в прошлое относительно
// `now()` той же базы, а не сном: проба, ждущая «достаточно долго», утверждала
// бы про расписание, а не про продукт.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// bearerTestTerm — срок приглашения в пробах. Величина пробы, а не продукта:
// предмет — поведение на границе срока, а не выбор умолчания.
const bearerTestTerm = domain.InvitationTerm(time.Hour)

func newBearerRepo(t *testing.T) (context.Context, *pgxpool.Pool, *kanamepg.Repository) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	return ctx, pool, kanamepg.New(pool, nil)
}

// invitePending заводит приглашение email в аккаунт acc и возвращает строку.
func inviteBearer(t *testing.T, ctx context.Context, repo *kanamepg.Repository,
	acc domain.AccountID, inviter domain.UserID, email string, term domain.InvitationTerm,
) domain.UserID {
	t.Helper()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	got, _, err := w.UsersW().InsertPending(ctx, domain.User{
		ID: domain.UserID(ids.NewID(domain.PrefixUser)), AccountID: acc,
		Email: domain.Email(email), DisplayName: "Invitee", InvitedBy: inviter,
	}, term)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return got.ID
}

func redeemBearer(t *testing.T, ctx context.Context, repo *kanamepg.Repository,
	id domain.UserID, ext string,
) domain.InviteActivation {
	t.Helper()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	got, err := w.UsersW().ActivateInvite(ctx, id, domain.ExternalSubject(ext), "Activated")
	require.NoError(t, err, "отказ выкупа — ИСХОД, а не ошибка хранилища")
	require.NoError(t, w.Commit(ctx))
	return got
}

func standingOf(t *testing.T, ctx context.Context, repo *kanamepg.Repository, id domain.UserID) domain.InvitationStanding {
	t.Helper()
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	got, err := rd.Users().InvitationStanding(ctx, id)
	require.NoError(t, err)
	return got
}

func userStatusOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id domain.UserID) (string, bool) {
	t.Helper()
	var st string
	var hasTerm bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT invite_status, invite_expires_at IS NOT NULL FROM kaname.users WHERE id = $1`,
		string(id)).Scan(&st, &hasTerm))
	return st, hasTerm
}

func expireTerm(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id domain.UserID) {
	t.Helper()
	tag, err := pool.Exec(ctx,
		`UPDATE kaname.users SET invite_expires_at = now() - interval '1 second' WHERE id = $1`, string(id))
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected(), "ПРЕДПОСЫЛКА: сдвиг срока обязан задеть строку")
}

// MAIL-23 (I): срок записан на строке при заведении, величиной из объявления.
func TestIntegration_InvitationTermIsWrittenAtIssuanceByTheDatabaseClock(t *testing.T) {
	ctx, pool, repo := newBearerRepo(t)
	inviter, acc := bootstrapAdmin(t, ctx, repo, "bterm")
	id := inviteBearer(t, ctx, repo, acc, inviter, "term-written-bterm@example.com", bearerTestTerm)

	var lag time.Duration
	var secs float64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT EXTRACT(EPOCH FROM (invite_expires_at - (now() + interval '1 hour')))
		   FROM kaname.users WHERE id = $1`, string(id)).Scan(&secs))
	lag = time.Duration(secs * float64(time.Second))
	require.InDelta(t, 0, lag.Seconds(), 60,
		"срок обязан быть «сейчас базы + объявленная величина»: он записан при заведении и "+
			"считается часами той же базы, что его судит")
}

// MAIL-23 (I), положительный контроль: вход внутри срока активирует строку.
// MAIL-22 (I): вторая активация той же строки — «уже активна», а не второе вступление.
func TestIntegration_InviteRedeemsOnceWithinItsTerm(t *testing.T) {
	ctx, pool, repo := newBearerRepo(t)
	inviter, acc := bootstrapAdmin(t, ctx, repo, "bonce")
	id := inviteBearer(t, ctx, repo, acc, inviter, "once-bonce@example.com", bearerTestTerm)

	require.Equal(t, domain.InvitationRedeemable, standingOf(t, ctx, repo, id))

	first := redeemBearer(t, ctx, repo, id, "ext-bonce-1")
	require.Equal(t, domain.InvitationRedeemable, first.Standing, "внутри срока строка обязана выкупаться")
	require.Equal(t, []domain.AccountID{acc}, first.Accounts,
		"выкуп обязан назвать РОВНО те аккаунты, чьи членства он перевёл в «активно»")
	require.Equal(t, domain.InviteStatusActive, first.User.InviteStatus)
	st, hasTerm := userStatusOf(t, ctx, pool, id)
	require.Equal(t, "ACTIVE", st)
	require.False(t, hasTerm, "у выкупленной строки срока нет: срок — свойство приглашения, а не личности")
	require.Equal(t, "ACTIVE", membershipsOf(t, ctx, pool, id)[0].State)

	second := redeemBearer(t, ctx, repo, id, "ext-bonce-2")
	require.Equal(t, domain.InvitationNotPending, second.Standing,
		"повторный выкуп обязан отказать как «уже активна»: второе вступление по тому же приглашению — "+
			"предъявитель, выкупаемый дважды")
	require.Empty(t, second.Accounts)
}

// MAIL-23 (I): вход после срока строку НЕ активирует, и человек участником не становится.
func TestIntegration_ExpiredInvitationDoesNotRedeem(t *testing.T) {
	ctx, pool, repo := newBearerRepo(t)
	inviter, acc := bootstrapAdmin(t, ctx, repo, "bexp")
	id := inviteBearer(t, ctx, repo, acc, inviter, "expired-bexp@example.com", bearerTestTerm)
	expireTerm(t, ctx, pool, id)

	require.Equal(t, domain.InvitationExpired, standingOf(t, ctx, repo, id),
		"читатель стоянки обязан судить тем же предикатом, что выкуп")
	got := redeemBearer(t, ctx, repo, id, "ext-bexp")
	require.Equal(t, domain.InvitationExpired, got.Standing)
	require.Empty(t, got.Accounts)
	st, _ := userStatusOf(t, ctx, pool, id)
	require.Equal(t, "PENDING", st, "истёкшая строка обязана остаться в ожидании")
	require.Equal(t, "PENDING", membershipsOf(t, ctx, pool, id)[0].State,
		"членство по истёкшему приглашению не вправе стать активным")
}

// Повторное приглашение продлевает срок — иначе «попросите пригласить заново»
// было бы советом, который не работает. Продление монотонно: оно не укорачивает.
func TestIntegration_ReinvitationRenewsTheTerm(t *testing.T) {
	ctx, pool, repo := newBearerRepo(t)
	inviter, accA := bootstrapAdmin(t, ctx, repo, "bren1")
	_, accB := bootstrapAdmin(t, ctx, repo, "bren2")
	const email = "renew-bren@example.com"
	id := inviteBearer(t, ctx, repo, accA, inviter, email, bearerTestTerm)

	// Тот же аккаунт: путь, минующий вставку (use-case отдаёт строку как есть).
	expireTerm(t, ctx, pool, id)
	{
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		renewed, rerr := w.UsersW().RenewInvitationTerm(ctx, id, bearerTestTerm)
		require.NoError(t, rerr)
		require.True(t, renewed, "продление строки ожидания со сроком обязано сообщить, что оно было")
		require.NoError(t, w.Commit(ctx))
	}
	require.Equal(t, domain.InvitationRedeemable, standingOf(t, ctx, repo, id))

	// Другой аккаунт: вставка находит строку по почте и продлевает ей срок.
	expireTerm(t, ctx, pool, id)
	again := inviteBearer(t, ctx, repo, accB, inviter, email, bearerTestTerm)
	require.Equal(t, id, again, "ПРЕДПОСЫЛКА: вторая вставка обязана найти ту же строку")
	require.Equal(t, domain.InvitationRedeemable, standingOf(t, ctx, repo, id))

	// Монотонность: продление коротким сроком длинного не укорачивает.
	var before, after time.Time
	require.NoError(t, pool.QueryRow(ctx, `SELECT invite_expires_at FROM kaname.users WHERE id=$1`, string(id)).Scan(&before))
	{
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		_, rerr := w.UsersW().RenewInvitationTerm(ctx, id, domain.InvitationTerm(time.Second))
		require.NoError(t, rerr)
		require.NoError(t, w.Commit(ctx))
	}
	require.NoError(t, pool.QueryRow(ctx, `SELECT invite_expires_at FROM kaname.users WHERE id=$1`, string(id)).Scan(&after))
	require.False(t, after.Before(before), "продление не вправе укорачивать уже выданный срок")
}

// Строка ожидания, заведённая НЕ приглашением (посевная), срока не несёт и не
// выкупается вовсе. Проверяется на НАСТОЯЩЕЙ посевной строке базовой миграции —
// входе из дерева, а не на синтетике, — плюс синтетический близнец той же формы.
func TestIntegration_PendingRowWithoutTermIsNotAnInvitation(t *testing.T) {
	ctx, pool, repo := newBearerRepo(t)

	// Посевная строка владельца системного аккаунта: ожидание без личности.
	var seededID string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT u.id FROM kaname.users u
		 WHERE u.invite_status = 'PENDING'
		   AND EXISTS (SELECT 1 FROM kaname.accounts a WHERE a.owner_user_id = u.id)
		 ORDER BY u.id LIMIT 1`).Scan(&seededID),
		"ПРЕДПОСЫЛКА: в посеве обязана быть строка ожидания, владеющая аккаунтом; нет её — "+
			"проба судит синтетику одну и не видит настоящего входа")
	_, hasTerm := userStatusOf(t, ctx, pool, domain.UserID(seededID))
	require.False(t, hasTerm, "посевная строка ожидания срока не несёт: она не приглашение")

	got := redeemBearer(t, ctx, repo, domain.UserID(seededID), "ext-seeded-claim")
	require.Equal(t, domain.InvitationNotIssued, got.Standing,
		"строка ожидания, заведённая не приглашением, не вправе выкупаться ни при каком входе")
	st, _ := userStatusOf(t, ctx, pool, domain.UserID(seededID))
	require.Equal(t, "PENDING", st)

	// Продление её не оживляет: приглашение адреса такой строки срока не заводит.
	{
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		renewed, rerr := w.UsersW().RenewInvitationTerm(ctx, domain.UserID(seededID), bearerTestTerm)
		require.NoError(t, rerr)
		require.False(t, renewed, "продлевать нечего: срока у строки нет")
		require.NoError(t, w.Commit(ctx))
	}
	require.Equal(t, domain.InvitationNotIssued, standingOf(t, ctx, repo, domain.UserID(seededID)))
}

// MAIL-24 / MAIL-46 (I): снятие участия обесценивает невыкупленное приглашение
// НЕМЕДЛЕННО. Положительный контроль — тот же предъявитель без снятия выкупается.
func TestIntegration_RemovedParticipationDevaluesTheBearer(t *testing.T) {
	ctx, pool, repo := newBearerRepo(t)
	inviter, acc := bootstrapAdmin(t, ctx, repo, "bwd")
	removed := inviteBearer(t, ctx, repo, acc, inviter, "removed-bwd@example.com", bearerTestTerm)
	kept := inviteBearer(t, ctx, repo, acc, inviter, "kept-bwd@example.com", bearerTestTerm)

	{
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		ok, rerr := w.UsersW().RemoveMembership(ctx, removed, acc)
		require.NoError(t, rerr)
		require.True(t, ok)
		require.NoError(t, w.Commit(ctx))
	}

	require.Equal(t, domain.InvitationWithdrawn, standingOf(t, ctx, repo, removed))
	got := redeemBearer(t, ctx, repo, removed, "ext-bwd-removed")
	require.Equal(t, domain.InvitationWithdrawn, got.Standing,
		"человек перестал быть участником — невыкупленный предъявитель обязан перестать действовать "+
			"сразу, а не по истечении срока")
	require.Empty(t, got.Accounts)
	st, _ := userStatusOf(t, ctx, pool, removed)
	require.Equal(t, "PENDING", st)
	require.Empty(t, membershipsOf(t, ctx, pool, removed), "снятое участие не вправе вернуться выкупом")

	control := redeemBearer(t, ctx, repo, kept, "ext-bwd-kept")
	require.Equal(t, domain.InvitationRedeemable, control.Standing,
		"КОНТРОЛЬ: без снятия участия тот же предъявитель выкупается — иначе отказ выше "+
			"неотличим от выкупа, сломанного целиком")
	require.Equal(t, []domain.AccountID{acc}, control.Accounts)
}

// Частичное снятие: приглашён в A и B, снят из A. Выкуп проходит ПО B и не
// называет A — ни членством, ни следствием.
func TestIntegration_PartialWithdrawalRedeemsOnlyTheRemainingInvitations(t *testing.T) {
	ctx, pool, repo := newBearerRepo(t)
	inviter, accA := bootstrapAdmin(t, ctx, repo, "bpw1")
	_, accB := bootstrapAdmin(t, ctx, repo, "bpw2")
	const email = "partial-bpw@example.com"
	id := inviteBearer(t, ctx, repo, accA, inviter, email, bearerTestTerm)
	require.Equal(t, id, inviteBearer(t, ctx, repo, accB, inviter, email, bearerTestTerm))

	{
		w, err := repo.Writer(ctx)
		require.NoError(t, err)
		_, rerr := w.UsersW().RemoveMembership(ctx, id, accA)
		require.NoError(t, rerr)
		require.NoError(t, w.Commit(ctx))
	}
	got := redeemBearer(t, ctx, repo, id, "ext-bpw")
	require.Equal(t, domain.InvitationRedeemable, got.Standing)
	require.Equal(t, []domain.AccountID{accB}, got.Accounts,
		"выкуп обязан назвать только аккаунт, чьё приглашение уцелело: названный A сделал бы "+
			"снятое участие поводом для следствий активации в A")
	ms := membershipsOf(t, ctx, pool, id)
	require.Len(t, ms, 1)
	require.Equal(t, string(accB), ms[0].AccountID)
	require.Equal(t, "ACTIVE", ms[0].State)
}

// Перепись ФОРМ снятия участия ВЫВОДИТСЯ из каталога базы, а не выписывается:
// каждое каскадное снятие строки членства (внешний ключ с ON DELETE CASCADE)
// плюс явный писатель снятия. По КАЖДОЙ форме — снятие участия в аккаунте, затем
// выкуп, и выкуп обязан не сделать человека участником ЭТОГО аккаунта.
// Требование сформулировано по ИСХОДУ, а не по имени глагола (MAIL-46): новый
// глагол, снимающий участие любой из этих форм, попадает под него по построению.
// Новая форма, о которой проба не знает, — отказ пробы с именем формы: иначе
// новый путь снятия уехал бы в слепую зону молча.
//
// Человек в каждой форме приглашён в ДВА аккаунта: первый — тот, что называет
// легаси-колонка его строки (её аккаунт снять нельзя by construction, ключ
// RESTRICT), второй — тот, из которого участие снимается. Так каскад аккаунта
// исполним, а утверждение «выкуп не называет снятый аккаунт» не зеленеет на
// выкупе, который не состоялся вовсе.
func TestIntegration_EveryFormOfParticipationRemovalDevaluesTheBearer(t *testing.T) {
	ctx, pool, repo := newBearerRepo(t)

	rows, err := pool.Query(ctx, `
		SELECT confrelid::regclass::text
		  FROM pg_constraint
		 WHERE conrelid = 'kaname.memberships'::regclass
		   AND contype = 'f' AND confdeltype = 'c'
		 ORDER BY 1`)
	require.NoError(t, err)
	var cascades []string
	for rows.Next() {
		var parent string
		require.NoError(t, rows.Scan(&parent))
		cascades = append(cascades, parent)
	}
	rows.Close()
	require.NoError(t, rows.Err())
	require.NotEmpty(t, cascades, "перепись каскадных форм пуста — судить не о чем")

	type form struct {
		name string
		// personGone — форма снимает саму строку предъявителя.
		personGone bool
		remove     func(t *testing.T, id domain.UserID, acc domain.AccountID)
	}
	forms := []form{{
		name: "явное снятие членства (RemoveMembership)",
		remove: func(t *testing.T, id domain.UserID, acc domain.AccountID) {
			w, werr := repo.Writer(ctx)
			require.NoError(t, werr)
			_, rerr := w.UsersW().RemoveMembership(ctx, id, acc)
			require.NoError(t, rerr)
			require.NoError(t, w.Commit(ctx))
		},
	}}
	for _, parent := range cascades {
		switch strings.TrimPrefix(parent, "kaname.") {
		case "accounts":
			forms = append(forms, form{name: "каскад снятия аккаунта", remove: func(t *testing.T, _ domain.UserID, acc domain.AccountID) {
				_, derr := pool.Exec(ctx, `DELETE FROM kaname.accounts WHERE id = $1`, string(acc))
				require.NoError(t, derr)
			}})
		case "users":
			forms = append(forms, form{name: "каскад снятия личности", personGone: true,
				remove: func(t *testing.T, id domain.UserID, _ domain.AccountID) {
					_, derr := pool.Exec(ctx, `DELETE FROM kaname.users WHERE id = $1`, string(id))
					require.NoError(t, derr)
				}})
		default:
			t.Fatalf("каскадная форма снятия участия через %s этой пробе неизвестна: научи пробу её "+
				"исполнять, иначе новый путь снятия участия остаётся без утверждения об отзыве", parent)
		}
	}
	t.Logf("перепись: форм снятия участия %d (каскадных из каталога %d, явных 1)", len(forms), len(cascades))

	for i, f := range forms {
		t.Run(f.name, func(t *testing.T) {
			inviter, home := bootstrapAdmin(t, ctx, repo, fmt.Sprintf("bfo%d", i))
			removedFrom := accountOwnedBy(t, ctx, repo, inviter, fmt.Sprintf("bfa%d", i))
			email := fmt.Sprintf("form%d-bfo@example.com", i)
			id := inviteBearer(t, ctx, repo, home, inviter, email, bearerTestTerm)
			require.Equal(t, id, inviteBearer(t, ctx, repo, removedFrom, inviter, email, bearerTestTerm))
			require.Len(t, membershipsOf(t, ctx, pool, id), 2, "ПРЕДПОСЫЛКА: приглашён в два аккаунта")

			f.remove(t, id, removedFrom)

			got := redeemBearer(t, ctx, repo, id, fmt.Sprintf("ext-bfo-%d", i))
			require.NotContains(t, got.Accounts, removedFrom,
				"форма «%s» сняла участие в аккаунте, а выкуп вернул человека туда", f.name)
			for _, m := range membershipsOf(t, ctx, pool, id) {
				require.NotEqual(t, string(removedFrom), m.AccountID,
					"форма «%s»: членство в снятом аккаунте вернулось выкупом", f.name)
			}
			if f.personGone {
				require.Equal(t, domain.InvitationAbsent, got.Standing,
					"строки предъявителя нет — выкупать нечего")
				return
			}
			require.Equal(t, domain.InvitationRedeemable, got.Standing,
				"КОНТРОЛЬ: уцелевшее приглашение выкупается — иначе «снятый аккаунт не назван» "+
					"зеленело бы на выкупе, не состоявшемся вовсе")
			require.Equal(t, []domain.AccountID{home}, got.Accounts)
		})
	}
}

// accountOwnedBy — аккаунт, на который НЕ указывает легаси-колонка ни одной
// строки человека: его снятие исполнимо, и каскад членств в нём настоящий.
func accountOwnedBy(t *testing.T, ctx context.Context, repo *kanamepg.Repository, owner domain.UserID, suffix string) domain.AccountID {
	t.Helper()
	acc := domain.AccountID(ids.NewID(domain.PrefixAccount))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccountsW().Insert(ctx, domain.Account{
		ID: acc, Name: domain.AccountName("acc-" + suffix + "-" + strings.ToLower(string(acc[len(acc)-6:]))),
		OwnerUserID: owner, Labels: domain.Labels{},
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return acc
}

// Гонка «снятие участия ⇄ выкуп». Исходов законных ровно два: снятие первым —
// выкуп отказывает; выкуп первым — человек вступил, затем исключён. Незаконный —
// строка активирована, а членства, которое она перевела бы, нет: тогда выкуп
// случился по снятому приглашению.
func TestIntegration_RemovalRacingRedemptionNeverRedeemsAWithdrawnInvitation(t *testing.T) {
	ctx, pool, repo := newBearerRepo(t)
	inviter, _ := bootstrapAdmin(t, ctx, repo, "brace")

	const rounds = 24
	var removalFirst, redeemFirst int
	for i := 0; i < rounds; i++ {
		_, acc := bootstrapAdmin(t, ctx, repo, fmt.Sprintf("brc%d", i))
		id := inviteBearer(t, ctx, repo, acc, inviter, fmt.Sprintf("race%d-brace@example.com", i), bearerTestTerm)

		start := make(chan struct{})
		var wg sync.WaitGroup
		var act domain.InviteActivation
		var actErr, remErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			w, err := repo.Writer(ctx)
			if err != nil {
				actErr = err
				return
			}
			act, actErr = w.UsersW().ActivateInvite(ctx, id, domain.ExternalSubject(fmt.Sprintf("ext-brace-%d", i)), "R")
			if actErr != nil {
				_ = w.Rollback(ctx)
				return
			}
			actErr = w.Commit(ctx)
		}()
		go func() {
			defer wg.Done()
			<-start
			w, err := repo.Writer(ctx)
			if err != nil {
				remErr = err
				return
			}
			if _, remErr = w.UsersW().RemoveMembership(ctx, id, acc); remErr != nil {
				_ = w.Rollback(ctx)
				return
			}
			remErr = w.Commit(ctx)
		}()
		close(start)
		wg.Wait()
		require.NoError(t, actErr)
		require.NoError(t, remErr)

		st, _ := userStatusOf(t, ctx, pool, id)
		require.Empty(t, membershipsOf(t, ctx, pool, id), "снятие обязано состояться в обоих порядках")
		switch act.Standing {
		case domain.InvitationRedeemable:
			redeemFirst++
			require.Equal(t, []domain.AccountID{acc}, act.Accounts,
				"выкуп, прошедший первым, обязан перевести членство, которое затем сняли")
			require.Equal(t, "ACTIVE", st)
		case domain.InvitationWithdrawn:
			removalFirst++
			require.Equal(t, "PENDING", st,
				"строка активирована, хотя выкуп отказал по снятию: активация без переведённого членства")
		default:
			t.Fatalf("раунд %d: выкуп дал %q — законных исходов гонки два", i, act.Standing)
		}
	}
	t.Logf("перепись гонки: раундов %d · выкуп первым %d · снятие первым %d", rounds, redeemFirst, removalFirst)
}

// Однократность под гонкой первого входа: N конкурентных выкупов одной строки —
// ровно один «активировано», остальные «уже активна».
func TestIntegration_ConcurrentRedemptionsRedeemExactlyOnce(t *testing.T) {
	ctx, _, repo := newBearerRepo(t)
	inviter, acc := bootstrapAdmin(t, ctx, repo, "bconc")
	id := inviteBearer(t, ctx, repo, acc, inviter, "concurrent-bconc@example.com", bearerTestTerm)

	const n = 8
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make([]domain.InviteActivation, n)
	errs := make([]error, n)
	wg.Add(n)
	for i := 0; i < n; i++ {
		go func(i int) {
			defer wg.Done()
			<-start
			w, err := repo.Writer(ctx)
			if err != nil {
				errs[i] = err
				return
			}
			results[i], errs[i] = w.UsersW().ActivateInvite(ctx, id, domain.ExternalSubject("ext-bconc"), "C")
			if errs[i] != nil {
				_ = w.Rollback(ctx)
				return
			}
			errs[i] = w.Commit(ctx)
		}(i)
	}
	close(start)
	wg.Wait()

	var activated, already int
	for i := 0; i < n; i++ {
		require.NoError(t, errs[i])
		switch results[i].Standing {
		case domain.InvitationRedeemable:
			activated++
		case domain.InvitationNotPending:
			already++
		default:
			t.Fatalf("выкуп %d дал %q", i, results[i].Standing)
		}
	}
	require.Equal(t, 1, activated, "выкупов обязано быть РОВНО один")
	require.Equal(t, n-1, already)
}

// Порядок замков один у вставки приглашения и у выкупа: строка человека, затем
// членства. Иначе повторное приглашение, совпавшее с первым входом, упиралось
// бы во взаимную блокировку.
func TestIntegration_ReinviteRacingRedemptionDoesNotDeadlock(t *testing.T) {
	ctx, pool, repo := newBearerRepo(t)
	inviter, accA := bootstrapAdmin(t, ctx, repo, "bdl1")

	const rounds = 16
	for i := 0; i < rounds; i++ {
		_, accC := bootstrapAdmin(t, ctx, repo, fmt.Sprintf("bdc%d", i))
		email := fmt.Sprintf("deadlock%d-bdl@example.com", i)
		id := inviteBearer(t, ctx, repo, accA, inviter, email, bearerTestTerm)

		start := make(chan struct{})
		var wg sync.WaitGroup
		var actErr, insErr error
		wg.Add(2)
		go func() {
			defer wg.Done()
			<-start
			w, err := repo.Writer(ctx)
			if err != nil {
				actErr = err
				return
			}
			if _, actErr = w.UsersW().ActivateInvite(ctx, id, domain.ExternalSubject(fmt.Sprintf("ext-bdl-%d", i)), "D"); actErr != nil {
				_ = w.Rollback(ctx)
				return
			}
			actErr = w.Commit(ctx)
		}()
		go func() {
			defer wg.Done()
			<-start
			w, err := repo.Writer(ctx)
			if err != nil {
				insErr = err
				return
			}
			if _, _, insErr = w.UsersW().InsertPending(ctx, domain.User{
				ID: domain.UserID(ids.NewID(domain.PrefixUser)), AccountID: accC,
				Email: domain.Email(email), DisplayName: "D", InvitedBy: inviter,
			}, bearerTestTerm); insErr != nil {
				_ = w.Rollback(ctx)
				return
			}
			insErr = w.Commit(ctx)
		}()
		close(start)
		wg.Wait()
		for _, e := range []error{actErr, insErr} {
			var pgErr *pgconn.PgError
			if errors.As(e, &pgErr) {
				require.NotEqual(t, "40P01", pgErr.Code, "раунд %d: взаимная блокировка выкупа и приглашения", i)
			}
			require.NoError(t, e, "раунд %d", i)
		}
		for _, m := range membershipsOf(t, ctx, pool, id) {
			require.Equal(t, "ACTIVE", m.State,
				"раунд %d: членство %s осталось в ожидании у вошедшего человека", i, m.AccountID)
		}
	}
}
