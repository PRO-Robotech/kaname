// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// identity_is_global_integration_test.go — писатели строки пользователя
// перестают опираться на парные ключи с аккаунтом (IAM-ID-1, задача kacho#981).
//
// # Предмет
//
// Идемпотентность записи держалась ПАРНЫМИ уникальными индексами —
// `(account_id, lower(email))` и `(account_id, external_id)`. Пока аккаунт
// входит в арбитр `ON CONFLICT`, «тот же человек в другом аккаунте» есть другая
// строка: писатель её заводит, и разъезжаются идентификатор, права и состояние.
//
// После того как ключ стал глобальным, тот же писатель на том же вводе
// упирается в нарушение ключа, которого он не арбитрирует, — то есть путь
// приглашения в ВТОРОЙ аккаунт ломается целиком. Поэтому обе половины —
// глобальный ключ и писатели — обязаны ехать одним изменением: порознь каждая
// есть регрессия.
//
// # Почему членство пишется ЯВНО, хотя есть зеркалящий триггер
//
// Триггер зеркалит от ЗАПИСИ в строку пользователя. При глобальном арбитре
// вторая попытка записи ничего не пишет (человек уже есть) — значит триггер не
// срабатывает, и членство во втором аккаунте не появляется ВОВСЕ. Зеркало
// остаётся верным для своего предмета (строка → её членство), но «пригласить
// человека во второй аккаунт» перестало быть записью в строку, и выражать это
// зеркалом больше нечем.
//
// # Что утверждают пробы этого файла
//
//   - IAM-ID-1-01/02 · один человек в двух аккаунтах — ОДНА строка, ДВА членства;
//   - IAM-ID-1-03 · неизвестная почта — одна строка и одно членство;
//   - IAM-ID-1-05 · повторное приглашение в тот же аккаунт идемпотентно;
//   - IAM-ID-1-04 · первый вход переводит в «активно» ВСЕ членства;
//   - IAM-ID-1-07 · конкурентное первое появление сериализуется — проба
//     параллельна, а не последовательна (`data-integrity.md` §Чек-лист п. 5).
//
// Каждое утверждение спрашивает СОСТОЯНИЕ таблиц после операции, а не факт
// вызова: «писатель вызван» зеленеет при любом исходе.

package pg_test

import (
	"context"

	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// rowsWithEmail — сколько строк пользователя несут эту почту (без учёта регистра).
func rowsWithEmail(t *testing.T, ctx context.Context, pool *pgxpool.Pool, email string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.users WHERE lower(email) = lower($1)`, email).Scan(&n))
	return n
}

// invitePending — путь приглашения на уровне репозитория: «человек существует и
// приглашён в ЭТОТ аккаунт».
func invitePending(
	t *testing.T, ctx context.Context, repo *kanamepg.Repository,
	acc domain.AccountID, email string, invitedBy domain.UserID,
) (domain.User, bool) {
	t.Helper()
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	committed := false
	defer func() {
		if !committed {
			_ = w.Rollback(ctx)
		}
	}()
	u, inserted, err := w.UsersW().InsertPending(ctx, domain.User{
		ID:          domain.UserID(ids.NewID(domain.PrefixUser)),
		AccountID:   acc,
		Email:       domain.Email(email),
		DisplayName: domain.DisplayName("Invitee"),
		InvitedBy:   invitedBy,
	})
	require.NoError(t, err, "приглашение в аккаунт %s обязано пройти", acc)
	require.NoError(t, w.Commit(ctx))
	committed = true
	return u, inserted
}

// TestIntegration_OnePersonTwoAccountsIsOneRowTwoMemberships — IAM-ID-1-01/02/03/05.
func TestIntegration_OnePersonTwoAccountsIsOneRowTwoMemberships(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	adminA, accA := bootstrapAdmin(t, ctx, repo, "glbA")
	adminB, accB := bootstrapAdmin(t, ctx, repo, "glbB")
	require.NotEqual(t, accA, accB, "фикстура обязана дать ДВА разных аккаунта")

	const email = "twin@example.com"

	// ── IAM-ID-1-03 · неизвестная почта: одна строка, одно членство ──────────
	first, inserted := invitePending(t, ctx, repo, accA, email, adminA)
	require.True(t, inserted, "неизвестная почта обязана завести строку")
	require.Equal(t, 1, rowsWithEmail(t, ctx, pool, email))
	require.Len(t, membershipsOf(t, ctx, pool, first.ID), 1)
	require.Equal(t, domain.InviteStatusPending, first.InviteStatus)

	// ── IAM-ID-1-01/02 · та же почта во ВТОРОЙ аккаунт ──────────────────────
	second, insertedAgain := invitePending(t, ctx, repo, accB, email, adminB)
	require.False(t, insertedAgain,
		"вторая строка заводиться не вправе: человек уже есть, и различить «завёл» "+
			"от «нашёл» обязан сам писатель — флаг несущий")
	require.Equal(t, first.ID, second.ID,
		"IAM-ID-1-01: идентификатор человека один и тот же в обоих ответах")
	require.Equal(t, 1, rowsWithEmail(t, ctx, pool, email),
		"IAM-ID-1-02: число строк с этой почтой обязано остаться 1")

	mems := membershipsOf(t, ctx, pool, first.ID)
	require.Len(t, mems, 2, "IAM-ID-1-01: у человека обязано стать ДВА членства")
	got := []string{mems[0].AccountID, mems[1].AccountID}
	require.ElementsMatch(t, []string{string(accA), string(accB)}, got,
		"членства обязаны вести в оба названных аккаунта, а не в один дважды")
	t.Logf("перепись: строк с почтой %s — %d; членств — %d (%s)",
		email, rowsWithEmail(t, ctx, pool, email), len(mems), strings.Join(got, ", "))

	// ── IAM-ID-1-05 · повторное приглашение в ТОТ ЖЕ аккаунт идемпотентно ────
	third, insertedThird := invitePending(t, ctx, repo, accB, email, adminB)
	require.False(t, insertedThird)
	require.Equal(t, first.ID, third.ID)
	require.Len(t, membershipsOf(t, ctx, pool, first.ID), 2,
		"IAM-ID-1-05: второго членства в том же аккаунте не появляется")

	// ── положительный контроль ───────────────────────────────────────────────
	//
	// Без него «строка не заведена» неотличимо от «писатель не заводит строк
	// вовсе»: отрицания выше зеленели бы на полностью сломанном пути.
	other, otherInserted := invitePending(t, ctx, repo, accA, "other@example.com", adminA)
	require.True(t, otherInserted, "другая почта обязана завести СВОЮ строку")
	require.NotEqual(t, first.ID, other.ID)
	require.Len(t, membershipsOf(t, ctx, pool, other.ID), 1)
}

// TestIntegration_FirstLoginActivatesEveryMembership — IAM-ID-1-04.
func TestIntegration_FirstLoginActivatesEveryMembership(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	adminA, accA := bootstrapAdmin(t, ctx, repo, "actA")
	adminB, accB := bootstrapAdmin(t, ctx, repo, "actB")

	const email = "never-logged-in@example.com"
	u, _ := invitePending(t, ctx, repo, accA, email, adminA)
	invitePending(t, ctx, repo, accB, email, adminB)

	before := membershipsOf(t, ctx, pool, u.ID)
	require.Len(t, before, 2, "предусловие сценария: два членства, оба «приглашён»")
	for _, m := range before {
		require.Equal(t, "PENDING", m.State,
			"предусловие обязано быть проверено: на уже активных членствах сценарий "+
				"проверял бы неизменность, а не активацию")
	}

	// Первый вход.
	{
		w, werr := repo.Writer(ctx)
		require.NoError(t, werr)
		_, aerr := w.UsersW().ActivateInvite(ctx, u.ID,
			domain.ExternalSubject("ext-"+string(u.ID)), domain.DisplayName("Logged In"))
		require.NoError(t, aerr)
		require.NoError(t, w.Commit(ctx))
	}

	after := membershipsOf(t, ctx, pool, u.ID)
	require.Len(t, after, 2, "активация не вправе ни завести, ни снять членство")
	for _, m := range after {
		require.Equal(t, "ACTIVE", m.State,
			"IAM-ID-1-04: первый вход переводит в «активно» ВСЕ членства, "+
				"а не то, которое стоит в колонке строки — членство %s в %s осталось в «приглашён»",
			m.ID, m.AccountID)
	}
	require.Equal(t, 1, rowsWithEmail(t, ctx, pool, email))
}

// TestIntegration_ConcurrentFirstAppearanceSerializes — IAM-ID-1-07.
//
// Проба ПАРАЛЛЕЛЬНА намеренно: гонка не ловится последовательным прогоном, а
// именно она и есть предмет — глобальный ключ обязан сериализовать конкурентное
// первое появление так же, как это делал пер-аккаунтный.
func TestIntegration_ConcurrentFirstAppearanceSerializes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	adminA, accA := bootstrapAdmin(t, ctx, repo, "racA")
	_, accB := bootstrapAdmin(t, ctx, repo, "racB")

	const email = "race@example.com"
	const racers = 8

	type outcome struct {
		id       domain.UserID
		inserted bool
		err      error
	}
	results := make([]outcome, racers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		acc := accA
		if i%2 == 1 {
			acc = accB
		}
		go func(idx int, acc domain.AccountID) {
			defer wg.Done()
			<-start
			w, werr := repo.Writer(ctx)
			if werr != nil {
				results[idx] = outcome{err: werr}
				return
			}
			u, ins, uerr := w.UsersW().InsertPending(ctx, domain.User{
				ID:          domain.UserID(ids.NewID(domain.PrefixUser)),
				AccountID:   acc,
				Email:       domain.Email(email),
				DisplayName: domain.DisplayName("Racer"),
				InvitedBy:   adminA,
			})
			if uerr != nil {
				_ = w.Rollback(ctx)
				results[idx] = outcome{err: uerr}
				return
			}
			if cerr := w.Commit(ctx); cerr != nil {
				results[idx] = outcome{err: cerr}
				return
			}
			results[idx] = outcome{id: u.ID, inserted: ins}
		}(i, acc)
	}
	close(start)
	wg.Wait()

	var inserts, failures int
	ids := map[domain.UserID]struct{}{}
	for _, r := range results {
		if r.err != nil {
			failures++
			continue
		}
		if r.inserted {
			inserts++
		}
		ids[r.id] = struct{}{}
	}
	t.Logf("перепись гонки: участников %d, заведений %d, отказов %d, различных идентификаторов %d",
		racers, inserts, failures, len(ids))

	require.Zero(t, failures,
		"конкурентное приглашение обязано СЕРИАЛИЗОВАТЬСЯ, а не отказывать: "+
			"отказ здесь означает, что вызывающий обязан ретраить то, что заведомо законно")
	require.Equal(t, 1, rowsWithEmail(t, ctx, pool, email),
		"IAM-ID-1-07: строк с этой почтой обязана остаться ровно одна")
	require.Len(t, ids, 1, "все участники обязаны сойтись на ОДНОМ идентификаторе человека")
	require.Equal(t, 1, inserts, "ровно один участник заводит строку, остальные её наблюдают")

	var only domain.UserID
	for id := range ids {
		only = id
	}
	mems := membershipsOf(t, ctx, pool, only)
	require.Len(t, mems, 2,
		"членств обязано стать по одному на каждый названный аккаунт — %d участников назвали два",
		racers)
	require.ElementsMatch(t,
		[]string{string(accA), string(accB)},
		[]string{mems[0].AccountID, mems[1].AccountID})
}
