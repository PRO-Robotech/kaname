// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// user_invite_second_account_integration_test.go — приглашение человека,
// который в платформе УЖЕ ЕСТЬ, во второй аккаунт.
//
// # Что здесь стояло раньше и почему переписано
//
// Файл заводился под миграцию `0011`, снявшую ГЛОБАЛЬНУЮ уникальность почты:
// пока действовала модель «один человек = N строк, по одной на аккаунт»,
// глобальный ключ ломал приглашение известной почты во второй аккаунт — вставка
// падала на 23505, и вся транзакция приглашения откатывалась.
//
// Модель снята. Миграция
// `20260823050000_users_identity_uniqueness_goes_global` возвращает глобальные
// ключи — но НЕ ту же вещь: тогда ключ запрещал приглашать человека во второй
// аккаунт (модель этого требовала), теперь он запрещает ЗАВОДИТЬ ему вторую
// строку, потому что второй аккаунт выражается ЧЛЕНСТВОМ, а не строкой.
//
// Значит посылка «после 0011 вторая строка обязана вставиться» пережила свой
// предмет и читалась бы как действующая. Утверждение переписано под НОВЫЙ
// наблюдаемый исход того же пути, а не снято: путь приглашения во второй
// аккаунт обязан работать, и проба по-прежнему стережёт именно это.
//
// # Что утверждают пробы этого файла
//
//   - приглашение УЖЕ ВОШЕДШЕГО человека во второй аккаунт даёт ту же строку и
//     ЕЩЁ ОДНО членство, сразу действующее: второго входа платформа не просит;
//   - конкурентное первое появление одного внешнего субъекта разрешается базой,
//     а не удачей: ровно один участник заводит строку.

import (
	"context"
	stderrors "errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// ── известный человек, приглашённый во ВТОРОЙ аккаунт ──────────────────────
//
// Человек ДЕЙСТВУЮЩИЙ в аккаунте A (он там завёлся и вошёл). Администратор
// второго аккаунта приглашает ТУ ЖЕ почту к себе.
//
// Прежняя редакция требовала здесь «свежую строку PENDING в аккаунте B». Такого
// исхода больше не бывает: строка у человека одна. Новый исход — та же строка и
// ВТОРОЕ членство, причём сразу в состоянии «действует»: человек уже
// подтвердил, что владеет этой почтой, и просить его войти второй раз не за чем.
//
// Утверждается СОСТОЯНИЕ таблиц после вызова, а не факт вызова: «писатель не
// отказал» зеленеет и тогда, когда членство во втором аккаунте не появилось
// вовсе, — а это ровно та поломка, ради которой файл и существует.
func TestUserInvite_ExistingActiveEmail_SecondAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	const email = domain.Email("multi-account@example.com")

	// Человек действует в аккаунте A (там его домашний аккаунт).
	adminA, accA := bootstrapAdmin(t, ctx, repo, "i11aA")
	w0, err := repo.Writer(ctx)
	require.NoError(t, err)
	activeID := domain.UserID(ids.NewID(domain.PrefixUser))
	_, err = w0.UsersW().InsertActive(ctx, domain.User{
		ID:           activeID,
		AccountID:    accA,
		ExternalID:   domain.ExternalSubject("ext-i11a-sub"),
		Email:        email,
		DisplayName:  domain.DisplayName("Multi Account"),
		InviteStatus: domain.InviteStatusActive,
	})
	require.NoError(t, err, "посев действующей строки в аккаунте A")
	require.NoError(t, w0.Commit(ctx))

	// Второй аккаунт со своим администратором — и третий, куда человека НИКТО
	// не звал: он нужен контролем к чтению по аккаунту ниже.
	_, accB := bootstrapAdmin(t, ctx, repo, "i11aB")
	_, accC := bootstrapAdmin(t, ctx, repo, "i11aC")

	// Приглашение ТОЙ ЖЕ почты в аккаунт B.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	out, inserted, err := w.UsersW().InsertPending(ctx, domain.User{
		ID:           domain.UserID(ids.NewID(domain.PrefixUser)),
		AccountID:    accB, // та же почта, другой аккаунт
		Email:        email,
		DisplayName:  domain.DisplayName("Multi Account (invited)"),
		InviteStatus: domain.InviteStatusPending,
		InvitedBy:    adminA,
	})
	require.NoError(t, err,
		"приглашение известной почты во второй аккаунт обязано пройти: отказ здесь означал бы, "+
			"что глобальный ключ сломал путь, ради которого он вводился")
	require.NoError(t, w.Commit(ctx))

	assert.False(t, inserted,
		"вторая строка заводиться не вправе — человек в платформе уже есть")
	assert.Equal(t, activeID, out.ID,
		"писатель обязан вернуть СТРОКУ ЧЕЛОВЕКА, а не идентификатор, который ему предложили")
	assert.Equal(t, domain.InviteStatusActive, out.InviteStatus,
		"приглашение не возвращает вошедшего человека в состояние «приглашён»")
	assert.Equal(t, domain.DisplayName("Multi Account"), out.DisplayName,
		"приглашающий не вправе переписать имя человеку, который в платформе уже есть")

	var rowsWithThatEmail int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.users WHERE lower(email) = lower($1)`,
		string(email)).Scan(&rowsWithThatEmail))
	assert.Equal(t, 1, rowsWithThatEmail, "строк с этой почтой обязана остаться одна")

	// Принадлежность двум аккаунтам выражена ЧЛЕНСТВАМИ — и оба действуют.
	mems := membershipsOf(t, ctx, pool, activeID)
	require.Len(t, mems, 2,
		"у человека обязано стать два членства: без этого «строка одна» означало бы, "+
			"что приглашение потерялось целиком")
	state := map[string]string{}
	for _, m := range mems {
		state[m.AccountID] = m.State
	}
	assert.Equal(t, "ACTIVE", state[string(accA)])
	assert.Equal(t, "ACTIVE", state[string(accB)],
		"членство вошедшего человека действует сразу — второго входа платформа не просит")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	// Приглашения, ждущего входа, не появилось: ждать нечего.
	pendings, err := rd.Users().FindPendingByEmail(ctx, email)
	require.NoError(t, err)
	assert.Empty(t, pendings,
		"вошедший человек не становится приглашённым оттого, что его позвали ещё куда-то")

	// Чтение «есть ли такой человек ЗДЕСЬ» отвечает по членству — и отвечает
	// одинаково про оба аккаунта, потому что строка одна.
	gotA, err := rd.Users().GetByAccountEmail(ctx, accA, email)
	require.NoError(t, err)
	assert.Equal(t, activeID, gotA.ID)
	gotB, err := rd.Users().GetByAccountEmail(ctx, accB, email)
	require.NoError(t, err, "в аккаунте B человек состоит — членство заведено приглашением")
	assert.Equal(t, activeID, gotB.ID)

	// Контроль к обоим чтениям выше: в аккаунте, куда человека не звали, тот же
	// вопрос обязан получить отказ. Без него «нашлось в A и в B» означало бы
	// лишь то, что читатель находит кого угодно где угодно.
	_, err = rd.Users().GetByAccountEmail(ctx, accC, email)
	require.Error(t, err, "в чужом аккаунте человека нет — членства туда никто не заводил")
	assert.True(t, stderrors.Is(err, iamerr.ErrNotFound),
		"отказ обязан приезжать сентинелом ErrNotFound, получено %v", err)
}

// ── конкурентное первое появление одного человека ──────────────────────────
//
// N параллельных первых входов ОДНОГО внешнего субъекта, и каждый заводит себе
// личный аккаунт — то есть свой, ОТЛИЧНЫЙ `account_id`. Пер-аккаунтные ключи
// такую гонку не сериализуют by construction: аккаунты разные, пары не
// совпадают. Разрешить её обязан ключ, аккаунта НЕ содержащий.
//
// Такой ключ здесь не один, и это надо назвать прямо, иначе проба выглядит
// утверждением про конкретное имя: глобальные `users_identity_email_uniq` и
// `users_identity_external_id_uniq` (20260823050000) плюс переживший их
// `users_active_external_id_uniq` (0011, только ACTIVE). Проба не спрашивает,
// КАКОЙ из них сработал, — она спрашивает ИСХОД: ровно один участник заводит
// строку, остальные получают отказ сентинелом. Утверждение об имени ограничения
// было бы утверждением о реализации и краснело бы на всякой её перестановке.
//
// Без ключа без аккаунта прошли бы ВСЕ: у человека завелось бы N действующих
// строк — ровно тот дефект, ради которого глобальная уникальность и заведена.
func TestUserInvite_ConcurrentBootstrap_RaceSafe(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	const ext = domain.ExternalSubject("ext-i11b-racing-sub")
	const email = domain.Email("racing-bootstrap@example.com")
	const N = 5

	var (
		wg        sync.WaitGroup
		successes int64
		failures  int64
		mu        sync.Mutex
		loserErrs []error
	)
	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w, err := repo.Writer(ctx)
			if err != nil {
				atomic.AddInt64(&failures, 1)
				return
			}
			defer func() { _ = w.Rollback(ctx) }()
			// Each racing first-login bootstraps a DISTINCT new account_id.
			uid := domain.UserID(ids.NewID(domain.PrefixUser))
			accID := domain.AccountID(ids.NewID(domain.PrefixAccount))
			if _, err := w.UsersW().InsertActive(ctx, domain.User{
				ID:           uid,
				AccountID:    accID,
				ExternalID:   ext, // SAME identity across all goroutines
				Email:        email,
				DisplayName:  domain.DisplayName("Racing"),
				InviteStatus: domain.InviteStatusActive,
			}); err != nil {
				atomic.AddInt64(&failures, 1)
				mu.Lock()
				loserErrs = append(loserErrs, err)
				mu.Unlock()
				return
			}
			if _, err := w.AccountsW().Insert(ctx, domain.Account{
				ID:          accID,
				Name:        domain.AccountName("racing-" + string(accID[len(accID)-6:])),
				OwnerUserID: uid,
				Labels:      domain.Labels{},
			}); err != nil {
				atomic.AddInt64(&failures, 1)
				return
			}
			if err := w.Commit(ctx); err != nil {
				atomic.AddInt64(&failures, 1)
				return
			}
			atomic.AddInt64(&successes, 1)
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(1), atomic.LoadInt64(&successes),
		"ровно один участник заводит действующую строку человека")
	assert.Equal(t, int64(N-1), atomic.LoadInt64(&failures),
		"остальные обязаны проиграть гонку НА КЛЮЧЕ, а не на удаче")

	// Проигравшие обязаны получить сентинел ErrAlreadyExists с каноническим
	// текстом: сырое имя ограничения наружу не течёт НИКОГДА
	// (`data-integrity.md` §SQLSTATE-маппинг) — по нему восстанавливается схема.
	// Имена перечислены в отрицаниях затем, что каждое из них и есть та строка,
	// которая потекла бы, окажись маппинг неполным.
	for _, e := range loserErrs {
		assert.True(t, stderrors.Is(e, iamerr.ErrAlreadyExists),
			"loser error maps to ErrAlreadyExists, got %v", e)
		assert.NotContains(t, e.Error(), "users_active_external_id_uniq",
			"канонический текст не вправе нести имя ограничения")
		assert.NotContains(t, e.Error(), "users_identity_external_id_uniq",
			"канонический текст не вправе нести имя ограничения")
		assert.NotContains(t, e.Error(), "users_identity_email_uniq",
			"канонический текст не вправе нести имя ограничения")
		assert.NotContains(t, e.Error(), "duplicate key value",
			"канонический текст не вправе нести сырой текст драйвера")
	}

	// Действующая строка у человека ровно одна — глобально, а не в аккаунте.
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	actives, err := rd.Users().FindActiveByExternalID(ctx, ext)
	require.NoError(t, err)
	assert.Len(t, actives, 1, "действующая строка личности одна — дублей не завелось")
}
