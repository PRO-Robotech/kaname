// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// invite_deadline_integration_test.go — СРОК живёт на СТРОКЕ приглашения, и
// активация по истечении отвергается (приёмка ID-MAIL-1, §10 п. 22, MAIL-23;
// однократность — MAIL-22).
//
// # Почему срок — КОЛОНКА, а не вычисление от времени заведения
//
// Величина срока есть ручка посадки, и менять её вправе оператор. Вычисляй
// службa срок на лету от `created_at`, правка ручки молча сдвинула бы срок у
// строк, ВЫДАННЫХ под прежней величиной: человек, которому сказали «неделя»,
// обнаружил бы, что у него сутки. Срок — свойство выданного приглашения,
// поэтому он записывается в момент выдачи и потом не двигается ничем.
//
// # Отказ решает CAS, а не чтение
//
// Единственный оператор `UPDATE … WHERE invite_status='PENDING' AND (срок не
// истёк)` и есть решение: под конкуренцией выигрывает ровно одна транзакция,
// остальные видят ноль строк. Чтение, называющее ПРИЧИНУ отказа, идёт после и
// решения не принимает — оно выбирает слова, а не исход (запрет #10 требует
// именно этого: инвариант держит оператор базы, а не проверка-перед-записью).

import (
	"context"
	stderrors "errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// TestInviteDeadline_ExpiredRowDoesNotActivate — ОТРИЦАНИЕ: срок истёк.
func TestInviteDeadline_ExpiredRowDoesNotActivate(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	adminID, accID := bootstrapAdmin(t, ctx, repo, "mail23a")

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	pending, _, err := w.UsersW().InsertPending(ctx, domain.User{
		ID:           uid,
		AccountID:    accID,
		Email:        "expired@example.com",
		DisplayName:  "Expired",
		InviteStatus: domain.InviteStatusPending,
		InvitedBy:    adminID,
	}, time.Now().UTC().Add(-time.Minute))
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, aerr := w2.UsersW().ActivateInvite(ctx, pending.ID,
		domain.ExternalSubject("sub-mail23a"), domain.DisplayName("Real"))
	_ = w2.Rollback(ctx)

	require.Error(t, aerr)
	assert.True(t, stderrors.Is(aerr, iamerr.ErrInviteExpired),
		"истёкшее приглашение обязано отвергаться СВОИМ исходом, а не «не найдено»: %v", aerr)
	assert.NotErrorIs(t, aerr, iamerr.ErrNotFound,
		"исход «не найдено» на истёкшей строке послал бы человека искать несуществующее")
	assert.Contains(t, aerr.Error(), "invite again",
		"отказ обязан называть следующий шаг, а не только причину")

	// Строка ОСТАЛАСЬ PENDING: отказ ничего не потратил.
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	got, gerr := rd.Users().Get(ctx, pending.ID)
	require.NoError(t, gerr)
	assert.Equal(t, domain.InviteStatusPending, got.InviteStatus)
}

// TestInviteDeadline_RowInsideTheDeadlineActivates — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ.
//
// Без него отрицание выше зеленело бы и на строке, которую не активирует ничто:
// «не активировалась» и «истекла» стали бы неразличимы.
func TestInviteDeadline_RowInsideTheDeadlineActivates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	adminID, accID := bootstrapAdmin(t, ctx, repo, "mail23b")

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	pending, _, err := w.UsersW().InsertPending(ctx, domain.User{
		ID:           uid,
		AccountID:    accID,
		Email:        "intime@example.com",
		DisplayName:  "InTime",
		InviteStatus: domain.InviteStatusPending,
		InvitedBy:    adminID,
	}, time.Now().UTC().Add(time.Hour))
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	activated, aerr := w2.UsersW().ActivateInvite(ctx, pending.ID,
		domain.ExternalSubject("sub-mail23b"), domain.DisplayName("Real"))
	require.NoError(t, aerr)
	require.NoError(t, w2.Commit(ctx))
	assert.Equal(t, domain.InviteStatusActive, activated.InviteStatus)
}

// TestInviteDeadline_NoDeadlineRowStillActivates — второй положительный
// контроль и граница правки: строка БЕЗ срока (заведена до того, как срок
// появился) активируется по-прежнему. Без него правка молча обесценила бы
// каждое приглашение, выданное раньше.
func TestInviteDeadline_NoDeadlineRowStillActivates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	adminID, accID := bootstrapAdmin(t, ctx, repo, "mail23c")

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	pending, _, err := w.UsersW().InsertPending(ctx, domain.User{
		ID:           uid,
		AccountID:    accID,
		Email:        "nodeadline@example.com",
		InviteStatus: domain.InviteStatusPending,
		InvitedBy:    adminID,
	}, time.Time{})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	activated, aerr := w2.UsersW().ActivateInvite(ctx, pending.ID,
		domain.ExternalSubject("sub-mail23c"), domain.DisplayName("Real"))
	require.NoError(t, aerr)
	require.NoError(t, w2.Commit(ctx))
	assert.Equal(t, domain.InviteStatusActive, activated.InviteStatus)
}

// TestInviteDeadline_ActivationHappensOnce — MAIL-22: приглашение выкупается
// ОДИН раз, и под конкуренцией тоже.
//
// Проба КОНКУРЕНТНАЯ намеренно: последовательный второй вызов ловит уже
// закоммиченное состояние и ничего не говорит о гонке, а именно гонка первого
// входа и есть спорный путь (`data-integrity.md` §«Чек-лист нового ссылочного
// поля», п. 5).
func TestInviteDeadline_ActivationHappensOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	adminID, accID := bootstrapAdmin(t, ctx, repo, "mail22")

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	pending, _, err := w.UsersW().InsertPending(ctx, domain.User{
		ID:           uid,
		AccountID:    accID,
		Email:        "once@example.com",
		InviteStatus: domain.InviteStatusPending,
		InvitedBy:    adminID,
	}, time.Now().UTC().Add(time.Hour))
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	const racers = 6
	var (
		mu       sync.Mutex
		won      int
		refusals []error
		wg       sync.WaitGroup
		start    = make(chan struct{})
	)
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			<-start
			tw, terr := repo.Writer(ctx)
			if terr != nil {
				mu.Lock()
				refusals = append(refusals, terr)
				mu.Unlock()
				return
			}
			_, aerr := tw.UsersW().ActivateInvite(ctx, pending.ID,
				domain.ExternalSubject("sub-mail22"), domain.DisplayName("Real"))
			if aerr != nil {
				_ = tw.Rollback(ctx)
				mu.Lock()
				refusals = append(refusals, aerr)
				mu.Unlock()
				return
			}
			if cerr := tw.Commit(ctx); cerr != nil {
				mu.Lock()
				refusals = append(refusals, cerr)
				mu.Unlock()
				return
			}
			mu.Lock()
			won++
			mu.Unlock()
		}(i)
	}
	close(start)
	wg.Wait()

	assert.Equal(t, 1, won, "активировать строку обязана РОВНО ОДНА транзакция, выиграло %d", won)
	assert.Len(t, refusals, racers-1)
	for _, e := range refusals {
		assert.True(t, stderrors.Is(e, iamerr.ErrNotFound),
			"проигравший обязан получить исход гонки («строку активировал конкурент»), а не срок: %v", e)
	}
}

// TestInviteDeadline_ReInvitingExtendsAnExpiredRow — приглашение, ВЫДАННОЕ
// ЗАНОВО, продлевает срок; рождённых истёкшими приглашений не бывает.
//
// Строка приглашения ГЛОБАЛЬНА: человека, уже известного платформе, приглашают
// во второй аккаунт ЭТОЙ ЖЕ строкой. Не тронь повторное приглашение срок —
// активация отказала бы сразу, и отказ говорил бы «попросите пригласить
// заново» тому, кого только что пригласили.
func TestInviteDeadline_ReInvitingExtendsAnExpiredRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	adminA, accA := bootstrapAdmin(t, ctx, repo, "mail23d1")
	_, accB := bootstrapAdmin(t, ctx, repo, "mail23d2")

	// Первое приглашение — уже истёкшее.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	first, _, err := w.UsersW().InsertPending(ctx, domain.User{
		ID:           domain.UserID(ids.NewID(domain.PrefixUser)),
		AccountID:    accA,
		Email:        "reinvited@example.com",
		InviteStatus: domain.InviteStatusPending,
		InvitedBy:    adminA,
	}, time.Now().UTC().Add(-time.Hour))
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	// Контроль: до повторного приглашения строка НЕ активируется.
	wx, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, xerr := wx.UsersW().ActivateInvite(ctx, first.ID,
		domain.ExternalSubject("sub-mail23d-pre"), domain.DisplayName("Real"))
	_ = wx.Rollback(ctx)
	require.Error(t, xerr, "проба судит не то состояние: строка активируется и без продления")
	require.True(t, stderrors.Is(xerr, iamerr.ErrInviteExpired))

	// Приглашение ЗАНОВО — во второй аккаунт, той же почты.
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, _, err = w2.UsersW().InsertPending(ctx, domain.User{
		ID:           domain.UserID(ids.NewID(domain.PrefixUser)),
		AccountID:    accB,
		Email:        "reinvited@example.com",
		InviteStatus: domain.InviteStatusPending,
		InvitedBy:    adminA,
	}, time.Now().UTC().Add(time.Hour))
	require.NoError(t, err)
	require.NoError(t, w2.Commit(ctx))

	// Теперь выкупается.
	w3, err := repo.Writer(ctx)
	require.NoError(t, err)
	activated, aerr := w3.UsersW().ActivateInvite(ctx, first.ID,
		domain.ExternalSubject("sub-mail23d"), domain.DisplayName("Real"))
	require.NoError(t, aerr, "приглашение, выданное заново, родилось истёкшим")
	require.NoError(t, w3.Commit(ctx))
	assert.Equal(t, domain.InviteStatusActive, activated.InviteStatus)
}

// TestInviteDeadline_ReInvitingNeverShortensALongerDeadline — срок НЕ
// укорачивается: приглашение в соседний аккаунт с более близкой границей не
// отнимает у человека времени, выданного первым приглашением.
func TestInviteDeadline_ReInvitingNeverShortensALongerDeadline(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	adminA, accA := bootstrapAdmin(t, ctx, repo, "mail23e1")
	_, accB := bootstrapAdmin(t, ctx, repo, "mail23e2")

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	first, _, err := w.UsersW().InsertPending(ctx, domain.User{
		ID:           domain.UserID(ids.NewID(domain.PrefixUser)),
		AccountID:    accA,
		Email:        "longdeadline@example.com",
		InviteStatus: domain.InviteStatusPending,
		InvitedBy:    adminA,
	}, time.Now().UTC().Add(48*time.Hour))
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	// Второе приглашение с УЖЕ ИСТЁКШЕЙ границей: укоротить срок оно не вправе.
	w2, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, _, err = w2.UsersW().InsertPending(ctx, domain.User{
		ID:           domain.UserID(ids.NewID(domain.PrefixUser)),
		AccountID:    accB,
		Email:        "longdeadline@example.com",
		InviteStatus: domain.InviteStatusPending,
		InvitedBy:    adminA,
	}, time.Now().UTC().Add(-time.Hour))
	require.NoError(t, err)
	require.NoError(t, w2.Commit(ctx))

	w3, err := repo.Writer(ctx)
	require.NoError(t, err)
	activated, aerr := w3.UsersW().ActivateInvite(ctx, first.ID,
		domain.ExternalSubject("sub-mail23e"), domain.DisplayName("Real"))
	require.NoError(t, aerr, "второе приглашение укоротило срок, выданный первым")
	require.NoError(t, w3.Commit(ctx))
	assert.Equal(t, domain.InviteStatusActive, activated.InviteStatus)
}
