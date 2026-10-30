// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// access_binding_integration_test.go — интеграционные пробы AccessBindingRepo
// (строгое создание из миграции 0003).
//
// Покрытие:
// - 31a: Insert новой выдачи → новая строка + новый id.
// - 31b (миграция 0003): Insert повтора активного кортежа из пяти полей → ErrAlreadyExists
//   с дословным текстом `these permissions are already granted to <subject_id> on <res_type>:<res_id>`.
// - 31c (миграция 0003): Insert того же кортежа из пяти полей после отзыва → новая строка ACTIVE
//   (частичный UNIQUE WHERE revoked_at IS NULL не блокирует отозванные строки).
// - 32: Insert с несущ. role_id → FailedPrecondition (FK access_bindings_role_fk).
// - 33: Insert с недопустимым subject_type → нарушение CHECK → InvalidArgument.
// - 34a: Успешный Delete.
// - 34b: Delete несущ. → NotFound.
// - 35a: ListByScope — несколько выдач одного ресурса.
// - 35b: ListBySubject — несколько выдач одного субъекта.

import (
	"context"
	stderrors "errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
)

// insertAB — вспомогательная функция посева AccessBinding.
//
// Использует assert.NoError + явный Rollback + t.FailNow (не голый
// `require.NoError`), чтобы освободить открытый Writer на любом пути исполнения. Иначе
// при нарушении FK (например, role_id ссылается на несуществующую роль)
// `require.FailNow` → `runtime.Goexit` ДО `w.Commit/Rollback` → соединение
// остаётся занятым → `pool.Close` блокируется на WaitGroup в puddle из pgxpool →
// тест висит до истечения срока. Параллель `mustBeginTx` из
// kac127_repos_integration_test.go.
func insertAB(t *testing.T, ctx context.Context, repo *kanamepg.Repository, b domain.AccessBinding) domain.AccessBinding {
	t.Helper()
	if b.ID == "" {
		b.ID = domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	}
	w, err := repo.Writer(ctx)
	if !assert.NoError(t, err) {
		t.FailNow()
	}
	out, err := bindingset.Insert(ctx, w.AccessBindingsW(), b)
	if err != nil {
		_ = w.Rollback(ctx) // освобождаем соединение до FailNow
		assert.NoError(t, err)
		t.FailNow()
	}
	if err := w.Commit(ctx); err != nil {
		_ = w.Rollback(ctx)
		assert.NoError(t, err)
		t.FailNow()
	}
	return out
}

func TestAB_31a_Insert_New(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "ab31a")
	acc := seedAccount(t, ctx, repo, "acc-ab31a", uid)

	b := domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       domain.SystemViewerRoleID, // системная роль посева (миграция 0011)
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	}
	out := insertAB(t, ctx, repo, b)
	assert.NotEmpty(t, out.ID)
	assert.Equal(t, b.SubjectID, out.SubjectID)
}

// TestAB_31b_Insert_DuplicateActiveIsAlreadyExists — миграция 0003.
//
// Двойная вставка ОДНОГО кортежа из пяти полей (обе строки были бы ACTIVE) должна давать
// SQLSTATE 23505 от access_bindings_active_grant_uniq, который mapErr
// преобразует в ErrAlreadyExists с каноническим текстом ошибки Kachō:
// `these permissions are already granted to <subject_id> on <res_type>:<res_id>`.
// Это заменяет прежнее поведение идемпотентного обновления при вставке.
func TestAB_31b_Insert_DuplicateActiveIsAlreadyExists(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "ab31b")
	acc := seedAccount(t, ctx, repo, "acc-ab31b", uid)

	b := domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       domain.SystemViewerRoleID, // системная роль посева (миграция 0011)
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	}
	_ = insertAB(t, ctx, repo, b)

	// Вторая вставка с новым кандидатом id, но тем же кортежем из пяти полей должна отказать.
	b2 := b
	b2.ID = domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, insErr := bindingset.Insert(ctx, w.AccessBindingsW(), b2)
	_ = w.Rollback(ctx) // освобождаем соединение и на пути ошибки

	require.Error(t, insErr, "duplicate active grant must surface")
	assert.True(t, stderrors.Is(insErr, iamerr.ErrAlreadyExists),
		"expected ErrAlreadyExists sentinel, got %v", insErr)
	// Канонический текст ошибки Kachō.
	wantMsg := "these permissions are already granted to " + string(uid) + " on account:" + string(acc.ID)
	assert.Contains(t, insErr.Error(), wantMsg,
		"error message must include the canonical Kachō error text")
}

// TestAB_31c_Insert_AfterRevokeIsAllowed — миграция 0003.
//
// Частичный UNIQUE access_bindings_active_grant_uniq ограничивает уникальность
// условием WHERE revoked_at IS NULL. Повторная выдача ТОГО ЖЕ кортежа из пяти полей
// ПОСЛЕ отзыва прежней строки должна пройти (повторная выдача операторами законна).
func TestAB_31c_Insert_AfterRevokeIsAllowed(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "ab31c")
	acc := seedAccount(t, ctx, repo, "acc-ab31c", uid)

	b := domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       domain.SystemViewerRoleID,
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	}
	first := insertAB(t, ctx, repo, b)

	// Отзываем первую выдачу.
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	revoker := domain.UserID(uid)
	_, err = w.AccessBindingsW().TransitionStatus(ctx, first.ID,
		[]domain.AccessBindingStatus{domain.AccessBindingStatusActive},
		domain.AccessBindingStatusRevoked, &revoker)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	// Повторно выдаём тот же кортеж из пяти полей — успешно (новая строка ACTIVE).
	b2 := b
	b2.ID = domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	second := insertAB(t, ctx, repo, b2)
	assert.NotEqual(t, first.ID, second.ID, "re-grant after revoke must produce a fresh row")
	assert.Equal(t, domain.AccessBindingStatusActive, second.Status)
}

func TestAB_32_Insert_MissingRole(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "ab32")

	b := domain.AccessBinding{
		ID:           domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)),
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       "rol0000000000000ghst", // не существует
		ResourceType: "account",
		ResourceID:   "acc0000000000000xxxx",
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = bindingset.Insert(ctx, w.AccessBindingsW(), b)
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition))
}

func TestAB_33_Insert_InvalidSubjectType(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "ab33")

	b := domain.AccessBinding{
		ID:           domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)),
		SubjectType:  domain.SubjectType("badtype"), // нарушает DB CHECK access_bindings_subject_ck
		SubjectID:    domain.SubjectID(uid),
		RoleID:       seedSystemRoleIDIAMView,
		ResourceType: "account",
		ResourceID:   "acc0000000000000xxxx",
	}
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = bindingset.Insert(ctx, w.AccessBindingsW(), b)
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrInvalidArg))
}

func TestAB_34a_Delete_Happy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "ab34a")
	acc := seedAccount(t, ctx, repo, "acc-ab34a", uid)
	ab := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       seedSystemRoleIDIAMView,
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	})

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().Delete(ctx, ab.ID))
	require.NoError(t, w.Commit(ctx))
}

func TestAB_34b_Delete_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w.AccessBindingsW().Delete(ctx, "acb0000000000000ghst")
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrNotFound))
}

func TestAB_35_ListByScopeAndBySubject(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "ab35a")
	uid2 := mustSeedUser(t, ctx, pool, "ab35b")
	acc := seedAccount(t, ctx, repo, "acc-ab35", uid)

	// uid → admin + viewer на acc
	_ = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       seedSystemRoleIDIAMAdmin,
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	})
	_ = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       seedSystemRoleIDIAMView,
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	})
	// uid2 → viewer на acc
	_ = insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid2),
		RoleID:       seedSystemRoleIDIAMView,
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	})

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()

	// ListByScope (account = acc.ID) → 3 выдачи.
	byRes, _, err := rd.AccessBindings().ListByScope(ctx, "account", string(acc.ID), repoab.PageFilter{PageSize: 100})
	require.NoError(t, err)
	assert.Equal(t, 3, len(byRes))

	// ListBySubject (uid) → 2 выдачи (admin + viewer).
	bySub, _, err := rd.AccessBindings().ListBySubject(ctx, domain.SubjectTypeUser, domain.SubjectID(uid), repoab.PageFilter{PageSize: 100})
	require.NoError(t, err)
	assert.Equal(t, 2, len(bySub))
}

// TestAccessBinding_ConcurrentActiveGrant_ExactlyOneWinner — миграция 0003,
// требование пробы гонки конкурентных горутин для оспариваемых инвариантов базы.
//
// AccessBinding.Create — самая нагруженная конкурентная запись IAM. Контракт
// строгого создания (частичный UNIQUE access_bindings_active_grant_uniq
// WHERE revoked_at IS NULL) должен защищать от ГОНОК в базе: N горутин,
// вставляющих ОДИНАКОВЫЙ активный кортеж из пяти полей, создают РОВНО ОДНУ строку,
// остальные безопасно отказывают с ErrAlreadyExists. Без победы второго писателя,
// паники и утечки ошибки pgx (запрет #10 — инвариант обеспечивает Postgres,
// а не проверка перед действием в коде). Последовательная проба повтора (TestAB_31b)
// не ловит гонку TOCTOU; эта проба ловит.
//
// Каждая горутина ведёт собственную транзакцию Writer (pool.Begin → Insert → Commit):
// общая функция insertAB НЕ безопасна для горутин (использует t.FailNow), поэтому
// жизненный цикл транзакции встроен здесь по образцу гонки из
// файла cluster_admin_grant_integration_test.go.
func TestAccessBinding_ConcurrentActiveGrant_ExactlyOneWinner(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "abconc")
	acc := seedAccount(t, ctx, repo, "acc-abconc", uid)

	// Оспариваемый кортеж из пяти полей одинаков во всех горутинах (различается
	// только кандидат id — реальная форма конкурентного Create).
	tuple := domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       seedSystemRoleIDIAMView,
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	}

	const N = 8
	var wg sync.WaitGroup
	winners := make(chan domain.AccessBindingID, N)
	dupErrs := make(chan error, N)
	otherErrs := make(chan error, N)

	for i := 0; i < N; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := tuple
			b.ID = domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))

			w, ierr := repo.Writer(ctx)
			if ierr != nil {
				otherErrs <- ierr
				return
			}
			out, ierr := bindingset.Insert(ctx, w.AccessBindingsW(), b)
			if ierr != nil {
				_ = w.Rollback(ctx) // освобождаем соединение на проигравшем пути
				if stderrors.Is(ierr, iamerr.ErrAlreadyExists) {
					dupErrs <- ierr
				} else {
					otherErrs <- ierr
				}
				return
			}
			if ierr := w.Commit(ctx); ierr != nil {
				// Гонка сериализации/коммита, выявляющая конфликт активной выдачи
				// при COMMIT, по-прежнему означает повторную выдачу.
				if stderrors.Is(ierr, iamerr.ErrAlreadyExists) {
					dupErrs <- ierr
				} else {
					otherErrs <- ierr
				}
				return
			}
			winners <- out.ID
		}()
	}
	wg.Wait()
	close(winners)
	close(dupErrs)
	close(otherErrs)

	// Нет неожиданных ошибок (кроме предусмотренных сигнальных).
	for e := range otherErrs {
		require.NoError(t, e, "only ErrAlreadyExists is an acceptable loser outcome")
	}

	winnerIDs := make([]domain.AccessBindingID, 0, N)
	for id := range winners {
		winnerIDs = append(winnerIDs, id)
	}
	dupCount := 0
	for range dupErrs {
		dupCount++
	}

	require.Len(t, winnerIDs, 1, "exactly one concurrent Insert of the same active 5-tuple must win")
	require.Equal(t, N-1, dupCount, "the remaining goroutines must fail with ErrAlreadyExists")

	// В базе сохранена ровно одна строка ACTIVE (без победы второго писателя).
	var active int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_bindings
		   WHERE subject_type = $1 AND subject_id = $2 AND role_id = $3
		     AND resource_type = $4 AND resource_id = $5
		     AND revoked_at IS NULL`,
		string(tuple.SubjectType), string(tuple.SubjectID), tuple.RoleID,
		string(tuple.ResourceType), tuple.ResourceID).Scan(&active))
	require.Equal(t, 1, active, "exactly one active grant row must persist after the race")
}

// TestAccessBinding_RegrantAfterRevoke_Succeeds — миграция 0003.
//
// Частичный UNIQUE access_bindings_active_grant_uniq ограничен условием
// WHERE revoked_at IS NULL, поэтому выдача REVOKED НЕ должна блокировать новую
// активную выдачу того же кортежа из пяти полей. Повторная выдача после отзыва законна.
// В отличие от существующей TestAB_31c, проверяет число сохранившихся активных
// строк через путь отзыва (TransitionStatus → REVOKED задаёт revoked_at).
func TestAccessBinding_RegrantAfterRevoke_Succeeds(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "abregr")
	acc := seedAccount(t, ctx, repo, "acc-abregr", uid)

	tuple := domain.AccessBinding{
		SubjectType:  domain.SubjectTypeUser,
		SubjectID:    domain.SubjectID(uid),
		RoleID:       seedSystemRoleIDIAMView,
		ResourceType: "account",
		ResourceID:   string(acc.ID),
	}
	first := insertAB(t, ctx, repo, tuple)
	require.Equal(t, domain.AccessBindingStatusActive, first.Status)

	// Отзываем первую выдачу настоящим путём репозитория (CAS UPDATE задаёт
	// поля revoked_at + status='REVOKED').
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	revoker := domain.UserID(uid)
	revoked, err := w.AccessBindingsW().TransitionStatus(ctx, first.ID,
		[]domain.AccessBindingStatus{domain.AccessBindingStatusActive},
		domain.AccessBindingStatusRevoked, &revoker)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	require.Equal(t, domain.AccessBindingStatusRevoked, revoked.Status)

	// Повторно выдаём ТОТ ЖЕ кортеж из пяти полей — УСПЕШНО (отозванная строка вне
	// области частичного UNIQUE), получая новую строку ACTIVE.
	regrant := tuple
	regrant.ID = domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	second := insertAB(t, ctx, repo, regrant)
	assert.NotEqual(t, first.ID, second.ID, "re-grant after revoke must produce a fresh row id")
	assert.Equal(t, domain.AccessBindingStatusActive, second.Status)

	// Ровно одна строка ACTIVE + одна историческая строка REVOKED для кортежа из пяти полей.
	var active, revokedCnt int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT
		   count(*) FILTER (WHERE revoked_at IS NULL),
		   count(*) FILTER (WHERE revoked_at IS NOT NULL)
		 FROM kaname.access_bindings
		 WHERE subject_type = $1 AND subject_id = $2 AND role_id = $3
		   AND resource_type = $4 AND resource_id = $5`,
		string(tuple.SubjectType), string(tuple.SubjectID), tuple.RoleID,
		string(tuple.ResourceType), tuple.ResourceID).Scan(&active, &revokedCnt))
	require.Equal(t, 1, active, "exactly one active grant after re-grant")
	require.Equal(t, 1, revokedCnt, "the revoked grant remains as history")
}
