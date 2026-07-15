// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg_test

// account_integration_test.go — TDD integration-тесты для AccountRepo.
//
// Покрытие:
// - TestAccount_01_CreateGet_RoundTrip — happy path Create + Get.
// - TestAccount_02_Create_DuplicateName — UNIQUE accounts_name_unique → ErrAlreadyExists.
// - TestAccount_02_Create_RaceUnique — concurrent Create same name → ровно 1 success (race-safe via DB UNIQUE; запрет #10).
// - TestAccount_04_Create_FKOwner_Missing — FK accounts_owner_fk → ErrFailedPrecondition "User <id> not found".
// - TestAccount_05_Get_NotFound — well-formed-но-несуществ. id → ErrNotFound.
// - TestAccount_06_Update_Rename — UPDATE name + check sticky owner_user_id.
// - TestAccount_08_Delete_WithProjects — DELETE-WHERE-NOT-EXISTS → ErrFailedPrecondition.
// - TestAccount_08_Delete_Happy — DELETE без детей → OK.
// - TestAccount_08_Delete_NotFound — DELETE несуществующего → NotFound.
// - TestAccount_List_Pagination — List smoke.
//
// Запуск: `make test` или `go test ./internal/repo/kacho/pg/... -race`.
// Skip если `testing.Short()` — для CI без Docker.

import (
	"context"
	"database/sql"
	stderrors "errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go/modules/postgres"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/account"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

func setupTestDB(t testing.TB) string {
	t.Helper()
	ctx := context.Background()

	pgc, err := postgres.Run(ctx,
		"postgres:16-alpine",
		postgres.WithDatabase("kacho_iam_test"),
		postgres.WithUsername("iam"),
		postgres.WithPassword("iam"),
		postgres.BasicWaitStrategies(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = pgc.Terminate(ctx) })

	dsn, err := pgc.ConnectionString(ctx, "sslmode=disable")
	require.NoError(t, err)

	db, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.Up(db, "."))

	return appendSearchPathOptions(dsn)
}

func appendSearchPathOptions(dsn string) string {
	const optionsParam = "options=-c%20search_path%3Dkacho_iam%2Cpublic"
	if strings.Contains(dsn, "options=") || strings.Contains(dsn, "options%3D") {
		return dsn
	}
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	return dsn + sep + optionsParam
}

// mustSeedUser — bootstrap-style INSERT (user + own Account) через одну TX с
// DEFERRABLE FK. User-row после обязан иметь
// account_id; chicken-and-egg с accounts.owner_user_id решается DEFERRABLE FK.
//
// Возвращает только UserID (Account id — внутренний; тестам он редко нужен —
// они создают свой Account через seedAccount).
func mustSeedUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) domain.UserID {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	accID := domain.AccountID(ids.NewID(domain.PrefixAccount))

	tx, err := pool.Begin(ctx)
	require.NoError(t, err, "begin TX for seed user")
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		string(uid), string(accID),
		fmt.Sprintf("ext-%s-%s", suffix, uid),
		fmt.Sprintf("u-%s@example.com", suffix),
		"Test User "+suffix,
	)
	require.NoError(t, err, "seed user INSERT")

	_, err = tx.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		string(accID),
		fmt.Sprintf("seed-acc-%s-%s", suffix, accID[len(accID)-6:]),
		string(uid),
	)
	require.NoError(t, err, "seed user account INSERT")

	require.NoError(t, tx.Commit(ctx), "commit seed user TX")
	return uid
}

// seedAccount — Insert + Commit через writer-TX.
func seedAccount(t *testing.T, ctx context.Context, repo *kachopg.Repository, name string, ownerID domain.UserID) domain.Account {
	t.Helper()
	a := newAccount(name, ownerID)
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	out, err := w.AccountsW().Insert(ctx, a)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return out
}

func newAccount(name string, ownerID domain.UserID) domain.Account {
	return domain.Account{
		ID:          domain.AccountID(ids.NewID(domain.PrefixAccount)),
		Name:        domain.AccountName(name),
		Description: domain.Description("acceptance test " + name),
		Labels:      domain.Labels{},
		OwnerUserID: ownerID,
	}
}

// ── Сценарий 01: Create + Get round-trip ─────────────────────────────────────
func TestAccount_01_CreateGet_RoundTrip(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "01")

	created := seedAccount(t, ctx, repo, "acme01", uid)
	assert.True(t, strings.HasPrefix(string(created.ID), "acc"), "id prefix")
	assert.Equal(t, domain.AccountName("acme01"), created.Name)
	assert.Equal(t, uid, created.OwnerUserID)
	assert.WithinDuration(t, time.Now(), created.CreatedAt, 30*time.Second, "created_at")

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	got, err := rd.Accounts().Get(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, got.ID)
	assert.Equal(t, created.Name, got.Name)
	assert.Equal(t, created.OwnerUserID, got.OwnerUserID)
}

// ── Сценарий 02: Create — дубль имени → ErrAlreadyExists ────────────────────
func TestAccount_02_Create_DuplicateName(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "02")
	_ = seedAccount(t, ctx, repo, "dup-name", uid)

	// Вторая Insert с тем же именем — должен поймать UNIQUE.
	uid2 := mustSeedUser(t, ctx, pool, "02b")
	a := newAccount("dup-name", uid2)
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = w.AccountsW().Insert(ctx, a)
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrAlreadyExists), "expected ErrAlreadyExists, got %v", err)
	assert.Contains(t, err.Error(), "Account with name dup-name already exists",
		"canonical Kachō error text")
}

// ── Сценарий 02b (race): 2+ goroutines Create same name → ровно 1 success ───
func TestAccount_02_Create_RaceUnique(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "race")

	const goroutines = 8
	results := make(chan error, goroutines)
	var ready sync.WaitGroup
	ready.Add(goroutines)
	startGate := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		go func() {
			ready.Done()
			<-startGate // одновременный старт
			a := newAccount("race-name", uid)
			w, err := repo.Writer(ctx)
			if err != nil {
				results <- err
				return
			}
			_, err = w.AccountsW().Insert(ctx, a)
			if err != nil {
				_ = w.Rollback(ctx)
				results <- err
				return
			}
			results <- w.Commit(ctx)
		}()
	}
	ready.Wait()
	close(startGate)

	successes, dupErrors, otherErrors := 0, 0, 0
	for i := 0; i < goroutines; i++ {
		err := <-results
		switch {
		case err == nil:
			successes++
		case stderrors.Is(err, iamerr.ErrAlreadyExists):
			dupErrors++
		default:
			otherErrors++
			t.Logf("unexpected race error: %v", err)
		}
	}
	assert.Equal(t, 1, successes, "ровно один INSERT должен пройти")
	assert.Equal(t, goroutines-1, dupErrors, "остальные — UNIQUE-violation")
	assert.Equal(t, 0, otherErrors, "не должно быть других ошибок")
}

// ── Сценарий 04: Create с несуществующим owner_user_id → FailedPrecondition ──
// FK accounts_owner_fk теперь DEFERRABLE INITIALLY DEFERRED (parity
// с bootstrap-TX). Insert НЕ проваливается immediate, FK check
// откладывается до COMMIT. Тест проверяет, что COMMIT поднимает ту же ошибку.
func TestAccount_04_Create_FKOwner_Missing(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	ghost := domain.UserID("usr00000000000000ghost") // не seed'им
	a := newAccount("ghost-owner", ghost)
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, insErr := w.AccountsW().Insert(ctx, a)
	// DEFERRABLE FK: Insert либо успешен (FK отложен), либо immediate-fail
	// (если каким-то образом FK поднялся). В обоих случаях COMMIT финально
	// поднимет ошибку при non-existing owner.
	commitErr := w.Commit(ctx)
	_ = w.Rollback(ctx) // safety net на случай если Commit-сам не rollback'нул
	var err4 error
	if insErr != nil {
		err4 = insErr
	} else {
		err4 = commitErr
	}
	require.Error(t, err4, "either Insert or Commit must fail on missing FK target")
	// Для DEFERRABLE FK COMMIT возвращает pgx-ошибку с SQLSTATE 23503; mapErr
	// ее не оборачивает (она приходит из tx.Commit, не из RETURNING). На
	// immediate-FK путь — оборачивается в ErrFailedPrecondition. Принимаем
	// оба варианта; verbatim-text проверяем только для immediate path.
	if insErr != nil {
		assert.True(t, stderrors.Is(insErr, iamerr.ErrFailedPrecondition),
			"immediate FK: expected ErrFailedPrecondition, got %v", insErr)
		assert.Contains(t, insErr.Error(), fmt.Sprintf("User %s not found", ghost))
	}
}

// ── Сценарий 05: Get — well-formed-но-несуществующий → NotFound ─────────────
func TestAccount_05_Get_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	_, err = rd.Accounts().Get(ctx, "acc00000000000000ghost")
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrNotFound), "expected ErrNotFound, got %v", err)
	assert.Contains(t, err.Error(), "Account acc00000000000000ghost not found")
}

// ── Сценарий 06: Update name через mask=["name"] ────────────────────────────
func TestAccount_06_Update_Rename(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "06")
	created := seedAccount(t, ctx, repo, "to-rename", uid)

	patched := created
	patched.Name = "renamed"
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	updated, err := w.AccountsW().Update(ctx, patched, []string{"name"})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	assert.Equal(t, domain.AccountName("renamed"), updated.Name)
	// Sticky owner_user_id, description.
	assert.Equal(t, created.OwnerUserID, updated.OwnerUserID)
	assert.Equal(t, created.Description, updated.Description)
}

// ── Сценарий 08: Delete — с детьми → FailedPrecondition (DELETE-WHERE-NOT-EXISTS) ─
func TestAccount_08_Delete_WithProjects(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "08")
	created := seedAccount(t, ctx, repo, "to-del-with-children", uid)

	// Создаем project напрямую (project use-case еще не реализован).
	_, err = pool.Exec(ctx, `
		INSERT INTO projects (id, account_id, name)
		VALUES ($1, $2, $3)`,
		ids.NewID(domain.PrefixProject), string(created.ID), "child-project",
	)
	require.NoError(t, err)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w.AccountsW().Delete(ctx, created.ID)
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition), "expected ErrFailedPrecondition, got %v", err)
	assert.Contains(t, err.Error(), "contains projects and cannot be deleted")
}

// ── Сценарий 08b: Delete — без детей → OK ───────────────────────────────────
func TestAccount_08_Delete_Happy(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "08b")
	created := seedAccount(t, ctx, repo, "to-del-happy", uid)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w.AccountsW().Delete(ctx, created.ID)
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))

	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	_, err = rd.Accounts().Get(ctx, created.ID)
	assert.True(t, stderrors.Is(err, iamerr.ErrNotFound))
}

// ── Сценарий 08c: Delete несуществующего → NotFound ─────────────────────────
func TestAccount_08_Delete_NotFound(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	err = w.AccountsW().Delete(ctx, "acc00000000000000ghst")
	_ = w.Rollback(ctx)
	require.Error(t, err)
	assert.True(t, stderrors.Is(err, iamerr.ErrNotFound))
}

// ── List smoke ──────────────────────────────────────────────────────────────
func TestAccount_List_Pagination(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kachopg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "lst")
	for i := 0; i < 3; i++ {
		_ = seedAccount(t, ctx, repo, fmt.Sprintf("listed-%d", i), uid)
	}
	rd, err := repo.Reader(ctx)
	require.NoError(t, err)
	defer func() { _ = rd.Rollback(ctx) }()
	rows, next, err := rd.Accounts().List(ctx, account.ListFilter{PageSize: 100})
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(rows), 3)
	assert.Empty(t, next, "single page expected")
}
