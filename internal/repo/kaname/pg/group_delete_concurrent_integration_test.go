// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// group_delete_concurrent_integration_test.go — доказательство защиты от гонки
// конкурентного CAS в продуктовом groupWriter.Delete (data-integrity.md,
// пункт #5: каждый конкурентный путь CAS/защиты требует пробы гонки,
// доказывающей ровно одного победителя). Соседний перекос записи удаления/создания
// пользователя проверен в access_binding_subject_exists_integration_test.go через
// ВСТРОЕННУЮ SQL-копию ветви users. Ветвь ГРУПП (отдельная обратная проверка по
// access_bindings + access_binding_subjects + проверка строки groups через
// FOR KEY SHARE миграции 0049 + триггер groups BEFORE DELETE миграции 0050) не имела
// конкурентной пробы и проверяется здесь через НАСТОЯЩИЙ groupWriter.Delete —
// без встроенной копии SQL.
//
// Обе подпробы детерминированы (без горутин, опроса pg_stat_activity и возможности
// зависания), повторяя TestABSubjectExists_ConcurrentDeleteVsCreate_
// NoDangling: настоящая запись AccessBinding для субъекта GROUP остаётся открытой
// в транзакции (её триггер subject_ref_exists из 0049 берёт FOR KEY SHARE на строку groups),
// затем продуктовый groupWriter.Delete выполняется в ОТДЕЛЬНОМ соединении с коротким
// сессионным lock_timeout, поэтому заблокированное удаление само завершается (SQLSTATE 55P03),
// не дожидаясь statement_timeout. Сама блокировка удаления ДОКАЗЫВАЕТ
// сериализацию двух путей на строке groups: окно перекоса записи, которое одна
// программная проверка NOT-EXISTS закрыть не могла. После коммита писателя новое
// защищённое удаление повторяет проверку по зафиксированной ссылке и отказывает с
// FailedPrecondition: выдача с висячей ссылкой на субъекта-группу не возникает.

import (
	"context"
	stderrors "errors"
	"strconv"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
)

// newLockTimeoutPool — pgxpool, каждая сессия которого задаёт `lock_timeout`, чтобы
// защищённая запись, заблокированная конфликтующим замком строки, сама завершалась (55P03),
// не дожидаясь statement_timeout. Используется на стороне удаления, чтобы
// доказательство сериализации было ограниченным по времени и детерминированным.
func newLockTimeoutPool(t *testing.T, ctx context.Context, dsn string, lockTimeoutMS int) *pgxpool.Pool {
	t.Helper()
	cfg, err := pgxpool.ParseConfig(dsn)
	require.NoError(t, err)
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["lock_timeout"] = strconv.Itoa(lockTimeoutMS)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool
}

func TestGroup_DeleteVsAddSubject_ConcurrentCAS_NoDangling(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: requires Postgres container")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)

	// Основной пул — посев + открытая транзакция записи AccessBinding.
	master, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer master.Close()
	seedRepo := kanamepg.New(master, nil)

	// Репозиторий стороны удаления использует пул с lock_timeout=2s, чтобы продуктовый
	// groupWriter.Delete завершался сам, не блокируясь до statement_timeout.
	delRepo := kanamepg.New(newLockTimeoutPool(t, ctx, dsn, 2000), nil)

	// realGroupDelete вызывает ПРОДУКТОВЫЙ groupWriter.Delete в новой транзакции
	// писателя с lock_timeout (откатывается — эта сторона никогда не фиксирует удаление).
	realGroupDelete := func(id domain.GroupID) error {
		w, werr := delRepo.Writer(ctx)
		require.NoError(t, werr)
		defer func() { _ = w.Rollback(ctx) }()
		return w.GroupsW().Delete(ctx, id)
	}

	// ── Проекция subjects[0]: проверка NOT-EXISTS в access_bindings ──────────
	t.Run("subjects0_access_bindings_guard", func(t *testing.T) {
		uid := mustSeedUser(t, ctx, master, "gdc-a")
		acc := seedAccount(t, ctx, seedRepo, "acc-gdc-a", uid)
		g := seedGroup(t, ctx, seedRepo, acc.ID, "gdc-a")

		// Настоящий AccessBinding.Create для субъекта group:g остаётся открытым (без коммита).
		// Его триггер subject_ref_exists из 0049 берёт FOR KEY SHARE на строку groups.
		wIns, err := seedRepo.Writer(ctx)
		require.NoError(t, err)
		committed := false
		defer func() {
			if !committed {
				_ = wIns.Rollback(ctx)
			}
		}()
		_, err = bindingset.Insert(ctx, wIns.AccessBindingsW(), domain.AccessBinding{
			ID:           domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding)),
			SubjectType:  domain.SubjectTypeGroup,
			SubjectID:    domain.SubjectID(g.ID),
			RoleID:       domain.SystemViewerRoleID,
			ResourceType: "account",
			ResourceID:   string(acc.ID),
		})
		require.NoError(t, err)

		// Продуктовый groupWriter.Delete должен заблокироваться замком записи KEY SHARE
		// и истечь по сроку — это доказывает сериализацию двух путей на строке groups.
		require.Error(t, realGroupDelete(g.ID),
			"guarded Group.Delete must block on the AB.Create key-share lock, not delete the group (race window would be open)")

		// Коммит → освобождение замка. Новое защищённое удаление видит зафиксированную
		// выдачу и отказывает: выдачи с висячей ссылкой на субъекта-группу нет.
		require.NoError(t, wIns.Commit(ctx))
		committed = true

		err = realGroupDelete(g.ID)
		require.Error(t, err)
		require.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition),
			"post-commit Group.Delete must reject (group still bound), got %v", err)

		// Инвариант: группа сохранилась, и выдача ссылается на существующую группу.
		var groupCnt, bindCnt int
		require.NoError(t, master.QueryRow(ctx,
			`SELECT count(*) FROM kaname.groups WHERE id=$1`, string(g.ID)).Scan(&groupCnt))
		require.Equal(t, 1, groupCnt, "bound group must survive the guarded delete")
		require.NoError(t, master.QueryRow(ctx,
			`SELECT count(*) FROM kaname.access_bindings WHERE subject_type='group' AND subject_id=$1`,
			string(g.ID)).Scan(&bindCnt))
		require.Equal(t, 1, bindCnt, "the committed binding must reference the live group")
	})

	// ── subjects[1..N]: защита access_binding_subjects + триггер 0050 ──────
	t.Run("subjectsN_access_binding_subjects_guard", func(t *testing.T) {
		uid := mustSeedUser(t, ctx, master, "gdc-b")
		acc := seedAccount(t, ctx, seedRepo, "acc-gdc-b", uid)
		g := seedGroup(t, ctx, seedRepo, acc.ID, "gdc-b")

		// ЗАФИКСИРОВАННАЯ выдача, у которой subjects[0] — пользователь: group:g НЕ входит
		// в проекцию access_bindings, а существует ТОЛЬКО как дочерняя строка
		// access_binding_subjects (путь subjects[1..N], защищённый триггером BEFORE DELETE
		// миграции 0050 + вторым NOT EXISTS в CTE Delete).
		bindingID := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
		wSeed, err := seedRepo.Writer(ctx)
		require.NoError(t, err)
		_, err = bindingset.Insert(ctx, wSeed.AccessBindingsW(), domain.AccessBinding{
			ID:           bindingID,
			SubjectType:  domain.SubjectTypeUser,
			SubjectID:    domain.SubjectID(uid),
			RoleID:       domain.SystemViewerRoleID,
			ResourceType: "account",
			ResourceID:   string(acc.ID),
		})
		require.NoError(t, err)
		require.NoError(t, wSeed.Commit(ctx))

		// Добавляем group:g дополнительным субъектом, оставляя запись открытой (без коммита):
		// триггер 0049 срабатывает и на access_binding_subjects, беря FOR KEY SHARE
		// на строку groups.
		wIns, err := seedRepo.Writer(ctx)
		require.NoError(t, err)
		committed := false
		defer func() {
			if !committed {
				_ = wIns.Rollback(ctx)
			}
		}()
		require.NoError(t, wIns.AccessBindingsW().InsertSubjects(ctx, bindingID, []domain.Subject{
			{Type: domain.SubjectTypeGroup, ID: domain.SubjectID(g.ID)},
		}))

		// Продуктовый groupWriter.Delete должен блокироваться/сериализоваться на строке groups.
		require.Error(t, realGroupDelete(g.ID),
			"guarded Group.Delete must block on the add-subject key-share lock (race window would be open)")

		require.NoError(t, wIns.Commit(ctx))
		committed = true

		// Новое защищённое удаление видит зафиксированную строку access_binding_subjects
		// → отказ (триггер 0050 / второй NOT EXISTS), висячей ссылки на субъекта нет.
		err = realGroupDelete(g.ID)
		require.Error(t, err)
		require.True(t, stderrors.Is(err, iamerr.ErrFailedPrecondition),
			"post-commit Group.Delete must reject (group still referenced as a binding subject), got %v", err)

		var groupCnt, subjCnt int
		require.NoError(t, master.QueryRow(ctx,
			`SELECT count(*) FROM kaname.groups WHERE id=$1`, string(g.ID)).Scan(&groupCnt))
		require.Equal(t, 1, groupCnt, "referenced group must survive the guarded delete")
		require.NoError(t, master.QueryRow(ctx,
			`SELECT count(*) FROM kaname.access_binding_subjects WHERE subject_type='group' AND subject_id=$1`,
			string(g.ID)).Scan(&subjCnt))
		require.Equal(t, 1, subjCnt, "the committed subject row must reference the live group")
	})
}
