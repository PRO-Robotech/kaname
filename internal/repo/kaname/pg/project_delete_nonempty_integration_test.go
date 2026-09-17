// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// project_delete_nonempty_integration_test.go — непустой проект не удаляется:
// пробы УРОВНЯ ПИСАТЕЛЯ (дом Р приёмки `non-empty-project-is-not-deleted.md`,
// §0.2в) — оператор `projectWriter.Delete` напрямую, исход оператора и текст его
// отказа, строки базы, порядок двух коммитов.
//
// Конверта операции и `ErrorInfo` дом Р не видит: их ставит прикладник, и они
// утверждаются пробами дома П (`internal/apps/kaname/api/project`).
//
// # Четыре полосы, и у каждой свой предмет
//
//	1-07 Б  ветвь зонда «проекта нет», достижимая ТОЛЬКО конкуренцией
//	1-10    удерживает КОЛОНКА родителя, а не цепь предков — с близнецом
//	1-13    регистрация, обогнавшая удаление, проект НЕ воскрешает (гонка)
//	1-14    «удалено» читается ПЕРВЫМ, зонд вторым

import (
	"context"
	stderrors "errors"
	"fmt"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"
)

// pneWriterEnv — пул, репозиторий и проект на пробу.
type pneWriterEnv struct {
	pool *pgxpool.Pool
	repo *kanamepg.Repository
	acc  domain.AccountID
}

func newPNEWriterEnv(t *testing.T, suffix string) *pneWriterEnv {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	repo := kanamepg.New(pool, nil)
	owner := mustSeedUser(t, ctx, pool, suffix)
	acc := seedAccount(t, ctx, repo, "acc-"+suffix, owner)
	return &pneWriterEnv{pool: pool, repo: repo, acc: acc.ID}
}

// deleteProject исполняет оператор писателя в своей транзакции и коммитит её
// на успехе. Возвращает ошибку оператора.
func (e *pneWriterEnv) deleteProject(t *testing.T, ctx context.Context, prj domain.ProjectID) error {
	t.Helper()
	w, err := e.repo.Writer(ctx)
	require.NoError(t, err)
	if derr := w.ProjectsW().Delete(ctx, prj); derr != nil {
		_ = w.Rollback(ctx)
		return derr
	}
	require.NoError(t, w.Commit(ctx))
	return nil
}

// insertMirrorRowDirect кладёт строку зеркала прямой вставкой — так, как её
// оставляет приём регистрации владельца.
func insertMirrorRowDirect(t *testing.T, ctx context.Context, pool *pgxpool.Pool, objectType string, parent domain.ProjectID) string {
	t.Helper()
	objectID := "obj-" + ids.NewID("pne")
	_, err := pool.Exec(ctx,
		`INSERT INTO kaname.resource_mirror
		     (object_type, object_id, parent_project_id, parent_account_id, labels)
		 VALUES ($1, $2, $3, '', '{}'::jsonb)`,
		objectType, objectID, string(parent))
	require.NoError(t, err)
	return objectID
}

func projectExists(t *testing.T, ctx context.Context, pool *pgxpool.Pool, prj domain.ProjectID) bool {
	t.Helper()
	var exists bool
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM kaname.projects WHERE id = $1)`, string(prj)).Scan(&exists))
	return exists
}

// ── IAM-PNE-1-07 полоса Б — ветвь зонда, достижимая только конкуренцией ─────

// TestProjectDelete_PNE_1_07B — проект существовал на момент синхронного чтения,
// чужое удаление закоммичено ПОСЛЕ него и ДО снимка нашего оператора; строки
// зеркала с этим родителем легли уже после чужого удаления (легли бы раньше —
// чужое удаление само было бы отвергнуто, приёмка §0.2в, Н10).
//
// Исход — NOT_FOUND, а не FAILED_PRECONDITION: зонд читает «проекта нет» раньше
// «проект не пуст». Обратный порядок ветвей отвечал бы «не пусто» о том, чего
// уже нет.
func TestProjectDelete_PNE_1_07B(t *testing.T) {
	env := newPNEWriterEnv(t, "pne107b")
	ctx := context.Background()
	prj := seedProject(t, ctx, env.repo, env.acc, "pne-1-07b").ID

	// «Синхронное чтение» полосы — проект на месте.
	require.True(t, projectExists(t, ctx, env.pool, prj))
	// Чужое удаление пустого проекта — закоммичено.
	require.NoError(t, env.deleteProject(t, ctx, prj), "пустой проект чужой оператор снимает")
	// Регистрация, легшая ПОСЛЕ чужого удаления: отсутствие проекта она не
	// проверяет (1-13).
	insertMirrorRowDirect(t, ctx, env.pool, "vpc.network", prj)
	insertMirrorRowDirect(t, ctx, env.pool, "vpc.network", prj)

	err := env.deleteProject(t, ctx, prj)
	require.Error(t, err)
	require.True(t, stderrors.Is(err, iamerr.ErrNotFound), "ожидался NOT_FOUND, получено: %v", err)
	require.False(t, stderrors.Is(err, iamerr.ErrFailedPrecondition), "о том, чего нет, не говорят «не пуст»: %v", err)
	require.Equal(t, fmt.Sprintf("Project %s not found", prj), iamerr.StripSentinel(err))
}

// ── IAM-PNE-1-10 — удерживает КОЛОНКА родителя, а не цепь предков ───────────

func TestProjectDelete_PNE_1_10(t *testing.T) {
	env := newPNEWriterEnv(t, "pne110")
	ctx := context.Background()
	prj := seedProject(t, ctx, env.repo, env.acc, "pne-1-10").ID
	objectID := insertMirrorRowDirect(t, ctx, env.pool, "vpc.network", prj)
	_, err := env.pool.Exec(ctx,
		`INSERT INTO kaname.resource_parent_edge (object_type, object_id, parent_type, parent_id, depth)
		 VALUES ('vpc_network', $1, 'project', $2, 1)`, objectID, string(prj))
	require.NoError(t, err, "ребро цепи предков к проекту")

	// Положительный близнец: строка с родителем в колонке удерживает.
	err = env.deleteProject(t, ctx, prj)
	require.Error(t, err, "близнец: строка зеркала с родителем P удерживает проект")
	require.True(t, stderrors.Is(err, iamerr.ErrReferenceInUse), "признак полосы: %v", err)
	require.Equal(t, fmt.Sprintf("Project %s is not empty (vpc.network: 1)", prj), iamerr.StripSentinel(err))
	require.True(t, projectExists(t, ctx, env.pool, prj))

	// Единственный факт, которым мир отличается от близнеца: колонка родителя
	// ЭТОЙ ЖЕ строки опустошена; ребро цепи на месте.
	tag, err := env.pool.Exec(ctx,
		`UPDATE kaname.resource_mirror SET parent_project_id = '' WHERE object_id = $1`, objectID)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())

	require.NoError(t, env.deleteProject(t, ctx, prj),
		"проверка читает колонку родителя, а не цепь: строка без родителя-проекта не удерживает")
	require.False(t, projectExists(t, ctx, env.pool, prj))
}

// ── IAM-PNE-1-13 — регистрация, обогнавшая удаление, проект НЕ воскрешает ───

// TestProjectDelete_PNE_1_13 — гонка двух сессий: регистрация на P открыта и не
// закоммичена; удаление P исполняется и коммитится раньше; затем регистрация
// коммитится без отказа. Занижение счёта окном доставки — ЗАКОННЫЙ исход
// (приёмка §3.4, пункт 4, прочтение Б), и проба на нём не падает.
//
// Регистрация идёт настоящим `resource_mirror.UpsertTx` — подделка была бы
// снисходительнее продукта: у настоящего приёма есть условие живости типа и
// запись цепи предков.
func TestProjectDelete_PNE_1_13(t *testing.T) {
	env := newPNEWriterEnv(t, "pne113")
	ctx := context.Background()
	prj := seedProject(t, ctx, env.repo, env.acc, "pne-1-13").ID
	objectID := "obj-" + ids.NewID("pne")

	// Сессия А: регистрация открыта, не закоммичена.
	regTx, err := env.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = regTx.Rollback(ctx) }()
	_, err = resource_mirror.UpsertTx(ctx, regTx, resource_mirror.Row{
		ObjectType:      "vpc.network",
		ObjectID:        objectID,
		ParentProjectID: string(prj),
		SourceVersion:   time.Now().UTC(),
		ParentChain:     []string{"project:" + string(prj)},
	})
	require.NoError(t, err, "приём регистрации")

	// Сессия Б: удаление P исполняется и коммитится раньше регистрации. Оно не
	// ждёт: у зеркала нет ключа на projects, строку проекта регистрация не
	// трогает.
	deleteCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	require.NoError(t, env.deleteProject(t, deleteCtx, prj), "удаление проходит: снимка регистрации у него нет")
	require.False(t, projectExists(t, ctx, env.pool, prj))

	// Сессия А коммитится без отказа — служба запись не отвергает.
	require.NoError(t, regTx.Commit(ctx), "регистрация коммитится без отказа")

	var parent string
	require.NoError(t, env.pool.QueryRow(ctx,
		`SELECT parent_project_id FROM kaname.resource_mirror WHERE object_id = $1`, objectID).Scan(&parent))
	require.Equal(t, string(prj), parent, "строка зеркала называет родителя, которого нет")
	require.False(t, projectExists(t, ctx, env.pool, prj), "проект не воскрешён")
}

// ── IAM-PNE-1-14 — «удалено» читается ПЕРВЫМ, зонд вторым ───────────────────

// TestProjectDelete_PNE_1_14 — у оператора один снимок, и удаление из своего же
// CTE внешнему чтению не видно: зонд того же оператора отвечает «проект
// существует» ПОСЛЕ успешного удаления. Код, прочитавший зонд первым, объявил бы
// только что снятый проект живым и вернул FAILED_PRECONDITION на успехе.
func TestProjectDelete_PNE_1_14(t *testing.T) {
	env := newPNEWriterEnv(t, "pne114")
	ctx := context.Background()
	prj := seedProject(t, ctx, env.repo, env.acc, "pne-1-14").ID

	require.NoError(t, env.deleteProject(t, ctx, prj), "пустой проект удаляется, что бы ни ответил зонд")
	require.False(t, projectExists(t, ctx, env.pool, prj))
}
