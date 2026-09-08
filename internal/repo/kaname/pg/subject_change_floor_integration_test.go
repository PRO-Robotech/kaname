// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// subject_change_floor_integration_test.go — ЧИТАТЕЛЬ ОБНАРУЖИВАЕТ ПРОПУСК
// (задача #1712).
//
// # Предмет
//
// Журнал читается окном `id > since AND id <= settled`. Снятая строка в такое
// окно просто не попадает: курсор переезжает через неё по последней прочитанной
// позиции, и «строк не было» становится НЕОТЛИЧИМО от «строки убрали». Полоса
// при этом fail-open by design — пропущенная строка означает непогашенный кэш
// вердиктов края, то есть неприменённый отзыв доступа, молча.
//
// Пол закрывает это тем же инвариантом, что у журналов подписки: уборка снимает
// ПРЕФИКС, поэтому `курсор >= пол` ⟹ дыр выше курсора не бывает. Ниже пола —
// явный отказ с возобновимой позицией.
//
// # Почему интеграция, а не юнит
//
// Утверждается ПАРА «что в таблице» ↔ «что ответил репозиторий», и обе половины
// вычисляются запросами к настоящей базе (`min(id)` и наблюдение границы
// устоявшегося по блокировкам журнала). Подставной источник вернул бы
// заготовленные числа и утверждал бы о себе.
//
// .3.
package pg_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jackc/pgx/v5/pgxpool"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

// seedSubjectChange кладёт строку ТЕМ ЖЕ путём, каким пишет прод: фикстура не
// вправе быть снисходительнее продукта.
func seedSubjectChange(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subjectID, op string) int64 {
	t.Helper()
	abRepo := kanamepg.New(pool, nil)
	w, err := abRepo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().EmitSubjectChangeEvent(ctx,
		access_binding.SubjectChangeEvent{SubjectID: subjectID, Op: op}))
	require.NoError(t, w.Commit(ctx))

	var id int64
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id FROM kaname.subject_change_outbox WHERE subject_id = $1`, subjectID).Scan(&id))
	return id
}

// TestSubjectChangeRepo_CursorBelowTheFloorIsRefusedByName — снятый префикс
// становится ОТКАЗОМ, а не тишиной.
func TestSubjectChangeRepo_CursorBelowTheFloorIsRefusedByName(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	repo := kanamepg.NewSubjectChangeRepo(pool, nil)

	id1 := seedSubjectChange(t, ctx, pool, "usr_floor_a", "binding_upsert")
	id2 := seedSubjectChange(t, ctx, pool, "usr_floor_b", "binding_delete")
	id3 := seedSubjectChange(t, ctx, pool, "usr_floor_c", "binding_upsert")
	id4 := seedSubjectChange(t, ctx, pool, "usr_floor_d", "binding_upsert")

	// ── Контроль ДО уборки: пола нет, отказа нет ────────────────────────────
	// Без него проба зеленела бы на репозитории, отвергающем всякий курсор.
	changes, _, err := repo.PollSubjectChanges(ctx, id1, 10)
	require.NoError(t, err, "нетронутый журнал не имеет нижней границы — отказу неоткуда взяться")
	require.Len(t, changes, 3)

	// ── Уборка снимает ПРЕФИКС ──────────────────────────────────────────────
	_, err = pool.Exec(ctx, `DELETE FROM kaname.subject_change_outbox WHERE id <= $1`, id2)
	require.NoError(t, err)

	// Курсор НИЖЕ пола: строка id2 снята и уже не придёт.
	_, _, err = repo.PollSubjectChanges(ctx, id1, 10)
	require.Error(t, err, "курсор ниже пола принят молча — снятая строка неотличима от «строк не было», "+
		"то есть отзыв доступа не применён и об этом никто не узнает")

	var lost *service.SubjectChangePositionLostError
	require.True(t, errors.As(err, &lost), "отказ без машинного признака полосы: %v", err)
	require.Equal(t, id3-1, lost.EarliestResumable,
		"возобновимая позиция обязана быть «самая ранняя удержанная минус один»")

	// ── Контроль: курсор РОВНО на полу — не отказ ───────────────────────────
	// Граница включающая: с пола возобновление ещё не теряет ничего.
	changes, _, err = repo.PollSubjectChanges(ctx, id3-1, 10)
	require.NoError(t, err, "курсор на полу отвергнут — граница обязана быть включающей")
	require.Len(t, changes, 2)
	require.Equal(t, id3, changes[0].ID)
	require.Equal(t, id4, changes[1].ID)

	// ── Контроль: вызывающий БЕЗ позиции не отвергается ─────────────────────
	// Ноль объявлен контрактом как «позиции нет» («0 on first call»), и такой
	// вызывающий страницу отбрасывает, усваивая голову. Отвергнуть его значило
	// бы отправить свежую реплику проигрывать удержанный хвост вместо прыжка на
	// голову — исход ХУЖЕ при нулевом выигрыше: потерять позицию нельзя, не имея
	// её.
	_, _, err = repo.PollSubjectChanges(ctx, 0, 10)
	require.NoError(t, err, "вызывающий без позиции отвергнут — терять ему нечего")
}

// TestSubjectChangeRepo_EmptiedJournalSeatsTheCallerOnTheSettledBoundary —
// журнал, вычищенный ЦЕЛИКОМ.
//
// Нижней удержанной строки не существует, поэтому возобновиться можно только с
// текущей границы: всё, что было до неё, снято. Отдельная проба потому, что это
// ВТОРАЯ ветвь формулы пола, и на непустом журнале она не исполняется никогда.
func TestSubjectChangeRepo_EmptiedJournalSeatsTheCallerOnTheSettledBoundary(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	repo := kanamepg.NewSubjectChangeRepo(pool, nil)

	id1 := seedSubjectChange(t, ctx, pool, "usr_empty_a", "binding_upsert")
	id2 := seedSubjectChange(t, ctx, pool, "usr_empty_b", "binding_upsert")

	// Граница наблюдается ДО уборки — иначе на пустой таблице её неоткуда взять.
	_, _, err = repo.PollSubjectChanges(ctx, 0, 10)
	require.NoError(t, err)

	_, err = pool.Exec(ctx, `DELETE FROM kaname.subject_change_outbox`)
	require.NoError(t, err)

	_, _, err = repo.PollSubjectChanges(ctx, id1, 10)
	require.Error(t, err, "вычищенный целиком журнал принял курсор молча")

	var lost *service.SubjectChangePositionLostError
	require.True(t, errors.As(err, &lost), "отказ без машинного признака полосы: %v", err)
	require.Equal(t, id2, lost.EarliestResumable,
		"у пустого журнала возобновимая позиция — сама граница устоявшегося")
}

// TestSubjectChangeRepo_ConcurrentSweepNeverProducesASilentGap — уборка ПОД
// работающим читателем.
//
// Утверждается инвариант, а не расписание: у вызывающего, стоящего на `id1`,
// удачный ответ ОБЯЗАН начинаться со следующей строки (`id2`). Ответ, начавшийся
// позже, означает, что читатель переехал через снятое, — то есть ровно тот
// молчаливый пропуск, ради которого пол и заводится. Второй законный исход —
// явный отказ.
//
// Гонка здесь настоящая и неустранимая: уборка идёт параллельно перепросам,
// поэтому исход каждого зависит от порядка фиксаций. Утверждение построено так,
// что верно при ЛЮБОМ порядке, — иначе оно проверяло бы расписание машины.
func TestSubjectChangeRepo_ConcurrentSweepNeverProducesASilentGap(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	repo := kanamepg.NewSubjectChangeRepo(pool, nil)

	// Граница наблюдается заранее: холодный старт отвечает отказом «позиции ещё
	// нет», и он к предмету пробы отношения не имеет.
	seedSubjectChange(t, ctx, pool, "usr_race_warmup", "binding_upsert")
	_, _, err = repo.PollSubjectChanges(ctx, 0, 10)
	require.NoError(t, err)

	// РАУНДОВ несколько, и это не «побольше на всякий случай».
	//
	// Окно между чтением страницы и наблюдением пола узкое, поэтому ОДИН раунд
	// ловит дефект не всегда: замер на дофиксовом дереве давал 4 падения на 20
	// прогонов, то есть инструмент срабатывал в пятой части случаев. Проба,
	// ловящая свой предмет с такой вероятностью, читается как нестабильная — и
	// первым же красным её объявляют флейком, а не находкой.
	//
	// Раунды берут ту же гонку многократно в ОДНОМ прогоне и поднимают
	// срабатывание до достоверного, ничего не ослабляя: утверждение в каждом
	// раунде то же самое.
	const (
		rounds  = 8
		readers = 8
	)
	violations := make(chan string, rounds*readers)

	for round := 0; round < rounds; round++ {
		// Каждый раунд — СВОЯ фикстура: инвариант формулируется про строку,
		// заведомо закоммиченную до старта читателей, и переиспользование строк
		// прошлого раунда сделало бы утверждение зависимым от порядка раундов.
		prefix := fmt.Sprintf("usr_race_r%d_", round)
		id1 := seedSubjectChange(t, ctx, pool, prefix+"a", "binding_upsert")
		id2 := seedSubjectChange(t, ctx, pool, prefix+"b", "binding_upsert")
		for _, suffix := range []string{"c", "d", "e", "f"} {
			seedSubjectChange(t, ctx, pool, prefix+suffix, "binding_upsert")
		}

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = pool.Exec(ctx,
				`DELETE FROM kaname.subject_change_outbox WHERE id <= $1`, id2)
		}()

		for i := 0; i < readers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				changes, headID, perr := repo.PollSubjectChanges(ctx, id1, 10)
				if perr != nil {
					var lost *service.SubjectChangePositionLostError
					if !errors.As(perr, &lost) {
						violations <- "отказ вне обеих законных полос: " + perr.Error()
					}
					return
				}
				// ИНВАРИАНТ: читатель не вправе уйти ЗА строку, которой не получил.
				//
				// Пустая страница нарушением НЕ является, пока голова не двигает
				// курсор: граница устоявшегося отстаёт, пока уборщик держит журнал
				// своей транзакцией, и «пока нечего отдать» — законный исход, при
				// котором ничего не теряется. Двинуть же курсор ЗА непрочитанное —
				// ровно тот молчаливый пропуск, ради которого проба написана.
				if len(changes) == 0 {
					if headID > id1 {
						violations <- fmt.Sprintf(
							"пустая страница ДВИНУЛА курсор: было %d, голова %d — "+
								"строки между ними не прочитал никто", id1, headID)
					}
					return
				}
				if changes[0].ID != id2 {
					violations <- fmt.Sprintf(
						"страница началась с %d, ожидалось %d (курсор %d, голова %d) — "+
							"читатель переехал через снятое", changes[0].ID, id2, id1, headID)
				}
			}()
		}
		wg.Wait()
	}
	close(violations)

	for v := range violations {
		t.Error(v)
	}
}
