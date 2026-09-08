// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// subject_change_retention_integration_test.go — УБОРКА ЖУРНАЛА СМЕНЫ СУБЪЕКТА
// (задача #1758).
//
// # Что здесь утверждается — ИНВАРИАНТ, а не расписание
//
// Читатель обнаруживает пропуск ПОЛОМ: пол есть «самая ранняя удержанная минус
// один», и курсор не ниже пола означает «выше дыр нет». Инвариант держится ровно
// одним свойством уборки — она снимает ПРЕФИКС. Уборка «по возрасту» его ломает
// молча: номер выдаётся на вставке, отметка времени — в начале транзакции,
// поэтому строка с бо́льшим номером бывает СТАРШЕ строки с меньшим; сняв верхнюю
// и оставив нижнюю, уборщик не двигает пол и заводит дыру НАД ним — то есть
// отзыв доступа, потерянный при исправном на вид читателе.
//
// # Почему интеграция, а не юнит
//
// Утверждается ПАРА «что осталось в таблице» ↔ «что ответил уборщик», и обе
// половины вычисляются запросами к настоящей базе: предикат целиком в SQL, часы
// уборки — базы, верхняя граница берётся наблюдением по блокировкам журнала.
// Подставной источник вернул бы заготовленные числа и утверждал бы о себе.
package pg_test

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/subjectchange"

	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// journalGrace — порог проб. Берётся у ЧИТАТЕЛЯ, а не выписывается числом: копия
// разошлась бы с ним молча, и проба продолжала бы зеленеть на уборщике, который
// снимает не то.
const journalGrace = subjectchange.JournalRetention

// ageSubjectChange сдвигает отметку времени строки НАЗАД относительно часов базы.
//
// Сдвиг берётся от `now()` самой базы, а не от часов процесса: предикат уборки
// судит часами базы, и разведение источников сделало бы пробу утверждением о
// разнице часов, а не о пороге.
func ageSubjectChange(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id int64, back time.Duration) {
	t.Helper()
	tag, err := pool.Exec(ctx,
		`UPDATE kaname.subject_change_outbox
		    SET created_at = now() - make_interval(secs => $2)
		  WHERE id = $1`, id, back.Seconds())
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected(), "состарить нечего — строки %d нет", id)
}

// journalIDs — номера удержанных строк по возрастанию.
func journalIDs(t *testing.T, ctx context.Context, pool *pgxpool.Pool) []int64 {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT id FROM kaname.subject_change_outbox ORDER BY id`)
	require.NoError(t, err)
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var id int64
		require.NoError(t, rows.Scan(&id))
		out = append(out, id)
	}
	require.NoError(t, rows.Err())
	return out
}

// TestSubjectChangeSweep_RemovesAPrefixAndSparesTheOldRowAboveAYoungOne — ПРОБА
// НЕСУЩЕГО РЕШЕНИЯ.
//
// Строка id4 СТАРШЕ порога, и уборка по возрасту сняла бы её. Уборка префиксом —
// не вправе: под ней стоит молодая id3, и снятие id4 оставило бы дыру НАД полом,
// которую читатель не обнаружит ничем.
//
// Проба утверждает ОБЕ стороны: старый префикс снят (иначе она зеленела бы на
// уборщике, не снимающем ничего), старая строка над молодой удержана.
func TestSubjectChangeSweep_RemovesAPrefixAndSparesTheOldRowAboveAYoungOne(t *testing.T) {
	ctx, pool := retentionPool(t)
	sweeper := kanamepg.NewSubjectChangeJournalSweeper(pool, nil)

	id1 := seedSubjectChange(t, ctx, pool, "usr_sweep_a", "binding_upsert")
	id2 := seedSubjectChange(t, ctx, pool, "usr_sweep_b", "binding_delete")
	id3 := seedSubjectChange(t, ctx, pool, "usr_sweep_c", "binding_upsert")
	id4 := seedSubjectChange(t, ctx, pool, "usr_sweep_d", "binding_upsert")
	id5 := seedSubjectChange(t, ctx, pool, "usr_sweep_e", "binding_upsert")

	// Старые: id1, id2 — и id4, стоящая НАД молодой id3.
	for _, id := range []int64{id1, id2, id4} {
		ageSubjectChange(t, ctx, pool, id, journalGrace+time.Hour)
	}

	removed, full, err := sweeper.SweepAgedRows(ctx, journalGrace, sweepBatch)
	require.NoError(t, err)
	require.EqualValues(t, 2, removed,
		"снято %d вместо 2: уборка обязана снять ПРЕФИКС до первой удержанной строки", removed)
	require.False(t, full, "партия объявлена полной, хотя снято меньше её размера")

	require.Equal(t, []int64{id3, id4, id5}, journalIDs(t, ctx, pool),
		"старая строка НАД молодой снята: пол не сдвинулся, а над ним появилась дыра — "+
			"читатель, законно допущенный по полу, потерял бы отзыв молча")
}

// TestSubjectChangeSweep_KeepsEverythingWhileNothingIsOldEnough — ПОЛОЖИТЕЛЬНЫЙ
// КОНТРОЛЬ порога.
//
// Без него проба выше зеленела бы на уборщике, снимающем всё подряд: «префикс
// снят» неотличимо от «снято всё, что попалось».
func TestSubjectChangeSweep_KeepsEverythingWhileNothingIsOldEnough(t *testing.T) {
	ctx, pool := retentionPool(t)
	sweeper := kanamepg.NewSubjectChangeJournalSweeper(pool, nil)

	id1 := seedSubjectChange(t, ctx, pool, "usr_fresh_a", "binding_upsert")
	id2 := seedSubjectChange(t, ctx, pool, "usr_fresh_b", "binding_upsert")

	removed, full, err := sweeper.SweepAgedRows(ctx, journalGrace, sweepBatch)
	require.NoError(t, err)
	require.EqualValues(t, 0, removed, "снята свежая строка — порог не действует")
	require.False(t, full)
	require.Equal(t, []int64{id1, id2}, journalIDs(t, ctx, pool))
}

// TestSubjectChangeSweep_BatchBoundsOnePassAndSaysSo — партия ограничивает один
// проход, и признак «ушла полной» это НАЗЫВАЕТ.
//
// Без признака проход не отличает «убрал всё, что было» от «упёрся в партию», и
// уборка со скоростью одна партия за тик не догоняла бы внешний темп НИКОГДА,
// оставаясь зелёной по всякой проверке «вызвался ли».
func TestSubjectChangeSweep_BatchBoundsOnePassAndSaysSo(t *testing.T) {
	ctx, pool := retentionPool(t)
	sweeper := kanamepg.NewSubjectChangeJournalSweeper(pool, nil)

	const total = 5
	var ids []int64
	for i := range total {
		id := seedSubjectChange(t, ctx, pool, fmt.Sprintf("usr_batch_%d", i), "binding_upsert")
		ageSubjectChange(t, ctx, pool, id, journalGrace+time.Hour)
		ids = append(ids, id)
	}

	removed, full, err := sweeper.SweepAgedRows(ctx, journalGrace, 2)
	require.NoError(t, err)
	require.EqualValues(t, 2, removed, "партия не ограничила проход")
	require.True(t, full, "партия ушла полной, а признак этого не назвал — "+
		"догон внешнего темпа стал бы вопросом без ответа")
	require.Equal(t, ids[2:], journalIDs(t, ctx, pool))

	// Проход повторяется, пока партия уходит полной, — это делает петля
	// (`retention.Sweeper.Pass`). Здесь утверждается лишь, что повтор ДВИГАЕТ
	// уборку дальше, а не топчется на месте.
	removed, _, err = sweeper.SweepAgedRows(ctx, journalGrace, 2)
	require.NoError(t, err)
	require.EqualValues(t, 2, removed)
	require.Equal(t, ids[4:], journalIDs(t, ctx, pool))
}

// TestSubjectChangeSweep_HoldsWhileTheBoundaryIsNotSettled — ХОЛОДНЫЙ СТАРТ И
// ПИШУЩИЙ СОСЕД: fail-closed.
//
// Граница устоявшегося ещё не подтверждена, пока журнал держит незавершившийся
// писатель. Снять что-либо в этом состоянии значило бы снять по номеру, о
// видимости которого мы не знаем ничего: номер выдаётся на вставке, видимость —
// на фиксации, и строка с МЕНЬШИМ номером вправе появиться позже уже снятой
// соседки — то есть НИЖЕ снятого участка, дырой над полом.
//
// Проба утверждает обе стороны: под писателем уборка не снимает ничего, после
// его фиксации — снимает. Односторонняя зеленела бы на уборщике, не снимающем
// никогда.
func TestSubjectChangeSweep_HoldsWhileTheBoundaryIsNotSettled(t *testing.T) {
	ctx, pool := retentionPool(t)

	id1 := seedSubjectChange(t, ctx, pool, "usr_hold_a", "binding_upsert")
	id2 := seedSubjectChange(t, ctx, pool, "usr_hold_b", "binding_upsert")
	for _, id := range []int64{id1, id2} {
		ageSubjectChange(t, ctx, pool, id, journalGrace+time.Hour)
	}

	// Писатель держит журнал своей незавершённой транзакцией.
	//
	// Строка кладётся в той же форме, в какой её пишет прод (`payload` несёт
	// субъект и вид события): фикстура не вправе быть снисходительнее продукта —
	// иначе она разошлась бы со схемой на первом же ограничении.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx,
		`INSERT INTO kaname.subject_change_outbox (subject_id, op, event_type, payload)
		 VALUES ($1, $2, $3, jsonb_build_object('subject_id', $1::text, 'op', $2::text, 'event_type', $3::text))`,
		"usr_hold_inflight", "binding_upsert", "binding_upsert")
	require.NoError(t, err)

	// Уборщик СВЕЖИЙ: его наблюдение ещё ни разу не подтверждалось.
	sweeper := kanamepg.NewSubjectChangeJournalSweeper(pool, nil)
	removed, full, err := sweeper.SweepAgedRows(ctx, journalGrace, sweepBatch)
	require.NoError(t, err, "неподтверждённая граница — состояние, а не отказ")
	require.EqualValues(t, 0, removed,
		"уборка пошла по неподтверждённой границе: снятый номер мог оказаться выше того, "+
			"который ещё появится, — и появился бы он дырой над полом")
	require.False(t, full)
	require.Equal(t, []int64{id1, id2}, journalIDs(t, ctx, pool))

	require.NoError(t, tx.Commit(ctx))

	// Писатель доистёк — граница ПОДТВЕРЖДАЕТСЯ, и уборка идёт.
	//
	// Проходов два, а сумма одна: подтверждение снимает ожидание, взятое
	// предыдущим проходом, и на КАКОМ из двух это случится, зависит от того,
	// успел ли писатель доистечь к первому. Утверждать номер прохода значило бы
	// утверждать расписание; утверждается ИСХОД — что журнал сошёлся к тому, что
	// удержание позволяет держать.
	var total int64
	for range 2 {
		n, _, serr := sweeper.SweepAgedRows(ctx, journalGrace, sweepBatch)
		require.NoError(t, serr)
		total += n
	}
	require.EqualValues(t, 2, total,
		"после фиксации писателя уборка так и не пошла — fail-closed стал бы вечным")
	require.Len(t, journalIDs(t, ctx, pool), 1,
		"снята и свежая строка писателя: порог не действует на только что зафиксированном")
}

// TestSubjectChangeSweep_ConcurrentWithReadersNeverProducesASilentGap — УБОРКА
// ПОД РАБОТАЮЩИМИ ЧИТАТЕЛЯМИ, настоящим уборщиком.
//
// Соседняя проба (`subject_change_floor_integration_test.go`) ставит тот же
// вопрос РУЧНЫМ удалением префикса. Здесь тот же инвариант утверждается против
// ПРОД-УБОРЩИКА: ручное удаление доказывает свойство читателя, а не свойство
// уборки, и пара «читатель + уборщик» ломается ровно на стыке, которого ни одна
// из двух половин не видит.
//
// Гонка настоящая и неустранимая: уборка идёт параллельно перепросам, поэтому
// исход каждого зависит от порядка фиксаций. Утверждение построено так, что
// верно при ЛЮБОМ порядке, — иначе оно проверяло бы расписание машины.
//
// РАУНДОВ несколько, и это не «побольше на всякий случай»: окно между чтением
// страницы и наблюдением пола узкое, поэтому один раунд ловит дефект не всегда, а
// проба, срабатывающая в пятой части случаев, читается как нестабильная — и
// первым же красным её объявляют флейком, а не находкой.
func TestSubjectChangeSweep_ConcurrentWithReadersNeverProducesASilentGap(t *testing.T) {
	ctx, pool := retentionPool(t)

	repo := kanamepg.NewSubjectChangeRepo(pool, nil)
	sweeper := kanamepg.NewSubjectChangeJournalSweeper(pool, nil)

	// Граница наблюдается заранее у ОБОИХ: холодный старт отвечает «позиции ещё
	// нет» и к предмету пробы отношения не имеет.
	seedSubjectChange(t, ctx, pool, "usr_sweeprace_warmup", "binding_upsert")
	_, _, err := repo.PollSubjectChanges(ctx, 0, 10)
	require.NoError(t, err)
	_, _, err = sweeper.SweepAgedRows(ctx, journalGrace, sweepBatch)
	require.NoError(t, err)

	const (
		rounds  = 8
		readers = 8
	)
	violations := make(chan string, rounds*readers)

	for round := range rounds {
		// Каждый раунд — СВОЯ фикстура: инвариант формулируется про строку,
		// заведомо закоммиченную до старта читателей, и переиспользование строк
		// прошлого раунда сделало бы утверждение зависимым от порядка раундов.
		prefix := fmt.Sprintf("usr_sweeprace_r%d_", round)
		id1 := seedSubjectChange(t, ctx, pool, prefix+"a", "binding_upsert")
		id2 := seedSubjectChange(t, ctx, pool, prefix+"b", "binding_upsert")
		for _, suffix := range []string{"c", "d", "e", "f"} {
			seedSubjectChange(t, ctx, pool, prefix+suffix, "binding_upsert")
		}
		// Уборке даётся предмет: строки до id2 включительно старше порога.
		// Порог при этом НАСТОЯЩИЙ — состариваются строки, а не сужается порог,
		// иначе проба утверждала бы о пороге, которого в бою не бывает.
		for _, id := range journalIDs(t, ctx, pool) {
			if id <= id2 {
				ageSubjectChange(t, ctx, pool, id, journalGrace+time.Hour)
			}
		}

		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, _ = sweeper.SweepAgedRows(ctx, journalGrace, sweepBatch)
		}()

		for range readers {
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
				// своей транзакцией, и «пока нечего отдать» — законный исход.
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
	t.Logf("перепись: раундов %d, читателей на раунд %d, удержано строк %d",
		rounds, readers, len(journalIDs(t, ctx, pool)))
}
