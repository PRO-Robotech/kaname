// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// subject_change_commit_order_integration_test.go — kacho#1374.
//
// # Что здесь доказывается
//
// Номер строки `kaname.subject_change_outbox` выдаёт счётчик на ВСТАВКЕ
// (умолчание колонки), а видимой строка становится на ФИКСАЦИИ. Выдачу здесь
// ничто не сериализует — в отличие от `kaname.limits`, где ревизию штампует
// триггер под транзакционной блокировкой, держащейся до коммита, — поэтому
// порядок номеров и порядок фиксаций НЕЗАВИСИМЫ.
//
// Потребитель (`pkg/subjectchange`.Watcher) хранит курсор между проходами и
// двигает его по ПРОЧИТАННЫМ строкам. Отдай ему чтение строку с бо́льшим
// номером, пока меньший ещё в полёте, — и меньшая не вернётся НИКОГДА:
// перечитывание идёт строго «больше курсора», пропуска в нумерации потребитель
// не видит, сходиться тут нечему.
//
// Цена именно этой потери названа: предмет журнала — оповещение о том, что
// вердикты по субъекту пора считать заново. Недоехавшая строка означает доступ,
// оставшийся действующим до следующего события ПО ТОМУ ЖЕ субъекту, а его может
// не быть. Отставание не ограничено окном и само не закрывается.
//
// # Почему настоящая база, а не дублёр
//
// Предмет — видимость строки в чужой незавершённой транзакции и блокировка,
// которую эта транзакция держит на таблице журнала. Ни то, ни другое подделкой
// не воспроизводится: она вернёт то, что в неё положили.

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// subjectChangeStand — журнал, читатель и писатель продукта над одной базой.
type subjectChangeStand struct {
	ctx  context.Context
	pool *pgxpool.Pool
	repo *kanamepg.SubjectChangeRepo
	ab   *kanamepg.Repository
}

func newSubjectChangeStand(t *testing.T) *subjectChangeStand {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	// Закрытие с пределом: отложенное ждало бы соединение, которое проба,
	// упавшая внутри открытой транзакции, не вернёт никогда.
	pgtest.ClosePoolAtEnd(t, pool)
	return &subjectChangeStand{
		ctx:  ctx,
		pool: pool,
		repo: kanamepg.NewSubjectChangeRepo(pool, nil),
		ab:   kanamepg.New(pool, nil),
	}
}

// beginWrite открывает транзакцию писателя ПРОДУКТА и пишет в неё строку
// журнала, НЕ фиксируя её. Возвращает саму транзакцию: сценарий потери строится
// только тем, что писатель остаётся в полёте.
//
// Пишет `EmitSubjectChangeEvent` — тот же путь, каким пишет прод. Собственный
// INSERT здесь был бы вторым местом об одном предмете: миграция 0097 требует от
// строки нагрузку, и посев, не знающий об этом, стерёг бы форму, которой в
// очереди не бывает.
func (s *subjectChangeStand) beginWrite(t *testing.T, subjectID string) kaname.Writer {
	t.Helper()
	w, err := s.ab.Writer(s.ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().EmitSubjectChangeEvent(s.ctx,
		access_binding.SubjectChangeEvent{
			SubjectID: subjectID, SubjectType: "user", Op: "binding_upsert",
		}))
	return w
}

// write пишет строку и фиксирует её.
func (s *subjectChangeStand) write(t *testing.T, subjectID string) {
	t.Helper()
	require.NoError(t, s.beginWrite(t, subjectID).Commit(s.ctx))
}

// idOf — номер уже зафиксированной строки названного субъекта.
func (s *subjectChangeStand) idOf(t *testing.T, subjectID string) int64 {
	t.Helper()
	var id int64
	require.NoError(t, s.pool.QueryRow(s.ctx,
		`SELECT id FROM kaname.subject_change_outbox WHERE subject_id = $1`,
		subjectID).Scan(&id))
	return id
}

// subjectsOf — имена субъектов порции в порядке, в котором она пришла.
func subjectsOf(changes []service.SubjectChange) []string {
	out := make([]string, 0, len(changes))
	for _, c := range changes {
		out = append(out, c.SubjectID)
	}
	return out
}

// TestSubjectChangePollNeverSkipsARowCommittedAfterALargerOne — НЕСУЩИЙ
// сценарий: строка, зафиксированная ПОСЛЕ строки с бо́льшим номером, обязана
// доехать.
func TestSubjectChangePollNeverSkipsARowCommittedAfterALargerOne(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	s := newSubjectChangeStand(t)

	// Прогрев: наблюдение границы обязано состояться ДО сценария — ровно так же,
	// как у потребителя, который поллит каждые две секунды и устоялся задолго до
	// первой мутации. Без прогрева отказ «граница не устоялась» был бы неотличим
	// от правильного молчания.
	s.write(t, "usr_warmup")
	_, cursor, err := s.repo.PollSubjectChanges(s.ctx, 0, 100)
	require.NoError(t, err, "прогрев обязан пройти: писателей в этот момент нет")
	require.Equal(t, s.idOf(t, "usr_warmup"), cursor,
		"после прогрева позиция обязана стоять на единственной видимой строке")

	// A берёт номер первым и остаётся В ПОЛЁТЕ.
	inflight := s.beginWrite(t, "usr_inflight")
	defer func() { _ = inflight.Rollback(s.ctx) }()

	// B берёт СЛЕДУЮЩИЙ номер и фиксируется ПЕРВЫМ.
	s.write(t, "usr_committed")

	// Пока A в полёте, чтение НЕ ВПРАВЕ отдать B: за ним ещё может появиться
	// меньший номер. Молчание здесь — правильный исход, и оно проверяется.
	changes, pos, err := s.repo.PollSubjectChanges(s.ctx, cursor, 100)
	require.NoError(t, err)
	require.Empty(t, subjectsOf(changes),
		"строка, за которой ещё может появиться меньший номер, отдана: курсор уйдёт за неё, "+
			"и строка писателя в полёте не вернётся никогда")
	require.Equal(t, cursor, pos, "позиция не вправе двигаться, пока граница не прошла писателя")

	// A фиксируется. Теперь обе строки обязаны доехать.
	require.NoError(t, inflight.Commit(s.ctx))

	idA := s.idOf(t, "usr_inflight")
	idB := s.idOf(t, "usr_committed")
	require.Less(t, idA, idB,
		"сценарий не воспроизведён: номер писателя в полёте (%d) не меньше зафиксированного (%d)", idA, idB)

	changes, pos, err = s.repo.PollSubjectChanges(s.ctx, cursor, 100)
	require.NoError(t, err)
	require.Equal(t, []string{"usr_inflight", "usr_committed"}, subjectsOf(changes),
		"строка, зафиксированная после строки с бо́льшим номером, не доехала — это и есть потеря навсегда")
	require.Equal(t, idB, pos)
}

// TestSubjectChangePollRefusesWhileThePositionIsNotSettledYet — ХОЛОДНЫЙ СТАРТ
// отвечает отказом, а не нулём.
//
// Ноль границы означает «позиции ещё нет», и от «журнал пуст» само значение
// неотличимо. Отдай его чтение позицией — вызывающий, усваивающий её на первом
// проходе вместо истории, сел бы в НАЧАЛО журнала и погасил бы кэш решений по
// всякому субъекту, когда-либо менявшемуся.
//
// Состояние строится ДВУМЯ условиями сразу, и второе выяснилось замером, а не
// чтением: наблюдатель холоден (репозиторий только собран) И в журнале уже есть
// ВИДИМАЯ строка. Пустой журнал под писателем наблюдение НЕ задерживает — там
// ноль есть настоящая позиция, пропускать нечего, и подтверждение приходит первым
// же проходом. Проба, забывшая посеять видимую строку, зеленела бы на отсутствии
// отказа и ничего бы не утверждала (проверено: без посева отказа нет).
//
// Вторая половина утверждения не менее важна первой: отказ обязан РАЗОЙТИСЬ.
// Признак подтверждённости монотонен, поэтому это состояние холодного старта, а
// не режим работы, — и проба, утверждающая только отказ, зеленела бы на чтении,
// которое не отвечает никогда.
func TestSubjectChangePollRefusesWhileThePositionIsNotSettledYet(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	s := newSubjectChangeStand(t)

	// Видимая строка — без неё наибольший видимый номер равен нулю, границе
	// двигаться некуда, и наблюдение состоится сразу.
	s.write(t, "usr_seen")

	// Писатель в полёте ДО первого наблюдения: наблюдатель холоден.
	inflight := s.beginWrite(t, "usr_cold")
	defer func() { _ = inflight.Rollback(s.ctx) }()

	_, _, err := s.repo.PollSubjectChanges(s.ctx, 0, 100)
	require.ErrorIs(t, err, service.ErrSubjectChangeNotSettled,
		"холодное наблюдение под писателем обязано ОТКАЗАТЬ: ноль позиции вызывающий "+
			"усвоил бы как «журнал кончается здесь» и сел бы в его начало")

	require.NoError(t, inflight.Commit(s.ctx))

	// Отказ РАЗОШЁЛСЯ: писатель доистёк, наблюдение подтвердилось.
	changes, pos, err := s.repo.PollSubjectChanges(s.ctx, 0, 100)
	require.NoError(t, err,
		"отказ не разошёлся после фиксации писателя: состояние холодного старта стало режимом работы")
	require.Equal(t, []string{"usr_seen", "usr_cold"}, subjectsOf(changes))
	require.Equal(t, s.idOf(t, "usr_cold"), pos)
}

// TestSubjectChangePollDoesNotStallOnARolledBackWriter — предмет ЖИВОСТЬ, а не
// потеря: номер откатившегося писателя не появится никогда, и поток обязан
// пойти ЗА дыру, а не залипнуть на ней.
func TestSubjectChangePollDoesNotStallOnARolledBackWriter(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	s := newSubjectChangeStand(t)

	s.write(t, "usr_warmup")
	_, cursor, err := s.repo.PollSubjectChanges(s.ctx, 0, 100)
	require.NoError(t, err)

	doomed := s.beginWrite(t, "usr_doomed")
	s.write(t, "usr_after")

	// Пока обречённый в полёте, граница его не проходит.
	changes, _, err := s.repo.PollSubjectChanges(s.ctx, cursor, 100)
	require.NoError(t, err)
	require.Empty(t, subjectsOf(changes))

	require.NoError(t, doomed.Rollback(s.ctx))

	// Дыра от отката закрывается тем же правилом: блокировка снята, номер не
	// появится никогда — граница переносится ЗА дыру.
	changes, pos, err := s.repo.PollSubjectChanges(s.ctx, cursor, 100)
	require.NoError(t, err)
	require.Equal(t, []string{"usr_after"}, subjectsOf(changes),
		"журнал залип на дыре отката: строка за ней не доехала")
	require.Equal(t, s.idOf(t, "usr_after"), pos)
}

// TestSubjectChangePollTruncatesThePositionToTheLastRowOfAFullPage — ВТОРАЯ
// полоса той же потери, и писателя в полёте она не требует вовсе.
//
// Полная страница означает, что чтение упёрлось в предел, и за её последней
// строкой в том же окне остались НЕПРОЧИТАННЫЕ. Отданная позиция обязана
// урезаться до последней прочитанной: назови она границу — курсор перепрыгнул бы
// через непрочитанный хвост.
func TestSubjectChangePollTruncatesThePositionToTheLastRowOfAFullPage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	s := newSubjectChangeStand(t)

	s.write(t, "usr_one")
	s.write(t, "usr_two")
	s.write(t, "usr_three")

	changes, pos, err := s.repo.PollSubjectChanges(s.ctx, 0, 2)
	require.NoError(t, err)
	require.Equal(t, []string{"usr_one", "usr_two"}, subjectsOf(changes))
	require.Equal(t, s.idOf(t, "usr_two"), pos,
		"позиция ушла за последнюю ПРОЧИТАННУЮ строку: непрочитанный хвост окна потерян")

	// Продолжение с той же позиции обязано отдать остаток.
	changes, pos, err = s.repo.PollSubjectChanges(s.ctx, pos, 2)
	require.NoError(t, err)
	require.Equal(t, []string{"usr_three"}, subjectsOf(changes))
	require.Equal(t, s.idOf(t, "usr_three"), pos)
}

// TestSubjectChangePollIsSafeUnderConcurrentPasses — параллельные проходы через
// ОДИН наблюдатель отвечают, а не отказывают и не портят окно.
//
// # Чего эта проба НЕ держит — сказано, потому что ИЗМЕРЕНО
//
// Состязание за общее состояние наблюдателя она НЕ ловит. Наблюдение здесь идёт
// через пул соединений, собственный замок пула создаёт связь «раньше-позже»
// между проходами, и снятие замка из [subscription.Watermark] оставляет её
// зелёной ДАЖЕ под `-race` (проверено снятием). Читать её молчание как
// «состязания нет» нельзя.
//
// Это свойство держит `pkg/subscription`.TestWatermarkSurvivesConcurrentPasses —
// там источник ответов синхронизации не заводит, и снятие замка находится
// немедленно. Здесь проверяется другое: что общий на процесс наблюдатель
// выдерживает параллельные проходы вызывающих и каждый получает окно, а не
// отказ.
func TestSubjectChangePollIsSafeUnderConcurrentPasses(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	s := newSubjectChangeStand(t)

	for i := 0; i < 8; i++ {
		s.write(t, fmt.Sprintf("usr_conc_%d", i))
	}

	const passes = 8
	var wg sync.WaitGroup
	errs := make([]error, passes)
	for i := 0; i < passes; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, _, err := s.repo.PollSubjectChanges(s.ctx, 0, 100)
			errs[i] = err
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		require.NoError(t, err, "проход %d", i)
	}
}
