// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// client_assertion_replay_integration_test.go — однократность предъявленного
// утверждения клиента (приёмка F2, сценарии F2-24, F2-25, F2-26, F2-27).
//
// # Почему эти пробы легли ПЕРВЫМИ
//
// Однократность — единственное свойство фазы, которое ПОСЛЕДОВАТЕЛЬНАЯ проба не
// отличает от сломанного. Реализация «посмотреть, потом записать» проходит все
// последовательные пробы: окна между чтением и записью при последовательном
// прогоне не существует. Написанная позже, конкурентная проба легла бы поверх
// уже построенного — и уронила бы фундамент, а не дельту.
//
// # На какой НЕВЕРНОЙ реализации каждая проба зелена — и чем это закрыто
//
//   - последовательный повтор зелен на паре «посмотреть — записать» ⇒ F2-24
//     гоняет N одновременных предъявлений;
//   - конкурентная проба зелена на хранилище в ПАМЯТИ процесса ⇒ F2-25 строит
//     два независимых экземпляра против одной базы;
//   - проба двух экземпляров зелена на переменной УРОВНЯ ПАКЕТА (её видят оба
//     экземпляра одного процесса) ⇒ F2-25 снимает строку напрямую в базе и
//     требует, чтобы ответ второго экземпляра изменился;
//   - однократность целиком зелена на реализации, отвергающей всё подряд ⇒
//     F2-26 требует, чтобы тот же идентификатор от ДРУГОГО клиента прошёл.
package pg_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"
	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg"
)

// TestClientAssertionReplay_ConcurrentRedeemAdmitsExactlyOne — F2-24.
//
// Первая красная проба фазы (§10). Свойство держится ИНВАРИАНТОМ БАЗЫ —
// уникальностью составного ключа, — а не программной парой, и последнее
// утверждение пробы доказывает именно это: попытка записать второе погашение
// того же ключа В ОБХОД прикладного пути тоже отвергается.
func TestClientAssertionReplay_ConcurrentRedeemAdmitsExactlyOne(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kachopg.NewClientAssertionReplayRepo(pool)

	const (
		clientID    = "uoc-concurrent-one"
		assertionID = "jti-concurrent-one"
		racers      = 16
	)
	expiresAt := time.Now().UTC().Add(5 * time.Minute)

	// N одновременных предъявлений ОДНОГО утверждения.
	start := make(chan struct{})
	results := make([]error, racers)
	var wg sync.WaitGroup
	wg.Add(racers)
	for i := range racers {
		go func(i int) {
			defer wg.Done()
			<-start
			results[i] = repo.Redeem(ctx, clientID, assertionID, expiresAt)
		}(i)
	}
	close(start)
	wg.Wait()

	var admitted, replayed int
	for i, err := range results {
		switch {
		case err == nil:
			admitted++
		case isReplayed(err):
			replayed++
		default:
			t.Fatalf("предъявление %d отказало не тем: %v", i, err)
		}
	}
	require.Equal(t, 1, admitted, "проходить обязан РОВНО один; прошло %d", admitted)
	require.Equal(t, racers-1, replayed)

	// Последовательный повтор тоже отвергается — но это НЕ доказательство:
	// половина зелена и на паре «посмотреть — записать».
	require.True(t, isReplayed(repo.Redeem(ctx, clientID, assertionID, expiresAt)))

	// Свойство держит ОГРАНИЧЕНИЕ СХЕМЫ, а не прикладной код: запись второго
	// погашения того же ключа в обход репозитория обязана быть отвергнута
	// базой. Без этого утверждения проба зелена на реализации, где
	// уникальности в схеме нет вовсе, а «ровно один» получился блокировкой.
	_, err = pool.Exec(ctx,
		`INSERT INTO kacho_iam.client_assertion_replay (client_id, assertion_id, expires_at) VALUES ($1,$2,$3)`,
		clientID, assertionID, expiresAt)
	require.Error(t, err, "база обязана отвергнуть второе погашение того же ключа")
}

// TestClientAssertionReplay_GuaranteeSpansTheFleetNotTheProcess — F2-25.
//
// Два НЕЗАВИСИМО построенных экземпляра против ОДНОЙ базы: у каждого свой пул,
// своё состояние. Одноэкземплярная проба не отличает хранилище в памяти
// процесса от общего — оба дают верный ответ.
func TestClientAssertionReplay_GuaranteeSpansTheFleetNotTheProcess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)

	// Два экземпляра, ни одного разделяемого поля.
	poolA, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, poolA)
	poolB, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, poolB)
	instanceA := kachopg.NewClientAssertionReplayRepo(poolA)
	instanceB := kachopg.NewClientAssertionReplayRepo(poolB)

	const clientID = "uoc-fleet"
	expiresAt := time.Now().UTC().Add(5 * time.Minute)

	// Положительный контроль: утверждение, предъявленное ВТОРОМУ экземпляру
	// первым, проходит. Без него проба зелена на экземпляре, отвергающем всё.
	require.NoError(t, instanceB.Redeem(ctx, clientID, "jti-fleet-control", expiresAt))

	// Предмет: погашено первым — отвергнуто вторым.
	const shared = "jti-fleet-shared"
	require.NoError(t, instanceA.Redeem(ctx, clientID, shared, expiresAt))
	require.True(t, isReplayed(instanceB.Redeem(ctx, clientID, shared, expiresAt)),
		"второй экземпляр обязан отвергнуть погашенное первым")

	// Ответ второго экземпляра привязан К БАЗЕ, а не к его памяти: снимаем
	// строку НАПРЯМУЮ, в обход прикладного пути, и требуем, чтобы ответ
	// изменился. Без этого утверждения проба зелена на хранилище в переменной
	// УРОВНЯ ПАКЕТА — она не поле экземпляра, её видят оба экземпляра одного
	// процесса, и второй отвергает погашенное при реализации, которая ломается
	// со второй репликой.
	tag, err := poolA.Exec(ctx,
		`DELETE FROM kacho_iam.client_assertion_replay WHERE client_id = $1 AND assertion_id = $2`,
		clientID, shared)
	require.NoError(t, err)
	require.EqualValues(t, 1, tag.RowsAffected())
	require.NoError(t, instanceB.Redeem(ctx, clientID, shared, expiresAt),
		"после снятия строки в базе второй экземпляр обязан принять то же утверждение")
}

// TestClientAssertionReplay_KeyIsScopedToTheClient — F2-26.
//
// Идентификатор однократности выбирает ПРЕДЪЯВИТЕЛЬ. Если ключом служит только
// он, клиент A, предъявив некоторое значение, занимает его у всех остальных:
// законное первое предъявление клиента B отвергалось бы как повтор. Отказ в
// обслуживании соседу получается дешёвым и выглядит корректной работой защиты.
func TestClientAssertionReplay_KeyIsScopedToTheClient(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kachopg.NewClientAssertionReplayRepo(pool)

	const shared = "jti-shared-between-clients"
	expiresAt := time.Now().UTC().Add(5 * time.Minute)

	require.NoError(t, repo.Redeem(ctx, "uoc-client-a", shared, expiresAt))
	// Тот же идентификатор от ДРУГОГО клиента проходит: область сужена клиентом.
	require.NoError(t, repo.Redeem(ctx, "sac-client-b", shared, expiresAt))
	// А повтор первого клиента — отвергается.
	require.True(t, isReplayed(repo.Redeem(ctx, "uoc-client-a", shared, expiresAt)))
}

// TestClientAssertionReplay_RowLivesExactlyAsLongAsTheAssertion — F2-27.
//
// Обе стороны §6.3 утверждаются ОДНИМ прогоном:
//
//   - «не дольше»: истёкшая строка убирается сборщиком, и число строк
//     возвращается к тому, что было ДО предъявления;
//   - «не короче»: строка ещё не истёкшего утверждения проход сборщика
//     ПЕРЕЖИВАЕТ, и повтор по-прежнему отвергается.
//
// Без второй половины «пережила» неотличимо от «истекла раньше», а все прочие
// утверждения проходят на сборщике, опустошающем таблицу целиком — то есть на
// реализации, делающей повтор законным.
func TestClientAssertionReplay_RowLivesExactlyAsLongAsTheAssertion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kachopg.NewClientAssertionReplayRepo(pool)

	before, err := repo.Len(ctx)
	require.NoError(t, err)

	now := time.Now().UTC()
	const clientID = "uoc-reaper"
	// Одно утверждение истечёт, второе — нет.
	require.NoError(t, repo.Redeem(ctx, clientID, "jti-short", now.Add(30*time.Second)))
	require.NoError(t, repo.Redeem(ctx, clientID, "jti-long", now.Add(10*time.Minute)))

	afterRedeem, err := repo.Len(ctx)
	require.NoError(t, err)
	require.Equal(t, before+2, afterRedeem)

	// Сборщик по часам, поданным ВХОДОМ: проба не спит и не зависит от
	// системного времени.
	reaped, err := repo.Reap(ctx, now.Add(time.Minute))
	require.NoError(t, err)
	require.EqualValues(t, 1, reaped)

	// «не дольше»: число строк вернулось к исходному плюс пережившая строка.
	afterReap, err := repo.Len(ctx)
	require.NoError(t, err)
	require.Equal(t, before+1, afterReap)

	// «не короче»: строка ещё не истёкшего утверждения проход сборщика
	// пережила, и повтор по-прежнему отвергается КАК ПОВТОР.
	require.True(t, isReplayed(repo.Redeem(ctx, clientID, "jti-long", now.Add(10*time.Minute))))

	// А истёкшее утверждение из таблицы ушло — и его слот свободен. Наружу оба
	// отказа побайтово совпадают (§7), поэтому «повтор» от «истёк» различает
	// проверка срока ВЫШЕ по потоку, а не эта таблица; здесь утверждается
	// состояние хранилища, а не тон ответа.
	require.NoError(t, repo.Redeem(ctx, clientID, "jti-short", now.Add(10*time.Minute)))
}

// isReplayed — предъявление отвергнуто как ПОВТОР.
func isReplayed(err error) bool { return domain.IsAssertionReplayed(err) }
