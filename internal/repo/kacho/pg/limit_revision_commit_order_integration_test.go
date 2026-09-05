// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// limit_revision_commit_order_integration_test.go — kacho#1373.
//
// # Что здесь доказывается — и почему это НЕ та проба, которую задача заказывала
//
// Задача #1373 утверждала, что дельта величин несёт тот же класс, что журнал
// изменений субъекта: номер выдан на вставке, строка видна на фиксации, курсор
// уходит за невидимый номер, строка теряется навсегда. ПОСЫЛКА ОПРОВЕРГНУТА
// ЗАМЕРОМ: сценарий на `kacho_iam.limits` НЕ СТРОИТСЯ.
//
// Ревизию штампует триггер `limits_stamp_revision` (миграция 0092), и он берёт
// `pg_advisory_xact_lock` ПЕРЕД `nextval`. Транзакционная консультативная
// блокировка держится до конца транзакции, поэтому невыданными в каждый момент
// остаются номера ОДНОГО писателя, и они старше всякого видимого. Значит порядок
// ревизий есть порядок фиксаций, и читатель (`LimitRepo.ChangedSince`),
// продвинувший курсор на ВИДИМУЮ ревизию, не теряет ничего by construction.
//
// # Тогда зачем проба
//
// Затем, что корректность читателя держится свойством ЧУЖОГО и ДАЛЁКОГО
// артефакта — тела триггера в применённой миграции. Шапка `limit_integration_test.go`
// это свойство ЗАЯВЛЯЛА («assigned under a lock held to commit, so its order is
// the order of commits»), но ни одна проба его не держала. Заявление без пробы
// переживает свой предмет молча: снять блокировку из триггера — правка одной
// строки будущей миграции, после которой чтение становится тем самым классом.
//
// Гейт `internal/repohygiene`.TestJournalReadersNeverAdvanceOnABareSequenceNumber
// читает эту закрытость из ТЕКСТА миграций и потому её тоже держит. Держит он,
// однако, ОБЪЯВЛЕНИЕ; здесь держится ПОВЕДЕНИЕ — что объявленное исполняется
// настоящей базой. Две разные половины одного предмета, и ни одна не заменяет
// другую.
//
// # Способность падать доказана ИНЪЕКЦИЕЙ, а не рассуждением
//
// Второй подслучай переопределяет тот же триггер БЕЗ блокировки — в собственной
// базе пробы, применённая миграция не трогается (ban #5), — и требует, чтобы
// сценарий потери СТАЛ строиться. Без него «писатель заблокирован» было бы
// неотличимо от «писатель не успел».

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// limitValueUpdateSQL — правка величины МИМО адаптера: проба обязана держать
// транзакцию открытой между выдачей ревизии и фиксацией, а адаптер коммитит сам.
const limitValueUpdateSQL = `
	UPDATE kacho_iam.limits SET limit_value = $2 WHERE id = $1 RETURNING revision`

// stampRevisionWithoutTheLock — ТОТ ЖЕ триггер без сериализации выдачи.
// Ставится только в базу пробы; миграция не трогается.
const stampRevisionWithoutTheLock = `
CREATE OR REPLACE FUNCTION kacho_iam.limits_stamp_revision() RETURNS trigger
    LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'UPDATE'
       AND NEW.limit_value  IS NOT DISTINCT FROM OLD.limit_value
       AND NEW.withdrawn_at IS NOT DISTINCT FROM OLD.withdrawn_at THEN
        NEW.revision := OLD.revision;
        RETURN NEW;
    END IF;
    NEW.revision := nextval('kacho_iam.limits_revision_seq');
    RETURN NEW;
END $$;`

// TestLimitRevisionOrderIsCommitOrder — выдача ревизии сериализована, поэтому
// порядок ревизий есть порядок фиксаций.
func TestLimitRevisionOrderIsCommitOrder(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}

	// inflightBlocksTheNextIssuer строит сценарий потери и отвечает, УДАЛОСЬ ли:
	// второй писатель либо взял ревизию, пока первый в полёте (сценарий построен,
	// класс живой), либо ждал его (выдача сериализована, класса нет).
	inflightBlocksTheNextIssuer := func(t *testing.T, injectUnlocked bool) (blocked bool, revA, revB int64) {
		t.Helper()
		ctx := context.Background()
		pool, err := coredb.NewPool(ctx, setupTestDB(t))
		require.NoError(t, err)
		pgtest.ClosePoolAtEnd(t, pool)

		if injectUnlocked {
			_, eerr := pool.Exec(ctx, stampRevisionWithoutTheLock)
			require.NoError(t, eerr,
				"инъекция не поставлена — доказательство способности падать не построено")
		}

		repo := kachopg.NewLimitRepo(pool)
		_, prj := seedLimitScopeObjects(t, ctx, pool, "revorder")
		l1, err := repo.Insert(ctx, newLimit(domain.LimitScopeProject, prj, "vpc.network", 4))
		require.NoError(t, err)
		l2, err := repo.Insert(ctx, newLimit(domain.LimitScopeProject, prj, "vpc.subnet", 8))
		require.NoError(t, err)

		// A берёт ревизию и остаётся в полёте.
		txA, err := pool.Begin(ctx)
		require.NoError(t, err)
		defer func() { _ = txA.Rollback(ctx) }()
		require.NoError(t, txA.QueryRow(ctx, limitValueUpdateSQL, string(l1.ID), 40).Scan(&revA))

		// B пробует взять СЛЕДУЮЩУЮ, пока A не зафиксировался.
		type outcome struct {
			rev int64
			err error
		}
		done := make(chan outcome, 1)
		go func() {
			txB, berr := pool.Begin(ctx)
			if berr != nil {
				done <- outcome{err: berr}
				return
			}
			var rev int64
			if qerr := txB.QueryRow(ctx, limitValueUpdateSQL, string(l2.ID), 80).Scan(&rev); qerr != nil {
				_ = txB.Rollback(ctx)
				done <- outcome{err: qerr}
				return
			}
			done <- outcome{rev: rev, err: txB.Commit(ctx)}
		}()

		// Барьер по времени — единственный возможный: доказывается ОТСУТСТВИЕ
		// события («B не взял номер»), а у отсутствия наблюдаемого состояния нет.
		// Порог щедрый: сценарий строится за миллисекунды, когда строится.
		select {
		case res := <-done:
			require.NoError(t, res.err)
			return false, revA, res.rev
		case <-time.After(5 * time.Second):
		}

		require.NoError(t, txA.Commit(ctx))
		res := <-done
		require.NoError(t, res.err)
		return true, revA, res.rev
	}

	t.Run("выдача ревизии сериализована: второй писатель ждёт первого", func(t *testing.T) {
		blocked, revA, revB := inflightBlocksTheNextIssuer(t, false)
		require.True(t, blocked,
			"второй писатель взял ревизию %d, пока первый (%d) был в полёте: порядок ревизий "+
				"перестал быть порядком фиксаций, и ChangedSince, продвигающий курсор по голому "+
				"номеру, теряет строку навсегда — читателю нужна верхняя граница по устоявшемуся",
			revB, revA)
		require.Greater(t, revB, revA,
			"ревизия, выданная после фиксации, обязана быть больше зафиксированной")
	})

	t.Run("проба способна упасть: без блокировки сценарий строится", func(t *testing.T) {
		blocked, revA, revB := inflightBlocksTheNextIssuer(t, true)
		require.False(t, blocked,
			"инъекция сняла сериализацию, а второй писатель всё равно ждал (ревизии %d и %d): "+
				"проба держится не тем, чем объявлено, и её молчание на настоящей схеме "+
				"ничего не доказывает",
			revA, revB)
	})
}
