// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ClientAssertionReplayRepo — хранилище однократности предъявленных утверждений
// клиента (задача #898, приёмка F2 §6).
//
// # Область гарантии — ФЛОТ, а не процесс
//
// Хранилище в памяти пода корректно ровно до второй реплики: повтор, попавший в
// соседнюю, чужой записи не находит и проходит. Со второй репликой такое
// хранилище даёт защиту, КОТОРОЙ НЕТ, и при этом выглядит исправным — ни одна
// одноэкземплярная проба его от общего не отличает. Поэтому запись лежит там,
// где её видят все реплики.
type ClientAssertionReplayRepo struct {
	pool *pgxpool.Pool
}

// NewClientAssertionReplayRepo — построитель.
func NewClientAssertionReplayRepo(pool *pgxpool.Pool) *ClientAssertionReplayRepo {
	return &ClientAssertionReplayRepo{pool: pool}
}

// Redeem погашает пару «клиент + идентификатор однократности».
//
// # Один оператор — это инвариант, а не аккуратность
//
// «Не предъявлялось ли уже» и «погасить» здесь НЕДЕЛИМЫ: их делает неделимыми
// первичный ключ таблицы. Пара «SELECT, потом INSERT» была бы ровно тем
// check-then-act, который запрещает ban #10: два одновременных предъявления
// одного утверждения промахнулись бы ОБА мимо чужой ещё не записанной строки и
// прошли бы ОБА. Окна между чтением и записью при последовательном прогоне не
// существует, поэтому такая реализация проходит все последовательные пробы —
// и остаётся сломанной ровно там, где однократность и нужна.
//
// Возврат `domain.ErrAssertionReplayed` означает ПОВТОР. Всякий иной отказ —
// недоступность хранилища, и вызывающий обязан закрыться (§6.5): отложенное
// погашение есть та же пара «проверить и записать», разнесённая на
// неопределённый срок.
func (r *ClientAssertionReplayRepo) Redeem(ctx context.Context, clientID, assertionID string, expiresAt time.Time) error {
	if clientID == "" {
		return fmt.Errorf("client assertion replay: redemption must name its client")
	}
	if err := domain.ValidateAssertionID(assertionID); err != nil {
		return err
	}
	// ОДИН вызов к базе. Гейт TestAssertionAdmissionIsASingleDatabaseCall
	// стережёт это число: второй вызов здесь — возвращённая пара
	// «посмотреть — записать», и вернуть её тихо нельзя.
	const q = `INSERT INTO kaname.client_assertion_replay (client_id, assertion_id, expires_at)
		VALUES ($1,$2,$3)
		ON CONFLICT (client_id, assertion_id) DO NOTHING`
	tag, err := r.pool.Exec(ctx, q, clientID, assertionID, expiresAt)
	if err != nil {
		return wrapPgErr(err, "ClientAssertionReplay", clientID)
	}
	if tag.RowsAffected() == 0 {
		// Конфликт по первичному ключу: строка уже есть, значит это повтор.
		return fmt.Errorf("%w: client %s", domain.ErrAssertionReplayed, clientID)
	}
	return nil
}

// Reap убирает строки утверждений, чей срок истёк РАНЬШЕ порога, — партией и
// по часам БАЗЫ.
//
// # Порог — функция предиката ЧИТАТЕЛЯ, а не свойство колонки срока
//
// Строку позволено снять не раньше момента, после которого ни один читатель не
// изменил бы из-за неё своего исхода. Читатель здесь один и судит по НАЛИЧИЮ
// строки (`Redeem` — вставка с погашением по конфликту, `expires_at` она не
// читает вовсе), а приём утверждения выше по потоку открыт до `exp + ClockSkew`.
// Значит порог `expires_at <= now()` открыл бы окно шириной ровно `ClockSkew`,
// в котором утверждение проверку времени ЕЩЁ проходит, а его строки УЖЕ нет, —
// то есть повтор принимался бы как впервые предъявленный.
//
// Слагаемое приходит ВХОДОМ и вычисляется вызывающим из `pkg/tokenpolicy`
// (`ClockSkew + RemovalSlack`, реестр `apps/kaname/retention`): копия величины
// разошлась бы с политикой молча и в опасную сторону.
//
// # Почему часы БАЗЫ, а не момент входом
//
// Здесь стояло обратное — момент приходил параметром, и шапка объясняла это
// проверяемостью: «иначе проба сборщика вынуждена была бы спать». Довод
// опровергнут собственным деревом. Убирает ОДНА реплика, а принимает ЛЮБАЯ,
// поэтому процессные часы уборки и процессные часы приёма — это «реплика против
// реплики», и величины, объявляющей допустимое расхождение между нашими же
// процессами, в дереве нет. Часы базы разницу не убирают, но делают её ОДНОЙ и
// наблюдаемой: источник у уборки становится единственным на весь сервис.
// Проверяемость при этом не теряется — её даёт ЭКСПОРТИРОВАННЫЙ метод, как у
// живого уборщика дерева (`gateway/internal/idempotencypg/store.go`, шапка
// `Store.Reap`), и проба ставит строки относительно `now()` базы, не засыпая.
//
// # Почему сборщик обязан существовать
//
// Строка живёт до истечения утверждения плюс порог — не дольше и не короче.
// Короче нельзя: снятая раньше строка делает повтор законным. Дольше нельзя: у
// утверждения, предъявленного один раз, нет никого, кто пришёл бы его убрать, и
// хранилище росло бы без границы, а темп роста выбирал бы предъявитель.
//
// Вызывающий живёт в фоновой петле сервиса — `retention.Sweeper.Start`,
// провязан в `cmd/kaname/retention.go`. Координата названа здесь затем, чтобы
// следующий читатель проверял провязку предикатом, а не верой; само свойство
// «у объявленного уборщика есть прод-вызывающий» держит гейт дерева
// `internal/repohygiene` `TestDeclaredRetentionSweepersHaveAProductionCaller`.
//
// Два вызова к базе здесь ЗАКОННЫ и это не исключение из правила допуска:
// сборщик не решает, принять ли предъявление, поэтому неделимости от него не
// требуется. Он — законный близнец гейта на число вызовов.
//
// Возвращает число снятых строк и признак «партия ушла полной»: без второго
// проход не отличает «убрал всё» от «упёрся в партию» и не догоняет внешний
// темп никогда, оставаясь зелёным по всякой проверке «вызвался ли».
func (r *ClientAssertionReplayRepo) Reap(ctx context.Context, grace time.Duration, batch int) (int64, bool, error) {
	const q = `
DELETE FROM kaname.client_assertion_replay
 WHERE ctid IN (
     SELECT ctid FROM kaname.client_assertion_replay
      WHERE expires_at <= now() - make_interval(secs => $1)
      ORDER BY expires_at
      LIMIT $2
      FOR UPDATE SKIP LOCKED
 )`
	tag, err := r.pool.Exec(ctx, q, grace.Seconds(), batch)
	if err != nil {
		return 0, false, wrapPgErr(err, "ClientAssertionReplay", "")
	}
	n := tag.RowsAffected()
	return n, n == int64(batch), nil
}

// Len — число строк погашения.
//
// Читается пробой сборщика: она утверждает ЧИСЛО СТРОК, а не то, что сборщик
// вызвался. «Вызвался» зелено и на сборщике, не удалившем ничего, и на
// сборщике, опустошившем таблицу целиком, — то есть на реализации, делающей
// повтор законным.
func (r *ClientAssertionReplayRepo) Len(ctx context.Context) (int64, error) {
	const q = `SELECT count(*) FROM kaname.client_assertion_replay`
	var n int64
	if err := r.pool.QueryRow(ctx, q).Scan(&n); err != nil {
		return 0, wrapPgErr(err, "ClientAssertionReplay", "")
	}
	return n, nil
}
