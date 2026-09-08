// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// provider_compensation_retention.go — уборщик доставленных строк очереди
// компенсаций у внешнего провайдера (задача #2069).
//
// # Предмет
//
// Строка заводится в writer-транзакции мутации, дренаж помечает доставленную
// `sent_at` и не удаляет её НИКОГДА: рост монотонный и вечный, темп задаёт
// арендатор. Реестр роста таблиц объявлял таблицу ДОЛГОМ и называл условие
// легализации — здесь оно и исполняется.
//
// # Почему уборщик СВОЙ, а не общий уборщик платформы
//
// Общий (`outbox.StartQueueRetentionSweep`) не применим by construction: он
// требует ключа партиции, потому что обязан щадить доставленную строку,
// защищающую отравленного предшественника от оживления реконсайлером. У этой
// очереди ключ партиции пуст НАМЕРЕННО — её поток коммутативен: каждое событие
// означает «снять у провайдера вот этот объект», и снятия независимы между
// собой. Щадить нечего, поэтому предикат проще.
//
// «Оживителя над этой очередью нет» — факт о ДЕРЕВЕ, а не свойство замысла, и
// он вправе перестать быть верным. Поэтому послабление несёт гейт
// `internal/check` `TestProviderCompensationRetentionPremiseHolds`: он покраснеет
// в тот день, когда оживитель над этой таблицей построят.
//
// # Что уборка НЕ трогает
//
// Недоставленную строку — ни при каком возрасте. Условие `sent_at IS NOT NULL`
// исключает и ожидающую, и отравленную by construction: у отравленной отметки
// доставки нет, а её намерение не доехало, и снять её значило бы потерять
// единственное свидетельство о нём.

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// providerCompensationSweepSQL — предикат уборки.
//
// # Имя таблицы стоит ЛИТЕРАЛОМ, а не подставляется из константы
//
// Соблазн собрать оператор из `clients.ProviderCompensationTable` силён —
// единственное место имени. Он ОТВЕРГНУТ замером: гейт роста таблиц
// (`internal/repohygiene` `TestLiveTablesNameTheirGrowthLimit`) разрешает имя
// таблицы у оператора снятия по СТРОКОВОМУ ЗНАЧЕНИЮ, и собранный форматом
// оператор он не видит ВОВСЕ — ни как механизм, ни как слепую зону: перепись
// «полос снятия строк» не сдвинулась ни на единицу (прод 110 → 110,
// с неразрешимым именем 6 → 6). То есть уборка была бы, а тревога о росте
// таблицы осталась бы висеть, и следующий читатель реестра завёл бы её заново.
//
// Та же форма и по той же причине у соседа — `reconcile_outbox.SweepDrained`.
// Цена решения названа, а не спрятана: имя таблицы записано вторым местом, и
// расхождение с эмиссией стерегут применённая миграция (таблицы с другим именем
// нет) и та же перепись гейта.
const providerCompensationSweepSQL = `
DELETE FROM kaname.provider_compensation_outbox
 WHERE id IN (
       SELECT id
         FROM kaname.provider_compensation_outbox
        WHERE sent_at IS NOT NULL
          AND sent_at < now() - make_interval(secs => $1)
        ORDER BY id
        LIMIT $2)`

// ProviderCompensationSweeper — уборщик доставленных строк очереди компенсаций.
type ProviderCompensationSweeper struct {
	pool *pgxpool.Pool
}

// NewProviderCompensationSweeper собирает уборщика над пулом владельца очереди.
func NewProviderCompensationSweeper(pool *pgxpool.Pool) *ProviderCompensationSweeper {
	return &ProviderCompensationSweeper{pool: pool}
}

// SweepDeliveredCompensations — один проход партии. Подпись — общая форма
// уборщика реестра (`retention.SweepFunc`): момент времени входом не приходит,
// часы у предиката — БАЗЫ, те же, которыми дренаж ставит `sent_at`.
//
// Возвращает число снятых строк и признак «партия ушла полной». Признак — не
// удобство: без него проход не отличает «убрал всё, что было» от «упёрся в
// партию», и уборка со скоростью одна партия за тик не догоняла бы внешний темп
// НИКОГДА, оставаясь зелёной по всякой проверке «вызвался ли».
func (s *ProviderCompensationSweeper) SweepDeliveredCompensations(
	ctx context.Context, grace time.Duration, batch int,
) (int64, bool, error) {
	if batch <= 0 {
		return 0, false, fmt.Errorf("provider_compensation: партия обязана быть положительной, получено %d", batch)
	}
	tag, err := s.pool.Exec(ctx, providerCompensationSweepSQL, grace.Seconds(), batch)
	if err != nil {
		return 0, false, fmt.Errorf("provider_compensation: уборка доставленных: %w", err)
	}
	removed := tag.RowsAffected()
	return removed, removed >= int64(batch), nil
}
