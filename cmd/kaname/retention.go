// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retention.go — провязка фоновой уборки таблиц, чей рост задаёт внешний
// (задача #1292, приёмка `retention-sweep-has-a-caller.md`).
//
// # Предмет
//
// Два уборщика по сроку были ОБЪЯВЛЕНЫ и не имели ни одного прод-вызывающего, у
// третьей таблицы уборщика не было вовсе. Восемь мест дерева при этом утверждали
// в настоящем времени, что сборщик работает: две строки применённой миграции,
// шапки двух методов, комментарий контракта, комментарий домена, шапка второй
// применённой миграции и записка архитектуры. Провязка делает все восемь
// истинными разом; впредь свойство держит гейт дерева
// `internal/repohygiene` `TestDeclaredRetentionSweepersHaveAProductionCaller`,
// а не этот комментарий.
//
// # Почему ОДНА петля на все предметы
//
// Несколько петель — несколько расписаний об одном предмете, и они расходятся
// молча. Петля владеет реестром: добавление уборщика — одна запись, а не новая
// петля. Четвёртым предметом заведены окна темпа заведения аккаунтов (#1364), и
// добавление стоило ровно одной строки — ровно то, ради чего петля одна.
package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/retention"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// buildRetentionSweeper собирает фоновую уборку и подключает её величины к
// съёму. НЕ запускает: старт — [startRetentionSweeps], после последнего отказа
// старта (#253).
//
// Отказывает, а не предупреждает: величины уже проверены стражем старта
// конфигурации, поэтому отказ здесь означает расхождение построителя со
// стражем — то есть ровно то состояние, в котором стенд поднимать нельзя.
func buildRetentionSweeper(
	pool *pgxpool.Pool,
	cfg config.Config,
	reg *metrics.Registry,
	human retention.HumanSessionReapers,
	logger *slog.Logger,
) (*retention.Sweeper, error) {
	sweeper, err := retention.New(
		cfg.Retention.Sweep(),
		// За базовым перечнем — предметы полосы входа: сессии человека, журнал
		// неверных предъявлений и прочие (Ф3, kacho#1269, `WithHumanSessions`).
		// Их уборщики приходят от полосы входа; полоса, не построенная (только
		// в пробах — на живом старте это отказ сборки), оставляет перечень
		// базовым.
		retention.WithHumanSessions(retention.Subjects(
			kanamepg.NewClientAssertionReplayRepo(pool),
			kanamepg.NewSessionRevocationRepo(pool),
			kanamepg.NewMintedTokenRevocationRepo(pool),
			kanamepg.NewIdentityAdmissionWindowRepo(pool),
			// Пятым предметом — журнал смены субъекта (#1758). Наблюдатель
			// границы устоявшегося у него СВОЙ, а не общий с читателем, и это
			// безопасно by construction: граница монотонна, поэтому величина,
			// наблюдённая до оператора, остаётся нижней оценкой — снимется не
			// больше, чем позволено.
			kanamepg.NewSubjectChangeJournalSweeper(pool, logger),
			// Шестым предметом — очередь сверки прав (#2050). Её дренированные
			// строки не снимались никогда, при том что приём уборки уже был и
			// применён к соседней очереди.
			kanamepg.NewReconcileOutboxSweeper(pool),
			// Седьмым предметом — очередь компенсаций у внешнего провайдера
			// (#2069). Её доставленные строки не снимались никогда, и реестр
			// роста таблиц объявлял её долгом; уборщик СВОЙ, потому что общий
			// уборщик платформы требует ключа партиции, а он у этой очереди
			// пуст намеренно — обоснование в росписи commutativeDrainExempt.
			kanamepg.NewProviderCompensationSweeper(pool),
			// Восьмым предметом базового перечня — записи выпуска токена доступа
			// церемонии (kaname#319). Писать строку обязан выпуск церемонии
			// (провязка — kaname#396); до неё предмет пуст, и проход снимает
			// ноль. После срока токена с допуском строка ни одного исхода
			// предъявления не меняет.
			kanamepg.NewOAuthCeremonyRepo(pool),
		), human),
		logger.With(slog.String("component", "retention_sweep")),
	)
	if err != nil {
		return nil, fmt.Errorf("фоновая уборка: %w", err)
	}

	// Величина обязана иметь читателя: накопитель без него считает в никуда.
	if reg != nil {
		reg.NewRetentionCollector(func() metrics.RetentionCounts {
			c := sweeper.Stats()
			return metrics.RetentionCounts{Passes: c.Passes, Removed: c.Removed, Failures: c.Failures}
		})
	}

	return sweeper, nil
}

// startRetentionSweeps запускает обе уборки по сроку: ресурсного журнала и
// таблиц службы.
//
// # Место — после ПОСЛЕДНЕГО отказа старта (#253)
//
// Первый проход уборки идёт сразу. Запущенная раньше стража, который ещё может
// отвергнуть старт, она встречала закрытие пула `defer`-ом корня на этом отказе,
// и проходы в полёте докладывали «retention sweep failed: closed pool» как СВОЙ
// отказ — шесть WARN над единственной строкой ERROR, которая и есть предмет.
// Порядок держит гейт `TestRetentionSweepsStartAfterTheLastBootRefusal`.
//
// # Контекст — корневой контекст задач
//
// Его отменяет `defer rootShutdown.Stop()`, стоящий ПОСЛЕ `defer pool.Close()`,
// то есть исполняемый раньше: уборки получают отмену прежде, чем пул закроется.
//
// # Отказ — только до первого запуска
//
// Уборка журнала поднимается вызовом фундамента, который собирает и запускает
// одним шагом и отказывает до запуска; поэтому она идёт первой, а уборка таблиц
// службы, собранная заранее, запускается без отказа. Отказ этой функции, таким
// образом, наступает раньше, чем запущена хоть одна уборка.
func startRetentionSweeps(
	ctx context.Context,
	own *retention.Sweeper,
	pool *pgxpool.Pool,
	cfg config.Config,
	logger *slog.Logger,
) error {
	if err := startJournalRetentionSweep(ctx, pool, logger); err != nil {
		return err
	}
	own.Start(ctx)
	logger.Info("retention sweep is on",
		slog.String("interval", cfg.Retention.Interval.String()),
		slog.Int("batch", cfg.Retention.Batch),
		slog.Int("max_batches_per_pass", cfg.Retention.MaxBatchesPerPass))
	return nil
}
