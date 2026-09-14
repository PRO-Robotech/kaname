// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// subscription_wiring.go — сборка сервера потока изменений ресурсов.
//
// Отдельным файлом, а не строкой в `serve.go`: композиционный корень службы
// держится гейтом, запрещающим ему нести собственную цепь, и сборка сервера —
// именно цепь (объявление владельца, дверь решения, сужатель, величины посадки,
// страж строки подключения).
//
// Провязка, и ничего больше: ни бизнес-логики, ни чтения окружения.
package main

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"

	subscriptionv1 "github.com/PRO-Robotech/corelib/api/corelib/subscription"
	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/listnarrow"
	coreretention "github.com/PRO-Robotech/corelib/retention"
	"github.com/PRO-Robotech/corelib/subscription"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/authzfilter"
	"github.com/PRO-Robotech/kaname/internal/subscriptionjournal"
)

// buildSubscriptionServer — сервер потока изменений ресурсов службы.
//
// Возвращает `nil, nil`, когда дверь решения не провязана: тогда глагол НЕ
// регистрируется и отвечает `Unimplemented`, и это честно. Поднять его с
// несужающим сужателем нельзя — за этим методом нет пообъектной проверки на
// крае, откатываться не на что, и фундамент такую сборку отвергает.
func buildSubscriptionServer(
	cfg config.Config, pool *pgxpool.Pool, door subscriptionjournal.Door, logger *slog.Logger,
) (subscriptionv1.InternalSubscriptionServiceServer, error) {
	if door == nil || pool == nil {
		return nil, nil
	}

	gate, err := subscriptionjournal.ProjectGate()
	if err != nil {
		return nil, err
	}

	dsn := cfg.SingleConnDSN()
	// СТРАЖ ПОСАДКИ: параметр пула в строке ОДИНОЧНОГО соединения означает отказ
	// на подключении, а не на сборке. Без него он наступил бы у каждой подписки
	// в бою — то есть там, где его никто не связал бы с этой строкой.
	if key := coredb.PoolParamFromDSN(dsn); key != "" {
		return nil, fmt.Errorf("поток изменений: строка подключения несёт параметр "+
			"пула %q: вне пула это неизвестный серверу параметр и отказ при "+
			"подключении, причём у каждой подписки, а не на сборке", key)
	}

	// Сужатель СВОЙ экземпляр, но дверь и предикат отношений — ТЕ ЖЕ, что у
	// списков. Своим он потому, что несёт ветвь снятия, которой списку не нужно
	// и которой он не достигает: список возвращает только живые строки.
	narrower := listnarrow.New(
		subscriptionjournal.NewNarrowClient(door, subscriptionjournal.NewPoolRemovalScopes(pool)),
		listnarrow.Config{Relations: subscriptionNarrowRelations()},
	).WithLogger(logger)

	srv, err := subscription.NewServer(subscription.Config{
		Journal:      subscriptionjournal.Journal(),
		DSN:          dsn,
		Narrower:     narrower,
		ProjectGate:  gate,
		MaxStreams:   cfg.APIServer.Subscription.MaxStreams,
		StreamBudget: cfg.APIServer.Subscription.StreamBudget,
		IdlePoll:     cfg.APIServer.Subscription.IdlePoll,
		Logger:       logger,
	})
	if err != nil {
		return nil, fmt.Errorf("сервер потока изменений: %w", err)
	}
	return srv, nil
}

// subscriptionNarrowRelations — предикат членства ПО ТИПУ, ВЫВЕДЕННЫЙ из
// единственного объявления видимости службы.
//
// Второй карты здесь не заводится: она разошлась бы с первой молча, и разошлась
// бы в сторону лишнего доступа. Карта обязана быть ТОТАЛЬНОЙ — запись под пустым
// ключом есть умолчание для типа, не названного поимённо.
func subscriptionNarrowRelations() map[string][]string {
	out := map[string][]string{"": authzfilter.RelationsFor("")}
	for kind := range subscriptionJournalKinds() {
		out[kind] = authzfilter.RelationsFor(kind)
	}
	return out
}

// subscriptionJournalKinds — виды, объявленные владельцем журнала.
//
// Отдельной функцией, потому что их читают ДВОЕ: посадка сужателя и проба,
// утверждающая тотальность карты. Второе перечисление разошлось бы с первым
// молча — ровно тот класс, который эта карта и обязана не вносить.
func subscriptionJournalKinds() map[string]struct{} {
	kinds := subscriptionjournal.Journal().Mapping.Kinds
	out := make(map[string]struct{}, len(kinds))
	for kind := range kinds {
		out[kind] = struct{}{}
	}
	return out
}

// startJournalRetentionSweep — фоновая уборка ресурсного журнала.
//
// ОТДЕЛЬНЫМ уборщиком, а не предметом общего: общий собирается constructor'ом
// фиксированной арности с именованными типами жнецов (`retention.Subjects`), и
// журнал в него не вставляется, не переписав его сигнатуру. Переписывать её ради
// восьмого предмета значило бы тронуть семь чужих ради одного своего.
//
// Уборщик собирается ИЗ ОБЪЯВЛЕНИЯ владельца, а не из второго описания таблицы:
// разойдись они — уборка сносила бы не то либо не сносила ничего, и оба исхода
// тихие.
//
// Пул, а не строка одиночного соединения: то занято `LISTEN` всё время жизни
// потока.
//
// Удержание объявлено ПАРОЙ: `RetainsFromEarliestRow` без уборщика означал бы
// обещанную подписчику нижнюю возобновимую позицию, которую никто не двигает.
func startJournalRetentionSweep(
	ctx context.Context, pool *pgxpool.Pool, logger *slog.Logger,
) error {
	if pool == nil {
		return nil
	}
	if _, err := subscription.StartJournalRetentionSweep(
		ctx, pool, subscriptionjournal.Journal(),
		coreretention.DefaultConfig(),
		logger.With(slog.String("component", "subscription_journal_sweep")),
	); err != nil {
		return fmt.Errorf("уборка ресурсного журнала: %w", err)
	}
	return nil
}
