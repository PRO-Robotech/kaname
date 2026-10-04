// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package subscriptionjournal_test

// group_create_ntf363_initiator_integration_test.go — событие журнала службы
// доступа несёт инициатора и время транзакции.
//
// Приёмка NTF-3 (`docs/specs/sub-phase-NTF-3-kacho-modules-notifications-acceptance.md`
// в репозитории продукта), сценарий NTF3-63: `usr-own` создаёт группу `grp-9`
// в `acc-1` глаголом `GroupService.Create`; подписчик журнала с `v_get` на
// группу получает `CREATED` с `initiator = "user:usr-own"` и `occurredAt`,
// равным времени строки журнала, усечённому до секунды.
//
// # Что настоящее, а что подставлено
//
// Настоящие: use-case создания группы со своим пишущим путём (репозиторий
// службы на Postgres, рабочий процесс операции), цепь миграций, объявление
// владельца `subscriptionjournal.Journal()` и общий сервер потока фундамента за
// настоящим gRPC. Подставлена только ДВЕРЬ РЕШЕНИЯ сужателя: она разрешает
// подписчику ровно созданную группу и ничего больше — видимость не предмет этой
// пробы, у неё свои (`removal_realdoor_integration_test.go`).
//
// # Почему через use-case, а не вставкой
//
// Предмет — не схема (её держит близнец в `internal/migrations`), а то, что
// ПИШУЩИЙ ПУТЬ службы открывает транзакцию с инициатором из проверенного
// субъекта запроса. Вставка мимо пути утверждала бы схему второй раз и
// осталась бы зелёной там, где путь инициатора не ставит.

import (
	"context"
	"database/sql"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	subscriptionv1 "github.com/PRO-Robotech/corelib/api/corelib/subscription"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/listnarrow/narrowtest"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/corelib/subscription"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/group"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/subscriptionjournal"
)

// ntf363Schema — своя база с накатанной цепью: строка для пула службы (с
// приведением схемы — репозиторий пишет неквалифицированными именами) и строка
// одиночного соединения сервера потока (таблица журнала квалифицирована).
func ntf363Schema(t *testing.T) (pool *pgxpool.Pool, streamDSN string) {
	t.Helper()
	dsn := pgtest.NewEmptyDB(t)

	sqlDB, err := sql.Open("pgx", dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	goose.SetLogger(goose.NopLogger())
	require.NoError(t, goose.Up(sqlDB, "."), "фикстура: цепь миграций обязана накатиться")

	pool, err = pgxpool.New(context.Background(), pgtest.WithSearchPath(dsn, "kaname,public"))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	return pool, dsn
}

// ntf363Subscriber — сервер потока службы за bufconn, вызывающий —
// `subscriber`; сужатель разрешает ровно `allow`.
func ntf363Subscriber(t *testing.T, streamDSN, subscriber string, allow ...string) subscriptionv1.InternalSubscriptionServiceClient {
	t.Helper()
	gate, err := subscriptionjournal.ProjectGate()
	require.NoError(t, err)
	srv, err := subscription.NewServer(subscription.Config{
		Journal:      subscriptionjournal.Journal(),
		DSN:          streamDSN,
		Narrower:     narrowtest.Allowing(allow...),
		ProjectGate:  gate,
		MaxStreams:   4,
		StreamBudget: 30 * time.Second,
		IdlePoll:     150 * time.Millisecond,
	})
	require.NoError(t, err, "фикстура: сервер потока на объявлении владельца обязан собраться")

	caller := narrowtest.CallerAs("user", subscriber)
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer(grpc.ChainStreamInterceptor(
		func(s any, ss grpc.ServerStream, _ *grpc.StreamServerInfo, h grpc.StreamHandler) error {
			ctx, stop := context.WithCancel(caller)
			go func() { <-ss.Context().Done(); stop() }()
			return h(s, ntf363Stream{ServerStream: ss, ctx: ctx})
		}))
	subscriptionv1.RegisterInternalSubscriptionServiceServer(gs, srv)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return subscriptionv1.NewInternalSubscriptionServiceClient(conn)
}

// ntf363Stream — поток с личностью подписчика и отменой настоящего потока.
type ntf363Stream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s ntf363Stream) Context() context.Context { return s.ctx }

// TestResourceJournal_NTF363_GroupCreateEventCarriesInitiatorAndTime — NTF3-63.
func TestResourceJournal_NTF363_GroupCreateEventCarriesInitiatorAndTime(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	ctx := context.Background()
	pool, streamDSN := ntf363Schema(t)

	// Given: `usr-own` — владелец аккаунта `acc-1`.
	usrOwn := ids.NewID(domain.PrefixUser)
	acc1 := ids.NewID(domain.PrefixAccount)
	// Одной транзакцией: ссылки пользователя на аккаунт и аккаунта на владельца
	// отложенные и взаимные, и порознь не вставляется ни одна из строк.
	seedTx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = seedTx.Exec(ctx, `
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, 'usr-own', 'ACTIVE')`,
		usrOwn, acc1, "ext-ntf363-"+usrOwn, "ntf363-"+usrOwn+"@example.com")
	require.NoError(t, err, "фикстура: пользователь")
	_, err = seedTx.Exec(ctx, `
		INSERT INTO kaname.accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`, acc1, "ntf363-"+acc1[len(acc1)-6:], usrOwn)
	require.NoError(t, err, "фикстура: аккаунт")
	require.NoError(t, seedTx.Commit(ctx), "фикстура: пользователь и аккаунт не зафиксированы")

	// When: `usr-own` вызывает создание группы `grp-9` в `acc-1`.
	opsRepo := operations.NewRepo(pool, "kaname")
	caller := operations.WithPrincipal(ctx,
		operations.Principal{Type: "user", ID: usrOwn, DisplayName: "usr-own"})
	op, err := group.NewCreateGroupUseCase(kanamepg.New(pool, nil), opsRepo).Execute(caller,
		domain.Group{AccountID: domain.AccountID(acc1), Name: domain.GroupName("grp-9")})
	require.NoError(t, err, "глагол создания группы отказал до операции")
	require.NoError(t, operations.Wait(ctx), "рабочий процесс операции не завершился")

	done, err := opsRepo.Get(ctx, op.ID)
	require.NoError(t, err)
	require.True(t, done.Done, "операция создания группы не завершена")
	require.Nil(t, done.Error,
		"операция создания группы завершилась ОТКАЗОМ: пишущий путь не ставит "+
			"транзакции инициатора, и строка журнала отвергнута: %v", done.Error)

	var grp9 string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT id FROM kaname.groups WHERE account_id = $1 AND name = 'grp-9'`, acc1).Scan(&grp9),
		"фикстура: созданной группы в таблице нет")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ ФИКСТУРЫ: строка журнала о создании ровно одна, и
	// её время прочитано из таблицы — с ним сравнивается событие.
	var rowTime time.Time
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT created_at FROM kaname.resource_journal
		 WHERE resource_kind = 'iam_group' AND resource_id = $1 AND event_type = 'CREATED'`,
		grp9).Scan(&rowTime), "фикстура: строки журнала о создании группы нет ровно одной")

	// Then: подписчик с `v_get` на `grp-9` получает `CREATED`.
	client := ntf363Subscriber(t, streamDSN, ids.NewID(domain.PrefixUser), grp9)
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	strm, err := client.Subscribe(sctx, &subscriptionv1.SubscriptionRequest{
		Kinds: []string{subscriptionjournal.KindGroup},
		Ids:   []string{grp9},
		Start: &subscriptionv1.SubscriptionRequest_Anchor{Anchor: subscriptionv1.SubscriptionAnchor_BEGINNING},
	})
	require.NoError(t, err, "фикстура: подписка не открылась")
	first, err := strm.Recv()
	require.NoError(t, err, "фикстура: служебное сообщение не пришло")
	require.NotNil(t, first.GetOpened(), "фикстура: первым пришло не служебное сообщение")

	var ev *subscriptionv1.SubscriptionEvent
	for ev == nil {
		m, rerr := strm.Recv()
		require.NoError(t, rerr, "поток закрылся до события о создании группы")
		if e := m.GetEvent(); e != nil && e.GetResourceId() == grp9 &&
			e.GetChange() == subscriptionv1.SubscriptionEvent_CREATED {
			ev = e
		}
	}

	// Предмет — после всей проверки фикстуры. Оба поля утверждаются независимо:
	// отказ одного не скрывает исход другого.
	assert.Equal(t, "user:"+usrOwn, ev.GetInitiator(),
		"событие CREATED группы несёт инициатора %q, ожидался субъект запроса", ev.GetInitiator())
	ts := ev.GetOccurredAt()
	if assert.NotNil(t, ts, "событие CREATED группы не несёт occurredAt") {
		assert.Zero(t, ts.GetNanos(), "occurredAt несёт дробную часть секунды")
		assert.True(t, ts.AsTime().Equal(rowTime.Truncate(time.Second)),
			"occurredAt %s ≠ время строки журнала, усечённое до секунды, %s",
			ts.AsTime(), rowTime.Truncate(time.Second))
	}
}
