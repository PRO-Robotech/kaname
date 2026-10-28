// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package subscriptionjournal_test

// account_id_string_form_integration_test.go — журнал ресурсов и подписка видят
// аккаунт заданной формы (задача kaname#1052, приёмка
// `docs/engineering/acceptance/account-id-may-be-supplied-at-create.md`, редакция
// 7, sha256 a3dff53e…3e52; сценарий AID-31, решение Р12, стадия S0).
//
// Ось идентификаторов подписки судит фундамент (`subscription.Journal.Accept`,
// corelib `subscription/request.go:105`) платформенным маршрутизатором формы, и
// подписка, суженная до аккаунта `godjee`, сегодня отвергается
// `ids: invalid resource id 'godjee'`. Проба зовёт `Accept` ОБЪЯВЛЕНИЯ ВЛАДЕЛЬЦА
// (`subscriptionjournal.Journal()`) — того самого, которым служба отдаёт свой
// журнал серверу фундамента (`subscription/server.go:245`), — и до пина
// фундамента с S0 красна по утверждению, а не по сборке (§4.3).
//
// Что здесь НЕ утверждается: доставка события потоком сервера подписки. Сервера
// в процессе у службы в пробах нет; приём оси — несущая часть S0, а журнал —
// производитель события (ниже), и оба судятся здесь порознь.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	subscriptionv1 "github.com/PRO-Robotech/corelib/api/corelib/subscription"
	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/subscriptionjournal"
	"github.com/PRO-Robotech/kaname/internal/testsupport/activewayin"
)

func acceptAccountIDs(idsAxis ...string) error {
	_, err := subscriptionjournal.Journal().Accept(&subscriptionv1.SubscriptionRequest{
		Kinds: []string{subscriptionjournal.KindAccount},
		Ids:   idsAxis,
	})
	return err
}

func requireAxisRefusal(t *testing.T, err error, message string) {
	t.Helper()
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "ожидается статус gRPC: %v", err)
	require.Equal(t, codes.InvalidArgument, st.Code(), "%v", err)
	require.Equal(t, message, st.Message())
}

// TestAccountID31_SubscriptionAxisAcceptsTheStringForm — AID-31, ось
// идентификаторов. Близнецы, каждый на одно различие: форма генератора
// (принималась и принимается), `dlputi1u` (форма годна, аккаунта нет — ось
// принимает: существование подписка не судит), `God Jee` (вне формы любого вида)
// и пустая строка — прежние отказы.
func TestAccountID31_SubscriptionAxisAcceptsTheStringForm(t *testing.T) {
	// Полоса пробы — интеграционная, как у её пары о журнале ниже: до пина
	// фундамента с S0 проба красна по утверждению (§4.3 приёмки), и судит её
	// интеграционный прогон пакета, а не короткий прогон хука отправки.
	if testing.Short() {
		t.Skip("integration: ось подписки S0 судится вместе с журналом пакета")
	}
	require.NoError(t, acceptAccountIDs(ids.NewID(domain.PrefixAccount)), "близнец: форма генератора")

	require.NoError(t, acceptAccountIDs("godjee"), "подписка, суженная до аккаунта заданной формы, не открывается")
	require.NoError(t, acceptAccountIDs("dlputi1u"), "годная форма без аккаунта: ось обязана принять")

	requireAxisRefusal(t, acceptAccountIDs("God Jee"), "ids: invalid resource id 'God Jee'")
	requireAxisRefusal(t, acceptAccountIDs(""), "ids: empty identifier")
}

// TestAccountID31_JournalRecordsTheStringFormVerbatim — AID-31, производитель:
// запись журнала ресурсов вида `account` о создании несёт `resource_id = godjee`
// побайтово. Аккаунт вставлен в обход службы (схема это допускает, Р5): предмет
// — триггер журнала, а не путь создания. Сегодня зелёная — журнал пишет
// идентификатор как есть — и закрепляет это против S1.
func TestAccountID31_JournalRecordsTheStringFormVerbatim(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	ctx := context.Background()
	pool, _ := freshSchema(t)

	uid := ids.NewID(domain.PrefixUser)
	personal := ids.NewID(domain.PrefixAccount)
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, 'AID-31', 'ACTIVE')`, uid, personal, "ext-aid31-"+uid, "aid31-"+uid+"@example.invalid")
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO kaname.accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`, personal, "aid31-personal-"+personal[len(personal)-6:], uid)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO kaname.accounts (id, name, owner_user_id, labels)
		VALUES ('godjee', 'godjee', $1, '{}'::jsonb)`, uid)
	require.NoError(t, err)
	activewayin.Seed(t, ctx, tx)
	require.NoError(t, tx.Commit(ctx))

	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.resource_journal
		WHERE resource_kind = 'account' AND resource_id = 'godjee' AND event_type = 'CREATED'`).Scan(&n))
	require.Equal(t, 1, n, "журнал ресурсов не записал создание аккаунта godjee побайтово")
}
