// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package subscriptionjournal_test

// removal_realdoor_integration_test.go — GWT-6 на НАСТОЯЩЕЙ двери решения.
//
// Пробы с подставной дверью утверждают развилку клиента; эта утверждает то, ради
// чего вся полоса: держатель выдачи, достающей до аккаунта, узнаёт о снятии
// предмета, а посторонний — нет.
//
// # Почему она НЕ может позеленеть по ошибке
//
// Рецензент назвал два способа, которыми такая проба зеленеет при неверном
// продукте: дренаж отзыва в харнессе не поднят, и положительный вердикт лежит в
// окне кеша сужателя. Здесь оба закрыты ПО ПОСТРОЕНИЮ, а не настройкой:
//
//   - вопрос идёт в дверь НАПРЯМУЮ, минуя `listnarrow.Narrower`, поэтому окна
//     положительного вердикта в этом прогоне нет вовсе;
//   - проба СНАЧАЛА утверждает, что дверь отвечает «нет» про снятый предмет, и
//     лишь потом — что клиент отвечает «да». Переживи отношение снятие строки,
//     первое утверждение упало бы, и «да» второго нельзя было бы списать на
//     задержавшийся факт.
//
// То есть «да» клиента доказано РАЗНИЦЕЙ с дверью, а не совпадением с ней.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/listnarrow"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/subscriptionjournal"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// systemRoleAdmin — системная роль администратора: 'rol' || substr(md5('admin'), 1, 17).
const systemRoleAdmin = "rol21232f297a57a5a74"

func TestIntegration_RemovalReachesTheGrantHolderAndNobodyElse(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	ctx := context.Background()
	pool, db := freshSchema(t)

	// Обе стороны правила системной роли кладёт ПРОДУКТ, а не фикстура: роль с
	// одними селекторами адресует объект и не разрешает на нём ничего.
	require.NoError(t, seed.SyncAllSystemRoleSelectors(ctx, pool))
	_, err := seed.ReseedSystemRoleVerbs(ctx, kanamepg.New(pool, nil), pool, catalogfixture.Facts(), nil)
	require.NoError(t, err)

	// Арендная обвязка и выдача роли НА АККАУНТ: захваченная область группы —
	// именно он, и предмет пробы в том, что выдача достаёт до неё.
	_, err = db.ExecContext(ctx, `
		INSERT INTO kaname.accounts (id, name, owner_user_id)
		VALUES ('acc-1', 'test-account', 'usr-1') ON CONFLICT DO NOTHING;
		INSERT INTO kaname.users (id, external_id, email, account_id)
		VALUES ('usr-1', 'ext-1', 'usr-1@kaname.local', 'acc-1') ON CONFLICT DO NOTHING;
		INSERT INTO kaname.service_accounts (id, account_id, name)
		VALUES ('sva-1', 'acc-1', 'sva-one') ON CONFLICT DO NOTHING;
		INSERT INTO kaname.access_bindings
		  (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		VALUES ('acb-1', 'service_account', 'sva-1', '`+systemRoleAdmin+`', 'account', 'acc-1', 'ACTIVE');
		INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id, resource_type, resource_id)
		VALUES ('acb-1', 'service_account', 'sva-1', 'account', 'acc-1');
		INSERT INTO kaname.groups (id, account_id, name) VALUES ('grp-1', 'acc-1', 'watched');`)
	require.NoError(t, err)

	door := authzcascade.Wrap(relverdict.NewAsker(pool))
	const holder, stranger = "service_account:sva-1", "service_account:sva-nobody"
	rel := "v_get"

	ask := func(subject, object string) bool {
		got, aerr := door.BatchCheckWithContext(ctx, subject, rel, []string{object}, nil)
		require.NoError(t, aerr)
		require.Len(t, got, 1)
		return got[0]
	}

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: пока группа жива, дверь отвечает «да» держателю.
	// Без него отрицание ниже зеленело бы на выдаче, которой нет вовсе.
	require.True(t, ask(holder, "iam_group:grp-1"),
		"живая группа обязана быть видна держателю выдачи на аккаунт: "+
			"иначе фикстура не воспроизводит выдачу, и дальше сравнивать нечего")
	require.False(t, ask(stranger, "iam_group:grp-1"),
		"постороннему живая группа видна быть не должна")

	_, err = db.ExecContext(ctx, `DELETE FROM kaname.groups WHERE id = 'grp-1'`)
	require.NoError(t, err)

	// ПРЕМИСА §2.3, утверждаемая ПРОГОНОМ, а не чтением: звено вместимости ушло
	// вместе со строкой, и дверь отвечает «нет» ДАЖЕ ДЕРЖАТЕЛЮ.
	require.False(t, ask(holder, "iam_group:grp-1"),
		"после снятия дверь обязана отвечать «нет» про сам предмет — на этом "+
			"стоит вся §3.3; ответь она «да», и «да» клиента ниже ничего бы не доказывало")
	require.True(t, ask(holder, "account:acc-1"),
		"аккаунт держателю виден: именно по нему и судится снятие")

	client := subscriptionjournal.NewNarrowClient(door, subscriptionjournal.NewPoolRemovalScopes(pool))
	check := func(subject string) listnarrow.Check {
		return listnarrow.Check{
			Subject: subject, ResourceType: "iam_group", ResourceID: "grp-1",
			Action: "iam.groups.list", RequiredRelation: rel,
		}
	}

	got, err := client.BatchCheck(ctx, []listnarrow.Check{check(holder), check(stranger)})
	require.NoError(t, err)
	assert.Equal(t, []bool{true, false}, got,
		"снятие доезжает до держателя выдачи и НЕ доезжает до постороннего: "+
			"первое — предмет полосы, второе — граница, без которой она была бы "+
			"расширением доступа, а не доставкой события")
}
