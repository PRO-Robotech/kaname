// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
)

// Точечная выдача — прямой факт НА САМОМ ОБЪЕКТЕ — обязана давать разрешение.
//
// ПОЧЕМУ ЭТО ОТДЕЛЬНАЯ ПРОБА. Соседние пробы формы сеют доступ ЧЕРЕЗ ПРАВИЛО И
// ПРИВЯЗКУ — путь, которым доступ приходит у арендатора. Но есть второй путь, и
// он несущий: строка `relation_fact` на конкретном объекте, без всякой области.
// Им пользуется всё, что выдаёт право на ОДИН объект, — и им же сеются сквозные
// пробы пообъектной фильтрации списков.
//
// Пока вердикт считал внешний движок, этот путь проверялся только сквозными
// пробами на поднятом стенде: у формы своей пробы на него не было. Сквозная
// краснеет через двадцать минут и называет виновником список, а не источник.
func TestAsk_DirectFactOnTheObjectItselfGrants(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.resource_mirror (object_type, object_id, labels)
			 VALUES ($1, 'snet-1', '{}'::jsonb) ON CONFLICT DO NOTHING`,
			catalogFormOf(t, "vpc_subnet"))

		// Прямой факт: право на ОДИН объект, без области и без правила.
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.relation_fact
			   (object_type, object_id, relation, subject, source_version, created_at)
			 VALUES ('vpc_subnet', 'snet-1', 'v_get', 'user:usr-1', now(), now())`)

		got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "vpc_subnet", ObjectID: "snet-1", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("вопрос с прямым фактом: %v", err)
		}
		if got != relverdict.Allow {
			t.Errorf("прямой факт на объекте: вердикт = %s, ожидался %s — "+
				"точечная выдача не действует, и это ровно то, чем краснеет "+
				"сквозная проба пообъектной фильтрации списка", got, relverdict.Allow)
		}

		// ЗАКОННЫЙ БЛИЗНЕЦ: соседний объект того же типа, на который факта нет,
		// обязан остаться закрытым. Без него проба зеленела бы и на форме,
		// которая разрешает всё подряд.
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.resource_mirror (object_type, object_id, labels)
			 VALUES ($1, 'snet-2', '{}'::jsonb) ON CONFLICT DO NOTHING`,
			catalogFormOf(t, "vpc_subnet"))
		other, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "vpc_subnet", ObjectID: "snet-2", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("вопрос про соседний объект: %v", err)
		}
		if other != relverdict.Deny {
			t.Errorf("объект без факта: вердикт = %s, ожидался %s", other, relverdict.Deny)
		}
	})
}
