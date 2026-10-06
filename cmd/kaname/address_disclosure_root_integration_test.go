// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// address_disclosure_root_integration_test.go — раскрытие Р3 приёмки
// `access-beyond-login-needs-a-verified-address.md` (kaname#456) на обработчике,
// СОБРАННОМ КОРНЕМ: причина `email_not_verified` уходит только самому субъекту;
// распорядитель ресурса, спросивший о другом человеке, получает нейтральный
// отказ — побайтно тот же, что у подтверждённого субъекта без отношения.
//
// Обработчик берётся у `buildAuthZServices`, а не собирается пробой: между
// транспортом и решателем корень ставит наблюдатель полос, и свойство обязано
// держаться на ТОЙ сборке, которую получает слушатель. Обе ветви корня —
// с реестром величин (так собирает `serve.go`) и без него — прогоняются.
package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/pgtest"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
)

// disclosureRootAsk — ответы края о человеке stranger: распорядителю аккаунта
// (delegated) и самому человеку (self).
func disclosureRootAsk(t *testing.T, reg *metrics.Registry, strangerVerified, strangerHolds bool) (
	delegated, self *iamv1.AuthorizeCheckResponse) {
	t.Helper()
	if testing.Short() {
		t.Skip("интеграция: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, iampgtest.NewTestPostgres(t))
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): пул к базе пробы")
	pgtest.ClosePoolAtEnd(t, pool)

	exec := func(sql string, args ...any) {
		t.Helper()
		_, err := pool.Exec(ctx, sql, args...)
		require.NoErrorf(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев %s", sql)
	}
	// fact — прямой факт отношения тем производителем, каким его кладёт продукт:
	// строкой журнала, которую триггер проецирует в `relation_fact`.
	fact := func(subject, relation, objectType, objectID string) {
		t.Helper()
		exec(`INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
		      VALUES ('fga.tuple.write',
		              jsonb_build_object('user', $1::text, 'relation', $2::text,
		                                 'object', $3::text || ':' || $4::text),
		              now())`, subject, relation, objectType, objectID)
		var landed int
		require.NoError(t, pool.QueryRow(ctx,
			`SELECT count(*)::int FROM kaname.relation_fact
			  WHERE object_type = $1 AND object_id = $2 AND relation = $3 AND subject = $4`,
			objectType, objectID, relation, subject).Scan(&landed))
		require.Equalf(t, 1, landed, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): факт %s:%s --%s--> %s не спроецировался",
			objectType, objectID, relation, subject)
	}
	// mark — отметка подтверждения писателем продукта.
	mark := func(user string) {
		t.Helper()
		require.NoErrorf(t, kanamepg.NewLoginMethodRepo(pool).MarkEmailVerified(ctx, domain.UserID(user),
			domain.Email(user+"@example.test"), time.Now().UTC()), "НЕ-ВЫПОЛНИЛОСЬ(фикстура): отметка %s", user)
	}

	const acc, owner, admin, stranger = "acc-rootdisc", "usr-rootdiscown", "usr-rootdiscadm", "usr-rootdiscstr"
	exec(`INSERT INTO kaname.clusters (id, name) VALUES ('cluster_root', 'kacho') ON CONFLICT DO NOTHING`)
	// Основатель аккаунта и владелец — одной транзакцией: второй ключ пары отложен.
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ($1, $1, $2)`, acc, owner)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев аккаунта")
	_, err = tx.Exec(ctx, `INSERT INTO kaname.users (id, external_id, email, account_id, email_verified_at)
	                       VALUES ($1, $1, $1 || '@example.test', $2, now())`, owner, acc)
	require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): посев владельца")
	seedWayIn(t, ctx, tx)
	require.NoError(t, tx.Commit(ctx))
	for _, u := range []string{admin, stranger} {
		exec(withWayIn(`INSERT INTO kaname.users (id, external_id, email, account_id) VALUES ($1, $1, $1 || '@example.test', $2)`), u, acc)
	}
	fact("user:"+admin, "admin", "account", acc)
	mark(admin)
	if strangerHolds {
		fact("user:"+stranger, "editor", "account", acc)
	}
	if strangerVerified {
		mark(stranger)
	}

	// Дверь — та же, что корень выдаёт стражам и решателю края (`wiring.go`).
	door := authzcascade.WrapAdmitted(relverdict.NewAsker(pool), personmarks.New(pool))
	require.True(t, door.FormReachable(), "НЕ-ВЫПОЛНИЛОСЬ(предпосылка): дверь собрана без формы")
	bundle := buildAuthZServices(kanamepg.New(pool, pool), door, reg, true)

	req := &iamv1.AuthorizeCheckRequest{Subject: "user:" + stranger, Resource: &iamv1.ResourceRef{Type: "account", Id: acc},
		Action: "iam.account.edit", RequiredRelation: "editor"}
	delegated, err = bundle.authorize.Check(operations.WithPrincipal(ctx, operations.Principal{ID: admin, Type: "user"}), req)
	require.NoError(t, err)
	self, err = bundle.authorize.Check(operations.WithPrincipal(ctx, operations.Principal{ID: stranger, Type: "user"}), req)
	require.NoError(t, err)
	return delegated, self
}

// TestRootEdgeDisclosesNotVerifiedOnlyToTheSubject — Р3 на обеих ветвях корня.
func TestRootEdgeDisclosesNotVerifiedOnlyToTheSubject(t *testing.T) {
	for _, branch := range []struct {
		name string
		reg  func() *metrics.Registry
	}{
		{"решатель под наблюдателем полос", metrics.NewRegistry},
		{"решатель без реестра величин", func() *metrics.Registry { return nil }},
	} {
		t.Run(branch.name, func(t *testing.T) {
			delegated, self := disclosureRootAsk(t, branch.reg(), false, true)
			twin, _ := disclosureRootAsk(t, branch.reg(), true, false)
			require.False(t, delegated.GetAllowed(), "Дано: неподтверждённому права не действуют")
			require.False(t, twin.GetAllowed(), "близнец: подтверждённый без отношения — отказ")
			require.Equal(t, []string{"email_not_verified"}, self.GetDenyReasons(), "самому субъекту — email_not_verified")
			require.Equal(t, twin.GetDenyReasons(), delegated.GetDenyReasons(),
				"распорядителю — нейтральный отказ, побайтно как у подтверждённого субъекта без отношения")
		})
	}
}
