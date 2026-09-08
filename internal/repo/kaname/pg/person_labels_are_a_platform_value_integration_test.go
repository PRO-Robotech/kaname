// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// person_labels_are_a_platform_value_integration_test.go — метка человека
// ОДНА на всю платформу, и пер-аккаунтного носителя у неё нет (#1126).
//
// # Решение, которое эта проба держит
//
// Задача #1126 называла три исхода: перенести метки на членство, снять их с
// контракта вместе с селекторной выдачей, либо оставить глобальными ОСОЗНАННО.
// Взят третий, и вот на чём он стоит.
//
//   - Правка метки уже НЕ право аккаунта: `UserService.Update` гейтится
//     `iam_user.record_writer`, у которого источников уровня аккаунта нет ни
//     одного (#1102). То есть посылка задачи — «метка, поставленная в аккаунте
//     A, меняет состав селекторов аккаунта B» — сегодня не имеет ПРОИЗВОДИТЕЛЯ:
//     поставить её из аккаунта нельзя вовсе. Это опровержение половины посылки,
//     и оно записано, а не умолчано.
//   - Перенос на членство (исход 1) требует ресурса членства, которого на
//     контракте нет (#1085): у `Get` нет аргумента аккаунта, поэтому «метки
//     этого человека» стали бы величиной, которую нечем адресовать. Половина
//     переноса — колонка есть, контракт читает старое место — хуже обоих целых
//     исходов.
//   - Снятие поля (исход 2) отняло бы у арендатора селекторную выдачу на людей
//     целиком; решать это отдельно от #1085 значит решать дважды.
//
// Отсюда норма, которую проба и стережёт: **носитель метки человека РОВНО ОДИН,
// и он не пер-аккаунтный**. Пока это так, «метка моего аккаунта» — величина,
// которой негде лежать, а значит пер-аккаунтное толкование невозможно by
// construction, а не по договорённости.
//
// # Почему это проба, а не абзац в документе
//
// Абзац переживает свой предмет молча. Если завтра у членства появится колонка
// меток, а контракт продолжит читать глобальную, платформа окажется в состоянии
// «две метки об одном человеке, и верна одна» — ровно тот класс, ради которого
// заведена эта проба. Она обязана краснеть на ПОЯВЛЕНИИ пер-аккаунтного
// носителя, чтобы перенос (исход 1) шёл ВМЕСТЕ с контрактом, а не половиной.
//
// Настоящий Postgres. Пропускается под кратким режимом.

package pg_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// TestIntegration_APersonHasExactlyOneLabelCarrier — норма #1126.
func TestIntegration_APersonHasExactlyOneLabelCarrier(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	// ── ПЕРЕПИСЬ ПО СХЕМЕ ────────────────────────────────────────────────────
	// Носители метки среди таблиц, адресующих человека. Объём осмотренного
	// печатается: «ноль находок» обязано быть отличимо от «ноль прочитанного».
	rows, err := pool.Query(ctx, `
		SELECT table_name
		  FROM information_schema.columns
		 WHERE table_schema = 'kaname'
		   AND column_name  = 'labels'
		   AND table_name IN ('users', 'memberships')
		 ORDER BY table_name`)
	require.NoError(t, err)
	var carriers []string
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		carriers = append(carriers, name)
	}
	rows.Close()
	require.NoError(t, rows.Err())

	var total int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*)::int FROM information_schema.columns
		  WHERE table_schema = 'kaname' AND table_name IN ('users','memberships')`).Scan(&total))
	require.Positive(t, total,
		"ПРЕДПОСЫЛКА: ни одной колонки у `users`/`memberships` не прочитано — перепись "+
			"беспредметна, и «носитель один» ниже означало бы «мы не смотрели»")

	require.Equalf(t, []string{"users"}, carriers,
		"носителей метки человека стало %v, а норма #1126 — РОВНО ОДИН, и он не пер-аккаунтный.\n"+
			"Метка человека объявлена ПЛАТФОРМЕННОЙ величиной: одна строка `iam_user` на все его "+
			"аккаунты, правит её только надзор облака (`record_writer`, #1102), и «метка моего "+
			"аккаунта» — величина, которой негде лежать.\n"+
			"Появление пер-аккаунтного носителя (`memberships.labels`) — это исход 1 задачи "+
			"#1126, и он законен: но идти он обязан ВМЕСТЕ с контрактом (какое чтение какую "+
			"метку отдаёт) и вместе с ресурсом членства (#1085). Половина переноса — колонка "+
			"есть, контракт читает старое место — оставляет две метки об одном человеке, из "+
			"которых верна одна.", carriers)

	// ── ЧЕЛОВЕК В ДВУХ АККАУНТАХ: метка у него ОДНА ──────────────────────────
	repo := kanamepg.New(pool, nil)
	ownerA, accA := bootstrapAdmin(t, ctx, repo, "lbl1")
	_, accB := bootstrapAdmin(t, ctx, repo, "lbl2")

	person := domain.UserID(ids.NewID(domain.PrefixUser))
	{
		w, werr := repo.Writer(ctx)
		require.NoError(t, werr)
		_, _, err = w.UsersW().InsertPending(ctx, domain.User{
			ID: person, AccountID: accA,
			Email: "two-accounts-lbl@example.com", DisplayName: "Two", InvitedBy: ownerA,
		})
		require.NoError(t, err)
		require.NoError(t, w.Commit(ctx))
	}
	{
		w, werr := repo.Writer(ctx)
		require.NoError(t, werr)
		_, _, err = w.UsersW().InsertPending(ctx, domain.User{
			ID: domain.UserID(ids.NewID(domain.PrefixUser)), AccountID: accB,
			Email: "two-accounts-lbl@example.com", DisplayName: "Two", InvitedBy: ownerA,
		})
		require.NoError(t, err)
		require.NoError(t, w.Commit(ctx))
	}
	require.Len(t, membershipsOf(t, ctx, pool, person), 2,
		"ПРЕДПОСЫЛКА: человек обязан состоять в ДВУХ аккаунтах, иначе «метка одна на оба» "+
			"утверждается о фигуре, которой нет")

	{
		w, werr := repo.Writer(ctx)
		require.NoError(t, werr)
		_, err = w.UsersW().UpdateLabels(ctx, person, domain.Labels{"team": "core"})
		require.NoError(t, err)
		require.NoError(t, w.Commit(ctx))
	}

	// Строк с меткой этого человека — ровно одна, и она общая для обоих
	// аккаунтов. Это и есть «величина платформенная»: разной по аккаунтам она
	// быть не может, потому что второго места для неё не существует.
	var withLabel int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*)::int FROM kaname.users WHERE id = $1 AND labels ? 'team'`,
		string(person)).Scan(&withLabel))
	require.Equal(t, 1, withLabel,
		"метка не легла на строку личности — тогда перепись носителей выше ничего не измеряла")

	t.Logf("перепись: колонок у users+memberships прочитано %d · носителей метки человека %v · "+
		"членств у испытуемого 2 · строк с меткой 1", total, carriers)
}
