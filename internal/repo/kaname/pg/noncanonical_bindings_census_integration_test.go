// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// noncanonical_bindings_census_integration_test.go — IAM-ID-1-36 (задача
// kacho#472): неканонические привязки переписаны поимённо.
//
// # Предмет
//
// Выдача резолвит субъекта в КАНОНИЧЕСКУЮ строку личности — старейшую ACTIVE по
// почте. Пока одна почта могла принадлежать нескольким строкам, в базе МОГЛИ
// лежать привязки, выданные не на каноническую строку: ровно те права, которые
// потерялись бы молча при схлопывании строк. Перепись П3 из §3 приёмки отвечает,
// сколько их.
//
// # Что изменилось и почему проба переписана, а не снята
//
// Миграция `20260823050000_users_identity_uniqueness_goes_global` объявила
// `users_identity_email_uniq` — глобальный ключ по `lower(email)`. С ним второй
// строки на одну почту не бывает ни при каком вводе, а значит и предмет переписи
// стал НЕКОНСТРУИРУЕМ ЧЕРЕЗ ПРОДУКТ: субъект привязки — единственная строка своей
// почты, поэтому канонической она и является.
//
// Прежняя редакция сеяла «теневую» строку той же почты в другом аккаунте, и на
// сегодняшнем дереве её посев отказывает 23505 — то есть проба падала на
// фикстуре, ни разу не дойдя до своего утверждения.
//
// Отсюда три части, и ни одна не заменяет остальные:
//
//  1. перепись на здоровом дереве объявляет «находок ноль» и НЕ падает: пустая
//     перепись есть ЦЕЛЬ, а не поломка (`testing.md` §«Гейт на класс» п. 5,
//     IAM-ID-1-36 дословно). Она же печатает объём осмотренного — «ноль находок»
//     обязано быть отличимо от «ноль прочитанного»;
//  2. НОВОЕ свойство: состояние, которое перепись считала, теперь отвергается
//     ключом. Утверждается отказ — с положительным контролем, потому что
//     «отвергнуто» истинно и у писателя, отвергающего всё подряд;
//  3. перепись ОБЯЗАНА НАХОДИТЬ. Доказать это через продукт больше нельзя, и
//     молчаливое «ноль» тогда неотличимо от сломанного предиката — то есть проба
//     превратилась бы в форму без содержания. Поэтому ключ снимается ВНУТРИ
//     транзакции, туда же кладётся теневая строка с привязкой, перепись
//     исполняется на ТОЙ ЖЕ транзакции и обязана назвать находку поимённо, после
//     чего транзакция откатывается. DDL в Postgres транзакционен, поэтому ни
//     ключ, ни строка за пределы пробы не выходят — и это проверяется повторной
//     переписью после отката.
//
// Часть 3 заодно отвечает на вопрос, который иначе остался бы догадкой: ноль в
// части 1 держится КЛЮЧОМ, а не тем, что предикат перестал работать.

package pg_test

import (
	"context"
	stderrors "errors"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// censusQuerier — общий знаменатель пула и транзакции.
//
// Перепись обязана исполняться на ОБОИХ: на пуле — чтобы судить о дереве, и на
// транзакции — чтобы её способность находить доказывалась состоянием, которого
// на дереве не бывает (часть 3 в шапке). Разные предикаты для этих двух случаев
// завели бы второй кодек, который разошёлся бы с первым молча.
type censusQuerier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// nonCanonicalBindingCensus — П3: привязки рода «пользователь», чей субъект НЕ
// есть каноническая (старейшая ACTIVE по своей почте) строка личности.
//
// Возвращает найденные идентификаторы привязок и число ОСМОТРЕННЫХ привязок:
// «ноль находок» обязано быть отличимо от «ноль прочитанного».
func nonCanonicalBindingCensus(t *testing.T, ctx context.Context, q censusQuerier) (found []string, examined int) {
	t.Helper()
	require.NoError(t, q.QueryRow(ctx, `
		SELECT count(*) FROM kaname.access_bindings
		 WHERE subject_type = 'user'`).Scan(&examined))

	rows, err := q.Query(ctx, `
		SELECT b.id
		  FROM kaname.access_bindings b
		  JOIN kaname.users subj ON subj.id = b.subject_id
		 WHERE b.subject_type = 'user'
		   AND b.subject_id <> (
			   SELECT canon.id
				 FROM kaname.users canon
				WHERE lower(canon.email) = lower(subj.email)
				  AND canon.invite_status = 'ACTIVE'
				ORDER BY canon.created_at, canon.id
				LIMIT 1)
		 ORDER BY b.id`)
	require.NoError(t, err)
	defer rows.Close()
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		found = append(found, id)
	}
	require.NoError(t, rows.Err())
	return found, examined
}

func TestIntegration_NonCanonicalBindingCensus(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	repo := kanamepg.New(pool, nil)

	canonUser, canonAcc := bootstrapAdmin(t, ctx, repo, "nc1")
	// Второй аккаунт со своим владельцем: он понадобится и отказу ключа
	// (часть 2), и теневой строке под снятым ключом (часть 3).
	_, otherAcc := bootstrapAdmin(t, ctx, repo, "nc2")
	role := anyRoleID(t, ctx, pool)

	var canonEmail string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT email FROM kaname.users WHERE id = $1`, string(canonUser)).Scan(&canonEmail))

	// Законная выдача на каноническую строку: без неё перепись осматривала бы
	// пустую таблицу, и «ноль находок» ничего не сообщало бы.
	legitBinding := grantAccountScoped(t, ctx, pool, canonUser, canonAcc, role)

	// ── часть 1 · перепись на здоровом дереве: находок ноль, и это НЕ отказ ──
	found, examined := nonCanonicalBindingCensus(t, ctx, pool)
	t.Logf("перепись П3: осмотрено привязок рода «пользователь» %d, неканонических %d",
		examined, len(found))
	require.Empty(t, found,
		"на здоровом дереве неканонических привязок нет — и проба это ОБЪЯВЛЯЕТ, а не падает: "+
			"пустая перепись есть цель, а не поломка")
	require.Positive(t, examined,
		"перепись обязана что-то ПРОЧИТАТЬ: на пустой таблице ноль находок не значит ничего")

	// ── часть 2 · состояние, которое перепись считала, отвергается ключом ────
	//
	// Вторая строка на ту же почту — ровно тот вход, из которого рождалась
	// неканоническая выдача. Пишется писателем первого появления
	// (`InsertActive`): он почту не арбитрирует, поэтому упирается в САМ ключ, а
	// не в собственную ветку разрешения конфликта.
	{
		w, werr := repo.Writer(ctx)
		require.NoError(t, werr)
		_, err = w.UsersW().InsertActive(ctx, domain.User{
			ID:           domain.UserID(ids.NewID(domain.PrefixUser)),
			AccountID:    otherAcc,
			ExternalID:   domain.ExternalSubject("ext-nc1-shadow"),
			Email:        domain.Email(canonEmail), // ТА ЖЕ почта, другой аккаунт
			DisplayName:  "Shadow",
			InviteStatus: domain.InviteStatusActive,
		})
		_ = w.Rollback(ctx)
		require.Error(t, err,
			"вторая строка на ту же почту обязана быть отвергнута ключом users_identity_email_uniq")
		require.True(t, stderrors.Is(err, iamerr.ErrAlreadyExists),
			"отказ ключа обязан приезжать сентинелом ErrAlreadyExists, получено %v", err)
	}
	{
		// Положительный контроль к отказу: тот же писатель на СВОБОДНОЙ почте в
		// том же аккаунте обязан пройти. Без него отказ выше доказывал бы лишь
		// то, что путь сломан целиком.
		w, werr := repo.Writer(ctx)
		require.NoError(t, werr)
		_, err = w.UsersW().InsertActive(ctx, domain.User{
			ID:           domain.UserID(ids.NewID(domain.PrefixUser)),
			AccountID:    otherAcc,
			ExternalID:   domain.ExternalSubject("ext-nc1-free"),
			Email:        domain.Email("free-nc1@example.com"),
			DisplayName:  "Free",
			InviteStatus: domain.InviteStatusActive,
		})
		require.NoError(t, err,
			"свободная почта обязана завести строку — иначе отказ выше про ключ не говорит ничего")
		require.NoError(t, w.Commit(ctx))
	}

	// ── часть 3 · перепись ОБЯЗАНА НАХОДИТЬ ─────────────────────────────────
	//
	// Состояние собирается под снятым ключом внутри транзакции и откатывается.
	// Иначе способность предиката находить осталась бы недоказанной, а «ноль» из
	// части 1 — неотличимым от сломанного запроса.
	shadowBinding := ids.NewID("acb")
	{
		tx, txerr := pool.Begin(ctx)
		require.NoError(t, txerr)
		defer func() { _ = tx.Rollback(ctx) }()

		_, err = tx.Exec(ctx, `DROP INDEX kaname.users_identity_email_uniq`)
		require.NoError(t, err,
			"ПРЕДПОСЫЛКА части 3: ключ обязан существовать — иначе снимать нечего, "+
				"и часть 2 утверждала бы про отказ, которого не бывает")

		shadowUser := domain.UserID(ids.NewID(domain.PrefixUser))
		_, err = tx.Exec(ctx, `
			INSERT INTO kaname.users
			    (id, account_id, external_id, email, display_name, invite_status, created_at)
			VALUES ($1, $2, 'ext-nc1-shadow', $3, 'Shadow', 'ACTIVE', now() + interval '1 second')`,
			string(shadowUser), string(otherAcc), canonEmail)
		require.NoError(t, err, "теневая строка под снятым ключом обязана лечь")

		// Предпосылка контроля: канонической осталась ПЕРВАЯ строка, а не
		// теневая, — иначе перепись назвала бы находкой законную выдачу.
		var canonical string
		require.NoError(t, tx.QueryRow(ctx, `
			SELECT id FROM kaname.users
			 WHERE lower(email) = lower($1) AND invite_status = 'ACTIVE'
			 ORDER BY created_at, id LIMIT 1`, canonEmail).Scan(&canonical))
		require.Equal(t, string(canonUser), canonical,
			"ПРЕДПОСЫЛКА: канонической обязана быть старейшая строка — иначе контроль ниже "+
				"проверяет не то, что называет")

		_, err = tx.Exec(ctx, `
			INSERT INTO kaname.access_bindings
			    (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			VALUES ($1, 'user', $2, $3, 'account', $4, 'ACTIVE')`,
			shadowBinding, string(shadowUser), role, string(otherAcc))
		require.NoError(t, err)
		_, err = tx.Exec(ctx, `
			INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id, ordinal)
			VALUES ($1, 'user', $2, 0)`, shadowBinding, string(shadowUser))
		require.NoError(t, err)

		foundTx, examinedTx := nonCanonicalBindingCensus(t, ctx, tx)
		t.Logf("перепись П3 под снятым ключом: осмотрено %d, неканонических %d — %v",
			examinedTx, len(foundTx), foundTx)
		require.Equal(t, []string{shadowBinding}, foundTx,
			"перепись обязана НАЗВАТЬ неканоническую привязку поимённо — и только её: "+
				"молчание здесь означало бы, что ноль из части 1 ничего не доказывал, "+
				"а лишний идентификатор — что она считает законные выдачи находками")

		require.NoError(t, tx.Rollback(ctx))
	}

	// ── откат состоялся: ни ключа, ни строки проба за собой не оставила ──────
	found, examined = nonCanonicalBindingCensus(t, ctx, pool)
	t.Logf("перепись П3 после отката: осмотрено %d, неканонических %d", examined, len(found))
	require.Empty(t, found, "теневое состояние обязано было уйти вместе с транзакцией")
	require.Contains(t, bindingIDs(t, ctx, pool), legitBinding,
		"законная выдача на каноническую строку переписью не тронута и из базы не исчезла")
	require.NotContains(t, bindingIDs(t, ctx, pool), shadowBinding,
		"теневая выдача за пределы транзакции не вышла")

	var shadowRows int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.users WHERE lower(email) = lower($1)`,
		canonEmail).Scan(&shadowRows))
	require.Equal(t, 1, shadowRows, "строка с этой почтой обязана остаться одна")
}

// bindingIDs — все привязки дерева поимённо.
func bindingIDs(t *testing.T, ctx context.Context, q censusQuerier) []string {
	t.Helper()
	rows, err := q.Query(ctx, `SELECT id FROM kaname.access_bindings ORDER BY id`)
	require.NoError(t, err)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		require.NoError(t, rows.Scan(&id))
		out = append(out, id)
	}
	require.NoError(t, rows.Err())
	return out
}
