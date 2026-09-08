// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed_test

// bootstrap_admin_row_choice_integration_test.go — какую строку посев
// администратора выбирает по адресу почты и когда не выбирает никакой.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ВЕРНО СЕЙЧАС
//
// Адрес почты называет РОВНО ОДНУ строку `users`, и держит это ключ БД, а не
// договорённость: `users_identity_email_uniq` (миграция
// 20260823050000_users_identity_uniqueness_goes_global) объявлен на
// `lower(email)` и предиката не имеет — почта непуста по `users_email_check`,
// значит строки, которую следовало бы исключить из ключа, не бывает.
//
// Принадлежность человека аккаунтам выражается строками `kaname.memberships`,
// которых у него может быть сколько угодно. Второй аккаунт больше НЕ ЗАВОДИТ
// второй строки — он заводит второе членство.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ СТОЯЛО И ПОЧЕМУ СНЯТО
//
// Прежняя редакция этой шапки объявляла обратное — «один человек = N строк с
// одним адресом (по одной на аккаунт): глобальная уникальность почты снята
// намеренно (миграция 0011)», — и на этой посылке держались две пробы:
//
//   - TestRunBootstrapAdmin_PicksOldestActiveRow_NotArbitrary — три ACTIVE-строки
//     одного адреса, права обязаны достаться старейшей, а не той, что легла
//     первой физически;
//   - TestRunBootstrapAdmin_PrefersActiveOverOlderBlocked — BLOCKED-строка старше
//     ACTIVE-строки того же адреса, возраст не отменяет состояния.
//
// Посылка стала ложной, а оба сценария — НЕКОНСТРУИРУЕМЫМИ: их предпосылку
// отвергает ключ, и падал сам посев фикстуры (23505 на
// `users_identity_email_uniq`), а не утверждение. Проба, падающая на посеве,
// о продукте не утверждает ничего.
//
// ЭТО РЕШЕНИЕ, А НЕ ПОТЕРЯ ПОКРЫТИЯ, и вот его основание. Упорядочивание
// `ORDER BY created_at ASC, id ASC` в запросе посева ОСТАЁТСЯ и отсюда снятия не
// требует: оно защищает данные, заведённые до ключа. Но на мигрированной базе
// оно ненаблюдаемо by construction — предусловие той же миграции отказывается
// идти, пока в `users` есть хоть одна почта с двумя строками, поэтому состояния,
// которое упорядочивание разрешает, в такой базе не существует. Утверждать
// разрешение спора, которого не бывает, значит утверждать несуществующее.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СТОИТ ВМЕСТО СНЯТОГО
//
// TestRunBootstrapAdmin_OneRowPerPerson_SecondAccountIsAMembership — проба самой
// посылки на том месте, где на неё сослались: вторая строка с тем же адресом
// отвергается ИМЕНОВАННЫМ ключом, второй аккаунт выражается членством, а посев
// выдаёт права той единственной строке, которую называет адрес, — и одну, сколько
// бы членств у человека ни было.
//
// Она заведена ради того, чтобы это послабление ИСТЕКАЛО САМО: снимут ключ —
// покраснеет здесь же и скажет, что снятые выше сценарии снова конструируемы, а
// значит и пробы на них надо вернуть. Владелец утверждения о самом ключе — не
// этот файл, а `services/iam/internal/migrations/identity_global_uniqueness_integration_test.go`
// (IAM-ID-1-06); здесь ключ спрашивается как предпосылка ЭТОГО файла, поэтому обе
// пробы краснеют вместе, а не расходятся молча.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ОСТАЛОСЬ ПРЕДМЕТОМ ФАЙЛА
//
// Решает СОСТОЯНИЕ строки, а не её существование: права уровня кластера не
// сеются ни на заблокированную личность, ни на неподтверждённое приглашение.
// Оба случая конструируемы одной строкой на адрес и оба осмысленны — это и есть
// то, что обязано покраснеть при снятии проверки состояния.
//
// Оба отрицания стоят В ОДНОЙ таблице с положительным контролем на ТОЙ ЖЕ
// фикстуре, и это не оформление: «прав не выдано» истинно и у посева, который не
// выдаёт их никогда, и у фикстуры, чью строку посев вообще не видит. Контроль,
// лежащий в соседнем файле на другой фикстуре, такого промаха не ловит.

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// seedUserRow вставляет ОДНУ строку человека вместе с аккаунтом, который его
// завёл, и возвращает оба идентификатора.
//
// Момента создания больше не принимает: он был здесь ради спора двух строк
// одного адреса, а такого спора на мигрированной базе не бывает (см. шапку).
// Параметр, который ни на что не влияет, читается как влияющий — поэтому снят,
// а не оставлен «на всякий случай».
//
// Аккаунт заводится в той же транзакции: ключи `users_account_fk` и
// `accounts_owner_fk` отложены (цикл «строка ↔ её аккаунт» законен), поэтому
// порядок вставок внутри транзакции значения не имеет.
func seedUserRow(
	t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	email, inviteStatus string,
) (userID, accountID string) {
	t.Helper()
	uid := ids.NewID(domain.PrefixUser)
	accID := ids.NewID(domain.PrefixAccount)

	// DB-CHECK users_invite_status_consistency: PENDING ⇔ external_id='',
	// ACTIVE/BLOCKED ⇔ external_id<>''.
	externalID := "ext-" + uid
	if inviteStatus == "PENDING" {
		externalID = ""
	}

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		uid, accID, externalID, email, "Bootstrap Admin", inviteStatus)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		accID, accountName(accID), uid)
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))
	return uid, accID
}

// seedAccount заводит ЕЩЁ ОДИН аккаунт, куда того же человека можно ввести
// членством. Владельцем ставится он сам — здесь важно лишь то, что аккаунт
// существует и на него можно сослаться.
func seedAccount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, ownerUserID string) string {
	t.Helper()
	accID := ids.NewID(domain.PrefixAccount)
	_, err := pool.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		accID, accountName(accID), ownerUserID)
	require.NoError(t, err)
	return accID
}

// accountName — имя аккаунта, годное по `accounts_name_check`
// (единственная форма имени дерева) и уникальное по `accounts_name_unique`: хвост
// идентификатора крокфордов, то есть уже в нужном алфавите.
func accountName(accountID string) string {
	return "boot-acc-" + strings.ToLower(accountID[len(accountID)-6:])
}

// TestRunBootstrapAdmin_OneRowPerPerson_SecondAccountIsAMembership — адрес почты
// называет одну строку, второй аккаунт выражается членством, и права уровня
// кластера получает эта одна строка — ровно одни, сколько бы членств ни было.
//
// Проба несёт три утверждения подряд намеренно: первое доказывает, что сценарий
// снятых проб неконструируем (иначе снятие держалось бы только шапкой), второе —
// что взамен него в модели есть исполнимая форма «человек в двух аккаунтах»,
// третье — что посев на этой форме ведёт себя правильно. Порознь первые два
// утверждали бы про схему, а не про посев.
func TestRunBootstrapAdmin_OneRowPerPerson_SecondAccountIsAMembership(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupBootstrapDB(t))
	require.NoError(t, err)
	defer pool.Close()

	const email = "multi@prorobotech.ru"
	uid, _ := seedUserRow(t, ctx, pool, email, "ACTIVE")
	second := seedAccount(t, ctx, pool, uid)

	// (1) Вторая СТРОКА с тем же адресом — пусть и в другом аккаунте — отвергается.
	other := ids.NewID(domain.PrefixUser)
	_, err = pool.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, 'Bootstrap Admin', 'ACTIVE')`,
		other, second, "ext-"+other, email)
	require.Error(t, err,
		"вторая строка с тем же адресом обязана быть отвергнута: пока она возможна, "+
			"выбор строки по адресу снова становится спором, и снятые пробы этого файла надо вернуть")
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr)
	require.Equal(t, "23505", pgErr.Code)
	// Имя ключа утверждается, а не только факт отказа: «вставка отвергнута»
	// истинно и когда сработало постороннее ограничение (внешний субъект, форма
	// адреса), — тогда проба зеленела бы при снятом ключе идентичности.
	require.Equal(t, "users_identity_email_uniq", pgErr.ConstraintName,
		"отказ обязан прийти от ключа идентичности, а не от постороннего ограничения")

	// (2) Второй аккаунт того же человека — ЧЛЕНСТВО. Первое членство завёл
	// триггер зеркала на вставке строки (миграция 470001), второе заводится здесь.
	_, err = pool.Exec(ctx, `
		INSERT INTO memberships (id, user_id, account_id, state)
		VALUES (kaname.membership_mirror_id($1, $2), $1, $2, 'ACTIVE')`, uid, second)
	require.NoError(t, err, "принадлежность второму аккаунту обязана быть выразима членством")

	var rows, members int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM users WHERE lower(email) = lower($1)`, email).Scan(&rows))
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM memberships WHERE user_id = $1`, uid).Scan(&members))
	assert.Equal(t, 1, rows, "адрес называет ровно одну строку")
	assert.Equal(t, 2, members, "человек состоит в двух аккаунтах, оставаясь одной строкой")

	// (3) Посев выдаёт права этой строке.
	res, err := seed.RunBootstrapAdmin(ctx, pool, slog.Default(), seed.BootstrapAdminInput{Email: email})
	require.NoError(t, err)
	require.False(t, res.Skipped)
	assert.Equal(t, uid, res.UserID, "права получает строка, которую называет адрес")

	var grants int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM cluster_admin_grants WHERE subject_id = $1`, uid).Scan(&grants))
	assert.Equal(t, 1, grants)
	// И ни одной выдачи на кого-либо ещё: число членств не умножает выдачу.
	// Посев пишет только subject_type='user', поэтому утверждение остаётся точным
	// независимо от того, какие служебные принципалы посеяны миграциями.
	var userGrants int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM cluster_admin_grants WHERE subject_type = 'user'`).Scan(&userGrants))
	assert.Equal(t, 1, userGrants, "выдача одна на человека, а не одна на членство")
}

// TestRunBootstrapAdmin_StateOfTheRowDecides — состояние строки решает, а не её
// существование.
//
// Три случая в ОДНОЙ таблице, и положительный среди них стоит не для полноты:
// «прав не выдано» истинно и у посева, который не выдаёт их никогда, и у
// фикстуры, чью строку посев не видит вовсе. Снять контроль, не тронув
// отрицаний, здесь нельзя by construction — они в одном перечне.
func TestRunBootstrapAdmin_StateOfTheRowDecides(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}

	cases := []struct {
		name string
		// email свой у каждого случая: адрес глобально уникален, и одинаковый
		// адрес в разных случаях читался бы как «одна личность в трёх состояниях»,
		// чего теперь не бывает.
		email        string
		inviteStatus string
		wantSkipped  bool
		wantReason   seed.BootstrapSkipReason
		wantGrants   int
		wantOutbox   int
	}{
		{
			name:         "active_row_is_granted",
			email:        "active@prorobotech.ru",
			inviteStatus: "ACTIVE",
			wantSkipped:  false,
			wantReason:   "",
			wantGrants:   1,
			wantOutbox:   1,
		},
		{
			// Заблокированная строка СУЩЕСТВУЕТ, поэтому проверка на наличие её
			// пропускала. Права на заблокированную личность не сеются.
			name:         "blocked_row_is_not_granted",
			email:        "blocked@prorobotech.ru",
			inviteStatus: "BLOCKED",
			wantSkipped:  true,
			wantReason:   seed.BootstrapSkipNotActive,
			wantGrants:   0,
			wantOutbox:   0,
		},
		{
			// Приглашение существует так же и внешнего субъекта не несёт вовсе:
			// подтвердит его тот, кто первым войдёт по этому адресу. До входа
			// права уровня кластера ему не сеются.
			name:         "pending_invitation_is_not_granted",
			email:        "invited@prorobotech.ru",
			inviteStatus: "PENDING",
			wantSkipped:  true,
			wantReason:   seed.BootstrapSkipNotActive,
			wantGrants:   0,
			wantOutbox:   0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			pool, err := coredb.NewPool(ctx, setupBootstrapDB(t))
			require.NoError(t, err)
			defer pool.Close()

			uid, _ := seedUserRow(t, ctx, pool, tc.email, tc.inviteStatus)

			res, err := seed.RunBootstrapAdmin(ctx, pool, slog.Default(),
				seed.BootstrapAdminInput{Email: tc.email})
			require.NoError(t, err)
			require.Equal(t, tc.wantSkipped, res.Skipped)
			assert.Equal(t, tc.wantReason, res.SkipReason,
				"причина пропуска обязана отличать «строки нет» от «строка есть, но не действует» — "+
					"иначе оператор ищет опечатку в адресе, которой нет")
			if !tc.wantSkipped {
				assert.Equal(t, uid, res.UserID)
			}

			var grants int
			require.NoError(t, pool.QueryRow(ctx,
				`SELECT count(*) FROM cluster_admin_grants WHERE subject_id = $1`, uid).Scan(&grants))
			assert.Equal(t, tc.wantGrants, grants)

			// Миграции сеют собственные строки очереди, поэтому считаются только
			// те, что называют ЭТУ личность.
			var outbox int
			require.NoError(t, pool.QueryRow(ctx,
				`SELECT count(*) FROM fga_outbox WHERE payload->>'user' = $1`, "user:"+uid).Scan(&outbox))
			assert.Equal(t, tc.wantOutbox, outbox,
				"очередь на выдачу обязана наполняться ровно тогда, когда выдача состоялась")
		})
	}
}

// TestRunBootstrapAdmin_EmailMatchIsCaseInsensitive — уникальность почты в этой
// схеме определена по lower(email); посев обязан спрашивать так же, иначе
// объявленный адрес администратора «не находится» из-за регистра.
func TestRunBootstrapAdmin_EmailMatchIsCaseInsensitive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupBootstrapDB(t))
	require.NoError(t, err)
	defer pool.Close()

	uid, _ := seedUserRow(t, ctx, pool, "Mixed.Case@ProRobotech.RU", "ACTIVE")

	res, err := seed.RunBootstrapAdmin(ctx, pool, slog.Default(),
		seed.BootstrapAdminInput{Email: "mixed.case@prorobotech.ru"})
	require.NoError(t, err)
	require.False(t, res.Skipped)
	assert.Equal(t, uid, res.UserID)
}
