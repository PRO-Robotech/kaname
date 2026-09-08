// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// identity_growth_integration_test.go — накопительный журнал ЛИЧНОСТЕЙ.
//
// # Предмет
//
// Потолок на число аккаунтов у личности (484002) обходится заведением личностей:
// регистрация самообслуживаемая и стоит подтверждённого адреса. Второй уровень —
// потолок темпа — удорожает автоматизацию, но не ловит МЕДЛЕННОЕ накопление.
// Третий уровень — увидеть рост, и это страховка, а не мера: отказ по такому
// порогу пришёл бы следующему честному человеку, поэтому сначала ВИДНО.
//
// # Почему журнал, а не счёт по строкам пользователей
//
// `count(DISTINCT external_id)` мгновенен и НЕ МОНОТОНЕН: строку пользователя
// удаляют, и величина падает. Тогда «личностей ноль» перестаёт быть утверждением
// о всей жизни платформы и становится утверждением о текущем мгновении — а
// вопрос задан именно про всю жизнь. Плюс на немонотонной величине не определён
// рост: `increase()` над падающим рядом молчит там, где рост и был.
//
// Журнал накопителен by construction: строка заводится при ПЕРВОМ появлении
// личности и не снимается никогда, в том числе при уходе человека. «Ноль за всё
// время» становится проверяемым утверждением.
//
// # Что здесь считается появлением личности
//
// Личность — внешний идентификатор входа, а не строка пользователя: строка есть
// ЧЛЕНСТВО в одном аккаунте. Держать по строке на каждый свой аккаунт человек
// будет — сцепку снимает отдельная работа; СЕГОДНЯ схема этого не допускает
// (`users_active_external_id_uniq`, 0011, сторож 0069), и ключ журнала выбран под
// то состояние, которое наступит, а не под то, которое действует: менять ключ
// вместе со снятием сцепки значило бы переписывать накопленное. Приглашённый, ещё не вошедший, личности НЕ несёт — схема этого
// прямо требует (`users_invite_status_consistency`), — и становится ею в момент
// активации, то есть на ПРАВКЕ строки, а не только на вставке. Журнал, слушающий
// одну вставку, потерял бы каждого приглашённого.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iampg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// newIdentityGrowthDB — своя база и пул на пробу.
func newIdentityGrowthDB(t *testing.T) (*pgxpool.Pool, context.Context) {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	return pool, ctx
}

// seedIdentityHomeAccount заводит аккаунт и его владельца — то, без чего в
// сегодняшней схеме не существует ни одной строки пользователя.
//
// Одной транзакцией: ссылки между аккаунтом и владельцем ВЗАИМНЫ, и сойтись они
// могут только на фиксации.
func seedIdentityHomeAccount(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix string) string {
	t.Helper()
	userID := ids.NewID(domain.PrefixUser)
	accountID := ids.NewID(domain.PrefixAccount)

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()

	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, 'Identity Growth Owner', 'ACTIVE')`,
		userID, accountID, "ext-growth-owner-"+suffix, "growth-owner-"+suffix+"@example.com")
	require.NoError(t, err, "seed owner")

	_, err = tx.Exec(ctx, `
		INSERT INTO accounts (id, name, owner_user_id, labels)
		VALUES ($1, $2, $3, '{}'::jsonb)`,
		accountID, "growth-acc-"+suffix, userID)
	require.NoError(t, err, "seed account")

	require.NoError(t, tx.Commit(ctx), "commit identity growth home account")
	return accountID
}

// seedIdentityMember заводит строку пользователя в УЖЕ существующем аккаунте,
// которым эта личность не владеет.
//
// Именно такую строку продукт умеет снимать: его `User.Delete` снимает строку
// пользователя, оставляя аккаунт жить. Строку владельца снять нельзя ни в каком
// порядке — обе ссылки объявлены `ON DELETE RESTRICT`, а RESTRICT не откладывается
// НИКОГДА, в отличие от NO ACTION. Поэтому «человек ушёл» моделируется уходом
// члена, а не владельца: так это и происходит в продукте.
//
// Пустой `external` означает приглашение, ещё не ставшее личностью.
func seedIdentityMember(t *testing.T, ctx context.Context, pool *pgxpool.Pool, accountID, external, email string) string {
	t.Helper()
	userID := ids.NewID(domain.PrefixUser)

	status := "ACTIVE"
	if external == "" {
		status = "PENDING"
	}
	_, err := pool.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, 'Identity Growth Member', $5)`,
		userID, accountID, external, email, status)
	require.NoError(t, err, "seed member")
	return userID
}

// removeIdentityMember снимает строку члена — тем же оператором, каким это делает
// продукт.
func removeIdentityMember(t *testing.T, ctx context.Context, pool *pgxpool.Pool, userID string) {
	t.Helper()
	_, err := pool.Exec(ctx, `DELETE FROM kaname.users WHERE id = $1`, userID)
	require.NoError(t, err, "снятие строки члена")
}

// journalCount — сколько личностей журнал видел за всё время.
func journalCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int64 {
	t.Helper()
	var n int64
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.identity_journal`).Scan(&n))
	return n
}

// TestIdentityGrowth_LedgerNotesOneIdentityOnceAcrossItsAppearances — личность
// считается ОДИН раз, сколько бы раз она ни появлялась.
//
// # Почему проба выглядит так, а не «одна личность — два членства»
//
// Первая редакция подавала два членства одной личности и падала на схеме:
// `users_active_external_id_uniq` (0011, сторож 0069) держит РОВНО ОДНУ активную
// строку на внешний идентификатор. Много членств у одной личности — состояние
// будущее, его снимает отдельная работа; сегодня оно невыразимо, и проба,
// требующая его, проверяла бы не журнал, а собственную посылку.
//
// Повторное появление той же личности представимо и сегодня: человек ушёл из
// аккаунта и вернулся. Для журнала это тот же вопрос — прибавит ли он платформе
// второго человека, — и отвечает на него та же идемпотентность.
//
// Положительный контроль стоит здесь же: вторая, ДРУГАЯ личность обязана
// прибавить единицу. Без него проба зеленела бы на журнале, не пишущем ничего.
func TestIdentityGrowth_LedgerNotesOneIdentityOnceAcrossItsAppearances(t *testing.T) {
	pool, ctx := newIdentityGrowthDB(t)
	accountID := seedIdentityHomeAccount(t, ctx, pool, "appearances")

	before := journalCount(t, ctx, pool)

	const alice = "ext-growth-alice"
	userID := seedIdentityMember(t, ctx, pool, accountID, alice, "growth-alice-1@example.com")
	require.Equal(t, before+1, journalCount(t, ctx, pool),
		"первое появление личности не записано: журнал не пишет вовсе")

	removeIdentityMember(t, ctx, pool, userID)
	seedIdentityMember(t, ctx, pool, accountID, alice, "growth-alice-2@example.com")

	require.Equal(t, before+1, journalCount(t, ctx, pool),
		"возвращение той же личности прибавило платформе второго человека: журнал "+
			"считает ПОЯВЛЕНИЯ, а не личности, и всякая величина роста над ним завышена "+
			"ровно на число возвращений")

	seedIdentityMember(t, ctx, pool, accountID, "ext-growth-bob", "growth-bob@example.com")
	require.Equal(t, before+2, journalCount(t, ctx, pool),
		"другая личность не прибавила ряда: журнал перестал писать, и предыдущее "+
			"утверждение прошло бы на любом сломанном механизме")
}

// TestIdentityGrowth_LedgerOutlivesTheIdentityItNoted — журнал накопителен: уход
// человека не отнимает у платформы того, что он однажды появился.
//
// Без этого свойства «личностей за всё время» превращается в «личностей сейчас»,
// и медленное накопление, ради которого журнал заведён, читается как ноль —
// достаточно заводить и снимать.
func TestIdentityGrowth_LedgerOutlivesTheIdentityItNoted(t *testing.T) {
	pool, ctx := newIdentityGrowthDB(t)
	accountID := seedIdentityHomeAccount(t, ctx, pool, "leaver")

	userID := seedIdentityMember(t, ctx, pool, accountID, "ext-growth-leaver", "growth-leaver@example.com")
	after := journalCount(t, ctx, pool)

	removeIdentityMember(t, ctx, pool, userID)

	require.Equal(t, after, journalCount(t, ctx, pool),
		"ряд журнала снят вместе со строкой пользователя: величина стала мгновенной, "+
			"и «ноль за всё время» больше не отличимо от «завели и убрали»")
}

// TestIdentityGrowth_InvitationBecomesAnIdentityOnlyOnActivation — приглашение
// личностью не является, а активация ею делает.
//
// Пара, а не одно утверждение: отрицание («приглашение не считается») зеленеет на
// журнале, не пишущем НИЧЕГО, и только положительная половина отличает верный
// механизм от мёртвого.
func TestIdentityGrowth_InvitationBecomesAnIdentityOnlyOnActivation(t *testing.T) {
	pool, ctx := newIdentityGrowthDB(t)
	accountID := seedIdentityHomeAccount(t, ctx, pool, "invited")

	before := journalCount(t, ctx, pool)

	userID := seedIdentityMember(t, ctx, pool, accountID, "", "growth-invited@example.com")
	require.Equal(t, before, journalCount(t, ctx, pool),
		"приглашение сосчитано личностью: считается строка пользователя, а не вход")

	_, err := pool.Exec(ctx, `
		UPDATE kaname.users SET external_id = $2, invite_status = 'ACTIVE' WHERE id = $1`,
		userID, "ext-growth-invited")
	require.NoError(t, err, "активация приглашения")

	require.Equal(t, before+1, journalCount(t, ctx, pool),
		"активация приглашения не завела личности: журнал слушает только вставку, "+
			"и каждый приглашённый проходит мимо него")
}

// TestIdentityGrowth_RepoCountsWhatTheLedgerHolds — читатель величины отдаёт то
// же число, что и журнал.
//
// Отдельная проба потому, что читателя и журнал легко развести молча: запрос,
// считающий строки пользователей вместо рядов журнала, вернёт правдоподобное
// число и восстановит ровно ту немонотонность, ради ухода от которой журнал
// заведён.
func TestIdentityGrowth_RepoCountsWhatTheLedgerHolds(t *testing.T) {
	pool, ctx := newIdentityGrowthDB(t)
	accountID := seedIdentityHomeAccount(t, ctx, pool, "reader")

	repo := iampg.NewIdentityGrowthRepo(pool)

	seedIdentityMember(t, ctx, pool, accountID, "ext-growth-reader-a", "growth-reader-a@example.com")
	seedIdentityMember(t, ctx, pool, accountID, "ext-growth-reader-b", "growth-reader-b@example.com")
	seedIdentityMember(t, ctx, pool, accountID, "ext-growth-reader-c", "growth-reader-c@example.com")

	got, err := repo.IdentitiesEverSeen(ctx)
	require.NoError(t, err)
	require.Equal(t, journalCount(t, ctx, pool), got,
		"читатель и журнал разошлись: величина на витрине перестала быть тем, "+
			"что она называет")
}
