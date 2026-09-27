// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// oauth_ceremony_issuance_overlap_integration_test.go — ВЫДАЧА КОДА ВНАХЛЁСТ с
// удалением человека и со снятием сессии (задача PRO-Robotech/kaname#369; заказы
// схемного ревью kn-313, круг 4).
//
// # Что держит выдачу и чего до этих проб не судило ничто
//
// `IssueAuthorizationCode` берёт три замка сверху вниз по каскаду — человек,
// клиент, сессия — и заводит семейство оператором с условием живости сессии.
// Порядок замков снимает цикл с удалением человека; замок сессии и условие —
// два слоя против снятия сессии, закрывающие РАЗНЫЕ чередования. Держали это
// замеры ревью, которые в дереве не живут, и шапка файла, которая не
// исполняется: верни замки в прежний порядок или убери условие — ни одна проба
// не краснела.
//
// # Контрольная рука — не украшение
//
// Зелёное главной руки на сцене, где дефект НЕ ВОСПРОИЗВОДИТСЯ, неотличимо от
// несозданного условия. Поэтому в каждой сцене рядом идёт контрольная рука —
// форма выдачи без одной из половин, — и она ОБЯЗАНА краснеть. Контрольная
// рука, позеленевшая там, где обязана краснеть, — не вердикт о продукте, а
// «не выполнилось»: сцена условия не создала.
//
// Руки собираются из ТЕХ ЖЕ текстов операторов, что исполняет продукт
// (`export_test.go`), и между собранной полной формой и контрольной рукой ровно
// один факт — снятая половина. Собранная полная форма — законный близнец
// контрольных рук; продукт (`IssueAuthorizationCode`) — главная рука:
// переставленные в нём замки собранную форму не тронут, а главную окрасят.
// Кода собранные руки не заводят: его вставка берёт замок лишь на строке
// семейства, заведённой той же транзакцией, и в порядок с чужими транзакциями
// не входит.
//
// # Сцена строится держателем и утверждается по состоянию движка
//
// Транзакция выдачи длится около миллисекунды, и сцена «по паузе» её не
// застаёт. Поэтому одну из сторон останавливает посторонний ДЕРЖАТЕЛЬ посреди её
// транзакции, а ожидание второй опознаётся по `pg_blocking_pids` — по тому,
// КОГО она ждёт. Не встала — сцена не построена, прогон идёт в «не выполнилось»,
// и вердикта у клетки нет. Держатель отпускается раньше, чем истекает половина
// `deadlock_timeout`: иначе проверка взаимной блокировки успела бы пройти до
// того, как цикл замкнулся, и жертву выбрало бы не расписание сцены, а часы.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// overlapRuns — прогонов на клетку «рука × сцена». Сцены построены держателем,
// поэтому исход клетки детерминирован; прогонов больше одного, чтобы
// детерминированность была наблюдаемой, а не заявленной.
const overlapRuns = 3

// overlapScene — аккаунт с владельцем, второй человек того же аккаунта, его
// сессия и клиент. Снимается ВТОРОЙ человек: владельца не даёт снять
// `accounts_owner_fk` (RESTRICT, отложенный), и снятие отказало бы на фиксации
// раньше, чем случится опыт. Всё уникальное выводится из номера сцены.
func overlapScene(t *testing.T, ctx context.Context, pool *pgxpool.Pool, n int) domain.CeremonyContext {
	t.Helper()
	tag := fmt.Sprintf("kn369%04d", n)
	owner := "usr" + ceremonyPad(tag+"a")
	member := "usr" + ceremonyPad(tag+"b")
	account := "acc" + ceremonyPad(tag)
	session := "hs-" + ceremonyPad(tag)
	client := "client-" + tag

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, 'overlap-owner', 'ACTIVE')`,
		owner, account, "ext-a-"+tag, tag+"a@example.invalid")
	require.NoError(t, err, "посев владельца")
	_, err = tx.Exec(ctx, `INSERT INTO accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`,
		account, "acc-"+tag, owner)
	require.NoError(t, err, "посев аккаунта")
	_, err = tx.Exec(ctx, `
		INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, $3, $4, 'overlap-member', 'ACTIVE')`,
		member, account, "ext-b-"+tag, tag+"b@example.invalid")
	require.NoError(t, err, "посев снимаемого человека")
	require.NoError(t, tx.Commit(ctx))

	_, err = pool.Exec(ctx, `
		INSERT INTO kaname.human_sessions
		       (id, user_id, bearer_digest, authenticated_at, last_presented_at, expires_at,
		        assurance_level, presented_methods)
		VALUES ($1, $2, $3, now(), now(), now() + interval '1 hour', '1', ARRAY['password'])`,
		session, member, ceremonyDigest(0x369000+n))
	require.NoError(t, err, "посев сессии")
	_, err = pool.Exec(ctx, `
		INSERT INTO kaname.interactive_clients (id, name, redirect_uris, client_id, token_endpoint_auth_method)
		VALUES ($1, $2, ARRAY['https://app.example.test/cb'], $3, 'none')`,
		"ic-"+ceremonyPad(tag), "ic-"+tag, client)
	require.NoError(t, err, "посев клиента")

	return domain.CeremonyContext{
		FamilyID:  "tfm-" + ceremonyPad(tag),
		ClientID:  client,
		UserID:    member,
		SessionID: session,
		Scope:     []string{"openid", "profile"},
	}
}

// ── Руки выдачи ─────────────────────────────────────────────────────────────

// ceremonyLock — оператор замка выдачи и чью строку он берёт.
type ceremonyLock struct {
	sql string
	arg func(domain.CeremonyContext) string
}

var (
	lockOfUser    = ceremonyLock{kanamepg.LockUserForKeySQL, func(sc domain.CeremonyContext) string { return sc.UserID }}
	lockOfClient  = ceremonyLock{kanamepg.LockCeremonyClientSQL, func(sc domain.CeremonyContext) string { return sc.ClientID }}
	lockOfSession = ceremonyLock{kanamepg.LockSessionOfCeremonySQL, func(sc domain.CeremonyContext) string { return sc.SessionID }}
)

// liveSessionCondition — условие живости сессии в операторе заведения
// семейства ЦЕЛИКОМ: снятие, срок и отсечка субъекта (kaname#423). Рука
// «только замок» — тот же оператор БЕЗ него.
const liveSessionCondition = "WHERE s.ended_at IS NULL AND s.expires_at > now() AND NOT " +
	kanamepg.SessionCutOffBySubjectSQL

// issuanceArm — одна форма выдачи. `control` — рука без одной из половин
// решения: её исход в сцене объявлен заранее, и позеленевшая там, где обязана
// краснеть, она означает несозданное условие.
type issuanceArm struct {
	name    string
	control bool
	issue   func(ctx context.Context, sc domain.CeremonyContext, n int) error
}

// productArm — главная рука: сам `IssueAuthorizationCode`.
func productArm(repo *kanamepg.OAuthCeremonyRepo) issuanceArm {
	return issuanceArm{name: "продукт", issue: func(ctx context.Context, sc domain.CeremonyContext, n int) error {
		return repo.IssueAuthorizationCode(ctx, kanamepg.NewAuthorizationCode{
			Context:             sc,
			CodeDigest:          ceremonyDigest(0x369800 + n),
			RedirectURI:         "https://app.example.test/cb",
			CodeChallenge:       ceremonyChallenge,
			CodeChallengeMethod: domain.PKCEMethodS256,
			ACR:                 "1",
			TTL:                 time.Minute,
		})
	}}
}

// composedArm — выдача, собранная из операторов продукта: замки в данном
// порядке, затем заведение семейства данным оператором, на том же названном
// уровне изоляции. Ноль строк сессии и ноль вставленных разбираются так же, как
// в продукте.
func composedArm(pool *pgxpool.Pool, name string, control bool, locks []ceremonyLock, insertSQL string) issuanceArm {
	return issuanceArm{name: name, control: control, issue: func(ctx context.Context, sc domain.CeremonyContext, _ int) error {
		tx, err := pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.ReadCommitted})
		if err != nil {
			return err
		}
		defer func() { _ = tx.Rollback(ctx) }()
		for _, l := range locks {
			if _, err := tx.Exec(ctx, l.sql, l.arg(sc)); err != nil {
				return err
			}
		}
		var sessionRows, inserted int
		// Шестой довод — снимок уровня гранта (`token_families.acr`, kaname#423).
		if err := tx.QueryRow(ctx, insertSQL, sc.FamilyID, sc.ClientID, sc.UserID, sc.SessionID, sc.Scope, "1").
			Scan(&sessionRows, &inserted); err != nil {
			return err
		}
		switch {
		case sessionRows == 0:
			return domain.ErrCeremonySessionUnknown
		case inserted == 0:
			return domain.ErrCeremonySessionNotLive
		}
		return tx.Commit(ctx)
	}}
}

// insertWithoutLivenessCondition — оператор продукта без условия живости.
// Условие, найденное в нём не ровно один раз, — рука не собрана: это отказ
// предпосылки, а не вердикт.
func insertWithoutLivenessCondition(t *testing.T) string {
	t.Helper()
	require.Equal(t, 1, strings.Count(kanamepg.InsertFamilyOnLiveSessionSQL, liveSessionCondition),
		"НЕ ВЫПОЛНИЛОСЬ: условие живости не найдено в операторе продукта ровно один раз — "+
			"рука «только замок» не собрана")
	return strings.Replace(kanamepg.InsertFamilyOnLiveSessionSQL, liveSessionCondition, "", 1)
}

// ── Наблюдение за движком ───────────────────────────────────────────────────

// blockedBy — номер процесса, стоящего на замке процесса `blocker`; false —
// за `within` такой не появился, и сцена не построена.
func blockedBy(ctx context.Context, observer *pgxpool.Pool, blocker int, within time.Duration) (int, bool) {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		var pid int
		err := observer.QueryRow(ctx, `
			SELECT a.pid FROM pg_stat_activity a
			 WHERE a.datname = current_database()
			   AND a.wait_event_type = 'Lock'
			   AND $1 = ANY (pg_blocking_pids(a.pid))
			 ORDER BY a.pid LIMIT 1`, blocker).Scan(&pid)
		if err == nil {
			return pid, true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return 0, false
}

// lockWaiters — стоят ли на замках РОВНО `want` процессов базы.
func lockWaiters(ctx context.Context, observer *pgxpool.Pool, want int, within time.Duration) bool {
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		var n int
		if err := observer.QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity a
			 WHERE a.datname = current_database() AND a.wait_event_type = 'Lock'`).Scan(&n); err == nil && n == want {
			return true
		}
		time.Sleep(5 * time.Millisecond)
	}
	return false
}

// deadlockTimeoutOf — `deadlock_timeout` сервера: предел, раньше которого
// держатель сцены обязан быть отпущен.
func deadlockTimeoutOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool) time.Duration {
	t.Helper()
	var raw string
	require.NoError(t, pool.QueryRow(ctx, `SHOW deadlock_timeout`).Scan(&raw))
	d, err := time.ParseDuration(raw)
	require.NoError(t, err, "deadlock_timeout %q не читается длительностью", raw)
	return d
}

// awaitSide — исход стороны, отпущенной держателем. Сторона, не вернувшаяся
// за 30 с, — повисшая транзакция, и это отказ, а не «не выполнилось».
func awaitSide(t *testing.T, done <-chan error, who string) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(30 * time.Second):
		t.Fatalf("%s не завершилась за 30 с после снятия держателя", who)
		return nil
	}
}

// ── Проба 1: выдача внахлёст с удалением человека ───────────────────────────

// deletionStart — кто из двоих идёт первым.
type deletionStart int

const (
	issuanceFirst deletionStart = iota
	deletionFirst
	bothTogether
)

// deletionScene — сцена старта и держатель, который её строит.
//
//   - «выдача первой»: держатель берёт строку КЛИЕНТА. Продукт встаёт на ней,
//     уже держа человека; форма «замок одной лишь сессии» встаёт на ней в
//     проверке ключа семейства, держа сессию и ещё не держа человека. Удаление
//     приходит вторым и встаёт на выдаче;
//   - «удаление первым»: держатель берёт строку СЕССИИ ключевым замком.
//     Удаление, уже взявшее человека, встаёт на ней в каскаде; выдача приходит
//     второй и встаёт на удалении;
//   - «одновременно»: держатель берёт обе строки, стороны стартуют разом, и
//     сцена построена, когда на замках стоят обе.
type deletionScene struct {
	name  string
	start deletionStart
	hold  func(sc domain.CeremonyContext) (string, []any)
}

var deletionScenes = []deletionScene{
	{name: "выдача первой", start: issuanceFirst, hold: func(sc domain.CeremonyContext) (string, []any) {
		return `SELECT 1 FROM kaname.interactive_clients WHERE client_id = $1 FOR UPDATE`, []any{sc.ClientID}
	}},
	{name: "удаление первым", start: deletionFirst, hold: func(sc domain.CeremonyContext) (string, []any) {
		return `SELECT 1 FROM kaname.human_sessions WHERE id = $1 FOR KEY SHARE`, []any{sc.SessionID}
	}},
	{name: "одновременно", start: bothTogether, hold: func(sc domain.CeremonyContext) (string, []any) {
		return `SELECT 1 FROM kaname.interactive_clients c, kaname.human_sessions s
		         WHERE c.client_id = $1 AND s.id = $2
		           FOR UPDATE OF c FOR KEY SHARE OF s`, []any{sc.ClientID, sc.SessionID}
	}},
}

// deleteUserByProductWriter — снятие человека ПРОДУКТОВЫМ писателем
// (`UsersW().Delete`): первый оператор его транзакции берёт строку человека, а
// каскад идёт вниз — сессия, семейство, код.
func deleteUserByProductWriter(ctx context.Context, repo *kanamepg.Repository, sc domain.CeremonyContext) error {
	w, err := repo.Writer(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = w.Rollback(ctx) }()
	if err := w.UsersW().Delete(ctx, domain.UserID(sc.UserID)); err != nil {
		return err
	}
	return w.Commit(ctx)
}

// deletionRun — исход одного столкновения и конечное состояние сцены.
type deletionRun struct {
	executed            bool
	issueErr, deleteErr error
	userLeft            int
	families, live      int
	codes               int
}

func runIssuanceAgainstDeletion(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	users *kanamepg.Repository, arm issuanceArm, scene deletionScene, n int, deadlockTimeout time.Duration,
) deletionRun {
	t.Helper()
	sc := overlapScene(t, ctx, pool, n)
	holdSQL, holdArgs := scene.hold(sc)
	holderPID, release := holdingTx(t, ctx, pool, "держатель сцены «"+scene.name+"»", holdSQL, holdArgs...)

	callCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	issued, deleted := make(chan error, 1), make(chan error, 1)
	var issueStarted, deleteStarted bool
	startIssue := func() {
		issueStarted = true
		go func() { issued <- arm.issue(callCtx, sc, n) }()
	}
	startDelete := func() {
		deleteStarted = true
		go func() { deleted <- deleteUserByProductWriter(callCtx, users, sc) }()
	}

	var built bool
	switch scene.start {
	case issuanceFirst:
		startIssue()
		if issuer, ok := blockedBy(ctx, pool, holderPID, 15*time.Second); ok {
			startDelete()
			_, built = blockedBy(ctx, pool, issuer, 15*time.Second)
		}
	case deletionFirst:
		startDelete()
		if deleter, ok := blockedBy(ctx, pool, holderPID, 15*time.Second); ok {
			startIssue()
			_, built = blockedBy(ctx, pool, deleter, 15*time.Second)
		}
	case bothTogether:
		startIssue()
		startDelete()
		built = lockWaiters(ctx, pool, 2, 15*time.Second)
	}
	builtAt := time.Now()
	release()
	// Отпущен поздно — жертву выбрали бы часы, а не сцена.
	prompt := time.Since(builtAt) < deadlockTimeout/2

	var run deletionRun
	if issueStarted {
		run.issueErr = awaitSide(t, issued, "выдача")
	}
	if deleteStarted {
		run.deleteErr = awaitSide(t, deleted, "удаление")
	}
	run.executed = built && prompt && issueStarted && deleteStarted
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT (SELECT count(*) FROM kaname.users WHERE id = $1),
		       (SELECT count(*) FROM kaname.token_families WHERE id = $2),
		       (SELECT count(*) FROM kaname.token_families WHERE id = $2 AND live),
		       (SELECT count(*) FROM kaname.authorization_codes WHERE family_id = $2)`,
		sc.UserID, sc.FamilyID).Scan(&run.userLeft, &run.families, &run.live, &run.codes))
	return run
}

// deletionCell — перепись клетки «рука × сцена».
type deletionCell struct {
	arm                                          issuanceArm
	scene                                        deletionScene
	runs                                         []deletionRun
	executed, notExecuted                        int
	deadlocks, victimDeletion, victimIssuance    int
	committed, sessionUnknown, userLeft, harmful int
}

func (c *deletionCell) add(r deletionRun) {
	c.runs = append(c.runs, r)
	if !r.executed {
		c.notExecuted++
		return
	}
	c.executed++
	if isDeadlock(r.issueErr) || isDeadlock(r.deleteErr) {
		c.deadlocks++
	}
	if isDeadlock(r.deleteErr) {
		c.victimDeletion++
	}
	if isDeadlock(r.issueErr) {
		c.victimIssuance++
	}
	if r.issueErr == nil {
		c.committed++
	}
	if errors.Is(r.issueErr, domain.ErrCeremonySessionUnknown) {
		c.sessionUnknown++
	}
	if r.userLeft > 0 {
		c.userLeft++
		if r.live > 0 {
			c.harmful++
		}
	}
}

// TestOAuthIssuanceOverlappingUserDeletion — выдача кода и удаление человека,
// идущие внахлёст, во всех трёх сценах старта: взаимных блокировок НОЛЬ,
// человек снят, семейство и код снесены каскадом. Контрольная рука — форма с
// замком одной лишь сессии — в каждой сцене ОБЯЗАНА дать взаимную блокировку, а
// в сцене «выдача первой» — проиграть УДАЛЕНИЕМ: человек и живое семейство
// остаются.
func TestOAuthIssuanceOverlappingUserDeletion(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool := catalogPool(t)
	deadlockTimeout := deadlockTimeoutOf(t, ctx, pool)

	// ПРЕДПОСЫЛКА сцены «выдача первой» для контрольной руки: ключ клиента
	// семейства проверяется РАНЬШЕ ключа человека (проверки ключей идут в
	// порядке имён их триггеров). Иначе держатель клиента остановил бы
	// контрольную руку уже держащей человека, и удалению не на чем было бы
	// встать навстречу.
	var firstChecked []string
	rows, err := pool.Query(ctx, `
		SELECT c.conname FROM pg_trigger t JOIN pg_constraint c ON c.oid = t.tgconstraint
		 WHERE t.tgrelid = 'kaname.token_families'::regclass AND c.contype = 'f'
		   AND c.conname IN ('token_families_client_fk', 'token_families_user_fk')
		   AND t.tgname LIKE 'RI_ConstraintTrigger_c_%'
		 ORDER BY t.tgname`)
	require.NoError(t, err)
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		firstChecked = append(firstChecked, name)
	}
	rows.Close()
	require.NoError(t, rows.Err())
	require.NotEmpty(t, firstChecked, "НЕ ВЫПОЛНИЛОСЬ: проверок ключей семейства не найдено")
	require.Equal(t, "token_families_client_fk", firstChecked[0],
		"НЕ ВЫПОЛНИЛОСЬ: ключ клиента семейства проверяется не первым (%v) — сцена «выдача первой» "+
			"не создаёт встречного порядка у контрольной руки", firstChecked)

	users := kanamepg.New(pool, nil)
	arms := []issuanceArm{
		productArm(kanamepg.NewOAuthCeremonyRepo(pool)),
		composedArm(pool, "собранная полная", false,
			[]ceremonyLock{lockOfUser, lockOfClient, lockOfSession}, kanamepg.InsertFamilyOnLiveSessionSQL),
		composedArm(pool, "замок одной лишь сессии", true,
			[]ceremonyLock{lockOfSession}, kanamepg.InsertFamilyOnLiveSessionSQL),
	}

	var cells []*deletionCell
	n := 0
	for _, arm := range arms {
		for _, scene := range deletionScenes {
			cell := &deletionCell{arm: arm, scene: scene}
			for run := 0; run < overlapRuns; run++ {
				n++
				cell.add(runIssuanceAgainstDeletion(t, ctx, pool, users, arm, scene, n, deadlockTimeout))
			}
			cells = append(cells, cell)
		}
	}

	// Перепись печатается ВСЯ, до утверждений: знаменатель каждой клетки виден и
	// тогда, когда первая же клетка краснеет.
	notExecuted := 0
	for _, c := range cells {
		notExecuted += c.notExecuted
		t.Logf("рука «%s» · сцена «%s»: прогонов %d · исполнено %d · не выполнилось %d · "+
			"взаимных блокировок %d (жертва — удаление %d, выдача %d) · выдача зафиксирована %d · "+
			"«сессии нет» %d · человек остался %d · из них с живым семейством %d",
			c.arm.name, c.scene.name, len(c.runs), c.executed, c.notExecuted,
			c.deadlocks, c.victimDeletion, c.victimIssuance, c.committed, c.sessionUnknown,
			c.userLeft, c.harmful)
	}
	require.Zero(t, notExecuted, "НЕ ВЫПОЛНИЛОСЬ: сцена не построена в %d прогонах — вердикта нет", notExecuted)

	for _, c := range cells {
		where := fmt.Sprintf("рука «%s» · сцена «%s»", c.arm.name, c.scene.name)
		if c.arm.control {
			require.Equal(t, c.executed, c.deadlocks,
				"НЕ ВЫПОЛНИЛОСЬ: %s — контрольная рука обязана дать взаимную блокировку в каждом прогоне; "+
					"без неё зелёное главной руки неотличимо от несозданного условия", where)
			if c.scene.start == issuanceFirst {
				assert.Equal(t, c.executed, c.victimDeletion,
					"%s: жертвой встречного порядка обязано быть УДАЛЕНИЕ", where)
				assert.Equal(t, c.executed, c.harmful,
					"%s: проигравшее удаление оставляет человека и живое семейство", where)
			}
			continue
		}
		assert.Zero(t, c.deadlocks, "%s: взаимных блокировок обязано быть ноль", where)
		assert.Zero(t, c.userLeft, "%s: человек обязан быть снят в каждом прогоне", where)
		for i, r := range c.runs {
			assert.NoError(t, r.deleteErr, "%s, прогон %d: удаление обязано пройти", where, i+1)
			assert.Zero(t, r.families, "%s, прогон %d: семейство обязано быть снесено каскадом", where, i+1)
			assert.Zero(t, r.codes, "%s, прогон %d: код обязан быть снесён каскадом", where, i+1)
			if r.issueErr != nil && !errors.Is(r.issueErr, domain.ErrCeremonySessionUnknown) {
				assert.Failf(t, "исход выдачи вне объявленных", "%s, прогон %d: %v", where, i+1, r.issueErr)
			}
		}
		// Знаменатель каскада: «семейства нет» говорит о каскаде лишь там, где
		// выдача его ЗАФИКСИРОВАЛА. В сцене «выдача первой» выдача держит
		// человека первой и обязана выиграть каждый раз; в сцене «удаление
		// первым» — застать человека снятым.
		switch c.scene.start {
		case issuanceFirst:
			assert.Equal(t, c.executed, c.committed, "%s: выдача, взявшая человека первой, обязана пройти", where)
		case deletionFirst:
			assert.Equal(t, c.executed, c.sessionUnknown, "%s: выдача после удаления обязана получить «сессии нет»", where)
		case bothTogether:
			assert.Equal(t, c.executed, c.committed+c.sessionUnknown, "%s: исход выдачи вне объявленных", where)
		}
	}
}

// ── Проба 2: выдача внахлёст со снятием сессии ──────────────────────────────

// endScene — сцена снятия: транзакция выхода ОТКРЫТА после своих операторов
// (отметка на сессии и отзыв семейств) либо уже зафиксирована.
type endScene struct {
	name      string
	committed bool
}

var endScenes = []endScene{
	{name: "снятие не зафиксировано", committed: false},
	{name: "снятие зафиксировано", committed: true},
}

// endRun — исход одного прогона.
type endRun struct {
	executed bool
	waited   bool
	issueErr error
	// liveInEnded — живых семейств в снятой сессии: это и есть дефект.
	liveInEnded int
}

// openEndPID — процесс транзакции выхода: он простаивает в транзакции и
// держит строку сессии. Ровно один — иначе сцена не построена.
func openEndPID(ctx context.Context, observer *pgxpool.Pool) (int, bool) {
	rows, err := observer.Query(ctx, `
		SELECT a.pid FROM pg_stat_activity a
		 WHERE a.datname = current_database() AND a.state = 'idle in transaction'
		   AND EXISTS (SELECT 1 FROM pg_locks l
		                WHERE l.pid = a.pid AND l.granted AND l.mode = 'RowExclusiveLock'
		                  AND l.relation = 'kaname.human_sessions'::regclass)`)
	if err != nil {
		return 0, false
	}
	defer rows.Close()
	var pids []int
	for rows.Next() {
		var pid int
		if rows.Scan(&pid) != nil {
			return 0, false
		}
		pids = append(pids, pid)
	}
	if rows.Err() != nil || len(pids) != 1 {
		return 0, false
	}
	return pids[0], true
}

func runIssuanceAgainstSessionEnd(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	sessions *kanamepg.HumanSessionRepo, arm issuanceArm, scene endScene, n int,
) endRun {
	t.Helper()
	sc := overlapScene(t, ctx, pool, n)

	// Выход — ПРОДУКТОВЫЙ писатель: отметка сессии и отзыв её семейств одной
	// транзакцией (`EndSession`). Фиксацию решает сцена.
	w, err := sessions.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	ended, err := w.EndSession(ctx, domain.HumanSessionID(sc.SessionID), time.Now(), domain.RevokeReasonLogout)
	require.NoError(t, err)
	require.True(t, ended, "выход обязан снять сессию сцены")

	var run endRun
	built := true
	if scene.committed {
		require.NoError(t, w.Commit(ctx))
		run.issueErr = arm.issue(ctx, sc, n)
	} else {
		endPID, ok := openEndPID(ctx, pool)
		built = ok
		done := make(chan error, 1)
		go func() { done <- arm.issue(ctx, sc, n) }()
		finished := false
		deadline := time.Now().Add(15 * time.Second)
		for ok && !finished && !run.waited && time.Now().Before(deadline) {
			select {
			case run.issueErr = <-done:
				finished = true
			default:
				var blocked bool
				require.NoError(t, pool.QueryRow(ctx, `
					SELECT EXISTS (SELECT 1 FROM pg_stat_activity a
					                WHERE a.datname = current_database()
					                  AND $1 = ANY (pg_blocking_pids(a.pid)))`, endPID).Scan(&blocked))
				run.waited = blocked
				if !blocked {
					time.Sleep(5 * time.Millisecond)
				}
			}
		}
		// Условие опыта: выдача либо стоит на открытом выходе, либо кончилась,
		// пока он открыт. Ни того, ни другого — сцена не построена.
		built = built && (finished || run.waited)
		require.NoError(t, w.Commit(ctx), "фиксация выхода")
		if !finished {
			run.issueErr = awaitSide(t, done, "выдача")
		}
	}

	var sessionEnded bool
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT (SELECT ended_at IS NOT NULL FROM kaname.human_sessions WHERE id = $1),
		       (SELECT count(*) FROM kaname.token_families f
		          JOIN kaname.human_sessions s ON s.id = f.session_id
		         WHERE f.session_id = $1 AND f.live AND s.ended_at IS NOT NULL)`,
		sc.SessionID).Scan(&sessionEnded, &run.liveInEnded))
	run.executed = built && sessionEnded
	return run
}

// TestOAuthIssuanceOverlappingSessionEnd — выдача кода внахлёст со снятием
// сессии в двух сценах: ни в одной живого семейства в снятой сессии не
// остаётся. Контрольных рук две: «только условие» краснеет ровно в сцене
// незафиксированного снятия, «только замок» — в обеих.
func TestOAuthIssuanceOverlappingSessionEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool := catalogPool(t)
	sessions := kanamepg.NewHumanSessionRepo(pool)
	all := []ceremonyLock{lockOfUser, lockOfClient, lockOfSession}
	withoutCondition := insertWithoutLivenessCondition(t)

	// redIn — сцены, в которых рука ОБЯЗАНА краснеть. Пусто — рука обязана
	// быть зелёной везде.
	arms := []struct {
		arm   issuanceArm
		redIn map[string]bool
	}{
		{arm: productArm(kanamepg.NewOAuthCeremonyRepo(pool))},
		{arm: composedArm(pool, "собранная полная", false, all, kanamepg.InsertFamilyOnLiveSessionSQL)},
		{
			arm:   composedArm(pool, "только условие", true, nil, kanamepg.InsertFamilyOnLiveSessionSQL),
			redIn: map[string]bool{"снятие не зафиксировано": true},
		},
		{
			arm:   composedArm(pool, "только замок", true, all, withoutCondition),
			redIn: map[string]bool{"снятие не зафиксировано": true, "снятие зафиксировано": true},
		},
	}

	type endCell struct {
		arm                                           issuanceArm
		scene                                         endScene
		red                                           bool
		runs                                          []endRun
		executed, notExecuted, waited, defects, clean int
		notLive                                       int
	}
	var cells []*endCell
	n := 500
	for _, a := range arms {
		for _, scene := range endScenes {
			cell := &endCell{arm: a.arm, scene: scene, red: a.redIn[scene.name]}
			for run := 0; run < overlapRuns; run++ {
				n++
				r := runIssuanceAgainstSessionEnd(t, ctx, pool, sessions, a.arm, scene, n)
				cell.runs = append(cell.runs, r)
				if !r.executed {
					cell.notExecuted++
					continue
				}
				cell.executed++
				if r.waited {
					cell.waited++
				}
				if r.liveInEnded > 0 {
					cell.defects++
				} else {
					cell.clean++
				}
				if errors.Is(r.issueErr, domain.ErrCeremonySessionNotLive) {
					cell.notLive++
				}
			}
			cells = append(cells, cell)
		}
	}

	notExecuted := 0
	for _, c := range cells {
		notExecuted += c.notExecuted
		t.Logf("рука «%s» · сцена «%s»: прогонов %d · исполнено %d · не выполнилось %d · "+
			"стояла на выходе %d · живое семейство в снятой сессии %d · чисто %d · «сессия не жива» %d",
			c.arm.name, c.scene.name, len(c.runs), c.executed, c.notExecuted,
			c.waited, c.defects, c.clean, c.notLive)
	}
	require.Zero(t, notExecuted, "НЕ ВЫПОЛНИЛОСЬ: сцена не построена в %d прогонах — вердикта нет", notExecuted)

	for _, c := range cells {
		where := fmt.Sprintf("рука «%s» · сцена «%s»", c.arm.name, c.scene.name)
		switch {
		case c.red:
			require.Equal(t, c.executed, c.defects,
				"НЕ ВЫПОЛНИЛОСЬ: %s — контрольная рука обязана оставить живое семейство в снятой сессии; "+
					"позеленевшая, она означает, что сцена условия не создала", where)
		case c.arm.control:
			// Контрольная рука, зелёная по объявлению: сцена, в которой краснеет
			// всё, различала бы не то, что обещает.
			assert.Zero(t, c.defects, "%s: в этой сцене контрольная рука обязана быть зелёной", where)
		default:
			assert.Zero(t, c.defects, "%s: живого семейства в снятой сессии быть не может", where)
			assert.Equal(t, c.executed, c.notLive, "%s: выдача обязана получить «сессия не жива»", where)
		}
	}
}
