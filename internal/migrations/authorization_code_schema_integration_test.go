// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// authorization_code_schema_integration_test.go — СХЕМА кода авторизации,
// семейства и обновляющего токена (задача PRO-Robotech/kaname#313, миграция
// `20260920175117_authorization_code_is_our_record.sql`).
//
// # Почему эта проба идёт ПОСЛЕ миграции
//
// Предмет пробы — САМА СХЕМА: до миграции утверждать не о чем, и «красное до
// кода» здесь невыразимо. Это единственное названное исключение из порядка.
//
// # Что утверждают пробы этого файла
//
//   - ГАШЕНИЕ ОДНОЙ ИНСТРУКЦИЕЙ. Две транзакции исполняют один и тот же
//     условный `UPDATE … RETURNING` по одному коду. Ровно одна получает строку,
//     вторая — ноль. Это и есть механизм, ради которого заведена колонка
//     `active`: пары «прочитать, затем записать» в обмене нет;
//   - `active` ПРОИЗВОДНА И НЕЗАПИСЫВАЕМА. Она вычисляется базой из отметки
//     снятия и живости семейства; попытка записать её отвергается кодом 428C9.
//     Гашение пишет ОТМЕТКУ, признак следует за ней сам;
//   - «НЕАКТИВЕН» И «НЕ НАЙДЕН» РАЗЛИЧИМЫ. Погашенный код ОСТАЁТСЯ строкой и
//     читается с `active = false`; удаление стёрло бы это различение, на котором
//     стоит обнаружение повтора;
//   - КОНТЕКСТ НЕ РАСХОДИТСЯ С СЕМЕЙСТВОМ. Составной внешний ключ отвергает
//     строку кода, чей клиент/человек/сессия/область не те, что у семейства;
//   - СЛОВАРИ ЗАКРЫТЫ. Метод испытания — только `S256`; причина снятия — только
//     из перечня; форма свёртки — 64 шестнадцатеричных знака;
//   - РОТАЦИЯ ТЕМ ЖЕ МЕХАНИЗМОМ. Условный `UPDATE … RETURNING` по обновляющему
//     токену даёт ровно одну победившую транзакцию; поколение в семействе одно
//     на номер;
//   - ОБРАТНЫЙ ХОД. Миграция снимается и накатывается снова.
//
// У каждого отрицания стоит ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: «вставка отвергнута»
// истинно и тогда, когда отвергается всё.
package migrations_test

import (
	"database/sql"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// authCodeMigration — файл, заводящий предмет этих проб. Имя стоит одним
// литералом: по нему вычисляется версия обратного хода.
const authCodeMigration = "20260920175117_authorization_code_is_our_record.sql"

// versionsOf — версия названного файла цепочки и версия непосредственно перед
// ним. Выводится ИЗ ЦЕПОЧКИ, а не выписывается числом: выписанное число не имеет
// производителя и разошлось бы с деревом молча.
func versionsOf(t *testing.T, file string) (own, previous int64) {
	t.Helper()
	entries, err := fs.ReadDir(migrations.FS, ".")
	require.NoError(t, err)
	var versions []int64
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		head, _, ok := strings.Cut(e.Name(), "_")
		require.True(t, ok, "имя миграции без номера: %s", e.Name())
		v, perr := strconv.ParseInt(head, 10, 64)
		require.NoError(t, perr, "номер миграции %s", e.Name())
		versions = append(versions, v)
		if e.Name() == file {
			own = v
		}
	}
	require.NotZero(t, own, "файл предмета %s не найден в цепочке", file)
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	for _, v := range versions {
		if v < own {
			previous = v
		}
	}
	require.NotZero(t, previous, "перед файлом предмета обязана стоять хотя бы одна миграция")
	return own, previous
}

func acDB(t *testing.T) *sql.DB {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	return upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
}

// acDigest — свёртка объявленной формы из счётчика: 64 шестнадцатеричных знака.
func acDigest(n int) string { return fmt.Sprintf("%064x", n) }

// acChallenge — испытание PKCE объявленной формы: 43 знака base64url.
const acChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

// acPad — 17 знаков crockford-base32 из метки: формы `ic-…`, `tfm-…` закрыты
// ограничениями схемы, и дополнение пробелами (`%017s`) их не проходит.
func acPad(tag string) string {
	out := tag
	for len(out) < 17 {
		out = "0" + out
	}
	return out[len(out)-17:]
}

// acScene заводит аккаунт, человека, его сессию, интерактивного клиента и
// семейство. Фикстура ПОЛНАЯ намеренно: гонка, поставленная на код без
// семейства, зеленела бы, не имея чего отвергать.
func acScene(t *testing.T, db *sql.DB, tag string) (clientID, userID, sessionID, familyID string) {
	t.Helper()
	userID = "usr" + acPad(tag+"u")
	account := "acc" + acPad(tag)
	sessionID = "hs-" + acPad(tag)
	clientID = "client-" + tag
	familyID = "tfm-" + acPad(tag)

	tx, err := db.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`
		INSERT INTO kaname.users (id, external_id, email, display_name, account_id, invite_status)
		VALUES ($1, $2, $3, 'owner', $4, 'ACTIVE')`,
		userID, "ext-"+tag, tag+"@example.invalid", account)
	require.NoError(t, err, "посев человека %s", tag)
	_, err = tx.Exec(`INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`,
		account, "acc-"+tag, userID)
	require.NoError(t, err, "посев аккаунта %s", tag)
	require.NoError(t, tx.Commit())

	_, err = db.Exec(`
		INSERT INTO kaname.human_sessions
		       (id, user_id, bearer_digest, authenticated_at, last_presented_at, expires_at,
		        assurance_level, presented_methods)
		VALUES ($1, $2, $3, now(), now(), now() + interval '1 hour', '1', ARRAY['password'])`,
		sessionID, userID, acDigest(len(tag)*7919+1))
	require.NoError(t, err, "посев сессии %s", tag)

	// Способ объявлен: клиента без способа схема не принимает
	// (`interactive_clients_auth_method_ck`, kaname#317), и фикстура не бывает
	// снисходительнее продукта.
	_, err = db.Exec(`
		INSERT INTO kaname.interactive_clients (id, name, redirect_uris, client_id, token_endpoint_auth_method)
		VALUES ($1, $2, ARRAY['https://app.example.test/cb'], $3, 'none')`,
		"ic-"+acPad(tag), "ic-"+tag, clientID)
	require.NoError(t, err, "посев клиента %s", tag)

	_, err = db.Exec(`
		INSERT INTO kaname.token_families (id, client_id, user_id, session_id, scope, acr)
		VALUES ($1, $2, $3, $4, ARRAY['openid','profile'], '1')`,
		familyID, clientID, userID, sessionID)
	require.NoError(t, err, "посев семейства %s", tag)
	return clientID, userID, sessionID, familyID
}

// acExecer — то, чем исполняется сырой оператор: база либо её транзакция.
// Проба ключа живости вставляет ребёнка ВНУТРИ транзакции, отозвавшей семейство.
type acExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// acInsertCode — вставка кода сырым оператором: предмет проб — СХЕМА, и путь
// через репозиторий отсёк бы негодный вход до базы.
func acInsertCode(db acExecer, digest, family, client, user, session string, scope []string,
	method, challenge string) error {
	_, err := db.Exec(`
		INSERT INTO kaname.authorization_codes
		       (code_digest, family_id, client_id, user_id, session_id, scope, redirect_uri,
		        code_challenge, code_challenge_method, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,'https://app.example.test/cb',$7,$8, now() + interval '5 minutes')`,
		digest, family, client, user, session, pqTextArray(scope), challenge, method)
	return err
}

// pqTextArray — литерал массива текста для драйвера database/sql.
func pqTextArray(in []string) string {
	out := "{"
	for i, s := range in {
		if i > 0 {
			out += ","
		}
		out += `"` + s + `"`
	}
	return out + "}"
}

// acRedeemSQL — ТОТ САМЫЙ оператор обмена: условие на ПРЕЖНЕЕ состояние и
// возврат затронутой строки. Он стоит здесь одним литералом и воспроизводит
// механизм, который исполняет слой доступа; второе написание разошлось бы молча.
const acRedeemSQL = `
UPDATE kaname.authorization_codes AS c
   SET deactivated_at = now(), deactivated_reason = 'redeemed'
 WHERE c.code_digest = $1
   AND c.active
   AND c.expires_at > now()
RETURNING c.family_id`

// TestIntegration_AuthorizationCodeRedemptionIsOneStatement — гашение одной
// инструкцией: две транзакции, ровно одна выдача.
func TestIntegration_AuthorizationCodeRedemptionIsOneStatement(t *testing.T) {
	db := acDB(t)
	client, user, session, family := acScene(t, db, "acdeem")
	digest := acDigest(0x11)
	require.NoError(t, acInsertCode(db, digest, family, client, user, session,
		[]string{"openid", "profile"}, "S256", acChallenge), "положительный контроль вставки кода")

	const racers = 8
	won := make([]bool, racers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			tx, err := db.Begin()
			if err != nil {
				return
			}
			defer func() { _ = tx.Rollback() }()
			var fam string
			if err := tx.QueryRow(acRedeemSQL, digest).Scan(&fam); err != nil {
				return // ноль затронутых строк — законный отказ проигравшего
			}
			if err := tx.Commit(); err == nil {
				won[i] = true
			}
		}(i)
	}
	close(start)
	wg.Wait()

	var winners int
	for _, w := range won {
		if w {
			winners++
		}
	}
	t.Logf("перепись: гонщиков %d, выдач %d, отказов %d", racers, winners, racers-winners)
	require.Equal(t, 1, winners,
		"выдач по одному коду обязано быть РОВНО одна: %d означает, что условие на прежнее "+
			"состояние не держит гонку", winners)

	// «Неактивен» и «не найден» РАЗЛИЧИМЫ: строка на месте, признак снят.
	var active bool
	var reason string
	require.NoError(t, db.QueryRow(
		`SELECT active, deactivated_reason FROM kaname.authorization_codes WHERE code_digest = $1`,
		digest).Scan(&active, &reason),
		"погашенный код ОБЯЗАН остаться строкой: удаление стёрло бы различение «неактивен» и «не найден»")
	require.False(t, active, "погашенный код обязан быть неактивен")
	require.Equal(t, "redeemed", reason)
}

// TestIntegration_AuthorizationCodeContextCannotDivergeFromItsFamily — составной
// внешний ключ: контекст кода и семейства — одно состояние.
func TestIntegration_AuthorizationCodeContextCannotDivergeFromItsFamily(t *testing.T) {
	db := acDB(t)
	client, user, session, family := acScene(t, db, "acfam")

	// Отрицания идут ПЕРВЫМИ: семейство несёт не больше одного кода, и
	// положительный контроль, поставленный раньше, отвергал бы их уникальностью,
	// а не тем ключом, о котором проба.
	//
	// Область РАЗОШЛАСЬ с семейством — отвергает база.
	err := acInsertCode(db, acDigest(0x22), family, client, user, session,
		[]string{"openid"}, "S256", acChallenge)
	requirePgRefusal(t, err, "23503", "authorization_codes_family_context_fk",
		"код с областью, которой у семейства нет, обязан быть отвергнут ключом")

	// Человек разошёлся с семейством — тем же ключом.
	err = acInsertCode(db, acDigest(0x23), family, client, "usr"+acPad("nobody"),
		session, []string{"openid", "profile"}, "S256", acChallenge)
	requirePgRefusal(t, err, "23503", "authorization_codes_family_context_fk",
		"код с чужим человеком обязан быть отвергнут ключом")

	// Положительный контроль: согласованный контекст проходит. Без него
	// «вставка отвергнута» было бы истинно и тогда, когда отвергается ВСЁ.
	require.NoError(t, acInsertCode(db, acDigest(0x21), family, client, user, session,
		[]string{"openid", "profile"}, "S256", acChallenge))
}

// TestIntegration_IssuedContextSurvivesAnUpdateOfItsFamily — КОНТЕКСТ ВЫДАННОГО
// НЕИЗМЕНЯЕМ СО СТОРОНЫ СЕМЕЙСТВА.
//
// # Что именно ловится
//
// Пока контекст и живость стояли в ОДНОМ ключе, каскад, заведённый ради
// живости, доставался и контексту: `UPDATE token_families SET session_id = …`
// и `SET scope = …` проходили и МОЛЧА переписывали сессию и область прав уже
// выданного кода. Измерено до расщепления: область `{openid,profile}` строки,
// выданной раньше, становилась `{openid,profile,admin}` — то есть права
// выданного расширялись задним числом обновлением родителя.
//
// Строка выданного есть СВИДЕТЕЛЬСТВО о предъявленном, а не кэш текущего
// семейства, поэтому отказ обязан приходить от БАЗЫ, а не от дисциплины
// писателя: писателя, который «просто не пишет эти колонки», не существует —
// существует ключ, который такую запись отвергает.
//
// # Почему положительный близнец обязателен
//
// Отрицание «обновление отвергнуто» было бы истинно и у схемы, которая
// отвергает ВСЯКОЕ обновление семейства, — а такая схема ломает сам отзыв,
// ради которого каскад и заводился. Поэтому рядом стоит близнец, меняющий
// РОВНО ОДИН факт: обновляется не контекст, а живость, и оно обязано ПРОЙТИ и
// снестись на ребёнка.
func TestIntegration_IssuedContextSurvivesAnUpdateOfItsFamily(t *testing.T) {
	db := acDB(t)
	client, user, session, family := acScene(t, db, "ackey")

	require.NoError(t, acInsertCode(db, acDigest(0x41), family, client, user, session,
		[]string{"openid", "profile"}, "S256", acChallenge), "положительный контроль посева")

	// Вторая сессия того же человека — чтобы было КУДА переписывать: отказ на
	// несуществующей сессии пришёл бы от другого ключа и о другом.
	_, err := db.Exec(`
		INSERT INTO kaname.human_sessions
		       (id, user_id, bearer_digest, authenticated_at, last_presented_at, expires_at,
		        assurance_level, presented_methods)
		VALUES ($1, $2, $3, now(), now(), now() + interval '1 hour', '1', ARRAY['password'])`,
		"hs-"+acPad("ackey2"), user, acDigest(0x4242))
	require.NoError(t, err, "посев второй сессии")

	// ОТРИЦАНИЕ 1: сессию выданного переписать нельзя.
	_, err = db.Exec(`UPDATE kaname.token_families SET session_id = $2 WHERE id = $1`,
		family, "hs-"+acPad("ackey2"))
	requirePgRefusal(t, err, "23503", "authorization_codes_family_context_fk",
		"сессию уже выданного кода нельзя переписать обновлением семейства")

	// ОТРИЦАНИЕ 2: область прав выданного переписать нельзя — это и есть
	// расширение прав задним числом.
	_, err = db.Exec(`UPDATE kaname.token_families SET scope = $2 WHERE id = $1`,
		family, pqTextArray([]string{"openid", "profile", "admin"}))
	requirePgRefusal(t, err, "23503", "authorization_codes_family_context_fk",
		"область прав уже выданного кода нельзя расширить обновлением семейства")

	// Контекст ребёнка НЕ СДВИНУЛСЯ: отказ обязан оставлять строку как была, а
	// не откатывать половину.
	var gotSession string
	var gotScope string
	require.NoError(t, db.QueryRow(
		`SELECT session_id, scope::text FROM kaname.authorization_codes WHERE code_digest = $1`,
		acDigest(0x41)).Scan(&gotSession, &gotScope))
	require.Equal(t, session, gotSession, "сессия выданного обязана остаться прежней")
	require.Equal(t, `{openid,profile}`, gotScope, "область выданного обязана остаться прежней")

	// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: отличается РОВНО ОДНИМ фактом — обновляется
	// живость, а не контекст. Обязан пройти и снестись каскадом.
	_, err = db.Exec(`
		UPDATE kaname.token_families
		   SET revoked_at = now(), revoked_reason = 'logout', live = false
		 WHERE id = $1 AND revoked_at IS NULL`, family)
	require.NoError(t, err, "отзыв семейства обязан ПРОХОДИТЬ: расщепление ключа его не трогает")

	var familyLive, active bool
	var ownMark sql.NullTime
	require.NoError(t, db.QueryRow(
		`SELECT family_live, active, deactivated_at FROM kaname.authorization_codes WHERE code_digest = $1`,
		acDigest(0x41)).Scan(&familyLive, &active, &ownMark))
	require.False(t, familyLive, "каскад живости обязан снестись на ребёнка")
	require.False(t, active, "ребёнок отозванного семейства обязан быть неактивен")
	require.False(t, ownMark.Valid,
		"СВОЕЙ отметки снятия у ребёнка быть не должно: он умер вместе с семейством, "+
			"а не собственным событием — основание читается у семейства")
}

// TestIntegration_ChildOfARevokedFamilyIsRefusedByItsLiveKey — строка,
// заводимая в ОТОЗВАННОЕ семейство, отвергается ключом живости
// `<t>_family_live_fk` кодом 23503 — у кода и токена обновления (заказы C и D
// схемного ревью kn-313, задача PRO-Robotech/kaname#369). Третий ребёнок —
// запись выпуска (`access_tokens`, kaname#319) — отвергается тем же ключом
// `access_tokens_family_live_fk`, и судит его своя проба
// `TestIntegration_LINE_A_1_28_AccessTokenIsIssuedIntoALiveFamilyOnly`.
//
// # Один факт между отказом и близнецом
//
// Отказ и близнец исполняют ОДНУ вставку над ОДНИМ семейством. Отличает их
// ровно живость семейства: отказ идёт в транзакции, отозвавшей семейство, и эта
// транзакция откатывается; близнец — после отката, над тем же, снова живым
// семейством. Близнец над другим семейством отличался бы ещё и строкой, и его
// зелёное не говорило бы, что отказ дал именно отзыв.
//
// # Почему судится имя ограничения, а не только код
//
// 23503 даёт и ключ КОНТЕКСТА (`<t>_family_context_fk`). Проба, судящая один
// код, зеленела бы и там, где ключ живости снят, а отказ пришёл от соседа.
func TestIntegration_ChildOfARevokedFamilyIsRefusedByItsLiveKey(t *testing.T) {
	db := acDB(t)
	// Метки сцен РАЗНОЙ длины: `acScene` выводит свёртку носителя сессии из
	// длины метки, а обе сцены живут в одной базе. Знаки — crockford-base32:
	// формы `ic-…` и `tfm-…` закрыты ограничениями схемы.
	children := []struct {
		name, liveKey, tag string
		insert             func(ex acExecer, family, client, user, session string) error
	}{
		{
			name: "authorization_codes", liveKey: "authorization_codes_family_live_fk", tag: "acrvk",
			insert: func(ex acExecer, family, client, user, session string) error {
				return acInsertCode(ex, acDigest(0x51), family, client, user, session,
					[]string{"openid", "profile"}, "S256", acChallenge)
			},
		},
		{
			name: "refresh_tokens", liveKey: "refresh_tokens_family_live_fk", tag: "acrvkt",
			insert: func(ex acExecer, family, client, user, session string) error {
				_, err := ex.Exec(`
					INSERT INTO kaname.refresh_tokens
					       (token_digest, family_id, client_id, user_id, session_id, scope, generation, expires_at)
					VALUES ($1,$2,$3,$4,$5,$6,0, now() + interval '30 days')`,
					acDigest(0x52), family, client, user, session, pqTextArray([]string{"openid", "profile"}))
				return err
			},
		},
	}
	for _, child := range children {
		t.Run(child.name, func(t *testing.T) {
			client, user, session, family := acScene(t, db, child.tag)

			tx, err := db.Begin()
			require.NoError(t, err)
			_, err = tx.Exec(`
				UPDATE kaname.token_families
				   SET revoked_at = now(), revoked_reason = 'logout', live = false
				 WHERE id = $1 AND revoked_at IS NULL`, family)
			require.NoError(t, err, "отзыв семейства в транзакции отказа обязан пройти")
			requirePgRefusal(t, child.insert(tx, family, client, user, session), "23503", child.liveKey,
				child.name+": строка в отозванное семейство обязана быть отвергнута ключом живости")
			require.NoError(t, tx.Rollback(), "откат снимает отзыв: близнецу нужно то же семейство живым")

			// Предпосылка близнеца: семейство снова живо. Иначе близнец отличался
			// бы от отказа не отзывом, а чем-то, чего проба не видит.
			var live bool
			require.NoError(t, db.QueryRow(
				`SELECT live FROM kaname.token_families WHERE id = $1`, family).Scan(&live))
			require.True(t, live, "после отката семейство обязано быть живым")

			require.NoError(t, child.insert(db, family, client, user, session),
				child.name+": та же строка в живое семейство обязана лечь — отказ выше дал отзыв, а не вставка")
			var rows int
			require.NoError(t, db.QueryRow(
				`SELECT count(*) FROM kaname.`+child.name+` WHERE family_id = $1 AND family_live`,
				family).Scan(&rows))
			t.Logf("%s: отказ по %s — 23503; близнец — строк живого семейства %d", child.name, child.liveKey, rows)
			require.Equal(t, 1, rows, "близнец обязан оставить ровно одну строку живого семейства")
		})
	}
}

// TestIntegration_AuthorizationCodeVocabulariesAreClosed — словари и формы.
func TestIntegration_AuthorizationCodeVocabulariesAreClosed(t *testing.T) {
	db := acDB(t)
	client, user, session, family := acScene(t, db, "acvcb")

	require.NoError(t, acInsertCode(db, acDigest(0x31), family, client, user, session,
		[]string{"openid", "profile"}, "S256", acChallenge), "положительный контроль")

	requirePgRefusal(t,
		acInsertCode(db, acDigest(0x32), family, client, user, session,
			[]string{"openid", "profile"}, "plain", acChallenge),
		"23514", "authorization_codes_challenge_method_ck",
		"метод испытания вне словаря обязан быть отвергнут: `plain` законным не станет")

	requirePgRefusal(t,
		acInsertCode(db, "NOT-A-DIGEST", family, client, user, session,
			[]string{"openid", "profile"}, "S256", acChallenge),
		"23514", "authorization_codes_digest_form_ck",
		"свёртка негодной формы обязана быть отвергнута")

	requirePgRefusal(t,
		acInsertCode(db, acDigest(0x33), family, client, user, session,
			[]string{"openid", "profile"}, "S256", "short"),
		"23514", "authorization_codes_challenge_form_ck",
		"испытание негодной формы обязано быть отвергнуто")

	// Признак активности ПРОИЗВОДЕН: рассогласовать его с отметкой нельзя,
	// потому что записать его нельзя вовсе. Имени ограничения у этого отказа
	// нет — его даёт не ограничение, а вид колонки.
	_, err := db.Exec(`
		UPDATE kaname.authorization_codes SET active = false WHERE code_digest = $1`, acDigest(0x31))
	requirePgRefusal(t, err, "428C9", "",
		"запись в производный признак активности обязана быть отвергнута: "+
			"признак следует за отметкой снятия, а не наоборот")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к отрицанию выше: отметка пишется, и признак
	// следует за ней САМ. Без него «запись отвергнута» было бы истинно и в мире,
	// где колонка не пишется НИКАК и снятие невыразимо.
	_, err = db.Exec(`
		UPDATE kaname.authorization_codes
		   SET deactivated_at = now(), deactivated_reason = 'redeemed'
		 WHERE code_digest = $1`, acDigest(0x31))
	require.NoError(t, err, "снятие ОТМЕТКОЙ обязано проходить")
	var active bool
	require.NoError(t, db.QueryRow(
		`SELECT active FROM kaname.authorization_codes WHERE code_digest = $1`,
		acDigest(0x31)).Scan(&active))
	require.False(t, active, "признак обязан пересчитаться сам по отметке снятия")
}

// TestIntegration_RefreshTokenRotationIsOneStatement — ротация ТЕМ ЖЕ
// механизмом: условный оператор с возвратом, ровно одна победа.
func TestIntegration_RefreshTokenRotationIsOneStatement(t *testing.T) {
	db := acDB(t)
	client, user, session, family := acScene(t, db, "acrtt")
	parent := acDigest(0x41)
	_, err := db.Exec(`
		INSERT INTO kaname.refresh_tokens
		       (token_digest, family_id, client_id, user_id, session_id, scope, generation, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,0, now() + interval '30 days')`,
		parent, family, client, user, session, pqTextArray([]string{"openid", "profile"}))
	require.NoError(t, err, "положительный контроль вставки токена")

	const racers = 8
	won := make([]bool, racers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < racers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			successor := acDigest(0x100 + i)
			tx, err := db.Begin()
			if err != nil {
				return
			}
			defer func() { _ = tx.Rollback() }()
			var gen int
			err = tx.QueryRow(`
				UPDATE kaname.refresh_tokens AS r
				   SET deactivated_at = now(), deactivated_reason = 'rotated',
				       successor_digest = $2
				 WHERE r.token_digest = $1 AND r.active AND r.expires_at > now()
				RETURNING r.generation`, parent, successor).Scan(&gen)
			if err != nil {
				return
			}
			if _, err := tx.Exec(`
				INSERT INTO kaname.refresh_tokens
				       (token_digest, family_id, client_id, user_id, session_id, scope, generation, expires_at)
				VALUES ($1,$2,$3,$4,$5,$6,$7, now() + interval '30 days')`,
				successor, family, client, user, session,
				pqTextArray([]string{"openid", "profile"}), gen+1); err != nil {
				return
			}
			if err := tx.Commit(); err == nil {
				won[i] = true
			}
		}(i)
	}
	close(start)
	wg.Wait()

	var winners int
	for _, w := range won {
		if w {
			winners++
		}
	}
	var generations int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.refresh_tokens WHERE family_id = $1`, family).Scan(&generations))
	t.Logf("перепись: гонщиков %d, ротаций %d, строк семейства %d", racers, winners, generations)
	require.Equal(t, 1, winners, "ротаций обязано быть РОВНО одна: %d означает разветвление семейства", winners)
	require.Equal(t, 2, generations, "в семействе обязано остаться два поколения: исходное и преемник")
}

// TestIntegration_AuthorizationCodeMigrationRollsBackAndForward — обратный ход.
func TestIntegration_AuthorizationCodeMigrationRollsBackAndForward(t *testing.T) {
	db := acDB(t)
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))

	own, previous := versionsOf(t, authCodeMigration)
	require.NoError(t, goose.DownTo(db, ".", previous), "обратный ход обязан снять предмет")

	var present int
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM information_schema.tables
		 WHERE table_schema = 'kaname'
		   AND table_name IN ('authorization_codes','refresh_tokens','token_families')`).Scan(&present))
	require.Zero(t, present, "после отката таблиц предмета остаться не должно, осталось %d", present)

	require.NoError(t, goose.Up(db, "."), "цепочка обязана накатываться снова")
	require.NoError(t, db.QueryRow(`
		SELECT count(*) FROM information_schema.tables
		 WHERE table_schema = 'kaname'
		   AND table_name IN ('authorization_codes','refresh_tokens','token_families')`).Scan(&present))
	require.Equal(t, 3, present, "после повторного наката обязаны стоять все три таблицы, стоит %d", present)

	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	// Не равенство, а «не ниже предмета»: цепочка живёт дальше — ствол кладёт
	// поверх новые файлы, и равенство красило бы пробу на каждом следующем.
	require.GreaterOrEqual(t, version, own, "цепочка обязана стоять не ниже предмета")
}
