// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// login_method_schema_integration_test.go — СХЕМА способа входа человека и
// подтверждённости его адреса (фаза Ф2, задача `kacho#1268`).
//
// # Санкция
//
// Одобренная Ф1 (`docs/engineering/acceptance/login-session-and-credentials-are-our-contract.md`,
// ведомость §5, строка Ф2: «строка удостоверения, строка адреса и её
// подтверждённость») и одобренная F4d воркспейса (сценарии F4d-13…F4d-15: форма
// строки, уникальность парой «человек, вид», конкуренция). Сценарии Ф1 здесь
// покрываются СТОРОНОЙ ХРАНИЛИЩА: вход (Ф3) и перенос (часть П3 фазы Ф2) —
// не здесь, и это названо у каждой пробы.
//
// # Что утверждают пробы этого файла
//
//   - F4d-13. Способ — СТРОКА своей таблицы; строка несёт вид, проверочный
//     материал и — с фазы Ф12 (kacho#1281, приёмка
//     `second-factor-totp-and-recovery-codes.md`, Р1, §4.1 п.1) — СОСТОЯНИЕ и
//     последний принятый шаг; исходный пароль в ней не выражается — поля нет, и
//     это проверено попыткой положить его туда, а не чтением. Уровень доверия в
//     строке не заведён и не будет: он функция предъявленного, а не способа
//     (Ф11 Р1, kacho#1280) — решение в шапке миграции Ф2 П1. Состав колонок
//     ЗАКРЫТ и держится здесь литералом, как объявленный набор ограничений у
//     гейта сдерживания (`lmDeclaredConstraints`): расширяется РЕШЕНИЕМ
//     приёмки, а не выводится из схемы — выведенный из схемы состав не может
//     покраснеть ни на какой колонке;
//   - F4d-14 · уникальность — ПАРОЙ «человек, вид», и отказ производит база;
//     второй вид заводится правкой словаря, без правки существующих строк;
//   - владение — внешний ключ на `users(id)` с каскадом: способ уходит вместе с
//     человеком и не бывает у несуществующего;
//   - пустой материал отвергается базой (23514), а не только типом;
//   - ключ — `users.id`, а не внешний субъект и не почта: способ заводится
//     приглашённому (PENDING) и переживает его активацию;
//   - подтверждённость адреса привязана к ЗНАЧЕНИЮ адреса: смена адреса снимает
//     её в том же операторе, какой бы писатель адрес ни менял;
//   - присоединение способа не пишет ни в человека, ни в его права и членства
//     (сторона хранилища Ф1-45/46) — и проверка этого способна покраснеть,
//     названо внесённым различием (аналог Ф1-47);
//   - обратный ход миграции ОТКАЗЫВАЕТСЯ уничтожать материал и отметки, не
//     теряет строку писателя, фиксирующего, пока откат ждёт замка, и, снятый
//     взаимной блокировкой (`40P01`), данных не трогает — повтор безопасен.
//
// # Почему у каждого отрицания стоит положительный контроль
//
// «Вставка отвергнута» истинно и тогда, когда отвергается ВСЁ. Поэтому рядом с
// каждым отказом стоит вставка, которая обязана пройти, и утверждается ИМЯ
// сработавшего ограничения, а не только код.
package migrations_test

import (
	"database/sql"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/pgtest"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/migrations"
)

// loginMethodMigration — файл, заводящий предмет этих проб. Имя стоит здесь
// одним литералом: по нему вычисляется версия для обратного хода, и второе
// написание разошлось бы с первым молча.
const loginMethodMigration = "20260915111233_login_methods_live_in_their_own_rows.sql"

// lmDB — база, приведённая цепочкой к концу.
func lmDB(t *testing.T) *sql.DB {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	return upAllIAMMigrations(t, pgtest.NewEmptyDB(t))
}

// lmDBAtOwn — база, приведённая РОВНО к предмету: миграции новее него сняты до
// сцены, и `DownTo(previous)` дальше — один шаг, откат самого предмета.
//
// Цепочка живёт дальше предмета: ствол кладёт новые файлы поверх, и
// `DownTo(previous)` от конца цепочки откатывает сперва их. Сцена, ждущая
// «откат стоит в очереди за замком писателя», увидела бы тогда замок ЧУЖОГО
// отката — соседняя миграция снимает колонку `users` и встаёт за писателем
// раньше, чем откат предмета возьмёт свою таблицу, — и цикл взаимной
// блокировки не замыкался бы никогда. Наблюдалось после слияния с
// накопительной: три файла новее предмета, проба взаимной блокировки красна
// три раза из трёх на пустой машине и зелёная на голове без них.
func lmDBAtOwn(t *testing.T) *sql.DB {
	t.Helper()
	db := lmDB(t)
	own, _ := loginMethodVersions(t)
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	require.NoError(t, goose.DownTo(db, ".", own), "миграции новее предмета обязаны сняться ДО сцены")
	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, own, version, "сцена начинается ровно на предмете, а не на конце цепочки")
	return db
}

// lmSeed заводит аккаунт, его владельца и ещё одного члена того же аккаунта.
// Член нужен пробам снятия: владельца аккаунта снять нельзя (`accounts_owner_fk`),
// и проба каскада упиралась бы в чужой ключ, а не в свой.
func lmSeed(t *testing.T, db *sql.DB, tag string) (owner, member string) {
	t.Helper()
	owner = "usr" + fmt.Sprintf("%017s", tag+"o")
	member = "usr" + fmt.Sprintf("%017s", tag+"m")
	account := "acc" + fmt.Sprintf("%017s", tag)

	tx, err := db.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`
		INSERT INTO kaname.users (id, external_id, email, display_name, account_id, invite_status)
		VALUES ($1, $2, $3, 'owner', $5, 'ACTIVE'),
		       ($4, $6, $7, 'member', $5, 'ACTIVE')`,
		owner, "ext-"+tag+"-o", tag+"-o@example.invalid",
		member, account, "ext-"+tag+"-m", tag+"-m@example.invalid")
	require.NoError(t, err, "посев людей %s", tag)
	_, err = tx.Exec(`INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`,
		account, "acc-"+tag, owner)
	require.NoError(t, err, "посев аккаунта %s", tag)
	require.NoError(t, tx.Commit())
	return owner, member
}

// lmInsert — вставка строки способа сырым оператором: предмет этих проб —
// СХЕМА, и путь через репозиторий отсёк бы негодный вход до базы.
func lmInsert(db *sql.DB, user, kind, verifier string) error {
	_, err := db.Exec(`INSERT INTO kaname.user_login_methods (user_id, kind, verifier) VALUES ($1, $2, $3)`,
		user, kind, verifier)
	return err
}

// requirePgRefusal утверждает ПАРУ «код состояния, имя ограничения».
func requirePgRefusal(t *testing.T, err error, code, constraint, why string) {
	t.Helper()
	require.Error(t, err, why)
	var pgErr *pgconn.PgError
	require.ErrorAs(t, err, &pgErr, "%s: отказ обязан прийти от базы", why)
	require.Equal(t, code, pgErr.Code, "%s: код состояния", why)
	if constraint != "" {
		require.Equal(t, constraint, pgErr.ConstraintName, "%s: сработать обязано ИМЕННО это ограничение", why)
	}
}

// lmDeclaredColumns — объявленный состав колонок строки способа: имя →
// допускает ли NULL. Состав ЗАКРЫТ: колонка, заведённая позже, делает пробу
// красной и требует решения, а не проходит незамеченной. Для таблицы, несущей
// секрет, это не педантизм: новая колонка — новое место, куда материал может
// лечь в другом виде.
//
// Четыре первых — Ф2 П1. Две последних — решение приёмки Ф12 (Р1, Р5, §4.1
// п.1; миграция `20260917160000_second_factor_rows_carry_state_and_step.sql`):
// состояние строки — непустое, с умолчанием `active` ради лежащих строк
// пароля; последний принятый шаг — NULL, пока шага не было. Обе судят
// `kind`/`state`/шаг и материала не несут. Расширение внесено ТЕМ ЖЕ приёмом,
// что у `lmDeclaredConstraints`: зелёная проба означает «лишних колонок ноль
// при объявленных шести», а не «состав не менялся». Столкновение ожиданий,
// из которого это выведено, — kaname#230.
var lmDeclaredColumns = map[string]string{
	"user_id":            "NO",
	"kind":               "NO",
	"verifier":           "NO",
	"created_at":         "NO",
	"state":              "NO",
	"last_accepted_step": "YES",
}

// lmKindOutsideEveryVocabulary — вид, которого нет НИ В ОДНОМ словаре:
// ни в ограничении схемы, ни в словаре способов предъявления Ф11 Р8
// (`assurance.Methods()`), откуда схема берёт имена. Прежняя редакция подавала
// `totp` — и была верна ровно до Ф12, которая внесла его в словарь. Значение
// вне словаря производителя законным стать не может ни одним решением, и это
// проверяется у самой пробы, а не помнится.
const lmKindOutsideEveryVocabulary = "probe_kind_outside_every_vocabulary"

// TestIntegration_LoginMethodIsARowNotAColumn — F4d-13.
func TestIntegration_LoginMethodIsARowNotAColumn(t *testing.T) {
	db := lmDB(t)
	owner, _ := lmSeed(t, db, "lmshape")

	rows, err := db.Query(`
		SELECT column_name, is_nullable
		  FROM information_schema.columns
		 WHERE table_schema = 'kaname' AND table_name = 'user_login_methods'
		 ORDER BY ordinal_position`)
	require.NoError(t, err)
	got := map[string]string{}
	var order []string
	for rows.Next() {
		var name, nullable string
		require.NoError(t, rows.Scan(&name, &nullable))
		got[name] = nullable
		order = append(order, name)
	}
	require.NoError(t, rows.Err())
	require.NoError(t, rows.Close())
	t.Logf("перепись: колонок у строки способа %d — %v", len(order), order)

	require.Equal(t, lmDeclaredColumns, got,
		"F4d-13: строка несёт владельца, вид, проверочный материал, состояние (Ф12 Р1) и последний "+
			"принятый шаг (Ф12 Р5); пуст бывает только шаг. Уровня доверия в строке нет и не будет (Ф11 Р1). "+
			"Колонка сверх объявленных — решение приёмки, а не молчаливый проход")

	// Колонки для самой человеческой почты у строки способа нет: адрес живёт
	// у человека, и второе место о нём разошлось бы с первым.
	_, hasEmail := got["email"]
	require.False(t, hasEmail, "адрес не дублируется в строку способа")

	// Исходный пароль НЕ ВЫРАЖАЕТСЯ — попытка положить его туда отвергнута
	// сервером как отсутствующее поле.
	_, err = db.Exec(`INSERT INTO kaname.user_login_methods (user_id, kind, verifier, password)
	                  VALUES ($1, 'password', 'x', 'plain')`, owner)
	requirePgRefusal(t, err, "42703", "", "F4d-13: поля для исходного пароля быть не должно")

	// Живой близнец: материал строка НЕСЁТ — вставка с ним проходит и читается.
	require.NoError(t, lmInsert(db, owner, "password", "$2a$12$lmshape.material"),
		"F4d-13, положительный контроль: строка с материалом заводится")
	var material string
	require.NoError(t, db.QueryRow(
		`SELECT verifier FROM kaname.user_login_methods WHERE user_id = $1 AND kind = 'password'`,
		owner).Scan(&material))
	require.Equal(t, "$2a$12$lmshape.material", material)
}

// TestIntegration_LoginMethodBelongsToAPersonAndLeavesWithHim — владение
// внешним ключом с каскадом.
func TestIntegration_LoginMethodBelongsToAPersonAndLeavesWithHim(t *testing.T) {
	db := lmDB(t)
	_, member := lmSeed(t, db, "lmfk")

	// Несуществующего человека способ не заводит.
	err := lmInsert(db, "usr0000000000000nobody", "password", "$2a$12$lmfk.ghost")
	requirePgRefusal(t, err, "23503", "user_login_methods_user_fk",
		"способ несуществующего человека обязан быть отвергнут ключом")

	// Положительный контроль: существующему — заводится.
	require.NoError(t, lmInsert(db, member, "password", "$2a$12$lmfk.member"))

	var before int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.user_login_methods WHERE user_id = $1`, member).Scan(&before))
	require.Equal(t, 1, before, "перепись до снятия: способ заведён")

	// Снятие человека уносит его способ — висячей строки с материалом не
	// остаётся ни на миг после фиксации.
	_, err = db.Exec(`DELETE FROM kaname.users WHERE id = $1`, member)
	require.NoError(t, err, "снятие члена аккаунта обязано пройти — иначе каскад не проверен вовсе")
	var after int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.user_login_methods WHERE user_id = $1`, member).Scan(&after))
	require.Zero(t, after, "способ обязан уйти вместе с человеком")
	t.Logf("перепись: способов человека до снятия %d, после %d", before, after)
}

// TestIntegration_LoginMethodIsUniquePerPersonAndKind — F4d-14.
//
// # Почему второй вид заводится ЗДЕСЬ, в изолированной базе пробы
//
// Без второго вида уникальность «по паре» и уникальность «по человеку»
// неотличимы НИ ОДНОЙ пробой. Словарь продукта с фазы Ф12 несёт три вида, но
// проба берёт не его, а СИНТЕТИЧЕСКИЙ вид: расширение словаря в базе пробы —
// ровно ОДИН факт (`testing.md` §«Гейт на класс», п.2), и он не привязан к
// продуктовому виду, у которого свои ограничения состояния. Заодно это и есть
// положительный контроль Р4 F4d: заведение ещё одного вида не требует правки
// ни одной существующей строки — что Ф12 затем сделала и в продукте.
func TestIntegration_LoginMethodIsUniquePerPersonAndKind(t *testing.T) {
	db := lmDB(t)
	owner, member := lmSeed(t, db, "lmuq")

	require.NoError(t, lmInsert(db, owner, "password", "$2a$12$lmuq.first"))
	var snapBefore string
	require.NoError(t, db.QueryRow(
		`SELECT to_jsonb(m)::text FROM kaname.user_login_methods m WHERE user_id = $1 AND kind = 'password'`,
		owner).Scan(&snapBefore))

	// Второй способ ТОГО ЖЕ вида тому же человеку — отказ уникальностью.
	err := lmInsert(db, owner, "password", "$2a$12$lmuq.second")
	requirePgRefusal(t, err, "23505", "user_login_methods_pkey",
		"F4d-14: второй способ того же вида отвергается уровнем базы")

	// Первый не изменился попыткой второго.
	var snapAfter string
	require.NoError(t, db.QueryRow(
		`SELECT to_jsonb(m)::text FROM kaname.user_login_methods m WHERE user_id = $1 AND kind = 'password'`,
		owner).Scan(&snapAfter))
	require.Equal(t, snapBefore, snapAfter, "F4d-14: отвергнутая попытка не тронула существующую строку")

	// Положительный контроль №1: ДРУГОЙ человек, тот же вид — проходит.
	// Уникальность не по виду.
	require.NoError(t, lmInsert(db, member, "password", "$2a$12$lmuq.member"),
		"уникальность обязана быть не по виду: другой человек заводит тот же вид")

	// Положительный контроль №2 (синтетический второй вид, см. шапку): ТОТ ЖЕ
	// человек, ДРУГОЙ вид — проходит. Уникальность не по человеку.
	var constraintDef string
	require.NoError(t, db.QueryRow(`
		SELECT pg_get_constraintdef(oid) FROM pg_constraint
		 WHERE conname = 'user_login_methods_kind_check'`).Scan(&constraintDef))
	require.Contains(t, constraintDef, "'password'", "словарь видов обязан быть объявлен ограничением")
	_, err = db.Exec(`
		ALTER TABLE kaname.user_login_methods DROP CONSTRAINT user_login_methods_kind_check;
		ALTER TABLE kaname.user_login_methods ADD CONSTRAINT user_login_methods_kind_check
		      CHECK (kind = ANY (ARRAY['password'::text, 'probe_second_kind'::text]))`)
	require.NoError(t, err, "расширение словаря в базе пробы обязано пройти без правки строк")

	var afterWiden string
	require.NoError(t, db.QueryRow(
		`SELECT to_jsonb(m)::text FROM kaname.user_login_methods m WHERE user_id = $1 AND kind = 'password'`,
		owner).Scan(&afterWiden))
	require.Equal(t, snapBefore, afterWiden,
		"Р4 F4d: заведение нового вида не требует правки ни одной существующей строки")

	require.NoError(t, lmInsert(db, owner, "probe_second_kind", "second-kind-material"),
		"F4d-14: тот же человек заводит способ ДРУГОГО вида — уникальность сужена парой")
	var kinds int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.user_login_methods WHERE user_id = $1`, owner).Scan(&kinds))
	require.Equal(t, 2, kinds, "F4d-14: оба способа сосуществуют двумя строками")

	// И тот же второй вид повторно — снова отказ тем же ключом.
	err = lmInsert(db, owner, "probe_second_kind", "second-kind-again")
	requirePgRefusal(t, err, "23505", "user_login_methods_pkey",
		"второй вид тоже уникален на человека")
}

// TestIntegration_LoginMethodRefusesAnEmptyMaterial — «материала нет» есть
// отсутствие строки, а не пустое значение в ней. Тип отвергает пустое раньше,
// база держит последний рубеж.
func TestIntegration_LoginMethodRefusesAnEmptyMaterial(t *testing.T) {
	db := lmDB(t)
	owner, member := lmSeed(t, db, "lmempty")

	err := lmInsert(db, owner, "password", "")
	requirePgRefusal(t, err, "23514", "user_login_methods_verifier_check",
		"пустой материал обязан быть отвергнут базой")

	// Вид вне словаря — значение, которого нет и у производителя словаря:
	// иначе проба утверждала бы о видах, которых просто ещё не завели.
	for _, m := range assurance.Methods() {
		require.NotEqual(t, m.String(), lmKindOutsideEveryVocabulary,
			"вид «вне словаря» обязан оставаться вне словаря производителя")
	}
	err = lmInsert(db, owner, lmKindOutsideEveryVocabulary, "$2a$12$lmempty.unknown")
	requirePgRefusal(t, err, "23514", "user_login_methods_kind_check",
		"вид вне словаря обязан быть отвергнут базой")

	_, err = db.Exec(`INSERT INTO kaname.user_login_methods (user_id, kind) VALUES ($1, 'password')`, owner)
	requirePgRefusal(t, err, "23502", "", "отсутствующий материал обязан быть отвергнут базой")

	// Положительный контроль: непустой материал известного вида проходит.
	require.NoError(t, lmInsert(db, member, "password", "$2a$12$lmempty.ok"))
}

// TestIntegration_LoginMethodIsKeyedByPersonID — ключ способа `users.id`.
//
// Внешний субъект у приглашённого пуст (`users_invite_status_consistency`) и
// принадлежит поставщику; почта изменяема. Способ, привязанный к любому из них,
// потерялся бы при активации либо при смене адреса.
func TestIntegration_LoginMethodIsKeyedByPersonID(t *testing.T) {
	db := lmDB(t)
	owner, _ := lmSeed(t, db, "lmpend")

	var account string
	require.NoError(t, db.QueryRow(`SELECT account_id FROM kaname.users WHERE id = $1`, owner).Scan(&account))
	pending := "usr" + fmt.Sprintf("%017s", "lmpendp")
	_, err := db.Exec(`
		INSERT INTO kaname.users (id, external_id, email, display_name, account_id, invite_status)
		VALUES ($1, '', 'lmpend-p@example.invalid', 'invitee', $2, 'PENDING')`, pending, account)
	require.NoError(t, err, "посев приглашённого")

	require.NoError(t, lmInsert(db, pending, "password", "$2a$12$lmpend.invitee"),
		"способ заводится приглашённому: ключ — идентификатор человека, а не внешний субъект")

	// Активация меняет внешний субъект и состояние — способ остаётся при том же id.
	_, err = db.Exec(`UPDATE kaname.users SET external_id = 'ext-lmpend-p', invite_status = 'ACTIVE' WHERE id = $1`, pending)
	require.NoError(t, err)
	// Смена адреса — тоже.
	_, err = db.Exec(`UPDATE kaname.users SET email = 'lmpend-p2@example.invalid' WHERE id = $1`, pending)
	require.NoError(t, err)

	var material string
	require.NoError(t, db.QueryRow(
		`SELECT verifier FROM kaname.user_login_methods WHERE user_id = $1 AND kind = 'password'`,
		pending).Scan(&material))
	require.Equal(t, "$2a$12$lmpend.invitee", material,
		"способ пережил активацию и смену адреса: он привязан к id, а не к внешнему субъекту и не к почте")
}

// verification читает момент подтверждения адреса человека.
func verification(t *testing.T, db *sql.DB, user string) sql.NullTime {
	t.Helper()
	var at sql.NullTime
	require.NoError(t, db.QueryRow(`SELECT email_verified_at FROM kaname.users WHERE id = $1`, user).Scan(&at))
	return at
}

func markVerified(t *testing.T, db *sql.DB, user string) {
	t.Helper()
	_, err := db.Exec(`UPDATE kaname.users SET email_verified_at = now() WHERE id = $1`, user)
	require.NoError(t, err)
	require.True(t, verification(t, db, user).Valid, "предусловие: адрес отмечен подтверждённым")
}

// TestIntegration_AddressVerificationIsBoundToTheValue — Д2.
//
// Подтверждённость есть свойство ЗНАЧЕНИЯ адреса, а не человека. Смена почты на
// чужую, сохранившая отметку, выглядела бы подтверждённой — и это предмет
// безопасности, а не аккуратности: подтверждённый адрес открывает действия,
// которые неподтверждённому закрыты (Ф1-06).
//
// Привязку держит база, одним оператором, какой бы писатель адрес ни менял:
// писателей почты у службы больше одного, и дисциплина каждого разошлась бы.
//
// Сравнение — ПОБАЙТОВОЕ. Смена одного регистра тоже снимает отметку: доказано
// было владение ТЕМ значением, которое подтверждали. Уникальность адреса при
// этом судится `lower(email)`, и это разные вопросы: «чей это адрес» и «что
// именно доказано».
func TestIntegration_AddressVerificationIsBoundToTheValue(t *testing.T) {
	db := lmDB(t)
	owner, _ := lmSeed(t, db, "lmver")

	require.False(t, verification(t, db, owner).Valid, "новый человек заводится неподтверждённым")

	// Положительный контроль №1: правка ДРУГОГО поля отметку не трогает —
	// иначе «снимает при смене адреса» было бы верно и о триггере, снимающем
	// её на любой правке.
	markVerified(t, db, owner)
	_, err := db.Exec(`UPDATE kaname.users SET display_name = 'renamed' WHERE id = $1`, owner)
	require.NoError(t, err)
	require.True(t, verification(t, db, owner).Valid, "правка имени не снимает подтверждённость")

	// Положительный контроль №2: адрес переписан ТЕМ ЖЕ значением — отметка
	// остаётся. Писатель, переписывающий поле своим же значением, законен.
	var email string
	require.NoError(t, db.QueryRow(`SELECT email FROM kaname.users WHERE id = $1`, owner).Scan(&email))
	_, err = db.Exec(`UPDATE kaname.users SET email = $2 WHERE id = $1`, owner, email)
	require.NoError(t, err)
	require.True(t, verification(t, db, owner).Valid, "тот же адрес не снимает подтверждённость")

	// Смена адреса — снимает.
	_, err = db.Exec(`UPDATE kaname.users SET email = 'lmver-new@example.invalid' WHERE id = $1`, owner)
	require.NoError(t, err)
	require.False(t, verification(t, db, owner).Valid, "Д2: смена адреса обязана снять подтверждённость")

	// Смена одного регистра — тоже снимает (побайтовая привязка, см. шапку).
	markVerified(t, db, owner)
	_, err = db.Exec(`UPDATE kaname.users SET email = 'LMVER-new@example.invalid' WHERE id = $1`, owner)
	require.NoError(t, err)
	require.False(t, verification(t, db, owner).Valid, "смена регистра — смена доказанного значения")

	// Отметку нельзя принести ВМЕСТЕ с новым адресом одним оператором: новое
	// значение ещё никто не подтверждал. Подтверждение нового адреса — отдельная
	// запись, сверяемая с ним.
	_, err = db.Exec(`UPDATE kaname.users SET email = 'lmver-third@example.invalid', email_verified_at = now() WHERE id = $1`, owner)
	require.NoError(t, err)
	require.False(t, verification(t, db, owner).Valid,
		"отметка, принесённая вместе с новым адресом, обязана быть снята: доказательства владения им нет")

	// Писатель, идущий путём конфликта вставки (`ON CONFLICT … DO UPDATE SET
	// email`), — тоже правка, и привязку обязан соблюдать: триггер строки не
	// различает, каким путём пришёл оператор.
	markVerified(t, db, owner)
	var account, ext string
	require.NoError(t, db.QueryRow(`SELECT account_id, external_id FROM kaname.users WHERE id = $1`, owner).Scan(&account, &ext))
	_, err = db.Exec(`
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ('usr0000000000lmverupsrt', $1, $2, 'lmver-upsert@example.invalid', 'x', 'ACTIVE')
		ON CONFLICT (external_id) WHERE external_id <> '' DO UPDATE SET email = EXCLUDED.email`,
		account, ext)
	require.NoError(t, err)
	require.False(t, verification(t, db, owner).Valid, "путь конфликта вставки меняет адрес и обязан снять отметку")
}

// lmPersonFootprint — всё, что принадлежит человеку ВНЕ таблицы способов:
// его строка, членства, выдачи, участие в группах и события журнала ресурсов о
// нём. Сверяется целиком до и после присоединения способа.
func lmPersonFootprint(t *testing.T, db *sql.DB) map[string]string {
	t.Helper()
	out := map[string]string{}
	for name, q := range map[string]string{
		"users":            `SELECT coalesce(jsonb_agg(to_jsonb(u) ORDER BY u.id), '[]')::text FROM kaname.users u`,
		"memberships":      `SELECT coalesce(jsonb_agg(to_jsonb(m) ORDER BY m.id), '[]')::text FROM kaname.memberships m`,
		"access_bindings":  `SELECT coalesce(jsonb_agg(to_jsonb(b) ORDER BY b.id), '[]')::text FROM kaname.access_bindings b`,
		"group_members":    `SELECT coalesce(jsonb_agg(to_jsonb(g) ORDER BY g.group_id, g.member_id), '[]')::text FROM kaname.group_members g`,
		"journal_of_users": `SELECT count(*)::text FROM kaname.resource_journal WHERE resource_kind = 'iam_user'`,
	} {
		var v string
		require.NoError(t, db.QueryRow(q).Scan(&v), "снимок %s", name)
		out[name] = v
	}
	return out
}

// lmFootprintDiff называет РАЗОШЕДШИЕСЯ части следа. Вывод — находка с
// координатой: «след изменился» без имени не восстанавливает, чей id сменился.
func lmFootprintDiff(before, after map[string]string) []string {
	var diff []string
	for k, v := range before {
		if after[k] != v {
			diff = append(diff, k)
		}
	}
	sort.Strings(diff)
	return diff
}

// TestIntegration_AttachingALoginMethodWritesNothingToThePerson — сторона
// хранилища Ф1-45/46: перенос (П3) присоединяет способ к существующему
// `users.id` и не обязан ради этого писать в человека. Хранилище это
// гарантирует: вставка строки способа не трогает ни строку человека, ни его
// членства, ни выдачи, ни журнал о нём.
//
// Внесённое различие (аналог Ф1-47): тот же снимок на базе, где присоединение
// ПИШЕТ в человека, обязан покраснеть и назвать, что именно изменилось. Без
// этого проба зеленела бы и на хранилище, скрывающем смену под присоединением.
func TestIntegration_AttachingALoginMethodWritesNothingToThePerson(t *testing.T) {
	db := lmDB(t)
	owner, member := lmSeed(t, db, "lmfoot")

	before := lmPersonFootprint(t, db)
	require.NotEqual(t, "[]", before["users"], "перепись: людей в снимке ноль — сверка беспредметна")
	require.NotEqual(t, "[]", before["memberships"], "перепись: членств в снимке ноль — сверка беспредметна")

	require.NoError(t, lmInsert(db, owner, "password", "$2a$12$lmfoot.owner"))
	require.NoError(t, lmInsert(db, member, "password", "$2a$12$lmfoot.member"))

	after := lmPersonFootprint(t, db)
	require.Empty(t, lmFootprintDiff(before, after),
		"присоединение способа изменило след человека: %v", lmFootprintDiff(before, after))

	// Внесённое различие: присоединение, пишущее в человека.
	_, err := db.Exec(`
		CREATE FUNCTION kaname.lm_probe_touch_person() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
		  UPDATE kaname.users SET display_name = display_name || '*' WHERE id = NEW.user_id;
		  RETURN NEW;
		END; $$;
		CREATE TRIGGER lm_probe_touch_person AFTER INSERT ON kaname.user_login_methods
		  FOR EACH ROW EXECUTE FUNCTION kaname.lm_probe_touch_person();`)
	require.NoError(t, err)
	_, third := lmSeed(t, db, "lmfoot2")
	before = lmPersonFootprint(t, db)
	require.NoError(t, lmInsert(db, third, "password", "$2a$12$lmfoot.third"))
	after = lmPersonFootprint(t, db)
	diff := lmFootprintDiff(before, after)
	require.Contains(t, diff, "users",
		"Ф1-47 (аналог): присоединение, переписавшее человека, обязано быть найдено сверкой следа")
	require.Contains(t, after["users"], third, "находка обязана указывать на изменённого человека")
	t.Logf("внесённое различие найдено: разошлись %v", diff)
}

// loginMethodVersions — версия файла предмета и версия, стоящая перед ним.
func loginMethodVersions(t *testing.T) (own, previous int64) {
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
		if e.Name() == loginMethodMigration {
			own = v
		}
	}
	require.NotZero(t, own, "файл предмета %s не найден в цепочке", loginMethodMigration)
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	for _, v := range versions {
		if v < own {
			previous = v
		}
	}
	require.NotZero(t, previous, "перед файлом предмета обязана стоять хотя бы одна миграция")
	return own, previous
}

// TestIntegration_LoginMethodRollbackRefusesToDestroyMaterial — обратный ход
// миграции не уничтожает материал.
//
// Материал перенесённого пароля — хеш, созданный ПРЕЖНИМ поставщиком. После его
// снятия (Ф10) взять этот хеш повторно негде: удалённая строка означает, что
// человек потерял вход, и вернуть его можно только сбросом — тем самым, от
// которого Р1 Ф1 отказывается как от способа миграции. Отказ отката — та же
// мера, что у стража секретов вида SECRET в откате свода.
//
// Обе стороны: с материалом откат отказан; без него — проходит.
func TestIntegration_LoginMethodRollbackRefusesToDestroyMaterial(t *testing.T) {
	db := lmDBAtOwn(t)
	owner, _ := lmSeed(t, db, "lmdown")
	_, previous := loginMethodVersions(t)

	require.NoError(t, lmInsert(db, owner, "password", "$2a$12$lmdown.material"))
	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))

	err := goose.DownTo(db, ".", previous)
	require.Error(t, err, "откат обязан отказать, пока хоть один способ хранит материал")
	require.Contains(t, err.Error(), "user_login_methods",
		"отказ обязан называть предмет, иначе оператор не знает, что именно откат уничтожил бы")
	var still int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.user_login_methods`).Scan(&still))
	require.Equal(t, 1, still, "отказанный откат не тронул материал")

	// Положительный контроль: без материала откат проходит, и таблица уходит.
	_, err = db.Exec(`DELETE FROM kaname.user_login_methods`)
	require.NoError(t, err)
	require.NoError(t, goose.DownTo(db, ".", previous), "без материала откат обязан пройти")
	var exists bool
	require.NoError(t, db.QueryRow(`SELECT to_regclass('kaname.user_login_methods') IS NOT NULL`).Scan(&exists))
	require.False(t, exists, "после отката таблицы нет")
	var hasColumn bool
	require.NoError(t, db.QueryRow(`
		SELECT EXISTS (SELECT 1 FROM information_schema.columns
		                WHERE table_schema = 'kaname' AND table_name = 'users'
		                  AND column_name = 'email_verified_at')`).Scan(&hasColumn))
	require.False(t, hasColumn, "после отката колонки подтверждённости нет")

	// И накат снова приводит схему к предмету — обратный ход не оставил мусора.
	require.NoError(t, goose.Up(db, "."), "повторный накат обязан пройти")
	require.NoError(t, db.QueryRow(`SELECT to_regclass('kaname.user_login_methods') IS NOT NULL`).Scan(&exists))
	require.True(t, exists)
}

// Что обязан назвать отказ отката: ЧИСЛО уничтожаемого по каждому предмету. Одно
// имя таблицы здесь не различало бы сцены — отказ называет оба предмета всегда.
const (
	lmRefusesMaterial = "1 login verifier row(s)"
	lmRefusesMarks    = "2 address verification mark(s)"
)

// rollbackScene — сцена обратного хода против писателя: один внесённый факт на
// сцену, остальное общее.
type rollbackScene struct {
	name string
	// write — оператор писателя; исполняется в ЕГО транзакции.
	write func(tx *sql.Tx, owner, member string) error
	// settle — фиксирует писатель ДО отката (true) либо ПОКА откат ждёт его
	// замка (false).
	settleBefore bool
	// commit — чем писатель заканчивает: фиксацией либо отказом от транзакции.
	commit bool
	// refuses — обязан ли откат отказать; пусто — обязан пройти.
	refuses string
}

// lmWriteMethod — писатель материала: вставка строки способа.
func lmWriteMethod(tx *sql.Tx, owner, _ string) error {
	_, err := tx.Exec(`INSERT INTO kaname.user_login_methods (user_id, kind, verifier)
	                   VALUES ($1, 'password', '$2a$12$lmrace.material')`, owner)
	return err
}

// lmWriteMarks — писатель отметок: две отметки подтверждения и ни одного способа.
func lmWriteMarks(tx *sql.Tx, owner, member string) error {
	_, err := tx.Exec(`UPDATE kaname.users SET email_verified_at = now() WHERE id IN ($1, $2)`, owner, member)
	return err
}

// TestIntegration_LoginMethodRollbackDoesNotRaceItsWriter — Б1 и Н1.
//
// # Предмет
//
// Защита отката — «посчитать, и если ноль — снести». Посчитанное и снесённое
// обязаны быть ОДНИМ состоянием таблицы: иначе писатель, зафиксировавший
// строку между подсчётом и сносом, теряет её, а откат возвращает успех. Под
// READ COMMITTED подсчёт не видит незафиксированной строки, а снос ждёт её
// замка — и дожидается фиксации, после которой уничтожает то, чего подсчёт не
// видел. Это проверка-затем-действие, запрещённая ban #10, только в миграции.
//
// Предмет Н1 — тот же, с другой колонкой: отметка подтверждения адреса после
// снятия прежнего поставщика не выводится ниоткуда, кроме этой колонки, и её
// снос — такая же невосстановимая потеря, как снос материала.
//
// # Как сцена создаёт гонку, не угадывая время
//
// Писатель держит транзакцию открытой; откат запускается рядом, и проба ЖДЁТ
// УСЛОВИЯ — пока в каталоге замков не появится ожидающий запрос отката на одну
// из двух таблиц. Только тогда писатель заканчивает. Порядок поэтому задан, а
// не выпал: сон здесь утверждал бы о расписании, а не о продукте.
//
// # Законные близнецы
//
// Писатель, зафиксировавший ДО отката, получает тот же отказ — это сцена, в
// которой защита работала и прежде. Писатель, ОТКАЗАВШИЙСЯ от транзакции, пока
// откат ждёт, материала не оставил — и откат обязан пройти: иначе «откат отказал»
// было бы верно и о защите, отказывающей всякому, кто ждал замка.
func TestIntegration_LoginMethodRollbackDoesNotRaceItsWriter(t *testing.T) {
	if testing.Short() {
		// Пропуск на уровне пробы, а не только сцен: иначе родитель отчитывался
		// бы зелёным при всех пропущенных сценах.
		t.Skip("integration: нужен Postgres в контейнере")
	}
	scenes := []rollbackScene{
		{name: "материал зафиксирован до отката", write: lmWriteMethod, settleBefore: true, commit: true,
			refuses: lmRefusesMaterial},
		{name: "материал фиксируется, пока откат ждёт замка", write: lmWriteMethod, commit: true,
			refuses: lmRefusesMaterial},
		{name: "писатель материала отказался от транзакции, пока откат ждёт", write: lmWriteMethod, commit: false},
		{name: "две отметки и ноль способов зафиксированы до отката", write: lmWriteMarks, settleBefore: true,
			commit: true, refuses: lmRefusesMarks},
		{name: "отметки фиксируются, пока откат ждёт замка", write: lmWriteMarks, commit: true,
			refuses: lmRefusesMarks},
	}
	_, previous := loginMethodVersions(t)
	for i, sc := range scenes {
		t.Run(sc.name, func(t *testing.T) {
			db := lmDBAtOwn(t)
			owner, member := lmSeed(t, db, fmt.Sprintf("lmrace%d", i))

			var tables []int64
			for _, rel := range []string{"kaname.user_login_methods", "kaname.users"} {
				var oid int64
				require.NoError(t, db.QueryRow(`SELECT $1::regclass::oid`, rel).Scan(&oid))
				tables = append(tables, oid)
			}

			tx, err := db.Begin()
			require.NoError(t, err)
			defer func() { _ = tx.Rollback() }()
			var writerPID int
			require.NoError(t, tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&writerPID))
			require.NoError(t, sc.write(tx, owner, member), "писатель обязан записать — иначе сцена беспредметна")
			if sc.settleBefore {
				require.NoError(t, tx.Commit())
			}

			goose.SetBaseFS(migrations.FS)
			require.NoError(t, goose.SetDialect("postgres"))
			done := make(chan error, 1)
			go func() { done <- goose.DownTo(db, ".", previous) }()

			var downErr error
			if sc.settleBefore {
				downErr = <-done
			} else {
				// Ждём УСЛОВИЯ: откат стоит в очереди за замком писателя.
				waited := false
				deadline := time.Now().Add(60 * time.Second)
				for !waited && time.Now().Before(deadline) {
					select {
					case downErr = <-done:
						t.Fatalf("откат завершился (%v), не дождавшись замка писателя — гонка не создана, сцена беспредметна", downErr)
					default:
					}
					var n int
					require.NoError(t, db.QueryRow(`
						SELECT count(*) FROM pg_locks
						 WHERE NOT granted AND pid <> $1 AND relation = ANY($2::oid[])`,
						writerPID, tables).Scan(&n))
					waited = n > 0
				}
				require.True(t, waited, "откат не встал в очередь за замком писателя за 60 с")
				if sc.commit {
					require.NoError(t, tx.Commit())
				} else {
					require.NoError(t, tx.Rollback())
				}
				select {
				case downErr = <-done:
				case <-time.After(60 * time.Second):
					t.Fatal("откат не завершился за 60 с после того, как писатель освободил замок")
				}
			}

			var tableLeft bool
			require.NoError(t, db.QueryRow(`SELECT to_regclass('kaname.user_login_methods') IS NOT NULL`).Scan(&tableLeft))
			var methods, marks int
			if tableLeft {
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.user_login_methods`).Scan(&methods))
			}
			var markColumn bool
			require.NoError(t, db.QueryRow(`
				SELECT EXISTS (SELECT 1 FROM information_schema.columns
				                WHERE table_schema = 'kaname' AND table_name = 'users'
				                  AND column_name = 'email_verified_at')`).Scan(&markColumn))
			if markColumn {
				require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.users WHERE email_verified_at IS NOT NULL`).Scan(&marks))
			}
			t.Logf("исход: ошибка отката %v; таблица способов на месте %v (строк %d); колонка отметок на месте %v (отметок %d)",
				downErr, tableLeft, methods, markColumn, marks)

			if sc.refuses == "" {
				require.NoError(t, downErr, "писатель не оставил ничего — откат обязан пройти")
				require.False(t, tableLeft, "прошедший откат снимает таблицу")
				return
			}
			require.Error(t, downErr, "откат обязан отказать: писатель зафиксировал то, что откат уничтожил бы")
			var pgErr *pgconn.PgError
			require.ErrorAs(t, downErr, &pgErr, "отказ обязан прийти от базы")
			require.Equal(t, "23001", pgErr.Code, "отказ — restrict_violation")
			require.Contains(t, downErr.Error(), sc.refuses, "отказ обязан называть то, что откат уничтожил бы")
			require.True(t, tableLeft, "отказанный откат не снял таблицу")
			require.True(t, markColumn, "отказанный откат не снял колонку отметок")
			if sc.refuses == lmRefusesMaterial {
				require.Equal(t, 1, methods, "материал писателя цел")
			} else {
				require.Equal(t, 2, marks, "отметки писателя целы")
			}
		})
	}
}

// TestIntegration_LoginMethodRollbackDeadlockLeavesDataIntact — откат, снятый
// взаимной блокировкой, данных не трогает, и его повтор безопасен.
//
// # Предмет
//
// Замок отката берёт таблицы в порядке «способы, люди». Писатель, взявший их в
// ОБРАТНОМ порядке — сперва строку человека, потом строку способа, — сходится с
// откатом во взаимной блокировке, и сервер снимает одну из сторон отказом
// `40P01 deadlock detected`. Этот текст говорит оператору только о самом
// факте; почему данные целы и что делать дальше, названо здесь:
//
//   - откат исполняется ОДНОЙ транзакцией мигратора, и замок — её первый
//     оператор. Снятая на нём, транзакция откатывается целиком — до подсчёта и
//     до сноса: сносить нечего, версия схемы не сдвигается;
//   - писатель доводит свою транзакцию, и его строки на месте;
//   - повторённый после писателя откат отказывает уже СВОИМ текстом (`23001`),
//     называющим, что он уничтожил бы. Повтор безопасен.
//
// Шапка отката в самой миграции об этом молчит, и это решение, а не пропуск:
// байты `.sql` входят в отпечаток предмета отчётов замера вердикта, и правка
// комментария требует пересъёма всех трёх отчётов. Пояснение живёт рядом с
// доказательством.
//
// # Как сцена задаёт жертву, не угадывая время
//
// Сервер проверяет взаимную блокировку ОДИН раз, спустя `deadlock_timeout` от
// начала ожидания, и жертвой становится проверивший. Писатель поднимает свой
// предел до минуты, откат живёт с умолчанием сервера, и писатель встаёт в
// очередь сразу после того, как в каталоге замков появился ожидающий запрос
// отката. Проверка отката приходит первой и находит цикл. Не нашла — жертвой
// через минуту стал бы писатель, и проба называет это несозданным порядком, а
// не вердиктом о продукте.
func TestIntegration_LoginMethodRollbackDeadlockLeavesDataIntact(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	db := lmDBAtOwn(t)
	owner, _ := lmSeed(t, db, "lmdead")
	own, previous := loginMethodVersions(t)

	var usersOID int64
	require.NoError(t, db.QueryRow(`SELECT 'kaname.users'::regclass::oid`).Scan(&usersOID))

	tx, err := db.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()
	_, err = tx.Exec(`SET LOCAL deadlock_timeout = '60s'`)
	require.NoError(t, err, "писатель обязан поднять свой предел — иначе жертву выбирает время")
	var writerPID int
	require.NoError(t, tx.QueryRow(`SELECT pg_backend_pid()`).Scan(&writerPID))
	// Порядок писателя — ОБРАТНЫЙ замку отката: сперва строка человека.
	_, err = tx.Exec(`UPDATE kaname.users SET email_verified_at = now() WHERE id = $1`, owner)
	require.NoError(t, err, "писатель обязан записать — иначе сцена беспредметна")

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	down := make(chan error, 1)
	go func() { down <- goose.DownTo(db, ".", previous) }()

	// Ждём УСЛОВИЯ: откат взял таблицу способов и стоит в очереди за людьми.
	waited := false
	for deadline := time.Now().Add(60 * time.Second); !waited && time.Now().Before(deadline); {
		select {
		case err := <-down:
			t.Fatalf("откат завершился (%v), не встав в очередь за писателем — порядок не создан", err)
		default:
		}
		var n int
		require.NoError(t, db.QueryRow(`
			SELECT count(*) FROM pg_locks WHERE NOT granted AND pid <> $1 AND relation = $2`,
			writerPID, usersOID).Scan(&n))
		waited = n > 0
	}
	require.True(t, waited, "откат не встал в очередь за писателем за 60 с — порядок не создан")

	// Писатель встаёт в очередь за откатом: цикл замкнут.
	insert := make(chan error, 1)
	go func() {
		_, err := tx.Exec(`INSERT INTO kaname.user_login_methods (user_id, kind, verifier)
		                   VALUES ($1, 'password', '$2a$12$lmdead.material')`, owner)
		insert <- err
	}()

	var downErr error
	select {
	case downErr = <-down:
	case <-time.After(30 * time.Second):
		t.Fatal("откат не завершился за 30 с — сервер не снял его, порядок не создан")
	}
	var pgErr *pgconn.PgError
	require.ErrorAs(t, downErr, &pgErr, "откат обязан быть снят сервером")
	require.Equal(t, "40P01", pgErr.Code, "жертва — откат, отказ — взаимная блокировка")

	select {
	case err := <-insert:
		require.NoError(t, err, "писатель обязан дописать, когда откат снят")
	case <-time.After(30 * time.Second):
		t.Fatal("писатель не дописал за 30 с после снятия отката")
	}
	require.NoError(t, tx.Commit())

	version, err := goose.GetDBVersion(db)
	require.NoError(t, err)
	require.Equal(t, own, version, "снятый откат не сдвинул версию схемы")
	var methods, marks int
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.user_login_methods`).Scan(&methods))
	require.NoError(t, db.QueryRow(`SELECT count(*) FROM kaname.users WHERE email_verified_at IS NOT NULL`).Scan(&marks))
	t.Logf("исход: откат снят %s; версия %d; строк способа %d; отметок %d", pgErr.Code, version, methods, marks)
	require.Equal(t, 1, methods, "материал писателя цел")
	require.Equal(t, 1, marks, "отметка писателя цела")

	// Повтор безопасен: откат отказывает уже своим текстом.
	err = goose.DownTo(db, ".", previous)
	require.ErrorAs(t, err, &pgErr, "повторённый откат обязан отказать базой")
	require.Equal(t, "23001", pgErr.Code, "повторённый откат отказывает текстом, называющим уничтожаемое")
	require.Contains(t, err.Error(), lmRefusesMaterial)
}

// lmVerificationTrigger — имя триггера, снимающего отметку при смене адреса.
const lmVerificationTrigger = "users_email_change_drops_verification"

// lmLaterBeforeUpdateNeighbours — пользовательские триггеры `users` вида BEFORE
// UPDATE FOR EACH ROW, чьё имя сортируется ПОСЛЕ нашего. Порядок триггеров
// одного вида задаётся именем (побайтово), и условие WHEN нашего вычисляется
// над строкой, какой её оставили стоящие ДО него.
func lmLaterBeforeUpdateNeighbours(t *testing.T, db *sql.DB) (later []string, sameKind int) {
	t.Helper()
	rows, err := db.Query(`
		SELECT tgname, tgname > $1 COLLATE "C"
		  FROM pg_trigger
		 WHERE tgrelid = 'kaname.users'::regclass AND NOT tgisinternal
		   AND (tgtype & 1) = 1 AND (tgtype & 2) = 2 AND (tgtype & 16) = 16
		 ORDER BY tgname COLLATE "C"`, lmVerificationTrigger)
	require.NoError(t, err)
	defer func() { _ = rows.Close() }()
	for rows.Next() {
		var name string
		var after bool
		require.NoError(t, rows.Scan(&name, &after))
		sameKind++
		if after {
			later = append(later, name)
		}
	}
	require.NoError(t, rows.Err())
	return later, sameKind
}

// TestIntegration_AddressVerificationTriggerHasNoLaterNeighbour — Н2.
//
// Граница нашего триггера: соседний BEFORE UPDATE-триггер на `users`, чьё имя
// сортируется ПОСЛЕ нашего, исполняется позже — и если он меняет адрес, условие
// нашего уже вычислено над прежним адресом, и отметка переживает смену. Сегодня
// таких соседей ноль, и проба это держит: сосед, заведённый завтра, требует
// решения, а не проходит незамеченным.
//
// Внесённое различие показывает, почему правило нужно, а не только что оно
// срабатывает: с таким соседом смена адреса ОСТАВЛЯЕТ отметку.
func TestIntegration_AddressVerificationTriggerHasNoLaterNeighbour(t *testing.T) {
	db := lmDB(t)
	later, sameKind := lmLaterBeforeUpdateNeighbours(t, db)
	t.Logf("перепись: триггеров BEFORE UPDATE FOR EACH ROW на users %d, из них после %s — %v",
		sameKind, lmVerificationTrigger, later)
	require.NotZero(t, sameKind, "свой триггер обязан найтись в переписи — иначе она не читает каталог")
	require.Empty(t, later,
		"BEFORE UPDATE-сосед после %s исполняется позже и может сменить адрес, не сняв отметку: "+
			"нужно решение — сосед не трогает адрес (доказать пробой) либо наш триггер переименовывается",
		lmVerificationTrigger)

	// Внесённое различие: сосед, сортирующийся после нашего и меняющий адрес.
	owner, _ := lmSeed(t, db, "lmn2")
	_, err := db.Exec(`
		CREATE FUNCTION kaname.lm_probe_rewrite_email() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN
		  IF NEW.display_name = 'rewrite-email' THEN
		    NEW.email := 'lmn2-rewritten@example.invalid';
		  END IF;
		  RETURN NEW;
		END; $$;
		CREATE TRIGGER zz_lm_probe_rewrite_email BEFORE UPDATE ON kaname.users
		  FOR EACH ROW EXECUTE FUNCTION kaname.lm_probe_rewrite_email();`)
	require.NoError(t, err)
	markVerified(t, db, owner)
	_, err = db.Exec(`UPDATE kaname.users SET display_name = 'rewrite-email' WHERE id = $1`, owner)
	require.NoError(t, err)
	var email string
	require.NoError(t, db.QueryRow(`SELECT email FROM kaname.users WHERE id = $1`, owner).Scan(&email))
	require.Equal(t, "lmn2-rewritten@example.invalid", email, "предпосылка: сосед сменил адрес")
	require.True(t, verification(t, db, owner).Valid,
		"граница наблюдаема: сосед после нашего сменил адрес, а отметка осталась")

	later, _ = lmLaterBeforeUpdateNeighbours(t, db)
	require.Equal(t, []string{"zz_lm_probe_rewrite_email"}, later, "перепись обязана назвать соседа по имени")
}
