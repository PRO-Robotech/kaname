// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// account_scope_ceilings_stop_applying_integration_test.go — величина области
// `ACCOUNT` перестаёт действовать, и потеря идёт В ОБЕ СТОРОНЫ.
//
// Задача `PRO-Robotech/kacho#2117`, приёмка `KAN-QUOTA-1`, сценарий `KAN-Q3-09`,
// условие готовности `DoD S3` п. 9. Фикстура — `F-KAN-Q3-SCOPE`.
//
// # Предмет: НАЗВАННАЯ цена принятого решения, а не дефект
//
// Решение `П25` перевыразило три собственных потолка службы доступа посадкой:
// внешнего авторитета в самостоятельной установке нет by construction, спросить
// величину не у кого. У посадки нет per-account измерения и быть не может — она
// объявляет ОДНУ величину на установку.
//
// Отсюда следствие, которое обязано быть названо, а не обнаружено арендатором:
// установка, где авторитет ограничил ОТДЕЛЬНЫЙ аккаунт, после наката получает
// величину посадки. Ось «безопасность» ban #18 отвергает расширение поверхности,
// не названное ни в одном артефакте, — а расширение здесь настоящее.
//
// # Почему в ОБЕ стороны, а не только «ослабление»
//
// Утверждение «после наката потолок стал равен величине посадки» зеленело бы на
// установке, где потолок не наступает ВООБЩЕ. Поэтому проба идёт по двум
// аккаунтам сразу и по каждому — в свою сторону:
//
//   - аккаунт `A` ограничен ЖЁСТЧЕ посадки (2 против 24) — после наката его
//     машина упирается в 24: это ОСЛАБЛЕНИЕ, и это цена решения;
//   - аккаунт `C` ограничен СЛАБЕЕ посадки (40 против 24) — после наката его
//     тридцать удостоверений СОХРАНЯЮТСЯ, а тридцать первое отвергается, и
//     отказ называет ДЕЙСТВУЮЩУЮ величину 24, а не прежнюю 40.
//
// Вторая половина — не украшение симметрии. Она ловит ровно тот класс, который
// нашёлся пробой на соседней полосе того же механизма: снимок величины,
// обновляемый ВМЕСТЕ со списанием, а не до него, доносит до арендатора прежнее
// число («предел 40» там, где предел уже 24). Текст отказа — часть контракта.
//
// # Отрицательный близнец — состояние ДО наката
//
// Проба утверждает исполнимость своего «Дано» до того, как что-либо менять:
// третье удостоверение машины `M` сегодня ОТВЕРГАЕТСЯ величиной 2, а тридцать
// удостоверений машины `K` сегодня ЗАКОННЫ. Без этой половины «третье
// удостоверение создаётся» было бы верно и на дереве, где область `ACCOUNT` не
// работала никогда.
//
// # Почему уведомления ловятся СОЕДИНЕНИЕМ, а не читаются из вывода наката
//
// Уведомление сервера (`RAISE NOTICE`/`RAISE WARNING`) библиотека отдаёт клиенту
// ТОЛЬКО при заданном обработчике. На штатной точке наката службы доступа он не
// задан — обработчик заведён в фундаменте (`pkg/migratorcli/notice.go`), а служба
// доступа отдельный Go-модуль и увидит его с бампом пина, не раньше. Предикат:
//
//	grep -n 'PRO-Robotech/kacho v0' services/iam/go.mod
//	git log -1 --format=%cI -- pkg/migratorcli/notice.go
//
// Поэтому утверждение «ОПЕРАТОР это видит» здесь НЕ делается и в прохождение не
// засчитывается: у такой доставки сегодня нет производителя (`П36`, предмет
// `ПР-11` — `PRO-Robotech/kacho#2544`). Проба утверждает более слабое и
// проверяемое: сервер это СКАЗАЛ — текст и пятое число переписи. Образец приёма
// назван приёмкой дословно и воспроизведён здесь:
// `services/vpc/internal/migrations/migration_0029_retired_contract_integration_test.go`.
//
// # Половина «пятое число переписи» СЕГОДНЯ НЕИСПОЛНИМА — и это ИЗМЕРЕНО
//
// Свод службы доступа объявляет `SET client_min_messages = warning`. `SET` без
// `LOCAL` переживает фиксацию своей транзакции и держится до конца СЕССИИ, а
// цепочку применяет одна сессия — значит `RAISE NOTICE` КАЖДОЙ последующей
// миграции сервер гасит раньше, чем оно уйдёт клиенту. Перепись `П35`, чей
// собственный комментарий обещает «печатается ВСЕГДА», не доходит ни до кого и
// не дойдёт даже после того, как обработчик уведомлений приедет с бампом пина.
//
// Радиус измерен: у службы доступа `RAISE NOTICE` несут 6 файлов миграций,
// девятью вхождениями, и все они позже объявления порога; у остальных шести
// служб порог сводом не глушится. Предикаты:
//
//	git grep -c 'RAISE NOTICE' -- 'services/iam/internal/migrations/*.sql'
//	git grep -n 'SET client_min_messages' -- 'services/*/internal/migrations/*.sql'
//
// Правку `П35` этот исход не выбирает: она ПРИМЕНЕНА (лежит в стволе продукта),
// а применённую миграцию править запрещено. Предмет заведён своей задачей —
// `PRO-Robotech/kacho#2560`; чинится он в тракте наката, а не в миграции.
//
// # Чего проба НЕ покрывает
//
// Внешнюю половину `KAN-Q3-09` (папка Newman `KAN-Q3-09/account-scope-loss`,
// настоящий процесс, край, полл `Operation`) — она принадлежит `DoD S3` п. 8 и
// требует поднятого стенда. Здесь предмет целиком лежит в базе: и потолок, и его
// источник, и текст отказа производит единственный атомарный оператор (ban #10),
// а не код службы.

package migrations_test

import (
	"context"
	"crypto/rand"
	"database/sql"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/ids"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// scopeLossKind — вид, к которому область `ACCOUNT` ПРИМЕНЯЛАСЬ. Он ровно один:
// `domain.AccountScopedKinds()` несёт единственный элемент, и согласие этого
// объявления с телом списания держит гейт `TestCredentialCeilingAnchor_AccountArmAgreesWithTheCatalogue`.
//
// Обещать ослабление у двух других собственных видов было бы утверждением о
// продукте неправды: строка области им могла быть назначена и не применялась
// ни разу.
const scopeLossKind = "iam.serviceAccount.credential"

// Величины «Дано» и посадки. Три первых объявляет ВНЕШНИЙ АВТОРИТЕТ установки
// версии до `П25`; четвёртая — поставляемый профиль (`П37`).
//
// Предикат производителя четвёртой:
//
//	grep -n -A3 '^ownCeilings:' services/iam/deploy/values.prod.yaml
//
// и она же пинится `services/iam/deploy/prod_profile_test.go`. Здесь число
// воспроизведено, а не прочитано из профиля намеренно: проба судит МЕХАНИЗМ
// (жёстче посадки → ослабло; слабее посадки → ужесточилось), и смена профиля не
// вправе её ронять — за профиль отвечает его собственный пин.
const (
	scopeLossDefaultCeiling = 9  // область DEFAULT у авторитета
	scopeLossTightCeiling   = 2  // область ACCOUNT аккаунта A — ЖЁСТЧЕ посадки
	scopeLossLooseCeiling   = 40 // область ACCOUNT аккаунта C — СЛАБЕЕ посадки
	scopeLossPosture        = 24 // величина поставляемого профиля (П37)

	// Потребление машины K на момент наката: больше посадки и меньше своей
	// прежней области. Обе стороны неравенства несущие — иначе «сохранились» и
	// «отвергнуто» не различались бы.
	scopeLossHeldByK = 30
)

// scopeLossNoticeSink — приёмник уведомлений соединения.
//
// Собирает и WARNING, и NOTICE: миграция говорит обоими, и утверждать надо оба —
// текст называет ЧТО перестало действовать, перепись называет СКОЛЬКО.
type scopeLossNoticeSink struct {
	mu    sync.Mutex
	lines []string
}

func (s *scopeLossNoticeSink) add(n *pgconn.Notice) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = append(s.lines, n.Severity+": "+n.Message)
}

func (s *scopeLossNoticeSink) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lines = nil
}

func (s *scopeLossNoticeSink) text() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return strings.Join(s.lines, "\n")
}

func (s *scopeLossNoticeSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.lines)
}

// ownCeilingsMigrationVersion — версия миграции `П35`, ВЫВЕДЕННАЯ из дерева, а не
// выписанная числом: выписанная разошлась бы с файлом молча при переименовании.
//
// Возвращает также версию НЕПОСРЕДСТВЕННО перед ней — это и есть «установка
// версии до `П25`»: ту же цепочку, теми же файлами продукта, остановленную на
// шаг раньше. Вручную сокращённая схема Given не воспроизводит.
func ownCeilingsMigrationVersion(t *testing.T) (before, target int64) {
	t.Helper()
	names, err := fs.Glob(migrations.FS, "*.sql")
	require.NoError(t, err)
	require.NotEmpty(t, names, "каталог миграций пуст: обходить нечего")

	versions := make([]int64, 0, len(names))
	for _, n := range names {
		head, _, ok := strings.Cut(n, "_")
		if !ok {
			continue
		}
		v, cerr := strconv.ParseInt(head, 10, 64)
		if cerr != nil {
			continue
		}
		versions = append(versions, v)
		if strings.Contains(n, "own_ceilings_come_from_the_posture") {
			target = v
		}
	}
	require.NotZerof(t, target, "миграция `П35` не найдена среди %d файлов цепочки: "+
		"предмет пробы производит именно она", len(names))
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })

	for i, v := range versions {
		if v == target {
			require.Positivef(t, i, "`П35` оказалась первой в цепочке: "+
				"состояния «до неё» не существует, и Given неисполним")
			before = versions[i-1]
			break
		}
	}
	return before, target
}

// scopeLossChain выдаёт пустую базу, применяет цепочку РОВНО до версии перед
// `П35` и отдаёт соединение вместе с приёмником уведомлений.
//
// Одно соединение на пробу: уведомление приходит по тому соединению, которое
// исполняло `DO`-блок, а пул мог бы отдать миграции одно, а утверждению другое.
func scopeLossChain(t *testing.T, before int64) (*sql.DB, string, *scopeLossNoticeSink) {
	t.Helper()
	dsn := pgtest.NewEmptyDB(t)

	cfg, err := pgx.ParseConfig(dsn)
	require.NoError(t, err)
	sink := &scopeLossNoticeSink{}
	cfg.OnNotice = func(_ *pgconn.PgConn, n *pgconn.Notice) { sink.add(n) }
	name := stdlib.RegisterConnConfig(cfg)
	t.Cleanup(func() { stdlib.UnregisterConnConfig(name) })

	db, err := sql.Open("pgx", name)
	require.NoError(t, err)
	t.Cleanup(func() { _ = db.Close() })
	db.SetMaxOpenConns(1)

	goose.SetBaseFS(migrations.FS)
	require.NoError(t, goose.SetDialect("postgres"))
	goose.SetLogger(goose.NopLogger())
	require.NoError(t, goose.UpTo(db, ".", before),
		"цепочка обязана дойти до версии перед `П35` — иначе Given не создан")
	return db, dsn, sink
}

// scopeLossSeedTenant сеет аккаунт, его владельца и машину ОДНОЙ транзакцией:
// аккаунт и владелец ссылаются друг на друга, ключи между ними отложены.
func scopeLossSeedTenant(t *testing.T, db *sql.DB, tag string) (accountID, ownerID, svaID string) {
	t.Helper()
	accountID = ids.NewID(domain.PrefixAccount)
	ownerID = ids.NewID(domain.PrefixUser)
	svaID = ids.NewID(domain.PrefixServiceAccount)

	tx, err := db.Begin()
	require.NoError(t, err)
	defer func() { _ = tx.Rollback() }()

	_, err = tx.Exec(`SET CONSTRAINTS ALL DEFERRED`)
	require.NoError(t, err)
	_, err = tx.Exec(`INSERT INTO kaname.accounts (id, name, owner_user_id, labels)
	                  VALUES ($1, $2, $3, '{}'::jsonb)`, accountID, "scope-loss-"+tag, ownerID)
	require.NoError(t, err, "посев аккаунта %s", tag)
	_, err = tx.Exec(`INSERT INTO kaname.users
	                    (id, account_id, external_id, email, display_name, invite_status)
	                  VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
		ownerID, accountID, "ext-scope-"+tag+"-"+ownerID,
		"scope-"+tag+"-"+ownerID+"@example.invalid", "Scope Loss "+tag)
	require.NoError(t, err, "посев владельца аккаунта %s", tag)
	_, err = tx.Exec(`INSERT INTO kaname.service_accounts (id, account_id, name)
	                  VALUES ($1, $2, $3)`, svaID, accountID, "scope-loss-sa-"+tag)
	require.NoError(t, err, "посев машины аккаунта %s", tag)
	require.NoError(t, tx.Commit(), "фиксация посева аккаунта %s", tag)
	return accountID, ownerID, svaID
}

// scopeLossStateLimit объявляет величину ТЕМ ЖЕ ОПЕРАТОРОМ и в ТОЙ ЖЕ таблице,
// в которую пишет прежний авторитет. Область `DEFAULT` уже посеяна сводом —
// её величина правится, а не заводится второй строкой: уникальный индекс
// `limits_scope_kind_uk` второй живой строки того же ключа не допускает.
func scopeLossStateLimit(t *testing.T, db *sql.DB, scope, scopeID string, value int64) {
	t.Helper()
	if scope == "DEFAULT" {
		res, err := db.Exec(`UPDATE kaname.limits SET limit_value = $2, revision = revision + 1
		                      WHERE scope = 'DEFAULT' AND kind = $1 AND withdrawn_at IS NULL`,
			scopeLossKind, value)
		require.NoError(t, err)
		n, err := res.RowsAffected()
		require.NoError(t, err)
		require.EqualValuesf(t, 1, n,
			"величины области DEFAULT вида %q у авторитета нет: Given неисполним, "+
				"а его недостижимость надо назвать, а не обойти", scopeLossKind)
		return
	}
	_, err := db.Exec(`INSERT INTO kaname.limits
	                     (id, scope, scope_id, kind, limit_value, revision)
	                   VALUES ($1, $2, $3, $4, $5, nextval('kaname.limits_revision_seq'))`,
		ids.NewHyphenID(ids.PrefixLimitHyphen), scope, scopeID, scopeLossKind, value)
	require.NoErrorf(t, err, "величина области %s %s не назначается: Given неисполним",
		scope, scopeID)
}

// scopeLossAddCredential вставляет удостоверение машины ТЕМ ЖЕ оператором, каким
// пишет продукт: решение о потолке принимает единственный атомарный оператор в
// той же транзакции, что вставка строки, и подать вход иначе нельзя.
func scopeLossAddCredential(db *sql.DB, svaID, createdBy string) error {
	id := ids.NewID(domain.PrefixSAOAuthClient)
	hash := make([]byte, 32)
	if _, err := rand.Read(hash); err != nil {
		return fmt.Errorf("свёртка секрета: %w", err)
	}
	_, err := db.Exec(`INSERT INTO kaname.service_account_oauth_clients
	    (id, sva_id, hydra_client_id, created_by_user_id, credential_kind, secret_hash,
	     public_key_pem, key_algorithm, trusted_subjects, expires_at)
	  VALUES ($1, $2, NULL, $3, 'SECRET', $4, '', '', '[]'::jsonb, now() + interval '30 days')`,
		id, svaID, createdBy, hash)
	return err
}

// scopeLossCredentials — сколько удостоверений у машины ЛЕЖИТ. Считается по
// таблице самих удостоверений, а не по строке учёта: строка учёта есть снимок, и
// проба, читающая её, утверждала бы о снимке, а не о ресурсах арендатора.
func scopeLossCredentials(t *testing.T, db *sql.DB, svaID string) int {
	t.Helper()
	var n int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.service_account_oauth_clients WHERE sva_id = $1`,
		svaID).Scan(&n))
	return n
}

func TestKANQ309AccountScopedCeilingsStopApplying(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}

	before, target := ownCeilingsMigrationVersion(t)
	db, dsn, sink := scopeLossChain(t, before)

	// ─── ДАНО: установка версии ДО `П25` ────────────────────────────────────
	accountA, ownerA, machineM := scopeLossSeedTenant(t, db, "a")
	accountC, ownerC, machineK := scopeLossSeedTenant(t, db, "c")

	scopeLossStateLimit(t, db, "DEFAULT", "", scopeLossDefaultCeiling)
	scopeLossStateLimit(t, db, "ACCOUNT", accountA, scopeLossTightCeiling)
	scopeLossStateLimit(t, db, "ACCOUNT", accountC, scopeLossLooseCeiling)

	// У машины `M` ровно два удостоверения…
	for i := 0; i < scopeLossTightCeiling; i++ {
		require.NoErrorf(t, scopeLossAddCredential(db, machineM, ownerA),
			"удостоверение %d машины M не создалось при величине области %d: "+
				"Given неисполним", i+1, scopeLossTightCeiling)
	}
	// …и третье СЕГОДНЯ отвергается величиной области, а не величиной DEFAULT.
	// Это отрицательный близнец всей пробы: без него «третье создаётся» ниже
	// зеленело бы на установке, где не работает ни один потолок.
	err := scopeLossAddCredential(db, machineM, ownerA)
	require.Errorf(t, err, "третье удостоверение машины M создалось при величине области %d: "+
		"область ACCOUNT не действует и ДО наката — проба судила бы не свою полосу",
		scopeLossTightCeiling)
	require.Containsf(t, err.Error(),
		fmt.Sprintf("has reached its limit of %d %s", scopeLossTightCeiling, scopeLossKind),
		"отказ до наката назвал не величину области")
	require.NotContainsf(t, err.Error(),
		fmt.Sprintf("has reached its limit of %d %s", scopeLossDefaultCeiling, scopeLossKind),
		"до наката действовала величина DEFAULT, а не область аккаунта: "+
			"приоритет областей сломан, и обе стороны потери измерялись бы не тем")

	// У машины `K` тридцать удостоверений законны — её область слабее посадки.
	for i := 0; i < scopeLossHeldByK; i++ {
		require.NoErrorf(t, scopeLossAddCredential(db, machineK, ownerC),
			"удостоверение %d машины K не создалось при величине области %d: "+
				"Given неисполним", i+1, scopeLossLooseCeiling)
	}
	require.Equal(t, scopeLossHeldByK, scopeLossCredentials(t, db, machineK))

	givenNotices := sink.count()
	sink.reset()

	// ─── КОГДА: оператор накатывает `П35` ───────────────────────────────────
	require.NoError(t, goose.UpTo(db, ".", target), "накат `П35` обязан проходить")
	saidByServer := sink.text()
	require.NotEmptyf(t, saidByServer,
		"накат не сказал НИ ОДНОГО уведомления: приёмник стоял (до наката получено %d), "+
			"значит либо `DO`-блок не исполнился, либо уведомления потерялись — "+
			"«ноль сказанного» и «никто не слушал» неотличимы без этой проверки", givenNotices)

	// ─── ТОГДА 1: снятая величина названа ПОИМЁННО, а не сведена к числу ────
	for _, want := range []string{
		fmt.Sprintf("ACCOUNT %s %s = %d", accountA, scopeLossKind, scopeLossTightCeiling),
		fmt.Sprintf("ACCOUNT %s %s = %d", accountC, scopeLossKind, scopeLossLooseCeiling),
	} {
		require.Containsf(t, saidByServer, want,
			"накат не назвал снятую величину «%s»: оператор обязан узнать, ЧТО именно "+
				"перестало действовать, а не «сколько строк». Сказано было:\n%s",
			want, saidByServer)
	}

	// ─── ТОГДА 2: пятое число переписи равно двум ───────────────────────────
	//
	// Перепись считает то же надмножество, которое перечислено выше: отбор идёт
	// БЕЗ условия на отзыв и включает область `PROJECT`. Поэтому утверждается
	// 2 — по строке на `A` и `C`, — а не «столько, сколько ограничивало».
	//
	// СЕГОДНЯ ЭТА ПОЛОВИНА НЕИСПОЛНИМА, и причина ИЗМЕРЕНА, а не предположена:
	// свод службы доступа объявляет `SET client_min_messages = warning`
	// (`0001_initial.sql`), а `SET` без `LOCAL` переживает фиксацию своей
	// транзакции и держится до конца СЕССИИ. Цепочку применяет одна сессия,
	// значит всякое `RAISE NOTICE` каждой последующей миграции сервер гасит
	// раньше, чем оно уйдёт клиенту. Опыт — один факт различия: до цепочки порог
	// `notice` и `NOTICE` доставляется, после цепочки порог `warning` и
	// доставляется только `WARNING`.
	//
	// Поэтому ветвь выбирается ИЗМЕРЕННЫМ состоянием мира, а не переключателем, и
	// послабление ИСТЕКАЕТ САМО: как только порог перестанет глотать `NOTICE`,
	// первая ветвь покраснеет и потребует вернуть настоящее утверждение.
	// Правку самой `П35` этот исход не выбирает: она применена (лежит в стволе
	// продукта), а применённую миграцию править запрещено — предмет заведён
	// отдельной задачей `PRO-Robotech/kacho#2560`.
	var threshold string
	require.NoError(t, db.QueryRow(`SHOW client_min_messages`).Scan(&threshold))
	const censusLine = "величин областей перестало действовать 2"
	if threshold == "warning" {
		require.NotContainsf(t, saidByServer, censusLine,
			"порог сессии `%s` обязан глотать перепись, а она доставлена: причина "+
				"отсутствия отпала, и половина ниже перестала быть неисполнимой — "+
				"верните утверждение переписи вместо этого послабления", threshold)
		t.Logf("НЕ ВЫПОЛНИЛОСЬ: пятое число переписи наката не проверено — "+
			"порог сессии `client_min_messages` = %q гасит `RAISE NOTICE` цепочки "+
			"(объявлен сводом `0001_initial.sql`). В прохождение не засчитывается "+
			"и из вердикта не вычитается", threshold)
	} else {
		require.Containsf(t, saidByServer, censusLine,
			"пятое число переписи наката не равно двум при пороге сессии %q. "+
				"Сказано было:\n%s", threshold, saidByServer)
	}

	// ─── ТОГДА 3: у авторитета не осталось строк этого вида НИ ОДНОЙ области ─
	var leftAtAuthority int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.limits WHERE kind = $1`, scopeLossKind).Scan(&leftAtAuthority))
	require.Zerof(t, leftAtAuthority,
		"строка вида %q осталась у авторитета: назначенное там было бы принято, "+
			"сохранено и не применено ни разу — списание читает проекцию посадки", scopeLossKind)

	// ЗАКОННЫЙ БЛИЗНЕЦ снятия: величина ЧУЖОГО вида у авторитета остаётся.
	// Без него «строк нет» зеленело бы на дереве, где пять потребителей потеряли
	// свои потолки, — а снятие авторитета целиком предмет стадии S4, не этой.
	var foreign int
	require.NoError(t, db.QueryRow(
		`SELECT count(*) FROM kaname.limits WHERE kind = 'vpc.network'`).Scan(&foreign))
	require.NotZero(t, foreign,
		"снятие ушло шире своего предмета: величина чужого вида снята вместе с собственными")

	// ─── КОГДА 2: первый пуск новой версии ──────────────────────────────────
	//
	// Величину проецирует ТОТ ЖЕ оператор, каким её пишет композиционный корень,
	// а не копия его текста: копия разошлась бы с ним молча.
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	accounts, users, machines := int64(5), int64(12), int64(scopeLossPosture)
	posture := config.OwnCeilingsConfig{
		AccountsPerIdentity:          &accounts,
		CredentialsPerUser:           &users,
		CredentialsPerServiceAccount: &machines,
	}
	census, err := pg.NewOwnCeilingRepo(pool).Apply(ctx, posture.Stated())
	require.NoError(t, err, "проекция посадки обязана применяться")
	require.Equal(t, 3, census.Stated, "посадка объявляет три величины")

	// ─── ТОГДА 4: ОСЛАБЛЕНИЕ — машина `M` упирается в величину посадки ──────
	for i := scopeLossTightCeiling; i < scopeLossPosture; i++ {
		require.NoErrorf(t, scopeLossAddCredential(db, machineM, ownerA),
			"удостоверение %d машины M отвергнуто при величине посадки %d: "+
				"после наката потолок обязан быть величиной посадки, а не прежней областью",
			i+1, scopeLossPosture)
	}
	require.Equal(t, scopeLossPosture, scopeLossCredentials(t, db, machineM),
		"у машины M не столько удостоверений, сколько разрешает посадка")

	err = scopeLossAddCredential(db, machineM, ownerA)
	require.Errorf(t, err, "удостоверение сверх величины посадки %d создалось: "+
		"потолок перестал наступать вовсе, и «ослабление» означало бы снятие", scopeLossPosture)
	require.Contains(t, err.Error(),
		fmt.Sprintf("has reached its limit of %d %s", scopeLossPosture, scopeLossKind),
		"отказ машины M назвал не действующую величину")

	// ─── ТОГДА 5: УЖЕСТОЧЕНИЕ — тридцать сохранены, тридцать первое отвергнуто ─
	require.Equalf(t, scopeLossHeldByK, scopeLossCredentials(t, db, machineK),
		"удостоверения машины K не сохранились: накат снял ресурсы арендатора, "+
			"а обещано было лишь перестать назначать новые сверх величины")

	err = scopeLossAddCredential(db, machineK, ownerC)
	require.Error(t, err, "тридцать первое удостоверение машины K создалось при потреблении "+
		"выше величины посадки: ужесточение не наступило")
	require.Containsf(t, err.Error(),
		fmt.Sprintf("has reached its limit of %d %s", scopeLossPosture, scopeLossKind),
		"отказ машины K назвал не действующую величину. Полный текст: %s", err.Error())
	require.NotContainsf(t, err.Error(),
		fmt.Sprintf("has reached its limit of %d %s", scopeLossLooseCeiling, scopeLossKind),
		"отказ назвал ПРЕЖНЮЮ величину %d: снимок величины обновляется вместе со "+
			"списанием, а не до него, и арендатор читает предел, которого уже нет",
		scopeLossLooseCeiling)

	t.Logf("перепись `KAN-Q3-09`: цепочка остановлена на %d, накачена до %d; "+
		"величин области назначено 2 (жёстче посадки %d, слабее посадки %d), "+
		"уведомлений наката получено %d (до наката %d); "+
		"удостоверений у M %d, у K %d; величина посадки %d",
		before, target, scopeLossTightCeiling, scopeLossLooseCeiling,
		len(strings.Split(saidByServer, "\n")), givenNotices,
		scopeLossCredentials(t, db, machineM), scopeLossCredentials(t, db, machineK),
		scopeLossPosture)
}
