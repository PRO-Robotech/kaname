// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package scopesourcecensus_test

// census_integration_test.go — S1 приёмки R7-4: МЕРКА.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПРОБЫ ГОНЯЮТ САМ СКРИПТ, А НЕ ЕГО КОПИЮ
//
// Перепись — прибор, и судить надо ЕГО, а не пересказ его логики на Go. Проба,
// переписавшая запрос и разбор у себя, доказывала бы согласие двух своих же
// записей и осталась бы зелёной при любой правке скрипта. Поэтому здесь
// исполняется `deploy/load-tests/iam-scope-source-census.sh` — тот самый файл,
// который запускают на стенде, — через переносимый путь `PSQL_DSN`. Оба пути
// исполняют ОДИН запрос: тот, что печатает генератор.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО БЫЛО КРАСНЫМ ДО РАБОТЫ И ПОЧЕМУ
//
// Прежняя перепись строила таблицу полным внешним соединением с группировкой по
// типу и печатала ДВА числа. Из этого следовало три дефекта, и каждый из них
// проба ниже ловит:
//
//	R7-4-01 — тип с нулём объектов С ОБЕИХ СТОРОН в вывод не попадал ВОВСЕ, а
//	          объём осмотренного («сколько типов из скольких объявлено») не
//	          печатался: «о типе не сказано» было неотличимо от «у типа всё
//	          хорошо»;
//	R7-4-02 — чисел было два, и «законно без предка» некуда было отнести:
//	          системная роль (у неё нет владеющего аккаунта ПО ПРАВИЛУ схемы)
//	          считалась потерей, то есть предмет выглядел ХУЖЕ, чем он есть;
//	R7-4-03 — послабление прощало ОБЕ полярности разом, выводя тип из-под
//	          сторожа целиком: следующая настоящая потеря по нему была бы
//	          невидима.
//
// Замер на стенде до достройки (перепись новой мерки): строк, чьего предка
// называет источник и не видит цепь, — 640. Прежняя мерка называла 15 085 —
// разница в том, что она считала потерями 14 454 объекта, у которых НЕТ СТРОКИ
// (их не существует), и 50 системных ролей, у которых предка не должно быть.

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/pkg/gitenv"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

const censusScript = "deploy/load-tests/iam-scope-source-census.sh"

// censusRun — исход прогона прибора: три категории, и третья не вычитается.
type censusRun struct {
	code   int
	stdout string
	stderr string
}

func (r censusRun) all() string { return r.stdout + "\n" + r.stderr }

func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := gitenv.Command("", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("корень дерева не установлен (%v): пробе негде взять прибор, и её "+
			"молчание не означало бы исправности переписи", err)
	}
	return strings.TrimSpace(string(out))
}

// runCensus исполняет ПРИБОР против названной базы.
func runCensus(t *testing.T, dsn string, env ...string) censusRun {
	t.Helper()
	if _, err := exec.LookPath("psql"); err != nil {
		t.Skipf("psql не установлен: прибор исполнить нечем (%v)", err)
	}
	root := repoRoot(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, "bash", filepath.Join(root, censusScript)) // #nosec G204 -- путь собран из корня СОБСТВЕННОГО дерева и константы пакета, снаружи сюда не приходит ничего
	cmd.Dir = root
	cmd.Env = append(os.Environ(), append([]string{"PSQL_DSN=" + dsn}, env...)...)
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	code := 0
	var ee *exec.ExitError
	if err != nil {
		if ok := asExitError(err, &ee); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("прибор не запустился (%v): это НЕ вердикт переписи, а «условие не "+
				"создано» на стороне пробы.\n%s", err, errb.String())
		}
	}
	return censusRun{code: code, stdout: out.String(), stderr: errb.String()}
}

func asExitError(err error, target **exec.ExitError) bool {
	if ee, ok := err.(*exec.ExitError); ok {
		*target = ee
		return true
	}
	return false
}

func openDB(t *testing.T) (context.Context, *pgx.Conn, string) {
	t.Helper()
	dsn := pgtest.NewDB(t)
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("подключение к базе пробы: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(context.Background()) })
	return ctx, conn, dsn
}

// seedTx исполняет весь посев в ОДНОЙ транзакции.
//
// Не удобство: ссылки `accounts.owner_user_id → users.id` и
// `users.account_id → accounts.id` ВЗАИМНЫ и объявлены отложенными
// (DEFERRABLE INITIALLY DEFERRED). Порознь, в автофиксации, каждая проверяется
// на своём же коммите, и завести пару «аккаунт с владельцем» нельзя ни в каком
// порядке. Отложенность существует ровно для этого; посев обязан ею
// пользоваться, а не обходить пустым владельцем.
func seedTx(t *testing.T, ctx context.Context, conn *pgx.Conn, seed func(pgx.Tx)) {
	t.Helper()
	tx, err := conn.Begin(ctx)
	if err != nil {
		t.Fatalf("посев: транзакция не начата: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	seed(tx)
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("посев: фиксация отвергнута (%v).\nОтложенные ссылки проверяются НА "+
			"КОММИТЕ, поэтому отказ здесь означает, что посев оставил пару "+
			"«аккаунт ↔ владелец» несогласованной", err)
	}
}

func mustExec(t *testing.T, ctx context.Context, tx pgx.Tx, sql string, args ...any) {
	t.Helper()
	if _, err := tx.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("посев (%s): %v", sql, err)
	}
}

// censusRow — одна строка таблицы переписи, разобранная из вывода прибора.
type censusRow struct {
	Total, InChain, NoParentOK, Lost, Extra, NoRow int
}

var reCensusRow = regexp.MustCompile(`^\s{2}([a-z_]+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$`)

func parseCensus(t *testing.T, out string) map[string]censusRow {
	t.Helper()
	rows := map[string]censusRow{}
	for _, line := range strings.Split(out, "\n") {
		m := reCensusRow.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		n := func(i int) int { v, _ := strconv.Atoi(m[i]); return v }
		rows[m[1]] = censusRow{n(2), n(3), n(4), n(5), n(6), n(7)}
	}
	return rows
}

// seedBaseline кладёт кластер и аккаунт — минимум, без которого цепь пуста и
// перепись честно отвечает «условие не создано».
func seedBaseline(t *testing.T, ctx context.Context, conn *pgx.Conn, extra ...func(pgx.Tx)) {
	t.Helper()
	seedTx(t, ctx, conn, func(tx pgx.Tx) {
		// Строка журнала — ЕДИНСТВЕННЫМ производителем проекции: триггер на
		// kaname.fga_outbox. Посев прямо в relation_fact обошёл бы его и
		// доказывал бы работу на данных, которые продукт произвести не может.
		mustExec(t, ctx, tx, `
			INSERT INTO kaname.fga_outbox (event_type, payload, created_at)
			VALUES ('fga.tuple.write',
			        jsonb_build_object('user', 'cluster:' || (SELECT id FROM kaname.clusters LIMIT 1),
			                           'relation', 'cluster',
			                           'object', 'project:' || $1::text), now())`, "prj-census-1")
		// Аккаунт и его владелец — пара со взаимными отложенными ссылками.
		mustExec(t, ctx, tx, `
			INSERT INTO kaname.accounts (id, name, owner_user_id, created_at)
			VALUES ($1, 'census', $2, now())`, "acc-census-1", "usr-census-owner")
		mustExec(t, ctx, tx, `
			INSERT INTO kaname.users (id, external_id, email, account_id, created_at)
			VALUES ($1, 'ext-census-owner', 'owner@example.invalid', $2, now())`,
			"usr-census-owner", "acc-census-1")
		for _, f := range extra {
			f(tx)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// R7-4-01: перепись отличает «ноль находок» от «ноль прочитанного» ПО КАЖДОМУ ТИПУ

// TestR7_4_01_CensusSpeaksAboutEveryDeclaredTypeIncludingEmptyOnes утверждает
// ИСХОД: в выводе есть строка по КАЖДОМУ выводимому типу, включая типы, у
// которых ноль объектов с обеих сторон, и напечатан объём осмотренного.
//
// Красное до правки: прежняя перепись строила таблицу полным внешним
// соединением с группировкой, поэтому тип с нулями не попадал в вывод ВОВСЕ, а
// «сколько типов из скольких объявлено» не печаталось нигде.
func TestR7_4_01_CensusSpeaksAboutEveryDeclaredTypeIncludingEmptyOnes(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx, conn, dsn := openDB(t)
	seedBaseline(t, ctx, conn)

	run := runCensus(t, dsn)
	rows := parseCensus(t, run.stdout)

	plans, err := PlansForTest()
	if err != nil {
		t.Fatalf("перечень типов не выведен: %v", err)
	}
	if len(plans) == 0 {
		t.Fatalf("перечень выводимых типов ПУСТ: проба сторожила бы пустоту")
	}
	for _, p := range plans {
		if _, ok := rows[p.ModelType]; !ok {
			t.Errorf("перепись НЕ ВЫСКАЗАЛАСЬ о типе %q.\n"+
				"Тип, о котором не сказано, — НАХОДКА, а не пропуск: его молчание "+
				"неотличимо от «у него всё хорошо».\nВывод:\n%s", p.ModelType, run.stdout)
		}
	}
	// Положительный контроль объёма: без него «строка есть по каждому типу»
	// зеленело бы и на приборе, который печатает заголовки и ничего не читает.
	if !strings.Contains(run.stdout, "осмотрено типов:") {
		t.Errorf("перепись не напечатала, СКОЛЬКО типов осмотрено из скольких объявлено:\n%s",
			run.stdout)
	}
	if !strings.Contains(run.stdout, "осмотрено: прямых фактов") {
		t.Errorf("перепись не напечатала объём прочитанного (факты, указатели, рёбра):\n%s",
			run.stdout)
	}
	want := "осмотрено типов: " + strconv.Itoa(len(plans)) + " из " + strconv.Itoa(len(plans))
	if !strings.Contains(run.stdout, want) {
		t.Errorf("объём осмотренного не сошёлся: ждали %q\n%s", want, run.stdout)
	}
}

// TestR7_4_01_CensusRefusesWhenThereIsNothingToRead — вторая половина сценария.
//
// На входе, где читать нечего, прибор обязан ответить «УСЛОВИЕ НЕ СОЗДАНО»
// (код 3), а не «расхождений нет». Третий исход не вычитается из вердикта: тот
// же ноль даёт и здоровое дерево, и пустая база.
func TestR7_4_01_CensusRefusesWhenThereIsNothingToRead(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	_, _, dsn := openDB(t)
	run := runCensus(t, dsn)
	if run.code != 3 {
		t.Fatalf("на пустой базе прибор вернул %d, а обязан 3 («условие не создано»).\n"+
			"«Расхождений нет» здесь означало бы «ничего не прочитано».\n%s",
			run.code, run.all())
	}
	if !strings.Contains(run.all(), "УСЛОВИЕ НЕ СОЗДАНО") {
		t.Errorf("прибор не назвал третий исход словами:\n%s", run.all())
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// R7-4-02: «объект без предка» посчитан ОТДЕЛЬНО от «предок потерян»

// TestR7_4_02_LegitimatelyParentlessIsCountedApartFromLost — три числа на тип, и
// различает их ПРЕДИКАТ ПО ИСТОЧНИКУ, а не перечень идентификаторов.
//
// Проба несёт ОБЕ стороны: без положительного близнеца («аккаунтная роль,
// у которой предок обязан быть») категория «законно без предка» поглотила бы
// настоящую потерю, и перепись выглядела бы ЧИЩЕ, чем есть.
func TestR7_4_02_LegitimatelyParentlessIsCountedApartFromLost(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx, conn, dsn := openDB(t)
	seedBaseline(t, ctx, conn)

	// БАЗОВЫЙ ЗАМЕР — до посева. Утверждается ПРИРОСТ, а не абсолют: миграции
	// продукта уже сеют системные роли и привязки, и абсолютное число «должно
	// быть 1» сломалось бы от первой же новой миграции, ничего не сказав о
	// свойстве. Прирост принадлежит ровно тому, что посеяла проба.
	before := parseCensus(t, runCensus(t, dsn).stdout)

	seedTx(t, ctx, conn, func(tx pgx.Tx) {
		// СИСТЕМНАЯ роль: якорь — кластер, ни аккаунта, ни проекта. Предка у неё
		// быть НЕ ДОЛЖНО: строка без владеющего аккаунта не может стать
		// достижимой ни из одного аккаунта.
		mustExec(t, ctx, tx, `
		INSERT INTO kaname.roles (id, name, permissions, rules, cluster_id, created_at)
		VALUES ($1, 'census.system', '["storage.volumes.*.get"]'::jsonb,
		        '[{"verbs": ["get"], "module": "storage", "resources": ["volumes"]}]'::jsonb,
		        (SELECT id FROM kaname.clusters LIMIT 1), now())`,
			"rol-census-sys")
		// АККАУНТНАЯ роль — ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: у неё предок обязан быть.
		// Без него «законно без предка» поглотило бы настоящую потерю, и
		// перепись выглядела бы ЧИЩЕ, чем есть.
		mustExec(t, ctx, tx, `
		INSERT INTO kaname.roles (id, name, permissions, rules, account_id, created_at)
		VALUES ($1, 'census_account', '["storage.volumes.*.get"]'::jsonb,
		        '[{"verbs": ["get"], "module": "storage", "resources": ["volumes"]}]'::jsonb,
		        $2, now())`,
			"rol-census-acc", "acc-census-1")
		// Привязка с областью ВНЕ закрытого набора — тоже законно без предка.
		mustExec(t, ctx, tx, `
		INSERT INTO kaname.access_bindings (id, resource_type, resource_id, role_id,
		                                       subject_type, subject_id, scope, created_at)
		VALUES ($1, 'vpc_network', 'net-census-1', $2, 'user', 'usr-census-owner', 3, now())`,
			"abn-census-res", "rol-census-acc")
		// Привязка с областью В наборе — положительный близнец.
		mustExec(t, ctx, tx, `
		INSERT INTO kaname.access_bindings (id, resource_type, resource_id, role_id,
		                                       subject_type, subject_id, scope, created_at)
		VALUES ($1, 'account', $2, $3, 'user', 'usr-census-owner', 2, now())`,
			"abn-census-acc", "acc-census-1", "rol-census-acc")
	})

	run := runCensus(t, dsn)
	after := parseCensus(t, run.stdout)

	delta := func(ty string, pick func(censusRow) int) int {
		return pick(after[ty]) - pick(before[ty])
	}
	noParent := func(r censusRow) int { return r.NoParentOK }
	inChain := func(r censusRow) int { return r.InChain }
	lost := func(r censusRow) int { return r.Lost }

	if got := delta("iam_role", noParent); got != 1 {
		t.Errorf("системная роль обязана попасть в «без предка ЗАКОННО»: прирост %d, ждали 1.\n"+
			"Посчитать её потерей значит показать предмет ХУЖЕ, чем он есть, и следующий "+
			"читатель начнёт «чинить» законное.\n%s", got, run.stdout)
	}
	if got := delta("iam_role", inChain); got != 1 {
		t.Errorf("аккаунтная роль обязана получить звено (положительный близнец): прирост "+
			"%d, ждали 1.\nБез него «законно без предка» поглотило бы настоящую потерю.\n%s",
			got, run.stdout)
	}
	if got := delta("iam_access_binding", noParent); got != 1 {
		t.Errorf("привязка с областью вне закрытого набора обязана попасть в «без предка "+
			"законно»: прирост %d, ждали 1\n%s", got, run.stdout)
	}
	if got := delta("iam_access_binding", inChain); got != 1 {
		t.Errorf("привязка с областью В наборе обязана получить звено: прирост %d, ждали 1\n%s",
			got, run.stdout)
	}
	if got := delta("iam_role", lost) + delta("iam_access_binding", lost); got != 0 {
		t.Errorf("законные исходы утекли в «потеряно»: прирост потерь %d\n%s", got, run.stdout)
	}
	// Различает их ПРЕДИКАТ ПО ИСТОЧНИКУ, а не имя типа целиком: у одного и того
	// же типа `iam_role` одна строка ушла в «законно без предка», другая — в
	// «в цепи». Именем типа так не разделить.
	t.Logf("предикат по источнику разделил ОДИН тип: iam_role → без предка +%d, в цепи +%d",
		delta("iam_role", noParent), delta("iam_role", inChain))
}

// ─────────────────────────────────────────────────────────────────────────────
// R7-4-03: послабление ПОЛЯРНО и истекает само

// TestR7_4_03_AllowanceIsPolarAndExpiresOnItsOwn — три утверждения об исходе:
// полярность «потеряно» не принимается НИКОГДА; неполярная запись отвергается;
// запись, которой нечего прощать, роняет перепись.
func TestR7_4_03_AllowanceIsPolarAndExpiresOnItsOwn(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx, conn, dsn := openDB(t)
	seedBaseline(t, ctx, conn)

	t.Run("полярность «потеряно» не прощается никогда", func(t *testing.T) {
		run := runCensus(t, dsn, "ALLOW_TYPES=iam_group:lost")
		if run.code == 0 {
			t.Fatalf("перепись ПРИНЯЛА послабление полярности «потеряно».\n"+
				"Потеря означает, что форма отказывает там, где решатель разрешает, и "+
				"простить её значит объявить дыру нормой.\n%s", run.all())
		}
		if !strings.Contains(run.all(), "не прощается НИКОГДА") {
			t.Errorf("отказ не назвал причину:\n%s", run.all())
		}
	})

	t.Run("неполярная запись отвергается", func(t *testing.T) {
		run := runCensus(t, dsn, "ALLOW_TYPES=iam_group")
		if run.code == 0 {
			t.Fatalf("перепись ПРИНЯЛА неполярное послабление: такая запись прощает обе "+
				"стороны разом и выводит тип из-под сторожа целиком.\n%s", run.all())
		}
		if !strings.Contains(run.all(), "без полярности") {
			t.Errorf("отказ не назвал причину:\n%s", run.all())
		}
	})

	t.Run("послаблению нечего прощать — находка", func(t *testing.T) {
		// Тип без «лишних»: прощать по нему нечего, и запись пережила бы свой
		// предмет, замаскировав следующее расхождение.
		run := runCensus(t, dsn, "ALLOW_TYPES=iam_group:extra")
		if !strings.Contains(run.all(), "Прощать нечего") {
			t.Errorf("перепись НЕ упала на послаблении без предмета: запись пережила бы "+
				"свой предмет и замаскировала следующее расхождение.\n%s", run.all())
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// R7-4-11: перепись даёт НОЛЬ В ОБЕ СТОРОНЫ

// TestR7_4_11_CensusIsZeroInBothDirections — на дереве со всеми достроенными
// звеньями перепись не находит ни потерь, ни лишних, и печатает объём.
//
// Красное до достройки: те же пять типов давали «потеряно» на каждом объекте,
// чей источник называет предка, — на стенде 640 строк.
func TestR7_4_11_CensusIsZeroInBothDirections(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx, conn, dsn := openDB(t)
	seedBaseline(t, ctx, conn, func(tx pgx.Tx) {
		// По одному объекту КАЖДОГО из пяти типов, у всех источник предка непуст —
		// то есть у всех предок ОБЯЗАН быть.
		mustExec(t, ctx, tx, `
		INSERT INTO kaname.users (id, external_id, email, account_id, created_at)
		VALUES ($1, 'ext-census-1', 'census@example.invalid', $2, now())`, "usr-census-1", "acc-census-1")
		mustExec(t, ctx, tx, `
		INSERT INTO kaname.groups (id, name, account_id, created_at)
		VALUES ($1, 'census', $2, now())`, "grp-census-1", "acc-census-1")
		mustExec(t, ctx, tx, `
		INSERT INTO kaname.service_accounts (id, name, account_id, created_at)
		VALUES ($1, 'census', $2, now())`, "sac-census-1", "acc-census-1")
		mustExec(t, ctx, tx, `
		INSERT INTO kaname.roles (id, name, permissions, rules, account_id, created_at)
		VALUES ($1, 'census_role', '["storage.volumes.*.get"]'::jsonb,
		        '[{"verbs": ["get"], "module": "storage", "resources": ["volumes"]}]'::jsonb,
		        $2, now())`, "rol-census-1", "acc-census-1")
		mustExec(t, ctx, tx, `
		INSERT INTO kaname.access_bindings (id, resource_type, resource_id, role_id,
		                                       subject_type, subject_id, scope, created_at)
		VALUES ($1, 'account', $2, $3, 'user', $4, 2, now())`,
			"abn-census-1", "acc-census-1", "rol-census-1", "usr-census-1")
	})

	run := runCensus(t, dsn)
	if run.code != 0 {
		t.Fatalf("перепись НЕ ЗЕЛЁНАЯ на дереве, где у каждого объекта источник называет "+
			"предка: код %d\n%s", run.code, run.all())
	}
	rows := parseCensus(t, run.stdout)
	for ty, r := range rows {
		if r.Lost != 0 {
			t.Errorf("тип %q: потеряно %d при достроенной цепи\n%s", ty, r.Lost, run.stdout)
		}
		if r.Extra != 0 {
			t.Errorf("тип %q: лишних %d\n%s", ty, r.Extra, run.stdout)
		}
	}
	// Положительный контроль: перепись действительно ЧИТАЛА объекты, а не
	// зеленела на пустоте.
	for _, ty := range []string{"iam_user", "iam_group", "iam_service_account",
		"iam_role", "iam_access_binding"} {
		if rows[ty].InChain == 0 {
			t.Errorf("тип %q: в цепи НОЛЬ объектов — «потерь нет» здесь означает «читать "+
				"было нечего»\n%s", ty, run.stdout)
		}
	}
	if !strings.Contains(run.stdout, "расхождений нет ни в одну сторону") {
		t.Errorf("перепись не объявила вердикт словами:\n%s", run.stdout)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// R7-4-15: предел обхода не достигнут ни одним объектом

// TestR7_4_15_WalkLimitIsCheckedNotAssumed — максимум звеньев на объект
// НАПЕЧАТАН и строго меньше предела; при достижении предела перепись ОТКАЗЫВАЕТ
// с названным объектом.
//
// Довод 740001 («строк на объект не больше глубин») отменён миграцией 781001 для
// журнальной ветви, и заменён он ЧИСЛОМ. Числа проверяют: объект, у которого
// звеньев столько же, сколько предел, усекается МОЛЧА.
func TestR7_4_15_WalkLimitIsCheckedNotAssumed(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	ctx, conn, dsn := openDB(t)
	seedBaseline(t, ctx, conn)

	run := runCensus(t, dsn)
	if !strings.Contains(run.stdout, "максимум звеньев на объект:") {
		t.Fatalf("перепись не напечатала максимум звеньев на объект — предел обхода "+
			"подразумевался бы, а не проверялся:\n%s", run.stdout)
	}

	// ОТРИЦАТЕЛЬНАЯ половина: понизив объявленный предел до достижимого, проба
	// требует ОТКАЗА с названным объектом. Без неё «максимум напечатан» ничего
	// не говорит о том, что прибор умеет на нём падать.
	low := runCensus(t, dsn, "MAX_DEPTH=1")
	if low.code == 0 {
		t.Fatalf("при пределе обхода 1 и звеньях 1 перепись ПРОШЛА: усечение цепи "+
			"осталось бы молчаливым, а отказ в доступе — неотличимым от честного.\n%s",
			low.all())
	}
	if !strings.Contains(low.all(), "усекает цепь МОЛЧА") {
		t.Errorf("отказ не объяснил, чем опасно достижение предела:\n%s", low.all())
	}
	// ПОЛОЖИТЕЛЬНЫЙ близнец: при штатном пределе тот же вход проходит проверку
	// предела — иначе красное означало бы «прибор всегда падает».
	if strings.Contains(run.all(), "усекает цепь МОЛЧА") {
		t.Errorf("перепись отказала по пределу при штатном значении:\n%s", run.all())
	}
}
