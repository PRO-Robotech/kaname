// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// credential_ceiling_anchor_test.go — АНКЕР второго источника имён (задача
// #1191, приёмка §3.3, утверждения G5, G6, G7).
//
// # Предмет
//
// Вид учёта обязан называть реальные типы модели прав. Удостоверение типом не
// является — право на него вычисляется от принципала, — поэтому заведён второй
// закрытый перечень: подчинённые ресурсы. Его внутреннюю согласованность держат
// G1–G4 у каталога; здесь держится то, без чего перечень остаётся
// САМОЗАЯВЛЕНИЕМ.
//
// У закрытой таблицы типов истинность анкерена безусловным гейтом дрейфа против
// канонической модели прав. У второй таблицы такого анкера не было бы вовсе, и
// опечатка `iam.credentials` (множественное — ровно та форма, на которой уже
// спотыкались) прошла бы ВСЕ проверки внутренней согласованности: она не тип
// модели прав, родители резолвятся, причина непуста, носитель среди родителей.
// А вид `iam.user.credentials` оказался бы несписываемым, и отказ наступил бы на
// первой же выдаче — то есть у арендатора, а не в сборке.
//
// Поэтому здесь спрашивается о ДЕРЕВЕ: таблицы существуют, и на них стоят
// триггеры списания, называющие вид.
//
// # G7 — про другое, но по той же причине
//
// Применимость области аккаунта объявлена каталогом и повторена литералом в теле
// функции списания: SQL не читает Go, и второго места избежать нельзя. Значит
// согласие двух мест обязано держаться проверкой, а не вниманием — иначе третий
// вид учёта молча унаследует ту ветку, в которую попадёт.

package migrations_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

var (
	reCreateTable  = regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*\.[a-z_][a-z0-9_]*)`)
	reCountTrigger = regexp.MustCompile(`(?is)CREATE\s+TRIGGER\s+\w+\s+AFTER[^;]*?\sON\s+([a-z_][a-z0-9_.]*)[^;]*?kacho_quota_count\(\s*'([a-zA-Z0-9.]+)'`)
	reAccountArm   = regexp.MustCompile(`v_kind\s+IN\s*\(([^)]*)\)`)

	// Ограничение носителя записывается в дереве ДВУМЯ законными формами, и обе
	// обязаны быть известны распознавателю: форма, о которой он не знает, даёт
	// не красное и не зелёное, а МОЛЧАНИЕ — предмет уходит из-под наблюдения,
	// ничего не нарушив (`testing.md` §«Гейт на класс» п. 7).
	//
	//   - рукописная миграция пишет членство как `carrier_type IN ('a','b')`;
	//   - свод, снятый `pg_dump`, — как `carrier_type = ANY (ARRAY['a'::text, …])`
	//     и оборачивает выражение в лишние скобки, поэтому `\(+`.
	//
	// Обе привязаны к ИМЕНИ ограничения: без привязки распознаватель читал бы
	// любой CHECK, называющий `carrier_type`, и принял бы за предмет соседний.
	reCarrierIn  = regexp.MustCompile(`(?is)CONSTRAINT\s+project_resource_quotas_carrier_ck\s+CHECK\s*\(+\s*carrier_type\s+IN\s*\(([^)]*)\)`)
	reCarrierAny = regexp.MustCompile(`(?is)CONSTRAINT\s+project_resource_quotas_carrier_ck\s+CHECK\s*\(+\s*carrier_type\s*=\s*ANY\s*\(\s*ARRAY\s*\[([^\]]*)\]`)
	reQuoted     = regexp.MustCompile(`'([^']*)'`)
	reSpace      = regexp.MustCompile(`\s+`)
)

// iamMigrationCorpus читает миграции сервиса и печатает объём осмотренного:
// «ноль находок» обязано быть отличимо от «ноль прочитанного».
func iamMigrationCorpus(t *testing.T) (bodies map[string]string, read int) {
	t.Helper()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	bodies = map[string]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		raw, rerr := os.ReadFile(filepath.Clean(e.Name())) // #nosec G304 -- имя из перечня каталога миграций
		require.NoError(t, rerr, "чтение %s", e.Name())
		bodies[e.Name()] = string(raw)
		read++
	}
	require.NotZero(t, read, "миграций не прочитано — предпосылка гейта сломана")
	return bodies, read
}

// anchorFindings — судья G5/G6, отделённый от дерева ради инъекции.
//
// tables — таблицы, объявленные деревом; charged — пары «таблица → вид»,
// вычитанные из объявлений триггеров.
func anchorFindings(
	records []domain.SubordinateResource,
	catalogue []domain.CountableKind,
	tables map[string]bool,
	charged map[string]map[string]bool,
) []string {
	var out []string
	for _, r := range records {
		// Виды, опирающиеся на эту запись, — то, что должно списываться.
		var kinds []domain.LimitKind
		for _, e := range catalogue {
			if e.Kind.ChildKind() == r.Kind {
				kinds = append(kinds, e.Kind)
			}
		}
		if len(kinds) == 0 {
			out = append(out, string(r.Kind)+
				" — подчинённый ресурс объявлен, но ни один вид каталога на него не опирается: "+
				"запись пережила свой предмет")
			continue
		}
		for _, table := range r.Tables {
			// G5 — таблица существует в дереве.
			if !tables[table] {
				out = append(out, string(r.Kind)+" — таблица "+table+
					" не объявлена ни одной миграцией: имя осталось самозаявлением")
				continue
			}
			// G6 — на ней стоит списание, называющее ОДИН из видов записи.
			var found bool
			for _, k := range kinds {
				if charged[table][string(k)] {
					found = true
					break
				}
			}
			if !found {
				out = append(out, string(r.Kind)+" — на таблице "+table+
					" нет триггера списания, называющего вид этой записи: величина задаётся, "+
					"а место не занимается — предел не наступит никогда")
			}
		}
	}
	sort.Strings(out)
	return out
}

// TestCredentialCeilingAnchor_TablesAndChargersExist — G5 и G6 на дереве.
func TestCredentialCeilingAnchor_TablesAndChargersExist(t *testing.T) {
	if testing.Short() {
		t.Skip("гейт читает дерево миграций; в коротком прогоне не нужен")
	}
	bodies, read := iamMigrationCorpus(t)

	tables := map[string]bool{}
	charged := map[string]map[string]bool{}
	for _, body := range bodies {
		flat := reSpace.ReplaceAllString(body, " ")
		for _, m := range reCreateTable.FindAllStringSubmatch(flat, -1) {
			tables[strings.ToLower(m[1])] = true
		}
		for _, m := range reCountTrigger.FindAllStringSubmatch(flat, -1) {
			table := strings.ToLower(m[1])
			if !strings.Contains(table, ".") {
				table = "kacho_iam." + table
			}
			if charged[table] == nil {
				charged[table] = map[string]bool{}
			}
			charged[table][m[2]] = true
		}
	}
	require.NotEmpty(t, tables, "предикат не нашёл ни одной таблицы — он мерит форму записи, а не факт")
	require.NotEmpty(t, charged, "предикат не нашёл ни одного триггера списания")

	require.Empty(t, anchorFindings(
		domain.SubordinateResources(), domain.CountableEntries(), tables, charged))

	t.Logf("перепись: миграций прочитано %d, таблиц объявлено %d, таблиц со списанием %d, записей подчинённых ресурсов %d",
		read, len(tables), len(charged), len(domain.SubordinateResources()))
}

// TestCredentialCeilingAnchor_GateCanFail — инъекция G5/G6 в обе стороны.
func TestCredentialCeilingAnchor_GateCanFail(t *testing.T) {
	t.Parallel()

	rec := domain.SubordinateResource{
		Kind:    "iam.credential",
		Parents: []domain.LimitKind{"iam.user"},
		Tables:  []string{"kacho_iam.user_oauth_clients"},
		Why:     "право вычисляется от принципала",
	}
	cat := []domain.CountableKind{{Kind: "iam.user.credential", Carrier: "iam.user"}}
	tables := map[string]bool{"kacho_iam.user_oauth_clients": true}
	charged := map[string]map[string]bool{
		"kacho_iam.user_oauth_clients": {"iam.user.credential": true},
	}

	t.Run("законный близнец: и таблица, и списание на месте", func(t *testing.T) {
		require.Empty(t, anchorFindings([]domain.SubordinateResource{rec}, cat, tables, charged))
	})

	t.Run("G5: имя таблицы с опечаткой", func(t *testing.T) {
		bad := rec
		bad.Tables = []string{"kacho_iam.user_oauth_client"} // единственное число
		found := anchorFindings([]domain.SubordinateResource{bad}, cat, tables, charged)
		require.Len(t, found, 1)
		require.Contains(t, found[0], "kacho_iam.user_oauth_client")
	})

	t.Run("G6: вид с опечаткой — списания под таким именем нет", func(t *testing.T) {
		// Ровно контрпример из приёмки: множественное число в имени вида.
		badCat := []domain.CountableKind{{Kind: "iam.user.credentials", Carrier: "iam.user"}}
		badRec := rec
		badRec.Kind = "iam.credentials"
		found := anchorFindings([]domain.SubordinateResource{badRec}, badCat,
			tables, charged)
		require.Len(t, found, 1)
		require.Contains(t, found[0], "нет триггера списания",
			"опечатка в имени вида обязана ловиться анкером: внутреннюю согласованность "+
				"записи она проходит целиком")
	})

	t.Run("запись, на которую не опирается ни один вид", func(t *testing.T) {
		found := anchorFindings([]domain.SubordinateResource{rec}, nil, tables, charged)
		require.Len(t, found, 1)
		require.Contains(t, found[0], "пережила свой предмет")
	})
}

// TestCredentialCeilingAnchor_AccountArmAgreesWithTheCatalogue — G7.
func TestCredentialCeilingAnchor_AccountArmAgreesWithTheCatalogue(t *testing.T) {
	if testing.Short() {
		t.Skip("гейт читает дерево миграций; в коротком прогоне не нужен")
	}
	bodies, read := iamMigrationCorpus(t)

	inSQL := map[string]bool{}
	files := 0
	for name, body := range bodies {
		if !strings.Contains(body, "kacho_quota_count()") {
			continue
		}
		flat := reSpace.ReplaceAllString(body, " ")
		hit := false
		for _, m := range reAccountArm.FindAllStringSubmatch(flat, -1) {
			for _, q := range reQuoted.FindAllStringSubmatch(m[1], -1) {
				if q[1] != "" {
					inSQL[q[1]] = true
					hit = true
				}
			}
		}
		if hit {
			files++
			_ = name
		}
	}
	require.NotEmpty(t, inSQL,
		"в телах списания не найдено НИ ОДНОГО вида, читающего область аккаунта: предикат "+
			"мерит форму записи, а не факт — либо ветка исчезла, и объявление каталога стало ложью")

	declared := map[string]bool{}
	for _, k := range domain.AccountScopedKinds() {
		declared[string(k)] = true
	}

	var onlySQL, onlyCatalogue []string
	for k := range inSQL {
		if !declared[k] {
			onlySQL = append(onlySQL, k)
		}
	}
	for k := range declared {
		if !inSQL[k] {
			onlyCatalogue = append(onlyCatalogue, k)
		}
	}
	sort.Strings(onlySQL)
	sort.Strings(onlyCatalogue)

	require.Emptyf(t, onlySQL,
		"вид читает область аккаунта в SQL, но каталог этого не объявляет: %v.\n"+
			"    Величина аккаунта применяется к виду, про который решения не принимали — "+
			"и узнать об этом можно только из тела функции.", onlySQL)
	require.Emptyf(t, onlyCatalogue,
		"каталог объявляет вид област-ным, но списание области не читает: %v.\n"+
			"    Администратор назначает величину, получает успех, и она не применяется "+
			"никогда — «принято-и-проигнорировано» на уровне подсистемы.", onlyCatalogue)

	t.Logf("перепись: миграций прочитано %d, тел списания с веткой области %d, видов в SQL %d, объявлено каталогом %d",
		read, files, len(inSQL), len(declared))
}

// TestCredentialCeilingAnchor_CarrierIsNamedTheSameEverywhere — CRED-CAP-34.
//
// Носитель называется в ДВУХ местах: каталог видов объявляет его записью, схема
// принимает его значением столбца и получает вторым аргументом триггера
// списания. Разойдись они — списание писало бы строки под одним носителем, а
// чтение спрашивало под другим: потребление показывалось бы нулевым при полном
// потолке, а отказ приходил бы «на пустом месте». Ни сборка, ни одна из сторон
// по отдельности этого не увидят.
func TestCredentialCeilingAnchor_CarrierIsNamedTheSameEverywhere(t *testing.T) {
	if testing.Short() {
		t.Skip("гейт читает дерево миграций; в коротком прогоне не нужен")
	}
	bodies, read := iamMigrationCorpus(t)

	// Носители, которые ПРИНИМАЕТ схема: последнее объявление ограничения
	// выигрывает — миграции применяются по ЧИСЛОВОЙ версии.
	//
	// По числу, а не по имени: строковый порядок ставит `20260824230000` РАНЬШЕ
	// `484002`, потому что сравнивает посимвольно, — и последним объявлением
	// оказалось бы прежнее. Ошибка тихая: гейт объявил бы находкой значение,
	// которое схема принимает.
	names := migrationNamesInVersionOrder(bodies)

	accepted, declarations := carrierValuesAccepted(names, bodies)
	require.NotZero(t, declarations,
		"ограничение носителя не найдено ни в одной миграции — предикат мерит форму записи, а не факт")
	require.NotEmpty(t, accepted)

	// Виды, у которых списание СТОИТ: первый аргумент вызова.
	//
	// Носитель вторым аргументом здесь НЕ передаётся и передаваться не должен:
	// он выводится из вида (его родительская часть), а строка в кавычках рядом с
	// видом неотличима от вида для гейтов дерева, читающих аргументы списания, —
	// два таких гейта на этом и споткнулись.
	reTriggerKind := regexp.MustCompile(`kacho_quota_count\(\s*'([a-zA-Z0-9.]+)'`)
	chargedKinds := map[string]bool{}
	for _, name := range names {
		flat := reSpace.ReplaceAllString(bodies[name], " ")
		for _, m := range reTriggerKind.FindAllStringSubmatch(flat, -1) {
			chargedKinds[m[1]] = true
		}
	}
	require.NotEmpty(t, chargedKinds, "ни один триггер не называет вида — предикат мерит форму, а не факт")

	checked := 0
	for _, e := range domain.CountableEntries() {
		if _, ok := domain.SubordinateResourceOf(e.Kind.ChildKind()); !ok {
			continue
		}
		carrier := string(e.Carrier)
		require.Truef(t, accepted[carrier],
			"каталог считает вид %q в носителе %q, а ограничение схемы такого значения НЕ ПРИНИМАЕТ: "+
				"строка учёта не вставится вовсе, и потолок молча перестанет действовать", e.Kind, carrier)
		require.Truef(t, chargedKinds[string(e.Kind)],
			"каталог объявляет вид %q, а триггера списания с таким именем в дереве нет: "+
				"величина задаётся и не применяется никогда", e.Kind)
		require.Equalf(t, string(e.Kind.ParentKind()), carrier,
			"носитель вида %q не совпадает с его родительской частью, а списание ВЫВОДИТ "+
				"носитель именно из неё: строка учёта заведётся под одним значением, "+
				"а списание будет искать её под другим", e.Kind)
		checked++
	}
	require.NotZero(t, checked,
		"ни один вид не опирается на подчинённый ресурс — проба стала вакуумной и должна "+
			"сниматься вместе со своим предметом, а не держаться зелёной")

	t.Logf("перепись: миграций прочитано %d, объявлений ограничения носителя %d, принимаемых значений %d, видов со списанием %d, видов сверено %d",
		read, declarations, len(accepted), len(chargedKinds), checked)
}

// migrationNamesInVersionOrder — имена миграций в том порядке, в каком их
// применяет goose: по числовой версии из начала имени.
func migrationNamesInVersionOrder(bodies map[string]string) []string {
	names := make([]string, 0, len(bodies))
	for name := range bodies {
		names = append(names, name)
	}
	version := func(name string) int64 {
		i := strings.IndexByte(name, '_')
		if i <= 0 {
			return 0
		}
		v, err := strconv.ParseInt(name[:i], 10, 64)
		if err != nil {
			return 0
		}
		return v
	}
	sort.Slice(names, func(i, j int) bool {
		vi, vj := version(names[i]), version(names[j])
		if vi != vj {
			return vi < vj
		}
		return names[i] < names[j]
	})
	return names
}

// carrierValuesAccepted — носители, которые ПРИНИМАЕТ ограничение схемы, и число
// объявлений, из которых это вычитано.
//
// Отделён от дерева ради инъекции: судить о том, знает ли распознаватель все
// законные формы записи, можно только подав ему каждую из них — на живом дереве
// он молчит одинаково и когда формы нет, и когда он её не узнал.
//
// Последнее объявление выигрывает: миграции применяются по ЧИСЛОВОЙ версии, и
// порядок имён здесь обязан приходить от `migrationNamesInVersionOrder`.
func carrierValuesAccepted(names []string, bodies map[string]string) (map[string]bool, int) {
	accepted := map[string]bool{}
	declarations := 0
	for _, name := range names {
		flat := reSpace.ReplaceAllString(bodies[name], " ")
		// Обратный ход миграции объявляет ПРЕЖНЮЮ форму — её читать нельзя:
		// действует то, что стоит в прямом ходе.
		if i := strings.Index(flat, "+goose Down"); i >= 0 {
			flat = flat[:i]
		}
		for _, re := range []*regexp.Regexp{reCarrierIn, reCarrierAny} {
			for _, m := range re.FindAllStringSubmatch(flat, -1) {
				next := map[string]bool{}
				for _, q := range reQuoted.FindAllStringSubmatch(m[1], -1) {
					next[q[1]] = true
				}
				if len(next) > 0 {
					accepted = next
					declarations++
				}
			}
		}
	}
	return accepted, declarations
}

// TestCredentialCeilingAnchor_CarrierRecognizerKnowsBothForms — ИНЪЕКЦИЯ по
// КАЖДОЙ законной форме записи предмета, с законным близнецом на каждой оси.
//
// Заведена по находке: свод миграций сервиса в один файл снят `pg_dump`, и тот
// пишет членство через `= ANY (ARRAY[…])`. Распознаватель знал только форму
// `IN (…)` — и предмет ушёл из-под наблюдения целиком. Обнаружилось это лишь
// потому, что у пробы стояла проверка СОБСТВЕННОЙ предпосылки («объявлений
// ноль»); без неё расхождение носителя перестало бы ловиться молча.
func TestCredentialCeilingAnchor_CarrierRecognizerKnowsBothForms(t *testing.T) {
	t.Parallel()

	const name = "project_resource_quotas_carrier_ck"
	want := map[string]bool{"project": true, "iam.user": true}

	t.Run("форма рукописной миграции: IN (…)", func(t *testing.T) {
		got, n := carrierValuesAccepted([]string{"0001_x.sql"}, map[string]string{
			"0001_x.sql": "ALTER TABLE q ADD CONSTRAINT " + name +
				" CHECK (carrier_type IN ('project', 'iam.user'));",
		})
		require.Equal(t, 1, n)
		require.Equal(t, want, got)
	})

	t.Run("форма свода pg_dump: = ANY (ARRAY[…]) в лишних скобках", func(t *testing.T) {
		got, n := carrierValuesAccepted([]string{"0001_x.sql"}, map[string]string{
			"0001_x.sql": "CREATE TABLE q (\n    CONSTRAINT " + name +
				" CHECK (((carrier_type = ANY (ARRAY['project'::text, 'iam.user'::text]))" +
				" AND (carrier_id <> ''::text)))\n);",
		})
		require.Equal(t, 1, n,
			"форма свода не узнана: распознаватель молчал бы, ничего не нарушив")
		require.Equal(t, want, got)
	})

	t.Run("законный близнец: ЧУЖОЕ ограничение того же столбца не читается", func(t *testing.T) {
		_, n := carrierValuesAccepted([]string{"0001_x.sql"}, map[string]string{
			"0001_x.sql": "CREATE TABLE q (\n    CONSTRAINT identity_admission_windows_carrier_ck" +
				" CHECK (((carrier_type = ANY (ARRAY['nonsense'::text])) AND (carrier_id <> ''::text)))\n);",
		})
		require.Zero(t, n,
			"распознаватель прочитал соседнее ограничение: без привязки к ИМЕНИ он мерит "+
				"столбец, а не предмет, и объявил бы принимаемым чужой перечень")
	})

	t.Run("форма, которой распознаватель не знает: объявлений ноль", func(t *testing.T) {
		_, n := carrierValuesAccepted([]string{"0001_x.sql"}, map[string]string{
			"0001_x.sql": "CREATE TABLE q (\n    CONSTRAINT " + name +
				" CHECK (carrier_type <@ '{project,iam.user}'::text[])\n);",
		})
		require.Zero(t, n,
			"неизвестная форма обязана давать НОЛЬ объявлений: именно на нуле срабатывает "+
				"проверка собственной предпосылки, и она — единственное, чем эта слепота видна")
	})

	t.Run("обратный ход не читается: действует прямой", func(t *testing.T) {
		got, n := carrierValuesAccepted([]string{"0001_x.sql"}, map[string]string{
			"0001_x.sql": "-- +goose Up\nCONSTRAINT " + name +
				" CHECK (carrier_type IN ('project', 'iam.user'))\n" +
				"-- +goose Down\nCONSTRAINT " + name +
				" CHECK (carrier_type IN ('прежнее'))",
		})
		require.Equal(t, 1, n)
		require.Equal(t, want, got)
	})

	t.Run("последнее объявление по числовой версии выигрывает", func(t *testing.T) {
		bodies := map[string]string{
			"484002_a.sql": "CONSTRAINT " + name + " CHECK (carrier_type IN ('project'))",
			"20260824230000_b.sql": "CONSTRAINT " + name +
				" CHECK (((carrier_type = ANY (ARRAY['project'::text, 'iam.user'::text]))))",
		}
		got, n := carrierValuesAccepted(migrationNamesInVersionOrder(bodies), bodies)
		require.Equal(t, 2, n)
		require.Equal(t, want, got,
			"выиграло объявление с МЕНЬШЕЙ версией: строковый порядок ставит "+
				"`20260824230000` раньше `484002`, и гейт объявил бы находкой значение, "+
				"которое схема принимает")
	})
}
