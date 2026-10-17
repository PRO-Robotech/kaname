// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict

// grantarm_home_gate_test.go — у предиката ветви выдач ОДИН дом (kaname#857).
//
// Предмет: текст, решающий «достаёт ли выдача роли до объекта», — сравнение
// ветви правила (`arm`) и колонки её селектора (`resource_names`,
// `match_labels`). Он живёт в `grantArmPredicate`, и только там. Копия рядом —
// ровно та форма, в которой три запроса пакета перестали читать цель привязки:
// правка одного места не доезжает до второго, и расходятся они в сторону
// лишнего доступа.
//
// ЧТО ГЕЙТ ИСПОЛНЯЕТ (распознаватель — grantarm_scan_test.go).
//
// Единица счёта — функция либо одно имя в объявлении константы/переменной
// пакета. У каждой единицы выводятся тексты её строковых выражений: литерал,
// склейка оператором «+» в порядке исходника, fmt.Sprintf с подстановкой %s %v
// %q %d по порядку, имя строковой константы либо переменной ЭТОГО пакета (из
// любого его файла) — её значение подставляется. Невыводимое (параметр, вызов
// функции, константа другого пакета, индексированный глагол формата) становится
// отдельной лексемой-заглушкой и с соседями не склеивается.
//
// Текст разбирается лексером SQL: комментарии «--» и «/* */» (с вложенностью)
// отброшены, строки в одинарных кавычках, имена в двойных и тела в долларовых
// кавычках прочитаны целиком — «--» внутри строки комментарием не считается.
//
// Класс — ЛЮБОЕ употребление столбца селектора (`arm`, `resource_names`,
// `match_labels`, с псевдонимом таблицы и без, в кавычках и без, любым
// регистром), кроме трёх положений: определение псевдонима (после AS); проза
// либо псевдоним без AS (перед словом стоит идентификатор, не являющийся словом
// SQL из sqlLeadKeywords); наблюдение — столбец в перечне вывода (слева
// SELECT, DISTINCT, «,» или «||», справа, за приведением типа, AS, FROM, «,»,
// «||» либо конец текста). Сравнение любым оператором, CASE … WHEN, IN, NOT IN,
// LIKE, BETWEEN, IS DISTINCT FROM, ANY — решение.
//
// Аргументы fmt.Errorf, errors.New, fmt.Print*/Fprint*, вызовов пакетов log и
// slog не читаются: это текст наружу либо журнал. Комментарии Go не читаются
// вовсе. Пробные файлы не читаются.
//
// Константа либо переменная, которую подставляет другая единица, — осколок:
// её текст засчитан у единицы-потребителя и отдельным домом не считается.
//
// ГРАНИЦА (что гейт НЕ видит): значения, собранные во время исполнения
// (strings.Builder, strings.Join/Replace, конкатенация в цикле, результат
// вызова функции), константы ДРУГИХ пакетов, индексированные глаголы формата
// и тела в долларовых кавычках. Копия, собранная этими средствами, гейтом не
// ловится; держит её только ревью.
//
// Перепись печатается, пустой обход — не зелёный.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// judgeGrantArmHomes — вердикт по переписи: ровно один дом, и это функция
// grantArmPredicate. Пустой обход и ноль домов — отказ предпосылки, а не зелёное.
func judgeGrantArmHomes(c grantArmCensus, homes []grantArmHome) error {
	if c.files == 0 || c.literals == 0 {
		return fmt.Errorf("предпосылка: прочитано файлов %d, литералов %d — обход не видит пакета, "+
			"вердикта нет", c.files, c.literals)
	}
	if len(homes) == 0 {
		return fmt.Errorf("предпосылка: текст ветви выдач не найден ни в одном объявлении " +
			"(файлов прочитано больше нуля) — распознаватель не читает своего предмета, вердикта нет")
	}
	if len(homes) == 1 && homes[0].decl == "grantArmPredicate" {
		return nil
	}
	var b strings.Builder
	for _, h := range homes {
		fmt.Fprintf(&b, "\n  %s %s", h.pos, h.decl)
	}
	return fmt.Errorf("текст ветви выдач стоит в %d объявлениях — дом у него один, "+
		"grantArmPredicate (grantarm.go); прочие подставляют его, а не повторяют:%s", len(homes), b.String())
}

func TestGrantArmPredicateHasASingleHome(t *testing.T) {
	c, homes, err := scanGrantArmHomes(".")
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("перепись: файлов %d · литералов %d · выведенных текстов %d · домов текста ветви выдач %d",
		c.files, c.literals, c.texts, len(homes))
	if err := judgeGrantArmHomes(c, homes); err != nil {
		t.Fatal(err)
	}
}

// ── Инъекции: тот же обход на синтетическом дереве ─────────────────────────────

const injShared = "package p\n\nfunc grantArmPredicate(id string) string {\n" +
	"\treturn `rs.arm = 'anchor' OR (rs.arm = 'names' AND ` + id + ` = ANY (rs.resource_names))`\n}\n"

func injTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, src := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func injJudge(t *testing.T, files map[string]string) (grantArmCensus, []grantArmHome, error) {
	t.Helper()
	c, homes, err := scanGrantArmHomes(injTree(t, files))
	if err != nil {
		t.Fatal(err)
	}
	return c, homes, judgeGrantArmHomes(c, homes)
}

// Законный близнец: один дом; тот же текст в комментарии Go, в SQL-комментарии
// запроса и в пробном файле домом не считается.
func TestGrantArmHomeInjection_LawfulTwinIsSilent(t *testing.T) {
	_, homes, err := injJudge(t, map[string]string{
		"shared.go": injShared,
		"other.go": "package p\n\n// rs.arm = 'names' AND x = ANY (rs.resource_names)\n" +
			"const q = `SELECT 1 -- rs.arm = 'labels' AND m.labels @> rs.match_labels\n FROM t`\n",
		"seed_test.go": "package p\n\nconst seed = `INSERT INTO s (arm, resource_names) VALUES ('names', '{}')`\n",
	})
	if err != nil {
		t.Fatalf("законный близнец дал находку: %v (дома %v)", err, homes)
	}
}

// Вторая копия ловится в каждой законной форме записи и называет координату.
func TestGrantArmHomeInjection_SecondCopyIsFoundWithItsCoordinate(t *testing.T) {
	for name, copySrc := range map[string]string{
		"тот же текст":          "package p\n\nconst listSQL = `WHERE (rs.arm = 'anchor' OR rs.arm = 'names')`\n",
		"другой псевдоним":      "package p\n\nconst q = `WHERE (rrs.arm='anchor')`\n",
		"сравнение справа":      "package p\n\nconst q = `WHERE 'labels' = rs.arm`\n",
		"перечень ветвей":       "package p\n\nconst q = `WHERE rs.arm IN ('anchor', 'names')`\n",
		"только колонка имён":   "package p\n\nconst q = `WHERE x = ANY (sel.resource_names)`\n",
		"только колонка меток":  "package p\n\nvar q = `WHERE m.labels @> sel.match_labels`\n",
		"внутри функции":        "package p\n\nfunc f() string { return \"rs.arm = 'anchor'\" }\n",
		"без псевдонима, в IN":  "package p\n\nconst q = `WHERE arm in ('names')`\n",
		"неравенство с ветвью":  "package p\n\nconst q = `WHERE rs.arm <> 'labels'`\n",
		"литерал в кавычках Go": "package p\n\nconst q = \"WHERE rs.arm = 'anchor'\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, homes, err := injJudge(t, map[string]string{"shared.go": injShared, "copy.go": copySrc})
			if err == nil {
				t.Fatalf("вторая копия (%s) не найдена: дома %v", name, homes)
			}
			if !strings.Contains(err.Error(), "copy.go:3") {
				t.Fatalf("находка не называет координату копии: %v", err)
			}
		})
	}
}

// Дом есть, но это не общая функция, — находка, а не зелёное.
func TestGrantArmHomeInjection_SoleHomeElsewhereIsFound(t *testing.T) {
	_, _, err := injJudge(t, map[string]string{
		"q.go": "package p\n\nconst q = `WHERE rs.arm = 'anchor'`\n",
	})
	if err == nil || !strings.Contains(err.Error(), "q.go:3") {
		t.Fatalf("единственный дом вне grantArmPredicate не назван: %v", err)
	}
}

// Пустой обход и обход без предмета — «не выполнилось», а не зелёное.
func TestGrantArmHomeInjection_EmptyWalkIsNotAVerdict(t *testing.T) {
	c, _, err := injJudge(t, map[string]string{})
	if err == nil || !strings.Contains(err.Error(), "предпосылка") {
		t.Fatalf("пустой обход (файлов %d) дал %v — ждали отказ предпосылки", c.files, err)
	}
	_, _, err = injJudge(t, map[string]string{"x.go": "package p\n\nconst q = `SELECT 1`\n"})
	if err == nil || !strings.Contains(err.Error(), "предпосылка") {
		t.Fatalf("обход без текста ветви дал %v — ждали отказ предпосылки", err)
	}
}

// grantArmForms — каждая законная форма записи употребления столбцов селектора
// (`arm`, `resource_names`, `match_labels`) в решающей позиции и её законный
// близнец той же формы, где столбец лишь наблюдается (выводится в ответ) либо
// стоит в комментарии. Копия обязана краснеть, близнец — молчать.
var grantArmForms = []struct {
	name, copySrc, twinSrc string
}{
	{"одним литералом",
		"package p\n\nconst q = `WHERE rs.arm = 'anchor'`\n",
		"package p\n\nconst q = `SELECT rs.arm AS arm FROM t`\n"},
	{"конкатенация литералов",
		"package p\n\nconst q = \"WHERE rs.arm \" + \"= 'anchor'\"\n",
		"package p\n\nconst q = \"SELECT rs.arm \" + \"AS arm FROM t\"\n"},
	{"конкатенация рассекает имя столбца",
		"package p\n\nconst q = \"WHERE x = ANY (sel.resource_\" + \"names)\"\n",
		"package p\n\nconst q = \"WHERE x = ANY (sel.resource_\" + \"ids)\"\n"},
	{"имя столбца константой",
		"package p\n\nconst col = \"arm\"\n\nconst q = \"WHERE rs.\" + col + \" = 'anchor'\"\n",
		"package p\n\nconst col = \"arm\"\n\nconst q = \"SELECT rs.\" + col + \" AS arm FROM t\"\n"},
	{"fmt.Sprintf",
		"package p\n\nimport \"fmt\"\n\nvar q = fmt.Sprintf(\"WHERE rs.%s = 'anchor'\", \"arm\")\n",
		"package p\n\nimport \"fmt\"\n\nvar q = fmt.Sprintf(\"SELECT rs.%s AS arm FROM t\", \"arm\")\n"},
	{"'--' внутри строкового литерала SQL",
		"package p\n\nconst q = `WHERE x <> '--' AND rs.arm = 'anchor'`\n",
		"package p\n\nconst q = `WHERE x <> 1 -- AND rs.arm = 'anchor'\n`\n"},
	{"блочный комментарий перед столбцом",
		"package p\n\nconst q = `WHERE /* c */ rs.arm = 'anchor'`\n",
		"package p\n\nconst q = `SELECT 1 /* rs.arm = 'x' */ FROM t`\n"},
	{"приведение типа",
		"package p\n\nconst q = `WHERE rs.arm::text = 'anchor'`\n",
		"package p\n\nconst q = `SELECT rs.arm::text AS arm FROM t`\n"},
	{"перенос строк вокруг оператора",
		"package p\n\nconst q = `WHERE rs.arm\n  =\n 'anchor'`\n",
		"package p\n\nconst q = `SELECT rs.arm\n  AS arm\n FROM t`\n"},
	{"CASE … WHEN",
		"package p\n\nconst q = `SELECT CASE rs.arm WHEN 'anchor' THEN true END`\n",
		"package p\n\nconst q = `SELECT rs.arm, CASE WHEN x THEN true END FROM t`\n"},
	{"IS DISTINCT FROM",
		"package p\n\nconst q = `WHERE rs.arm IS DISTINCT FROM 'labels'`\n",
		"package p\n\nconst q = `SELECT x IS DISTINCT FROM y, rs.arm FROM t`\n"},
	{"= ANY (ARRAY …)",
		"package p\n\nconst q = `WHERE rs.arm = ANY (ARRAY['anchor'])`\n",
		"package p\n\nconst q = `SELECT rs.arm FROM t WHERE x = ANY (ARRAY['anchor'])`\n"},
	{"LIKE",
		"package p\n\nconst q = `WHERE rs.arm LIKE 'a%'`\n",
		"package p\n\nconst q = `SELECT rs.arm FROM t WHERE x LIKE 'a%'`\n"},
	{"NOT IN",
		"package p\n\nconst q = `WHERE rs.arm NOT IN ('labels')`\n",
		"package p\n\nconst q = `SELECT rs.arm FROM t WHERE x NOT IN ('labels')`\n"},
	{"BETWEEN",
		"package p\n\nconst q = `WHERE rs.arm BETWEEN 'a' AND 'z'`\n",
		"package p\n\nconst q = `SELECT rs.arm FROM t WHERE x BETWEEN 'a' AND 'z'`\n"},
	{"сравнение справа",
		"package p\n\nconst q = `WHERE 'labels' = rs.arm`\n",
		"package p\n\nconst q = `SELECT 'labels' AS l, rs.arm FROM t`\n"},
	{"неравенство",
		"package p\n\nconst q = `WHERE rs.arm <> 'labels'`\n",
		"package p\n\nconst q = `SELECT rs.arm FROM t WHERE x <> 'labels'`\n"},
	{"столбец в кавычках",
		"package p\n\nconst q = `WHERE rs.\"arm\" = 'anchor'`\n",
		"package p\n\nconst q = `SELECT rs.\"arm\" AS arm FROM t`\n"},
	{"заглавными",
		"package p\n\nconst q = `WHERE RS.ARM = 'anchor'`\n",
		"package p\n\nconst q = `SELECT RS.ARM AS ARM FROM T`\n"},
	{"без псевдонима таблицы",
		"package p\n\nconst q = `WHERE arm IN ('names')`\n",
		"package p\n\nconst q = `SELECT arm FROM t`\n"},
	{"только колонка меток",
		"package p\n\nvar q = `WHERE m.labels @> sel.match_labels`\n",
		"package p\n\nvar q = `SELECT sel.match_labels AS ml FROM t`\n"},
	{"внутри тела функции",
		"package p\n\nfunc f() string { return \"WHERE rs.arm = 'anchor'\" }\n",
		"package p\n\nfunc f() string { return \"SELECT rs.arm AS arm FROM t\" }\n"},
	{"внутри блока констант",
		"package p\n\nconst (\n\ta = 1\n\tq = `WHERE rs.arm = 'anchor'`\n)\n",
		"package p\n\nconst (\n\ta = 1\n\tq = `SELECT rs.arm AS arm FROM t`\n)\n"},
}

func TestGrantArmHomeInjection_EveryFormIsFoundAndItsTwinIsSilent(t *testing.T) {
	for _, f := range grantArmForms {
		t.Run(f.name, func(t *testing.T) {
			_, homes, err := injJudge(t, map[string]string{"shared.go": injShared, "copy.go": f.copySrc})
			if err == nil || !strings.Contains(err.Error(), "copy.go:") {
				t.Errorf("копия не найдена либо без координаты: %v (дома %v)", err, homes)
			}
			_, homes, err = injJudge(t, map[string]string{"shared.go": injShared, "copy.go": f.twinSrc})
			if err != nil {
				t.Errorf("законный близнец дал находку: %v (дома %v)", err, homes)
			}
		})
	}
}

// Текст наружу и комментарии домом не бывают: строка ошибки, где слово `arm`
// стоит рядом со знаком равенства, блочный комментарий SQL, комментарий Go.
func TestGrantArmHomeInjection_ProseAndCommentsAreSilent(t *testing.T) {
	for name, src := range map[string]string{
		"переменная с текстом ошибки": "package p\n\nvar e = \"unknown arm = \"\n",
		"fmt.Errorf": "package p\n\nimport \"fmt\"\n\nfunc f(x string) error { return fmt.Errorf(\"rs.arm = %s\", x) }\n",
		"errors.New": "package p\n\nimport \"errors\"\n\nvar e = errors.New(\"rs.arm = 'names'\")\n",
		"блочный комментарий SQL": "package p\n\nconst q = `SELECT 1 /* rs.arm = 'x' /* вложенный */ AND rs.arm = 'y' */ FROM t`\n",
		"комментарий Go":          "package p\n\n// rs.arm = 'names'\nconst q = `SELECT 1`\n",
	} {
		t.Run(name, func(t *testing.T) {
			_, homes, err := injJudge(t, map[string]string{"shared.go": injShared, "copy.go": src})
			if err != nil {
				t.Errorf("находка на тексте, который запросом не является: %v (дома %v)", err, homes)
			}
		})
	}
}
