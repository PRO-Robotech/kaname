// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// acceptancekeystate_test.go — §17.4 приёмки трёх разделов манифеста объявляет
// СОСТОЯНИЕ ключей глагола в контракте. Утверждение обязано совпадать со схемой
// `schema/module-manifest.schema.json`, а объявленный заведённым ключ — назвать
// читателя, существующего в не-тестовом дереве модуля.
//
// # Что стережётся
//
// Утверждение, пережившее свой предмет, в APPROVED-документе. Раздел объявлял
// отсутствие четырёх ключей и объяснял, ПОЧЕМУ их нет; один из них
// (`internal`) с тех пор заведён вместе с читателями. Читатель, сверяющий
// контракт по приёмке, получал подтверждение отсутствия там, где ключ есть, —
// и либо заводил его второй раз, либо не шёл за ним в код.
//
// # Судится в ОБЕ стороны, и это несущее
//
// Односторонний предикат («ни один заведённый ключ не объявлен отсутствующим»)
// зеленел бы на разделе, где не сказано ничего. Поэтому две оси:
//
//   - ТАБЛИЦА состояний: строка сверяется со схемой в обе стороны — «есть» при
//     отсутствии в схеме находка ровно так же, как «нет» при наличии; сверх
//     того «есть» обязано назвать читателя, и читатель обязан существовать в
//     не-тестовом Go модуля;
//   - ПРОЗА: строка вне таблицы, утверждающая «в контракте нет» про ключ,
//     который схема ОБЪЯВЛЯЕТ, — находка, ЕСЛИ таблица её не перекрывает.
//
// # Почему проза перекрывается таблицей, а не переписывается
//
// Решение круга приёмки верно на своей ревизии, и слово APPROVED покрывает
// именно его текст: переписать заголовок значило бы утверждать, что рецензент
// читал другое. Поэтому раздел сохраняет запись круга, а состояние дописывает
// врезкой — тот же порядок, каким §2.6а этой приёмки записала сработавший
// предикат пересмотра. Гейт это и проверяет: устаревшая проза законна ровно
// пока рядом стоит строка таблицы, называющая сегодняшнее состояние ключа.
// Исчезнет строка — проза снова станет находкой, то есть послабление истекает
// само.
//
// # Формы записи, которые распознаватель обязан знать
//
// Таблица состояний живёт ВНУТРИ врезки `> [!important]` — так её записала
// §2.6а, и это законная форма корпуса. Строки такой таблицы несут маркер
// цитаты, поэтому маркер снимается до разбора: распознаватель, знающий только
// голую строку, не видел бы врезку вовсе — не находкой, а невидимостью.
//
// # Почему проза судится ПОСТРОЧНО
//
// Строка, смешавшая два утверждения («их нет, а этот есть»), разобрана быть не
// может: у распознавателя нет способа отнести токен к нужной половине. Граница
// названа, а не спрятана: таблица судится своей осью, проза — своей, и раздел
// обязан не смешивать их в одной строке.
//
// # Чего гейт НЕ судит, и это граница, а не пропуск
//
// Он не судит, ПРАВДУ ли говорит объяснение раздела и достаточен ли названный
// читатель по существу: «достаточен» машинного предиката не имеет. Он судит
// совпадение перечислимых множеств — ключей, названных разделом, и свойств,
// объявленных схемой.
package manifest_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const (
	// keyStateDoc — приёмка трёх разделов манифеста.
	keyStateDoc = "../../docs/engineering/acceptance/module-manifest-resources-roles-deprecated.md"
	// keyStateSchema — контракт манифеста, о котором §17.4 делает утверждение.
	keyStateSchema = "../../schema/module-manifest.schema.json"
	// keyStateGoRoot — корень модуля: там ищутся читатели заведённых ключей.
	keyStateGoRoot = "../.."
	// keyStateHeading — заголовок судимого раздела.
	keyStateHeading = "### 17.4."
)

var (
	// keyStateTokenRe — токен в обратных кавычках: так раздел называет ключ.
	keyStateTokenRe = regexp.MustCompile("`([A-Za-z_][A-Za-z0-9_]*)`")
	// keyStateAbsenceRe — утверждение об отсутствии в контракте. Две формы —
	// заголовочная («в контракте НЕТ») и строчная («в контракте нет»).
	keyStateAbsenceRe = regexp.MustCompile(`(?i)в контракте\s+нет`)
	// keyStateMarkupRe — разметка выделения перед словом состояния.
	keyStateMarkupRe = regexp.MustCompile(`^[*_\s]+`)
	// keyStateIdentRe — читатель, названный колонкой: последний сегмент
	// квалифицированного имени в обратных кавычках («manifest.Verb.Internal»).
	keyStateIdentRe = regexp.MustCompile("`([A-Za-z_][A-Za-z0-9_.]*)`")
	// keyStateWordRe строится по идентификатору при поиске читателя в дереве.
	keyStateWordRe = regexp.MustCompile(`\w+`)
)

// keyStateVerdict читает колонку состояния. Слово русское, поэтому предикат
// НЕ строится на `\b`: в Go `\w` — только ASCII, и границы слова между `т` и
// `*` не существует. Односторонняя проверка на этом молча возвращала бы
// «состояние не читается» для КАЖДОЙ строки — то есть перепись росла бы, а
// сверка не выполнялась ни разу.
func keyStateVerdict(cell string) (present, absent bool) {
	v := strings.ToLower(keyStateMarkupRe.ReplaceAllString(strings.TrimSpace(cell), ""))
	return strings.HasPrefix(v, "есть"), strings.HasPrefix(v, "нет")
}

// keyStateUnquote снимает маркеры цитаты врезки и внешние пробелы: строка
// таблицы внутри `> [!important]` — законная форма записи, и распознаватель,
// её не знающий, оставил бы врезку вне наблюдения.
func keyStateUnquote(raw string) string {
	ln := strings.TrimSpace(raw)
	for strings.HasPrefix(ln, ">") {
		ln = strings.TrimSpace(strings.TrimPrefix(ln, ">"))
	}
	return ln
}

// schemaDeclaredProperties — множество имён, объявленных схемой хоть где-то в
// `properties`. Обход рекурсивный: ключ глагола лежит внутри `oneOf`, и путь к
// нему выписывать нельзя — он переедет вместе с формой.
func schemaDeclaredProperties(path string) (map[string]bool, error) {
	body, err := os.ReadFile(path) // #nosec G304 -- путь — константа пакета
	if err != nil {
		return nil, err
	}
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, err
	}
	out := make(map[string]bool)
	var walk func(any)
	walk = func(n any) {
		switch v := n.(type) {
		case map[string]any:
			if props, ok := v["properties"].(map[string]any); ok {
				for k := range props {
					out[k] = true
				}
			}
			for _, child := range v {
				walk(child)
			}
		case []any:
			for _, child := range v {
				walk(child)
			}
		}
	}
	walk(doc)
	return out, nil
}

// cutHeadingSection вырезает раздел от его заголовка до следующего заголовка
// того же или более высокого уровня.
func cutHeadingSection(text, heading string) string {
	lines := strings.Split(text, "\n")
	start := -1
	for i, ln := range lines {
		if strings.HasPrefix(ln, heading) {
			start = i
			break
		}
	}
	if start < 0 {
		return ""
	}
	for i := start + 1; i < len(lines); i++ {
		ln := lines[i]
		if strings.HasPrefix(ln, "### ") || strings.HasPrefix(ln, "## ") || strings.HasPrefix(ln, "# ") {
			return strings.Join(lines[start:i], "\n")
		}
	}
	return strings.Join(lines[start:], "\n")
}

// goIdentifierIsDeclared — назван ли идентификатор в не-тестовом Go дерева.
// Единица счёта — файл: гейт печатает, сколько их прочитано, чтобы «читателя
// нет» было отличимо от «не читали».
func goIdentifierIsDeclared(root, qualified string) (bool, int, error) {
	parts := strings.Split(qualified, ".")
	ident := parts[len(parts)-1]
	if !keyStateWordRe.MatchString(ident) {
		return false, 0, nil
	}
	needle := regexp.MustCompile(`\b` + regexp.QuoteMeta(ident) + `\b`)
	read := 0
	found := false
	err := filepath.WalkDir(root, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // нечитаемый узел не делает вердикт ложным
		}
		if d.IsDir() {
			if d.Name() == "testdata" || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		read++
		if found {
			return nil
		}
		body, rerr := os.ReadFile(p) // #nosec G304 -- обход дерева модуля
		if rerr != nil {
			return nil
		}
		if needle.Match(body) {
			found = true
		}
		return nil
	})
	return found, read, err
}

// keyStateFindings — разбор §17.4. К *testing.T не обращается: проба
// способности падать иначе роняла бы саму себя.
func keyStateFindings(docPath, schemaPath, goRoot string) (findings []string, rows int, seen []string, props, goFiles int) {
	declared, err := schemaDeclaredProperties(schemaPath)
	if err != nil {
		return []string{"схема не прочитана: " + err.Error()}, 0, nil, 0, 0
	}
	props = len(declared)

	body, err := os.ReadFile(docPath) // #nosec G304 -- путь — константа пакета
	if err != nil {
		return []string{"приёмка не прочитана: " + err.Error()}, 0, nil, props, 0
	}
	section := cutHeadingSection(string(body), keyStateHeading)
	if strings.TrimSpace(section) == "" {
		return []string{"раздел «" + keyStateHeading + "» не найден — гейт судил бы о непрочитанном"}, 0, nil, props, 0
	}

	lines := strings.Split(section, "\n")

	// Проход 1 — таблица состояний. Она обязана быть прочитана ЦЕЛИКОМ до
	// прозы: перекрытие иначе зависело бы от порядка строк в документе.
	stated := make(map[string]string)
	for _, raw := range lines {
		ln := keyStateUnquote(raw)
		if !strings.HasPrefix(ln, "|") {
			continue
		}
		cols := strings.Split(strings.Trim(ln, "|"), "|")
		if len(cols) < 3 {
			continue
		}
		keyCell := strings.TrimSpace(cols[0])
		if strings.HasPrefix(keyCell, "---") || strings.EqualFold(keyCell, "ключ") {
			continue
		}
		if m := keyStateTokenRe.FindStringSubmatch(keyCell); m != nil {
			stated[m[1]] = strings.TrimSpace(cols[1])
		}
	}

	for _, raw := range lines {
		ln := keyStateUnquote(raw)
		if strings.HasPrefix(ln, "|") {
			cols := strings.Split(strings.Trim(ln, "|"), "|")
			if len(cols) < 3 {
				continue
			}
			keyCell := strings.TrimSpace(cols[0])
			if strings.HasPrefix(keyCell, "---") || strings.EqualFold(keyCell, "ключ") {
				continue
			}
			m := keyStateTokenRe.FindStringSubmatch(keyCell)
			if m == nil {
				continue
			}
			rows++
			seen = append(seen, m[1])
			key := m[1]
			state := strings.TrimSpace(cols[1])
			reader := strings.TrimSpace(cols[2])
			present, absent := keyStateVerdict(state)
			switch {
			case present:
				if !declared[key] {
					findings = append(findings, "строка таблицы объявляет ключ `"+key+
						"` заведённым, а схема его НЕ объявляет"+
						"\n    состояние выдано авансом: читатель напишет ключ, который загрузчик отвергнет")
					continue
				}
				rm := keyStateIdentRe.FindStringSubmatch(reader)
				if rm == nil {
					findings = append(findings, "ключ `"+key+"` объявлен заведённым и НЕ называет читателя"+
						"\n    ключ без читателя есть «принято-и-проигнорировано» в самом контракте")
					continue
				}
				ok, read, werr := goIdentifierIsDeclared(goRoot, rm[1])
				goFiles = read
				if werr != nil {
					findings = append(findings, "дерево не обойдено: "+werr.Error())
					continue
				}
				if read == 0 {
					findings = append(findings, "обход пуст: не-тестовых файлов Go прочитано ноль — "+
						"«читателя нет» неотличимо от «не читали»")
					continue
				}
				if !ok {
					findings = append(findings, "ключ `"+key+"` называет читателем `"+rm[1]+
						"`, которого в не-тестовом Go модуля НЕТ"+
						"\n    держатель выдан авансом: строка обещает читателя, за которым никого нет")
				}
			case absent:
				if declared[key] {
					findings = append(findings, "строка таблицы объявляет ключ `"+key+
						"` отсутствующим, а схема его ОБЪЯВЛЯЕТ"+
						"\n    утверждение пережило свой предмет: сверяющий контракт по приёмке увидит подтверждение отсутствия")
				}
			default:
				findings = append(findings, "ключ `"+key+"`: состояние «"+state+
					"» не читается ни как «есть», ни как «нет»"+
					"\n    неразобранная строка молча выпадает из наблюдения")
			}
			continue
		}
		// Проза. Утверждение об отсутствии в контракте связывает КАЖДЫЙ ключ,
		// названный этой же строкой.
		if !keyStateAbsenceRe.MatchString(ln) {
			continue
		}
		for _, m := range keyStateTokenRe.FindAllStringSubmatch(ln, -1) {
			key := m[1]
			if !declared[key] {
				continue
			}
			if present, _ := keyStateVerdict(stated[key]); present {
				// Запись круга сохранена, состояние перекрыто таблицей —
				// раздел стоящего утверждения об отсутствии не делает.
				continue
			}
			seen = append(seen, key)
			findings = append(findings, "проза раздела утверждает «в контракте нет» про ключ `"+key+
				"`, который схема ОБЪЯВЛЯЕТ, и таблица состояний его НЕ перекрывает"+
				"\n    строка: "+ln+
				"\n    утверждение пережило свой предмет — ключ заведён после того, как раздел был написан")
		}
	}

	if len(seen) == 0 {
		findings = append(findings, "обход пуст: §17.4 не назвал ни одного ключа — "+
			"«находок 0» неотличимо от «прочитано 0»")
	}
	sort.Strings(seen)
	return findings, rows, seen, props, goFiles
}

func TestAcceptanceSectionKeyStateMatchesTheSchema(t *testing.T) {
	findings, rows, seen, props, goFiles := keyStateFindings(keyStateDoc, keyStateSchema, keyStateGoRoot)
	for _, f := range findings {
		t.Error(f)
	}
	if len(seen) == 0 || props == 0 {
		t.Fatal("обход пуст — гейт судил бы о непрочитанном")
	}
	t.Logf("перепись: строк таблицы §17.4 прочитано %d · утверждений о ключах осмотрено %d (%s) · "+
		"свойств объявлено схемой %d · не-тестовых файлов Go прочитано %d · находок %d",
		rows, len(seen), strings.Join(seen, ","), props, goFiles, len(findings))
}

// ─────────────────────────────────────────────────────────────────────────────
// Доказательство способности упасть. Инъекция идёт по КОПИИ во временном
// каталоге: правка настоящей приёмки ради пробы оборвала бы соседнюю сессию в
// том же дереве. Каждый случай меняет РОВНО ОДИН факт против законного
// близнеца — иначе неизвестно, какой из двух дал красное.

const (
	// keyStateInjSchema — синтетический контракт: `internal` объявлен, `acr` нет.
	// Ключ лежит внутри `oneOf`, как в настоящей схеме: обход обязан быть
	// рекурсивным, а не по выписанному пути.
	keyStateInjSchema = `{"properties":{"verbs":{"items":{"oneOf":[` +
		`{"type":"string"},` +
		`{"properties":{"name":{},"internal":{}}}]}}}}`
	// keyStateInjReaderGo — не-тестовый Go, называющий читателя.
	keyStateInjReaderGo = "package p\n\nfunc VerbProducesRelation() bool { return true }\n"
)

// keyStateInjDoc собирает раздел из прозы и строк таблицы.
func keyStateInjDoc(prose string, rows ...string) string {
	doc := "## 17. Отступления\n\n### 17.3. Прочее\n\nтекст\n\n" +
		"### 17.4. Состояние ключей\n\n" + prose + "\n\n"
	if len(rows) > 0 {
		doc += "> | ключ | состояние | читатель |\n> |---|---|---|\n"
		for _, r := range rows {
			doc += "> " + r + "\n"
		}
	}
	return doc + "\n### 17.5. Дальше\n\nтекст\n"
}

// keyStateInjFixture кладёт приёмку, схему и корень Go во временный каталог.
func keyStateInjFixture(t *testing.T, doc, schema, goFile string) (string, string, string) {
	t.Helper()
	root := t.TempDir()
	docPath := filepath.Join(root, "acceptance.md")
	schemaPath := filepath.Join(root, "schema.json")
	goRoot := filepath.Join(root, "code")
	if err := os.WriteFile(docPath, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(schemaPath, []byte(schema), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(goRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	if goFile != "" {
		if err := os.WriteFile(filepath.Join(goRoot, "reader.go"), []byte(goFile), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return docPath, schemaPath, goRoot
}

func TestAcceptanceSectionKeyState_CanFailAndStaysSilent(t *testing.T) {
	const (
		goodPresent = "| `internal` | **есть** в контракте | `manifest.VerbProducesRelation` |"
		goodAbsent  = "| `acr` | **нет** в контракте | — |"
		stalePros   = "Ключей `internal` · `acr` в контракте НЕТ"
		plainProse  = "Раздел о форме глагола."
	)

	cases := []struct {
		name   string
		doc    string
		schema string
		goFile string
		want   string
		why    string
	}{
		{
			name:   "законный близнец: таблица сходится со схемой",
			doc:    keyStateInjDoc(plainProse, goodPresent, goodAbsent),
			schema: keyStateInjSchema,
			goFile: keyStateInjReaderGo,
			why:    "верный раздел обязан молчать, иначе первый же ложный срабат отключит гейт",
		},
		{
			name:   "законный близнец: устаревшая проза ПЕРЕКРЫТА строкой таблицы",
			doc:    keyStateInjDoc(stalePros, goodPresent, goodAbsent),
			schema: keyStateInjSchema,
			goFile: keyStateInjReaderGo,
			why:    "запись круга сохраняется, состояние дописывается — тот же порядок, что у §2.6а",
		},
		{
			name:   "проза объявляет отсутствующим ключ, который схема ОБЪЯВЛЯЕТ",
			doc:    keyStateInjDoc(stalePros, goodAbsent),
			schema: keyStateInjSchema,
			goFile: keyStateInjReaderGo,
			want:   "проза раздела утверждает «в контракте нет» про ключ `internal`",
			why:    "утверждение, пережившее свой предмет, и таблица его не перекрывает",
		},
		{
			name:   "таблица объявляет отсутствующим ключ, который схема ОБЪЯВЛЯЕТ",
			doc:    keyStateInjDoc(plainProse, "| `internal` | **нет** в контракте | — |", goodAbsent),
			schema: keyStateInjSchema,
			goFile: keyStateInjReaderGo,
			want:   "объявляет ключ `internal` отсутствующим, а схема его ОБЪЯВЛЯЕТ",
			why:    "вторая сторона той же оси: устареть может и сама таблица",
		},
		{
			name:   "таблица объявляет заведённым ключ, которого схема НЕ объявляет",
			doc:    keyStateInjDoc(plainProse, goodPresent, "| `acr` | **есть** в контракте | `manifest.VerbProducesRelation` |"),
			schema: keyStateInjSchema,
			goFile: keyStateInjReaderGo,
			want:   "объявляет ключ `acr` заведённым, а схема его НЕ объявляет",
			why:    "состояние, выданное авансом, читается как обещание контракта",
		},
		{
			name:   "заведённый ключ НЕ называет читателя",
			doc:    keyStateInjDoc(plainProse, "| `internal` | **есть** в контракте | — |", goodAbsent),
			schema: keyStateInjSchema,
			goFile: keyStateInjReaderGo,
			want:   "объявлен заведённым и НЕ называет читателя",
			why:    "ключ без читателя есть «принято-и-проигнорировано» в самом контракте",
		},
		{
			name:   "названный читатель в не-тестовом Go отсутствует",
			doc:    keyStateInjDoc(plainProse, "| `internal` | **есть** в контракте | `manifest.NoSuchReaderXyz` |", goodAbsent),
			schema: keyStateInjSchema,
			goFile: keyStateInjReaderGo,
			want:   "которого в не-тестовом Go модуля НЕТ",
			why:    "держатель, выданный авансом, неотличим от настоящего при чтении",
		},
		{
			name:   "состояние не читается ни как «есть», ни как «нет»",
			doc:    keyStateInjDoc(plainProse, "| `internal` | под вопросом | `manifest.VerbProducesRelation` |", goodAbsent),
			schema: keyStateInjSchema,
			goFile: keyStateInjReaderGo,
			want:   "не читается ни как «есть», ни как «нет»",
			why:    "неразобранная строка выпала бы из наблюдения молча",
		},
		{
			name:   "раздел не называет ни одного ключа — обход пуст",
			doc:    keyStateInjDoc(plainProse),
			schema: keyStateInjSchema,
			goFile: keyStateInjReaderGo,
			want:   "обход пуст",
			why:    "«находок 0» обязано быть отличимо от «прочитано 0»",
		},
		{
			name:   "раздела нет вовсе — гейт судил бы о непрочитанном",
			doc:    "## 17. Отступления\n\n### 17.3. Прочее\n\nтекст\n",
			schema: keyStateInjSchema,
			goFile: keyStateInjReaderGo,
			want:   "не найден",
			why:    "исчезнувший раздел не есть зелёный вердикт",
		},
		{
			name:   "корень Go пуст — читателя не искали, а не «его нет»",
			doc:    keyStateInjDoc(plainProse, goodPresent, goodAbsent),
			schema: keyStateInjSchema,
			goFile: "",
			want:   "обход пуст: не-тестовых файлов Go прочитано ноль",
			why:    "«не знаю» не выдаётся ни за «есть», ни за «нет»",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			docPath, schemaPath, goRoot := keyStateInjFixture(t, tc.doc, tc.schema, tc.goFile)
			findings, rows, seen, props, goFiles := keyStateFindings(docPath, schemaPath, goRoot)
			joined := strings.Join(findings, "\n")
			t.Logf("перепись случая: строк %d · ключей %d · свойств схемы %d · файлов Go %d · находок %d",
				rows, len(seen), props, goFiles, len(findings))
			if tc.want == "" {
				if len(findings) != 0 {
					t.Fatalf("законный близнец обязан молчать (%s), а гейт сказал:\n%s", tc.why, joined)
				}
				return
			}
			if !strings.Contains(joined, tc.want) {
				t.Fatalf("гейт обязан назвать «%s» (%s), а сказал:\n%s", tc.want, tc.why, joined)
			}
		})
	}
}

// TestAcceptanceSectionKeyState_SchemaWalkIsRecursive закрепляет предпосылку
// гейта: ключ глагола лежит ВНУТРИ `oneOf`, поэтому обход схемы по выписанному
// пути промахнулся бы, а гейт объявил бы заведённый ключ отсутствующим.
func TestAcceptanceSectionKeyState_SchemaWalkIsRecursive(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "schema.json")
	if err := os.WriteFile(path, []byte(keyStateInjSchema), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := schemaDeclaredProperties(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got["internal"] {
		t.Error("обход не достал ключ из `oneOf` — предпосылка гейта неверна")
	}
	if got["acr"] {
		t.Error("обход выдумал ключ, которого схема не объявляет")
	}
	names := make([]string, 0, len(got))
	for k := range got {
		names = append(names, k)
	}
	sort.Strings(names)
	t.Logf("перепись: свойств прочитано %d (%s)", len(got), strings.Join(names, ","))
}
