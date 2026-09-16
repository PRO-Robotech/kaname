// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package declaredbreak — АДЪЮДИКАЦИЯ ломающих изменений контракта, а не голый
// `buf breaking`.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАЧЕМ АДЪЮДИКАЦИЯ, А НЕ ПРОСТО ПРОВЕРКА
//
// Голый `buf breaking` верен ровно до того дня, когда ломающее изменение
// становится ОСОЗНАННЫМ — снят метод, отвечающий отказом при любом входе; снято
// поле, которое служба принимает и не читает. Тогда шаг красен ПО ПОСТРОЕНИЮ, и
// у читателя остаются два плохих хода: снять шаг — потерять защиту от СЛУЧАЙНЫХ
// разрывов на всём дереве ради одного объявленного; либо внести файл в
// `breaking.ignore` — послабление без предмета и без срока, ослепляющее проверку
// на целом файле НАВСЕГДА.
//
// Поэтому разрыв проходит только через перечень объявленных, и запись живёт
// ровно пока у неё есть предмет: НАХОДКА ВНЕ ПЕРЕЧНЯ — КРАСНОЕ, ЗАПИСЬ БЕЗ
// НАХОДКИ — ТОЖЕ КРАСНОЕ. Вторая половина и есть самоистечение: без неё перечень
// пережил бы свой предмет и остался бы слепой зоной, выданной вперёд.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ СВОЯ РЕАЛИЗАЦИЯ, А НЕ КОПИЯ ПЛАТФОРМЕННОЙ
//
// У платформы адъюдикатор того же класса есть. Взять его файлом нельзя: копия
// файла чужого репозитория запрещена, и запрет не смягчается совпадением
// содержимого — он им ДОКАЗЫВАЕТСЯ, потому что расхождение наступит молча.
// Взять пином тоже нельзя: ребро `kaname → kacho` снято, и заводить его обратно
// ради проверки значило бы замкнуть граф.
//
// Поэтому здесь ПОВТОРЕН ПРЕДМЕТ, а не текст: те же три исхода, то же
// самоистечение, тот же разбор вывода. Расхождение реализаций расхождением
// СВОЙСТВА не является — свойство у каждого дерева своё, и доказывается оно
// своей инъекцией на СВОЁМ выводе buf.
//
// ─────────────────────────────────────────────────────────────────────────────
// ИСХОДОВ ТРИ, И ТРЕТИЙ НЕСУЩИЙ
//
//	0 — находок нет и перечень пуст либо каждая находка объявлена;
//	1 — НАХОДКА: разрыв вне перечня либо запись, которой нечего прощать;
//	2 — гейт НЕ СДЕЛАЛ СВОЕЙ РАБОТЫ: вывод не разобран, перечень не прочитан.
//
// Код возврата самого `buf` разбирает вызывающий: 100 — «есть находки» (штатный
// вход сюда), 0 — «разрывов нет», ЛЮБОЙ ДРУГОЙ — третий исход. Схлопни их, и
// сетевой отказ читался бы как «разрывов нет».
package declaredbreak

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Finding — одна находка `buf breaking`, как её печатает `--error-format=json`.
type Finding struct {
	Path    string `json:"path"`
	Type    string `json:"type"`
	Message string `json:"message"`
	Line    int    `json:"start_line"`
}

// Coordinate — координата находки для сопоставления и для текста.
func (f Finding) Coordinate() string { return f.Type + " " + f.Path + " " + f.Symbol() }

// Symbol — имя снятого символа. buf называет его В КАВЫЧКАХ, и это предпосылка,
// а не догадка: она снята с настоящего вывода buf 1.72.0 и проверяется пробой.
//
// У снятия ФАЙЛА символ совпадает с путём: предмет такой находки — сам файл, и
// другого имени у неё нет.
func (f Finding) Symbol() string {
	if f.Type == fileDeletionRule {
		return f.Path
	}
	m := quotedNameRe.FindAllStringSubmatch(f.Message, -1)
	// Имя символа — ПЕРВОЕ кавычечное вхождение ВИДА ИМЕНИ, и это не мелочь
	// порядка: сообщение называет сперва номер поля, затем СНЯТЫЙ символ, и лишь
	// потом объемлющее сообщение либо службу —
	//
	//	Previously present field "1" with name "id" on message "Role" was deleted.
	//	Previously present RPC "Get" on service "RoleService" was deleted.
	//
	// Предмет находки — то, что СНЯЛИ (`id`, `Get`), а не то, ОТКУДА сняли
	// (`Role`, `RoleService`). Последнее вхождение дало бы контейнер, и запись
	// ведомости назвала бы не тот символ, что находка: сопоставление рассыпалось
	// бы молча — обе стороны остались бы синтаксически верными.
	//
	// Номер поля (`"1"`) именем не является и отсеивается `nameRe` — он начинается
	// с цифры. Ровно поэтому первое вхождение ВИДА ИМЕНИ и первое вхождение в
	// кавычках — разные вещи.
	//
	// Комментарий здесь до задачи #127 говорил «ПОСЛЕДНЕЕ», описывая при этом
	// верный порядок сообщения: читатель, поверивший слову, а не коду, «починил»
	// бы разбор под него. Утверждает выбор проба на НАСТОЯЩЕМ выводе buf —
	// TestSymbolTakesTheRemovedNameNotItsContainer.
	for _, g := range m {
		if nameRe.MatchString(g[1]) {
			return g[1]
		}
	}
	return ""
}

const fileDeletionRule = "FILE_NO_DELETE"

// minReasonLen — причина короче этого причиной не является. Число не выведено из
// природы вещей: оно отсекает заполнители («так надо», «ок»), которые нечем
// оспорить при снятии записи.
const minReasonLen = 24

var (
	quotedProtoRe = regexp.MustCompile(`"([^"]+\.proto)"`)
	quotedNameRe  = regexp.MustCompile(`"([^"]+)"`)
	nameRe        = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.]*$`)
	ruleRe        = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,}$`)
	// Ссылка на задачу ОБЯЗАНА быть разрешимой: по голому `#71` объявление не
	// может истечь даже в принципе — ни человеком, ни машиной.
	issueRe = regexp.MustCompile(
		`^([a-z0-9][a-z0-9._-]*#[0-9]+|https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+/issues/[0-9]+)$`)
)

// Declaration — объявленный разрыв. Полей пять, и все обязательны.
type Declaration struct {
	Rule   string `yaml:"rule"`
	Path   string `yaml:"path"`
	Symbol string `yaml:"symbol"`
	Reason string `yaml:"reason"`
	Issue  string `yaml:"issue"`
}

// Validate — негодная запись есть находка, а не молчание: объявление, которое
// нельзя сопоставить, прощает не то, что называет.
func (d Declaration) Validate() []string {
	var bad []string
	if !ruleRe.MatchString(d.Rule) {
		bad = append(bad, fmt.Sprintf("rule %q не похоже на идентификатор правила buf", d.Rule))
	}
	if d.Path == "" {
		bad = append(bad, "path пуст — запись прощала бы разрыв в ЛЮБОМ файле")
	}
	if d.Symbol == "" {
		bad = append(bad, "symbol пуст — запись прощала бы ЛЮБОЙ разрыв этого файла")
	}
	if len([]rune(strings.TrimSpace(d.Reason))) < minReasonLen {
		bad = append(bad, fmt.Sprintf("reason короче %d знаков — объявление без причины "+
			"нечем оспорить при снятии", minReasonLen))
	}
	if !issueRe.MatchString(d.Issue) {
		bad = append(bad, fmt.Sprintf("issue %q не разрешима — по такой ссылке объявление "+
			"не может истечь даже в принципе", d.Issue))
	}
	if d.Rule == fileDeletionRule && d.Path != d.Symbol {
		bad = append(bad, "у снятия файла path и symbol обязаны совпадать: предмет такой "+
			"находки — сам файл, другого имени у неё нет")
	}
	return bad
}

func (d Declaration) matches(f Finding) bool {
	return d.Rule == f.Type && d.Path == f.Path && d.Symbol == f.Symbol()
}

// ParseFindings — разбор вывода `buf breaking --error-format=json`.
//
// СТРОКА, НЕ ЯВЛЯЮЩАЯСЯ ОБЪЕКТОМ JSON, — ОТКАЗ, а не пропуск: buf печатает в
// поток вывода только находки, и всё прочее означает, что шаг не сделал своей
// работы. Молчание здесь читалось бы как «разрывов нет».
func ParseFindings(r io.Reader) ([]Finding, error) {
	var out []Finding
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for n := 1; sc.Scan(); n++ {
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		if !strings.HasPrefix(raw, "{") {
			return nil, fmt.Errorf("строка %d вывода buf не является объектом JSON: %q",
				n, truncate(raw, 160))
		}
		var f Finding
		if err := json.Unmarshal([]byte(raw), &f); err != nil {
			return nil, fmt.Errorf("строка %d вывода buf не разобрана: %w", n, err)
		}
		if f.Path == "" {
			p, err := pathFromMessage(f.Message)
			if err != nil {
				return nil, fmt.Errorf("строка %d вывода buf: %w", n, err)
			}
			f.Path = p
		}
		if f.Symbol() == "" {
			return nil, fmt.Errorf("строка %d вывода buf: имя символа не названо в кавычках "+
				"(%q) — сопоставить объявление не с чем", n, truncate(f.Message, 160))
		}
		out = append(out, f)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("чтение вывода buf: %w", err)
	}
	return out, nil
}

// pathFromMessage — путь находки, у которой поля пути НЕТ.
//
// Поля нет не потому, что buf его забыл: предмет находки — сам файл, которого в
// новом дереве уже не существует, и указывать не на что. Единственное место, где
// buf называет предмет, — сообщение, и называет он его в кавычках.
//
// НЕ УГАДЫВАЕТ: годится ровно один путь `.proto` в кавычках. Ноль (форма
// сообщения изменилась) и больше одного (какой из двух предмет — решить нечем) —
// отказ. Молчаливая догадка дала бы объявление, сопоставленное не с тем разрывом.
func pathFromMessage(msg string) (string, error) {
	m := quotedProtoRe.FindAllStringSubmatch(msg, -1)
	switch len(m) {
	case 1:
		return m[0][1], nil
	case 0:
		return "", fmt.Errorf("у находки нет поля пути, и сообщение не называет файла "+
			"в кавычках: %q", truncate(msg, 160))
	default:
		return "", fmt.Errorf("у находки нет поля пути, а сообщение называет %d файлов — "+
			"какой из них предмет, решить нечем: %q", len(m), truncate(msg, 160))
	}
}

// LoadDeclarations — перечень объявленных разрывов.
//
// ОТСУТСТВИЕ ФАЙЛА — ОТКАЗ, А НЕ ПУСТОЙ ПЕРЕЧЕНЬ: «перечня нет» и «перечень пуст»
// ведут читателя в разные места, и схлопывание их сделало бы удаление файла
// способом снять проверку.
func LoadDeclarations(path string) ([]Declaration, error) {
	body, err := os.ReadFile(path) // #nosec G304 -- путь перечня даёт вызывающий
	if err != nil {
		return nil, fmt.Errorf("перечень объявленных разрывов не прочитан: %w", err)
	}
	var doc struct {
		Breaks []Declaration `yaml:"breaks"`
	}
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("перечень %s не разобран: %w", path, err)
	}
	return doc.Breaks, nil
}

// Result — исход адъюдикации.
type Result struct {
	// Undeclared — разрывы, которых нет в перечне.
	Undeclared []Finding
	// Expired — записи, которым нечего прощать. Самоистечение перечня.
	Expired []Declaration
	// Matched — объявленные разрывы, нашедшие свой предмет.
	Matched int
	// Invalid — негодные записи перечня.
	Invalid []string
	// Findings — сколько находок разобрано, Declarations — сколько записей прочитано.
	Findings     int
	Declarations int
}

// Clean — гейт зелен только когда пусты ВСЕ три половины.
func (r Result) Clean() bool {
	return len(r.Undeclared) == 0 && len(r.Expired) == 0 && len(r.Invalid) == 0
}

// Adjudicate — сопоставление находок с объявлениями.
func Adjudicate(findings []Finding, decls []Declaration) Result {
	res := Result{Findings: len(findings), Declarations: len(decls)}
	used := make([]bool, len(decls))
	for i, d := range decls {
		for _, bad := range d.Validate() {
			res.Invalid = append(res.Invalid,
				fmt.Sprintf("запись %d (%s %s %s): %s", i+1, d.Rule, d.Path, d.Symbol, bad))
		}
	}
	for _, f := range findings {
		hit := false
		for i, d := range decls {
			if d.matches(f) {
				used[i] = true
				hit = true
				res.Matched++
				break
			}
		}
		if !hit {
			res.Undeclared = append(res.Undeclared, f)
		}
	}
	for i, d := range decls {
		if !used[i] {
			res.Expired = append(res.Expired, d)
		}
	}
	return res
}

// Report — перепись и находки. Объём осмотренного печатается ВСЕГДА: «ноль
// находок» обязано быть отличимо от «ноль прочитанного».
func (r Result) Report() string {
	var b strings.Builder
	fmt.Fprintf(&b, "адъюдикация разрывов: находок разобрано %d · записей перечня %d · "+
		"объявлено и найдено %d · вне перечня %d · записей без предмета %d · негодных записей %d\n",
		r.Findings, r.Declarations, r.Matched, len(r.Undeclared), len(r.Expired), len(r.Invalid))
	for _, f := range r.Undeclared {
		fmt.Fprintf(&b, "  РАЗРЫВ ВНЕ ПЕРЕЧНЯ: %s — %s\n", f.Coordinate(), truncate(f.Message, 200))
	}
	for _, d := range r.Expired {
		fmt.Fprintf(&b, "  ЗАПИСИ НЕЧЕГО ПРОЩАТЬ: %s %s %s (%s) — разрыв стал историей "+
			"либо не наступал; запись снимается\n", d.Rule, d.Path, d.Symbol, d.Issue)
	}
	for _, s := range r.Invalid {
		fmt.Fprintf(&b, "  НЕГОДНАЯ ЗАПИСЬ: %s\n", s)
	}
	sort.Strings(r.Invalid)
	return b.String()
}

func truncate(s string, n int) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}
