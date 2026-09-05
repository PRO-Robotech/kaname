// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzplan

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Разбор БОЕВОЙ модели прав и компиляция её в план вердикта формы E.
//
// # Зачем это здесь, а не рядом переписанной моделью
//
// Замер XC-10 доказал эквивалентность вердиктов на фикстуре из ОДНОЙ роли и
// ЧЕТЫРЁХ глаголов, тогда как модель объявляет 24 типа с глаголами и 99 глаголов
// суммарно. Утверждение «политика останется той же» на такой фикстуре не
// проверяется: она не содержит ни каскада через чужой указатель, ни владельца как
// источника глаголов, ни членства в группе, ни подстановочного субъекта, ни
// условия на кортеже.
//
// Модель здесь ЧИТАЕТСЯ из канонического файла и разбирается, а не переписывается
// рядом. Причина та же, по которой трансформы форм C и D сделаны трансформами
// текста: две рукописные модели об одном предмете расходятся молча — расхождение в
// прозе не даёт конфликта слияния. Если завтра в модель добавят тип, глагол или
// источник, разбор увидит это сам, а вопросник спросит про новое, потому что он
// СТРОИТСЯ из разбора.
//
// # Классификация без корзины «прочее»
//
// Компилятор обязан отнести КАЖДЫЙ терм КАЖДОГО отношения к одному из названных
// видов. Терм, который не отнесён, — это исход (в) задания: часть модели, не
// выразимая в схеме формы E. Он не проглатывается и не сваливается в «остальное»:
// он называется поимённо и печатается в отчёте. Молчаливое проглатывание дало бы
// форму E, «совпавшую» с движком ровно потому, что про непонятое её не спросили.

// ── разбор ────────────────────────────────────────────────────────────────────

// TermKind — вид терма в правой части объявления отношения.
type TermKind int

const (
	// TermDirect — прямой список назначаемых субъектов: `[user, group#member]`.
	TermDirect TermKind = iota
	// TermComputed — отношение ТОГО ЖЕ объекта: `admin`.
	TermComputed
	// TermTTU — отношение объекта, на который указывает указатель: `admin from account`.
	TermTTU
)

// DirectSubject — одна запись прямого списка.
type DirectSubject struct {
	Type      string // тип субъекта либо тип-указатель: user, service_account, group, cluster…
	Wildcard  bool   // `user:*`
	Userset   string // `group#member` → "member"
	Condition string // `user with mfa_fresh` → "mfa_fresh"
}

// String возвращает запись в том виде, в каком она стоит в модели.
func (d DirectSubject) String() string {
	s := d.Type
	switch {
	case d.Wildcard:
		s += ":*"
	case d.Userset != "":
		s += "#" + d.Userset
	}
	if d.Condition != "" {
		s += " with " + d.Condition
	}
	return s
}

// Term — один дизъюнкт правой части.
type Term struct {
	Kind        TermKind
	Direct      []DirectSubject
	Computed    string
	TTURelation string
	TTUPointer  string
	Raw         string
}

// Relation — одно объявление `define`.
type Relation struct {
	Owner *ModelType
	Name  string
	Terms []Term
	Raw   string
	Line  int
}

// ModelType — один `type`.
type ModelType struct {
	Name      string
	Relations []*Relation
	byName    map[string]*Relation
}

// Rel возвращает отношение типа либо nil.
func (t *ModelType) Rel(name string) *Relation { return t.byName[name] }

// Model — разобранная модель целиком.
type Model struct {
	Types      []*ModelType
	Conditions []string
	byName     map[string]*ModelType

	// pointers — имена отношений-указателей, ВЫВЕДЕННЫЕ из текста: указателем
	// считается ровно то отношение, через которое хоть одно объявление ходит
	// формой `X from <указатель>`. Признак выводится, а не выписывается: список
	// имён в этом файле был бы вторым местом об одном предмете.
	// Pointers — тип → имена его указателей на предка. Экспортировано: цепь
	// областей есть ЧАСТЬ разобранной модели, и всякий, кто по ней ходит
	// (вычисление предков, проверка выразимости, замер), обязан ходить по ЭТОЙ
	// карте, а не строить свою из тех же объявлений.
	Pointers map[string]map[string]bool
}

// Type возвращает тип по имени либо nil.
func (m *Model) Type(name string) *ModelType { return m.byName[name] }

// TypeNames возвращает имена типов в порядке объявления.
func (m *Model) TypeNames() []string {
	out := make([]string, 0, len(m.Types))
	for _, t := range m.Types {
		out = append(out, t.Name)
	}
	return out
}

// VerbPrefix — приставка отношения-глагола.
//
// Она не выбрана здесь, а выведена из продукта: имя отношения-глагола собирает
// реконсайлер iam, приводя глагол роли к канонической форме и приписывая эту
// приставку (комментарий у `v_addtargets` в самой модели это и фиксирует).
// Поэтому «глагол» здесь — свойство ИМЕНИ, и держит его сама модель, а не
// память автора.
//
// Приведение имени происходит НЕ ЗДЕСЬ, и назвать его действующей защитой этого
// пакета было бы неправдой: пакет разбирает уже готовый текст модели и имён не
// строит. Прежняя редакция называла функцию приведения по имени — после переезда
// компилятора из прибора в прод она осталась в другом пакете, и комментарий стал
// утверждать, что сегмент закрыт тем, чего в этом доме нет. Поймано гейтом
// TestCommentsNamingAGuardHaveItInScope, а не чтением: комментарий уже ответил
// на вопрос «закрыт ли», поэтому проверять его никто не шёл.
const VerbPrefix = "v_"

// IsVerb отвечает, является ли отношение отношением-глаголом.
func IsVerb(rel string) bool { return strings.HasPrefix(rel, VerbPrefix) }

// Verbs возвращает глаголы типа в порядке объявления.
func (t *ModelType) Verbs() []string {
	var out []string
	for _, r := range t.Relations {
		if IsVerb(r.Name) {
			out = append(out, r.Name)
		}
	}
	return out
}

// ParseModel разбирает канонический DSL.
//
// Он отвергает вход, а не пропускает непонятое: нераспознанная строка внутри
// блока `relations`, отношение без термов, пересечение или вычитание (`and` /
// `but not`) — ошибка. Разбор, молча пропускающий конструкцию, произвёл бы план,
// который «совпал» с движком потому, что о пропущенном не спросили.
func ParseModel(dsl string) (*Model, error) {
	m := &Model{byName: map[string]*ModelType{}, Pointers: map[string]map[string]bool{}}
	var cur *ModelType
	inRelations := false

	for i, raw := range strings.Split(dsl, "\n") {
		line := strings.TrimRight(raw, " \t\r")
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "" || strings.HasPrefix(trimmed, "#"):
			continue
		case strings.HasPrefix(line, "model") || strings.HasPrefix(trimmed, "schema "):
			continue
		case strings.HasPrefix(line, "condition "):
			name := strings.TrimSpace(strings.SplitN(strings.TrimPrefix(line, "condition "), "(", 2)[0])
			m.Conditions = append(m.Conditions, name)
			cur, inRelations = nil, false
			continue
		case strings.HasPrefix(line, "type "):
			name := strings.TrimSpace(strings.TrimPrefix(line, "type "))
			if name == "" {
				return nil, fmt.Errorf("строка %d: `type` без имени", i+1)
			}
			cur = &ModelType{Name: name, byName: map[string]*Relation{}}
			m.Types = append(m.Types, cur)
			m.byName[name] = cur
			inRelations = false
			continue
		case trimmed == "relations":
			if cur == nil {
				return nil, fmt.Errorf("строка %d: `relations` вне типа", i+1)
			}
			inRelations = true
			continue
		case strings.HasPrefix(trimmed, "define "):
			if cur == nil || !inRelations {
				return nil, fmt.Errorf("строка %d: `define` вне блока relations", i+1)
			}
			rel, err := parseDefine(strings.TrimPrefix(trimmed, "define "), i+1)
			if err != nil {
				return nil, err
			}
			rel.Owner = cur
			cur.Relations = append(cur.Relations, rel)
			cur.byName[rel.Name] = rel
			continue
		default:
			// Тело условия (CEL) — единственное, что законно лежит вне типов после
			// объявления `condition`; всё прочее нераспознанное отвергается.
			if cur == nil {
				continue
			}
			return nil, fmt.Errorf("строка %d: нераспознанная строка внутри типа %q: %q", i+1, cur.Name, trimmed)
		}
	}

	if len(m.Types) == 0 {
		return nil, fmt.Errorf("в модели не разобрано ни одного типа — предмет разбора отсутствует")
	}

	// Указатели выводятся из фактического употребления `X from <ptr>`.
	for _, t := range m.Types {
		for _, r := range t.Relations {
			for _, term := range r.Terms {
				if term.Kind != TermTTU {
					continue
				}
				if m.Pointers[t.Name] == nil {
					m.Pointers[t.Name] = map[string]bool{}
				}
				m.Pointers[t.Name][term.TTUPointer] = true
			}
		}
	}
	return m, m.validate()
}

func parseDefine(body string, line int) (*Relation, error) {
	i := strings.IndexByte(body, ':')
	if i <= 0 {
		return nil, fmt.Errorf("строка %d: объявление без двоеточия: %q", line, body)
	}
	name := strings.TrimSpace(body[:i])
	rhs := strings.TrimSpace(body[i+1:])
	if name == "" || rhs == "" {
		return nil, fmt.Errorf("строка %d: пустое имя или пустая правая часть: %q", line, body)
	}
	if strings.Contains(rhs, " but not ") || strings.Contains(" "+rhs+" ", " and ") {
		return nil, fmt.Errorf("строка %d: отношение %q использует пересечение либо вычитание — "+
			"разбор их не поддерживает и НЕ вправе делать вид, что понял", line, name)
	}
	rel := &Relation{Name: name, Raw: rhs, Line: line}
	for _, part := range strings.Split(rhs, " or ") {
		term, err := parseTerm(strings.TrimSpace(part), line)
		if err != nil {
			return nil, err
		}
		rel.Terms = append(rel.Terms, term)
	}
	if len(rel.Terms) == 0 {
		return nil, fmt.Errorf("строка %d: отношение %q без термов", line, name)
	}
	return rel, nil
}

func parseTerm(s string, line int) (Term, error) {
	t := Term{Raw: s}
	switch {
	case strings.HasPrefix(s, "["):
		if !strings.HasSuffix(s, "]") {
			return t, fmt.Errorf("строка %d: незакрытый список субъектов: %q", line, s)
		}
		t.Kind = TermDirect
		for _, e := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(s, "["), "]"), ",") {
			e = strings.TrimSpace(e)
			if e == "" {
				return t, fmt.Errorf("строка %d: пустая запись в списке субъектов: %q", line, s)
			}
			var d DirectSubject
			if k := strings.Index(e, " with "); k >= 0 {
				d.Condition = strings.TrimSpace(e[k+len(" with "):])
				e = strings.TrimSpace(e[:k])
			}
			switch {
			case strings.HasSuffix(e, ":*"):
				d.Type, d.Wildcard = strings.TrimSuffix(e, ":*"), true
			case strings.Contains(e, "#"):
				p := strings.SplitN(e, "#", 2)
				d.Type, d.Userset = p[0], p[1]
			default:
				d.Type = e
			}
			t.Direct = append(t.Direct, d)
		}
	case strings.Contains(s, " from "):
		p := strings.SplitN(s, " from ", 2)
		t.Kind = TermTTU
		t.TTURelation, t.TTUPointer = strings.TrimSpace(p[0]), strings.TrimSpace(p[1])
		if t.TTURelation == "" || t.TTUPointer == "" {
			return t, fmt.Errorf("строка %d: неполный терм `X from Y`: %q", line, s)
		}
	default:
		if strings.ContainsAny(s, " []#:") {
			return t, fmt.Errorf("строка %d: нераспознанный терм: %q", line, s)
		}
		t.Kind = TermComputed
		t.Computed = s
	}
	return t, nil
}

// validate сверяет разобранное само с собой: каждое вычисляемое отношение и
// каждый указатель обязаны существовать, а тип каждой записи прямого списка —
// быть объявленным типом.
func (m *Model) validate() error {
	for _, t := range m.Types {
		for _, r := range t.Relations {
			for _, term := range r.Terms {
				switch term.Kind {
				case TermDirect:
					for _, d := range term.Direct {
						if m.byName[d.Type] == nil {
							return fmt.Errorf("%s.%s: тип субъекта %q не объявлен", t.Name, r.Name, d.Type)
						}
					}
				case TermComputed:
					if t.Rel(term.Computed) == nil {
						return fmt.Errorf("%s.%s: вычисляемое отношение %q у типа не объявлено", t.Name, r.Name, term.Computed)
					}
				case TermTTU:
					ptr := t.Rel(term.TTUPointer)
					if ptr == nil {
						return fmt.Errorf("%s.%s: указатель %q у типа не объявлен", t.Name, r.Name, term.TTUPointer)
					}
					for _, target := range m.PointerTargets(ptr) {
						tt := m.byName[target]
						if tt == nil {
							return fmt.Errorf("%s.%s: указатель %q ведёт в необъявленный тип %q", t.Name, r.Name, term.TTUPointer, target)
						}
						if tt.Rel(term.TTURelation) == nil {
							return fmt.Errorf("%s.%s: у типа %q нет отношения %q, которого требует `%s`",
								t.Name, r.Name, target, term.TTURelation, term.Raw)
						}
					}
				}
			}
		}
	}
	return nil
}

// pointerTargets — типы, на которые ведёт отношение-указатель.
// PointerTargets — типы, на которые ведёт указатель. Экспортировано по той же
// причине, что и Pointers: это чтение модели, а не шаг компиляции.
func (m *Model) PointerTargets(ptr *Relation) []string {
	// nil — законный вход, а не ошибка вызывающего: отношение спрашивают у
	// КОНКРЕТНОГО блока, а перечни указателей ключуются ИМЕНЕМ типа, и на модели
	// с задвоенным именем блок не знает указателей своего однофамильца. Пустой
	// перечень здесь честнее паники: «этот блок туда не ведёт» — факт, а падение
	// на чужом тексте — не отказ (#1987).
	if ptr == nil {
		return nil
	}
	var out []string
	for _, term := range ptr.Terms {
		if term.Kind != TermDirect {
			continue
		}
		for _, d := range term.Direct {
			out = append(out, d.Type)
		}
	}
	return out
}

// IsPointer отвечает, является ли отношение типа указателем — то есть ходит ли
// через него хоть одно объявление модели.
func (m *Model) IsPointer(typeName, rel string) bool { return m.Pointers[typeName][rel] }

// ── компиляция плана ──────────────────────────────────────────────────────────

// AtomKind — вид источника разрешения в плане формы E.
type AtomKind int

const (
	// AtomBinding — субъект назван в привязке, роль которой даёт спрошенный
	// глагол, правило-селектор которой накрывает объект, а область которой
	// содержит объект. Ровно то, что у движка лежит материализованным кортежем.
	AtomBinding AtomKind = iota
	// AtomFact — строка факта на объекте или на его предке: владелец аккаунта,
	// администратор кластера, членство, подстановочная выдача публичного чтения.
	// Это НЕ материализация состава: строк здесь порядка числа аккаунтов и
	// привязок, а не числа объектов × глаголов.
	AtomFact
)

// Atom — один источник разрешения.
type Atom struct {
	Kind AtomKind
	// ParentType — тип предка, на котором лежит факт; пустая строка означает сам
	// объект. Путь выражен ТИПОМ, а не последовательностью указателей: в этой
	// модели у типа не бывает двух указателей на один и тот же тип предка, и это
	// проверяется (`assertOnePointerPerParentType`), а не предполагается.
	ParentType string
	// Relation — имя отношения. У AtomFact это имя факта, у AtomBinding — ГЛАГОЛ,
	// который обязана давать роль привязки. Он не равен спрошенному отношению
	// всегда: `v_addtargets` выводится в модели от `v_update`, и привязку надо
	// спрашивать про `v_update`. Подставить сюда спрошенное имя значило бы молча
	// отказывать держателю права, которое модель ему даёт.
	Relation string
	Origin   string // откуда терм пришёл — для отчёта и для падения пробы
}

func (a Atom) key() string {
	return fmt.Sprintf("%d|%s|%s", a.Kind, a.ParentType, a.Relation)
}

// Plan — скомпилированный вердикт одного отношения одного типа.
type Plan struct {
	Type     string
	Relation string
	Atoms    []Atom

	// Conditioned — записи прямых списков, несущие условие на кортеже (`with
	// mfa_fresh`). У формы E места под условие НЕТ: её факт — строка, у строки
	// нет контекста запроса, и CEL она не исполняет. Поэтому такие записи
	// называются поимённо и выносятся в исход (в), а не растворяются в атоме.
	Conditioned []string

	// Unclassified — термы, которые компилятор НЕ отнёс ни к одному виду.
	// Непустой список означает, что план неполон и вердикт по нему давать нельзя.
	Unclassified []string
}

// Expressible отвечает, выразим ли план целиком.
func (p Plan) Expressible() bool { return len(p.Unclassified) == 0 }

// Compile строит план вердикта для одного отношения одного типа.
//
// Обход рекурсивный и завершается по построению: ключ посещения несёт ТИП, ИМЯ
// отношения и путь, а глубина пути ограничена (`MaxPointerDepth`). Цикл в модели
// не повесил бы обход, а стал бы находкой — и это лучше, чем незавершимый разбор.
// ErrTypeNotDeclared — тип, о котором спрашивают, в словаре модели не объявлен.
//
// ПОЧЕМУ ЭТО ОТДЕЛЬНАЯ, СИГНАЛЬНАЯ ОШИБКА. По ней вызывающий принимает РЕШЕНИЕ О
// ДОСТУПЕ, и решения тут два разных. «Типа нет вовсе» — это факт о модели:
// объектов такого типа не существует, отношений на них не существует, и честный
// ответ — ОТКАЗ. «Не смог ответить» (сломанный план, недостижимый источник) —
// это незнание, и выдавать его за отказ запрещено: незнание, поданное как «нет»,
// прячет поломку ровно там, где она опаснее всего.
//
// Различать их сравнением ТЕКСТА нельзя: первая же правка формулировки увела бы
// вызывающего в другую ветвь, и увела бы молча.
//
// Наблюдалось на снятии внешнего движка (#880): вопрос про снятый тип-носитель
// точечных выдач кончался ошибкой вместо отказа, и для вызывающего «нет прав»
// стало неотличимо от «сломалось».
var ErrTypeNotDeclared = errors.New("authzplan: тип не объявлен моделью")

func (m *Model) Compile(typeName, relation string) (Plan, error) {
	t := m.byName[typeName]
	if t == nil {
		return Plan{}, fmt.Errorf("%w: %q", ErrTypeNotDeclared, typeName)
	}
	if t.Rel(relation) == nil {
		return Plan{}, fmt.Errorf("у типа %q нет отношения %q", typeName, relation)
	}
	p := Plan{Type: typeName, Relation: relation}
	seen := map[string]bool{}
	if err := m.walk(&p, t, relation, nil, seen); err != nil {
		return Plan{}, err
	}
	// Дедупликация — план читается человеком и печатается в отчёт; один и тот же
	// источник, пришедший двумя ветвями (частый случай: `admin` и `super_admin`
	// оба приводят к администратору кластера), не должен читаться как два.
	uniq := make([]Atom, 0, len(p.Atoms))
	seenAtom := map[string]bool{}
	for _, a := range p.Atoms {
		if seenAtom[a.key()] {
			continue
		}
		seenAtom[a.key()] = true
		uniq = append(uniq, a)
	}
	p.Atoms = uniq
	sort.Strings(p.Conditioned)
	sort.Strings(p.Unclassified)
	return p, nil
}

// MaxPointerDepth — предел глубины цепи указателей на предка.
//
// Экспортирован намеренно: предел — часть КОНТРАКТА компиляции, а не деталь. Он
// объявляет, сколько уровней иерархии областей вообще может быть пройдено, и
// потребитель (в том числе прибор замера) обязан видеть ту же величину, иначе
// два места разойдутся в том, что считают «слишком глубоко».
const MaxPointerDepth = 4

func (m *Model) walk(p *Plan, cur *ModelType, relation string, path []string, seen map[string]bool) error {
	if len(path) > MaxPointerDepth {
		p.Unclassified = append(p.Unclassified,
			fmt.Sprintf("%s.%s: цепь указателей глубже %d — обход остановлен", cur.Name, relation, MaxPointerDepth))
		return nil
	}
	key := strings.Join(path, "/") + "|" + cur.Name + "|" + relation
	if seen[key] {
		return nil
	}
	seen[key] = true

	r := cur.Rel(relation)
	if r == nil {
		p.Unclassified = append(p.Unclassified,
			fmt.Sprintf("%s.%s: отношение не объявлено у типа, до которого довёл обход", cur.Name, relation))
		return nil
	}
	parent := ""
	if len(path) > 0 {
		parent = path[len(path)-1]
	}

	for _, term := range r.Terms {
		switch term.Kind {
		case TermDirect:
			var termConditions []string
			for _, d := range term.Direct {
				if d.Condition != "" {
					p.Conditioned = append(p.Conditioned,
						fmt.Sprintf("%s.%s: `%s` — условие %q", cur.Name, relation, d.String(), d.Condition))
					termConditions = append(termConditions, d.Condition)
				}
			}
			// Прямой список отношения-ГЛАГОЛА на самом объекте — это то, что
			// реконсайлер разворачивает из привязки; у формы E ему соответствует
			// привязка, а не строка. Рядом остаётся и атом факта: тот же прямой
			// список у продукта наполняется ещё и НЕ из привязки — накладной
			// кортеж публичного чтения репозитория пишет реестр, а не выдача.
			//
			// Глагол, выведенный от глагола ПРЕДКА, формой E не выражается и
			// объявляется таковым, а не приближается: привязка сужается
			// правилом-селектором по типу и меткам ПРЕДКА, а область содержания
			// пришлось бы считать от предка, а не от спрошенного объекта.
			// Сегодня в модели такого нет — и запись самоистекает: появится —
			// план станет невыразимым и проба назовёт координату.
			//
			// Условие на прямом списке ГЛАГОЛА формой E тоже не выражается, и по
			// той же причине: списку глагола соответствует ПРИВЯЗКА, а привязка
			// условия не несёт — роль раздаёт глаголы, места под условие у неё
			// нет. Отдать здесь безусловную привязку значило бы выдать право при
			// НЕВЫПОЛНЕННОМ условии, и потребитель, читающий `Expressible()`, об
			// этом не узнал бы.
			//
			// Условие на отношении-НЕ-глаголе невыразимым НЕ объявляется: ему
			// соответствует атом факта, а строка факта несёт условие на себе
			// (`condition_name`/`condition_params`) и вычисляется на пути запроса.
			// Там ничего не теряется, и отказ отобрал бы доступ у трёх живых
			// отношений канона вместе с их БЕЗУСЛОВНЫМИ источниками.
			//
			// В каноне условия на глаголе нет — предмет приходит ДОСТАВЛЕННЫМ
			// манифестом: имя условия канона доставленному типу доступно, и такой
			// глагол проходит и разбор, и допуск (#1979).
			switch {
			case IsVerb(relation) && parent == "" && len(termConditions) > 0:
				p.Unclassified = append(p.Unclassified,
					fmt.Sprintf("%s.%s: условие %q стоит на прямом списке ГЛАГОЛА — форма E такого не "+
						"выражает: прямому списку глагола соответствует привязка, а привязка условия "+
						"не несёт, и право было бы выдано при невыполненном условии",
						cur.Name, relation, strings.Join(termConditions, ", ")))
			case IsVerb(relation) && parent == "":
				p.Atoms = append(p.Atoms, Atom{Kind: AtomBinding, Relation: relation,
					Origin: cur.Name + "." + relation})
			case IsVerb(relation) && parent != "":
				p.Unclassified = append(p.Unclassified,
					fmt.Sprintf("%s.%s: глагол выводится от глагола предка (%s) — форма E такого не выражает",
						cur.Name, relation, parent))
			}
			p.Atoms = append(p.Atoms, Atom{Kind: AtomFact, ParentType: parent, Relation: relation,
				Origin: cur.Name + "." + relation + " → " + term.Raw})
		case TermComputed:
			if err := m.walk(p, cur, term.Computed, path, seen); err != nil {
				return err
			}
		case TermTTU:
			ptr := cur.Rel(term.TTUPointer)
			if ptr == nil {
				p.Unclassified = append(p.Unclassified,
					fmt.Sprintf("%s.%s: указатель %q не объявлен", cur.Name, relation, term.TTUPointer))
				continue
			}
			targets := m.PointerTargets(ptr)
			if len(targets) == 0 {
				p.Unclassified = append(p.Unclassified,
					fmt.Sprintf("%s.%s: указатель %q никуда не ведёт", cur.Name, relation, term.TTUPointer))
				continue
			}
			for _, target := range targets {
				tt := m.byName[target]
				if tt == nil {
					p.Unclassified = append(p.Unclassified,
						fmt.Sprintf("%s.%s: указатель %q ведёт в необъявленный тип %q", cur.Name, relation, term.TTUPointer, target))
					continue
				}
				if err := m.walk(p, tt, term.TTURelation, append(append([]string{}, path...), target), seen); err != nil {
					return err
				}
			}
		default:
			p.Unclassified = append(p.Unclassified,
				fmt.Sprintf("%s.%s: терм %q не отнесён ни к одному виду", cur.Name, relation, term.Raw))
		}
	}
	return nil
}

// assertOnePointerPerParentType проверяет предпосылку, на которой стоит выражение
// пути ТИПОМ предка вместо последовательности указателей: у типа не должно быть
// двух указателей, ведущих в один и тот же тип. Предпосылка проверяется, а не
// предполагается, — иначе первый же такой тип сделал бы два разных источника
// неразличимыми, и план молча объединил бы их.
// AssertOnePointerPerParentType — у типа не больше одного указателя на каждый
// тип-предка.
//
// Экспортирована, потому что это утверждение о МОДЕЛИ, а не шаг компиляции:
// его обязан уметь задать и тот, кто модель проверяет, не компилируя.
func (m *Model) AssertOnePointerPerParentType() error {
	// Имя типа, объявленное дважды, разбирается на ДВА блока, а карта указателей
	// ключуется именем и несёт указатели обоих. Утверждение «у типа не больше
	// одного указателя на предка» на таком имени НЕ ОПРЕДЕЛЕНО: какой из блоков
	// «тот самый», решал бы порядок сборки. Поэтому здесь отказ, а не подсчёт по
	// одному из блоков: молчание читалось бы как «предпосылка держится», и
	// вызывающий выразил бы путь типом предка на модели, где это неоднозначно.
	//
	// Отказ, а не паника (#1987): метод объявлен утверждением О МОДЕЛИ и зовётся
	// на доставленном тексте, поэтому обязан отвечать на любой вход, который
	// принял `ParseModel`.
	seen := map[string]bool{}
	for _, t := range m.Types {
		if seen[t.Name] {
			return fmt.Errorf("тип %q объявлен в модели более одного раза — утверждение о "+
				"единственности указателя на тип-предка на нём не определено: какой блок "+
				"действует, решал бы порядок сборки", t.Name)
		}
		seen[t.Name] = true
	}
	for _, t := range m.Types {
		byTarget := map[string]string{}
		for rel := range m.Pointers[t.Name] {
			for _, target := range m.PointerTargets(t.Rel(rel)) {
				if prev, ok := byTarget[target]; ok && prev != rel {
					return fmt.Errorf("тип %q ведёт в %q двумя указателями (%s и %s) — "+
						"выражение пути типом предка перестало быть однозначным", t.Name, target, prev, rel)
				}
				byTarget[target] = rel
			}
		}
	}
	return nil
}

// ── перепись ──────────────────────────────────────────────────────────────────

// Census — счётные величины модели. Печатаются в отчёте, потому что «ноль
// расхождений» обязано быть отличимо от «ноль спрошенного».
type Census struct {
	Types           int
	Declarations    int
	VerbTypes       int
	VerbDeclaration int
	Pointers        int
	Conditions      int
}

// Census считает модель по разобранному дереву, а не по строкам файла.
func (m *Model) Census() Census {
	c := Census{Types: len(m.Types), Conditions: len(m.Conditions)}
	for _, t := range m.Types {
		c.Declarations += len(t.Relations)
		if v := t.Verbs(); len(v) > 0 {
			c.VerbTypes++
			c.VerbDeclaration += len(v)
		}
		c.Pointers += len(m.Pointers[t.Name])
	}
	return c
}
