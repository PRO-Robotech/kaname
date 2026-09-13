// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// audit_payload_pii.go — ГЕЙТ КЛАССА: нагрузка записи журнала аудита не несёт
// личных данных (задача `kacho#2483`).
//
// Норма платформы названа здесь ФАКТОМ, а не ссылкой на документ: личные данные
// конечного пользователя — почта, телефон, предъявляемый секрет — не пишутся в
// след ни на успехе, ни на отказе, а корреляция ведётся по неизменяемому
// идентификатору.
//
// # Предмет
//
// Приёмник журнала аудита — собственный поток записей службы, и он кладёт ВСЕ
// поля нагрузки как есть: шага сокрытия нет ни одного. Значит всякий личный
// ключ, положенный в нагрузку, уезжает в поток, а срок хранения потока
// становится сроком хранения личных данных. Корреляция при этом личных полей
// НЕ требует: идентификатор субъекта (`user_id` / `resource_id`) в нагрузке уже
// есть, он неизменяем и остаётся правдой через год, тогда как почта и
// отображаемое имя изменяемы и правдой не остаются.
//
// # Почему ГЕЙТ, а не правка двух мест
//
// Правка закрывает экземпляр; класс приходит не по одному. Мест построения
// нагрузки в дереве три с лишним десятка, они лежат в разных пакетах, и ни одно
// из них не видит остальных. Автор следующего, скопировав соседнее, внесёт
// личный ключ незамеченным: отказа нет, красного нет, наблюдаемо это только у
// получателя потока.
//
// # Перечень личных ключей объявлен ЗАКРЫТЫМ СПИСКОМ, и он не выдуман
//
// Он взят у самого дерева: проба `set_blocked_test.go` уже утверждает
// отсутствие `email` / `display_name` / `displayName` / `external_id` в
// нагрузке пользовательского события — то есть решение о составе личных ключей
// дерево приняло раньше этого гейта, а гейт распространяет его с одного
// события на все. Сверх того перечень несёт ключи-секреты: та же нагрузка
// объявляет о себе «No secrets in payload», и это утверждение до сих пор
// держалось комментарием.
//
// `external_id` попадает в перечень СОЗНАТЕЛЬНО, и это расходится с нормой
// платформы, называющей его не-личным идентификатором корреляции для журнала
// процесса. Расхождение разрешается ЕДИНИЦЕЙ НОСИТЕЛЯ: та норма — о СТРОКЕ ЖУРНАЛА
// процесса, которую читает оператор и которая живёт до ротации; здесь — о
// ЗАПИСИ ПОТОКА АУДИТА, которая живёт срок хранения потока и уезжает к внешнему
// получателю. Для второго носителя дерево выбрало строже, и выбрало до нас.
//
// # Чего перечень НЕ содержит и почему
//
// Ключа `name` в нём нет, хотя проба пользовательского события требует его
// отсутствия. Причина — предмет: в нагрузке роли, группы и реестра `name` есть
// имя РЕСУРСА, а не человека, и оно там законно (пять мест дерева). Запрет по
// имени ключа, верный для одного вида события и неверный для пяти, гейтом
// дерева быть не может; держит его проба СВОЕГО события, где известно, чьё это
// имя.
//
// # Формы построения нагрузки — перечислены ВСЕ, и каждая доказана
//
// Распознаватель, не знающий одной из форм, не даёт ни красного, ни зелёного —
// он МОЛЧИТ, и записанное в этой форме оказывается вне наблюдения, оставаясь на
// вид покрытым. Формы поэтому измерены по дереву, а не придуманы:
//
//	FormFieldLiteral    `Payload: map[string]any{…}` — литерал прямо в поле;
//	FormHelperDecl      `func …Payload(…) map[string]any { … }` — построитель,
//	                    чьи ключи живут у ОБЪЯВЛЕНИЯ, а не у вызова;
//	FormIndexAssign     `p["ключ"] = …` — ключ, добавленный ПОСЛЕ литерала;
//	                    литеральный разбор без него теряет условные ключи;
//	FormFieldIdent      `Payload: p`, где `p` собран выше в той же функции.
//
// Поле `EventPayload` формой НЕ является и в счёт не идёт: это уже
// сериализованные байты у писателя, а не место построения. Разбор, судящий по
// подстроке `Payload:`, принял бы его за пятую форму — и судил бы место, где
// ключей нет вовсе.
//
// Значение поля `Payload`, не сводящееся ни к одной форме, разбор объявляет
// НЕПРОЗРАЧНЫМ и печатает числом. Ноль непрозрачных — вердикт обхода, а не
// свойство записи: пока их ноль, «личных ключей нет» сказано обо всех местах.
//
// # Чем держится способность упасть
//
// `audit_payload_pii_injection_test.go` — инъекция в обе стороны по КАЖДОЙ
// форме и по КАЖДОМУ объявленному ключу: дефект находится с координатой,
// законный близнец (тот же ключ в НЕ-нагрузочном литерале, идентификатор вместо
// личного поля) молчит.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

// AuditPersonalKey — один ключ, которому в нагрузке журнала аудита не место.
type AuditPersonalKey struct {
	// Key — ключ ДОСЛОВНО, как он стоит в литерале. Сверка точная: `token_id`
	// не есть `token`, и подстрочное сравнение сделало бы находкой законный
	// идентификатор.
	Key string
	// Why — чем именно ключ личен либо секретен. Текст уезжает в находку:
	// проверка, не называющая причины, снимается следующим как непонятная.
	Why string
}

// auditPersonalKeys — ЗАКРЫТЫЙ перечень. Каждая запись доказана инъекцией:
// ключ, объявленный и не ловимый, есть обещание защиты, которой нет.
var auditPersonalKeys = []AuditPersonalKey{
	{"email", "почта субъекта — личные данные и изменяемое значение; корреляцию несёт id"},
	{"e_mail", "та же почта другим написанием"},
	{"mail", "та же почта третьим написанием"},
	{"display_name", "отображаемое имя человека — личные данные и изменяемое значение"},
	{"displayName", "то же отображаемое имя в верблюжьей форме"},
	{"external_id", "субъект внешнего поставщика личности — долговременный личный идентификатор; в ПОТОКЕ аудита он живёт срок хранения потока"},
	{"externalId", "тот же субъект в верблюжьей форме"},
	{"phone", "телефон субъекта — личные данные"},
	{"phone_number", "тот же телефон другим написанием"},
	{"given_name", "имя человека — личные данные"},
	{"family_name", "фамилия человека — личные данные"},
	{"full_name", "полное имя человека — личные данные"},
	{"password", "секрет: нагрузка объявляет о себе «No secrets in payload», и это до сих пор держалось комментарием"},
	{"secret", "секрет по имени ключа"},
	{"token", "предъявляемый секрет; `token_id` им НЕ является и под сверку не подпадает"},
	{"access_token", "предъявляемый секрет"},
	{"refresh_token", "предъявляемый секрет"},
	{"private_key", "секрет: закрытая половина ключа"},
}

// AuditPersonalKeys — объявленный перечень; гейт сверяет его с деревом.
func AuditPersonalKeys() []AuditPersonalKey {
	out := make([]AuditPersonalKey, len(auditPersonalKeys))
	copy(out, auditPersonalKeys)
	return out
}

// auditPersonalKeyIndex — ключ → причина, для сверки за одно обращение.
var auditPersonalKeyIndex = func() map[string]string {
	m := make(map[string]string, len(auditPersonalKeys))
	for _, k := range auditPersonalKeys {
		m[k.Key] = k.Why
	}
	return m
}()

// Формы построения нагрузки. Имена уезжают в перепись: раскладка по формам
// показывает, какая из них перестала встречаться, — а перестать она может и
// оттого, что разбор её больше не видит.
const (
	// FormFieldLiteral — литерал прямо в поле `Payload`.
	FormFieldLiteral = "литерал-в-поле"
	// FormHelperDecl — объявление построителя `…Payload(…) map[string]any`.
	FormHelperDecl = "построитель"
	// FormIndexAssign — ключ, добавленный присваиванием по индексу.
	FormIndexAssign = "присваивание-по-индексу"
	// FormFieldIdent — `Payload: p`, где `p` собран выше в той же функции.
	FormFieldIdent = "имя-собранное-рядом"
	// FormHelperCall — ВЫЗОВ построителя в поле `Payload`. Ключей не несёт:
	// они судятся у объявления. Считается, чтобы вызов был виден переписи
	// учтённым, а не пропал между формами.
	FormHelperCall = "вызов-построителя"
	// FormOpaque — значение поля `Payload`, не сводящееся ни к одной форме.
	// Литеральным разбором НЕ судится; печатается числом.
	FormOpaque = "непрозрачное"
)

// auditPayloadForms — формы, О КОТОРЫХ РАЗБОР ЗНАЕТ, с синтетическим примером
// на каждую. Пример нужен затем, чтобы форму можно было предъявить разбору
// сквозным путём: объявленная и не ловимая форма — слепая зона, выглядящая
// покрытой.
var auditPayloadForms = []struct {
	Name    string
	Why     string
	Example string
}{
	{
		Name: FormFieldLiteral,
		Why:  "основная форма дерева: литерал прямо в поле события",
		Example: `package x

func f() {
	_ = Event{Payload: map[string]any{"email": v}}
}
`,
	},
	{
		Name: FormHelperDecl,
		Why:  "построитель: ключи живут у объявления, вызов их не показывает",
		Example: `package x

func thingAuditPayload(v string) map[string]any {
	return map[string]any{"email": v}
}
`,
	},
	{
		Name: FormIndexAssign,
		Why:  "условный ключ, добавленный после литерала; литеральный разбор без этого его теряет",
		Example: `package x

func thingAuditPayload(v string) map[string]any {
	p := map[string]any{"actor": "system"}
	p["email"] = v
	return p
}
`,
	},
	{
		Name: FormFieldIdent,
		Why:  "нагрузка собрана в переменную выше и подставлена в поле именем",
		Example: `package x

func f(v string) {
	p := map[string]any{"email": v}
	_ = Event{Payload: p}
}
`,
	},
}

// AuditPayloadForms — объявленные формы с примерами; гейт предъявляет каждую.
func AuditPayloadForms() []struct {
	Name    string
	Why     string
	Example string
} {
	out := make([]struct {
		Name    string
		Why     string
		Example string
	}, len(auditPayloadForms))
	copy(out, auditPayloadForms)
	return out
}

// AuditPayloadFinding — один личный ключ с координатой.
type AuditPayloadFinding struct {
	Where string // путь:строка
	Form  string // какой формой он записан
	Key   string
	Why   string
}

func (f AuditPayloadFinding) String() string {
	return fmt.Sprintf("%s: ключ %q в нагрузке (%s) — %s", f.Where, f.Key, f.Form, f.Why)
}

// AuditPayloadCensus — объём осмотренного. Печатается всегда: «личных ключей
// нет» обязано быть отличимо от «ничего не разобрано».
type AuditPayloadCensus struct {
	Tracked     int            // элементов в индексе дерева
	Read        int            // прочитано файлов Go
	Parsed      int            // из них разобрано без ошибки
	Sites       int            // мест построения нагрузки
	SitesByForm map[string]int // форма → сколько мест
	Keys        int            // ключей осмотрено
	Files       []string       // файлы, где найдено хоть одно место
}

// String — перепись одной строкой.
func (c AuditPayloadCensus) String() string {
	forms := make([]string, 0, len(auditPayloadForms)+2)
	for _, f := range auditPayloadForms {
		forms = append(forms, fmt.Sprintf("%s=%d", f.Name, c.SitesByForm[f.Name]))
	}
	forms = append(forms,
		fmt.Sprintf("%s=%d", FormHelperCall, c.SitesByForm[FormHelperCall]),
		fmt.Sprintf("%s=%d", FormOpaque, c.SitesByForm[FormOpaque]))
	return fmt.Sprintf(
		"перепись: в индексе %d, файлов Go прочитано %d, разобрано %d; мест построения "+
			"нагрузки %d в %d файлах [%s]; ключей осмотрено %d; объявлено личных ключей %d",
		c.Tracked, c.Read, c.Parsed, c.Sites, len(c.Files),
		strings.Join(forms, " "), c.Keys, len(auditPersonalKeys))
}

// auditPayloadSkip — что из дерева под разбор не идёт, и почему.
//
// Тестовый корпус вычтен ровно по той причине, по какой он вычтен у гейта
// отсрочки: фикстура инъекции ОБЯЗАНА уметь написать форму дефекта, иначе гейт
// нечем проверить. Сгенерированные стабы вычтены потому, что их ключи
// принадлежат генератору контрактов, а не автору дерева.
func auditPayloadSkip(rel string) bool {
	return strings.HasSuffix(rel, "_test.go") ||
		strings.Contains(rel, "/testdata/") ||
		strings.HasPrefix(rel, "pkg/api/")
}

// ScanAuditPayloads обходит ОТСЛЕЖИВАЕМОЕ дерево модуля и находит личные ключи
// в нагрузках журнала аудита.
//
// Состав берётся из индекса git, а не выписывается: каталог, заведённый завтра,
// попадает под гейт в день появления.
func ScanAuditPayloads(root string) (findings []AuditPayloadFinding, census AuditPayloadCensus, err error) {
	census.SitesByForm = map[string]int{}

	tracked, terr := treecorpus.Under(root)
	if terr != nil {
		return nil, census, fmt.Errorf("состав дерева: %w", terr)
	}
	census.Tracked = len(tracked)

	for _, abs := range tracked {
		rel, rerr := filepath.Rel(root, abs)
		if rerr != nil {
			return nil, census, fmt.Errorf("путь %s: %w", abs, rerr)
		}
		slashed := filepath.ToSlash(rel)
		if !strings.HasSuffix(slashed, ".go") || auditPayloadSkip(slashed) {
			continue
		}

		raw, berr := os.ReadFile(abs) // #nosec G304 -- путь из индекса git ЭТОГО дерева
		if berr != nil {
			return nil, census, fmt.Errorf("чтение %s: %w", slashed, berr)
		}
		census.Read++

		sites, perr := ParseAuditPayloadSites(slashed, raw)
		if perr != nil {
			return nil, census, fmt.Errorf("разбор %s: %w", slashed, perr)
		}
		census.Parsed++
		if len(sites) > 0 {
			census.Files = append(census.Files, slashed)
		}
		for _, s := range sites {
			census.Sites++
			census.SitesByForm[s.Form]++
			census.Keys += len(s.Keys)
			for _, k := range s.Keys {
				if why, bad := auditPersonalKeyIndex[k.Name]; bad {
					findings = append(findings, AuditPayloadFinding{
						Where: fmt.Sprintf("%s:%d", slashed, k.Line),
						Form:  s.Form,
						Key:   k.Name,
						Why:   why,
					})
				}
			}
		}
	}

	sort.Strings(census.Files)
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Where != findings[j].Where {
			return findings[i].Where < findings[j].Where
		}
		return findings[i].Key < findings[j].Key
	})
	return findings, census, nil
}

// AuditPayloadKey — один ключ нагрузки с его строкой.
type AuditPayloadKey struct {
	Name string
	Line int
}

// AuditPayloadSite — одно место построения нагрузки.
type AuditPayloadSite struct {
	Form string
	Line int
	Keys []AuditPayloadKey
}

// ParseAuditPayloadSites разбирает ОДИН файл и находит места построения
// нагрузки со всеми ключами, записанными любой из объявленных форм.
//
// Вынесено отдельной функцией с экспортом затем, чтобы предикат можно было
// предъявить синтетическому входу: на чистом дереве находок ноль, и без такого
// предъявления «ноль находок» было бы неотличимо от разбора, который ничего не
// ищет.
func ParseAuditPayloadSites(path string, src []byte) ([]AuditPayloadSite, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, err
	}

	var sites []AuditPayloadSite
	lineOf := func(p token.Pos) int { return fset.Position(p).Line }

	// Построитель: имя оканчивается на `Payload`, результат — map[string]any.
	// Ключи такой функции живут У ОБЪЯВЛЕНИЯ: вызов их не показывает, и разбор
	// вызова о них не узнал бы никогда.
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || !isAuditPayloadBuilder(fn) {
			continue
		}
		sites = append(sites, AuditPayloadSite{
			Form: FormHelperDecl,
			Line: lineOf(fn.Pos()),
			Keys: stringKeysOfAnyMapLiterals(fn.Body, lineOf),
		})
		// Ключ, досланный по индексу, — СВОЁ место, а не строка чужого.
		// Свернуть его в место построителя значило бы оставить в переписи
		// число, которое не может сдвинуться ни при каком дереве, — а число без
		// производителя не показывает своего устаревания.
		for _, k := range stringKeysOfIndexAssigns(fn.Body, lineOf) {
			sites = append(sites, AuditPayloadSite{
				Form: FormIndexAssign, Line: k.Line, Keys: []AuditPayloadKey{k},
			})
		}
	}

	// Поле `Payload` — литерал, имя, собранное рядом, либо вызов построителя.
	ast.Inspect(f, func(n ast.Node) bool {
		kv, ok := n.(*ast.KeyValueExpr)
		if !ok {
			return true
		}
		key, ok := kv.Key.(*ast.Ident)
		// Сверка ТОЧНАЯ: `EventPayload` — уже сериализованные байты у писателя,
		// а не место построения. Разбор по подстроке принял бы его за форму и
		// судил бы место, где ключей нет вовсе.
		if !ok || key.Name != "Payload" {
			return true
		}
		line := lineOf(kv.Pos())

		switch v := kv.Value.(type) {
		case *ast.CompositeLit:
			if !isAnyMapType(v.Type) {
				return true
			}
			sites = append(sites, AuditPayloadSite{
				Form: FormFieldLiteral, Line: line, Keys: stringKeysOfLiteral(v, lineOf),
			})
		case *ast.CallExpr:
			// Вызов построителя: ключи судятся у объявления, здесь он только
			// учитывается. Вызов, чьё имя построителем не оканчивается, формой
			// не является и уходит в непрозрачные.
			if auditPayloadCallName(v) != "" {
				sites = append(sites, AuditPayloadSite{Form: FormHelperCall, Line: line})
				return true
			}
			sites = append(sites, AuditPayloadSite{Form: FormOpaque, Line: line})
		case *ast.Ident:
			// Нагрузка собрана выше в той же функции. Ключи ищутся по ВСЕМУ
			// файлу: сузить до объемлющей функции значило бы потерять форму,
			// где сборка и подстановка разнесены.
			keys, byIndex := stringKeysOfBinding(f, v.Name, lineOf)
			if keys == nil && byIndex == nil {
				sites = append(sites, AuditPayloadSite{Form: FormOpaque, Line: line})
				return true
			}
			sites = append(sites, AuditPayloadSite{Form: FormFieldIdent, Line: line, Keys: keys})
			for _, k := range byIndex {
				sites = append(sites, AuditPayloadSite{
					Form: FormIndexAssign, Line: k.Line, Keys: []AuditPayloadKey{k},
				})
			}
		default:
			sites = append(sites, AuditPayloadSite{Form: FormOpaque, Line: line})
		}
		return true
	})

	sort.Slice(sites, func(i, j int) bool { return sites[i].Line < sites[j].Line })
	return sites, nil
}

// isAuditPayloadBuilder — функция строит нагрузку: имя оканчивается на
// `Payload`, единственный результат — `map[string]any`.
//
// Судится ОБЪЯВЛЕНИЕ, а не имя вызова: имя можно переставить, форма результата
// остаётся, и именно она делает функцию построителем.
func isAuditPayloadBuilder(fn *ast.FuncDecl) bool {
	if fn.Body == nil || !strings.HasSuffix(fn.Name.Name, "Payload") {
		return false
	}
	if fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
		return false
	}
	return isAnyMapType(fn.Type.Results.List[0].Type)
}

// auditPayloadCallName — имя вызываемого построителя либо пусто.
func auditPayloadCallName(call *ast.CallExpr) string {
	var name string
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		name = fun.Name
	case *ast.SelectorExpr:
		name = fun.Sel.Name
	default:
		return ""
	}
	if !strings.HasSuffix(name, "Payload") {
		return ""
	}
	return name
}

// isAnyMapType — тип есть `map[string]any` (либо `map[string]interface{}`).
func isAnyMapType(expr ast.Expr) bool {
	m, ok := expr.(*ast.MapType)
	if !ok {
		return false
	}
	k, ok := m.Key.(*ast.Ident)
	if !ok || k.Name != "string" {
		return false
	}
	switch v := m.Value.(type) {
	case *ast.Ident:
		return v.Name == "any"
	case *ast.InterfaceType:
		return v.Methods == nil || len(v.Methods.List) == 0
	default:
		return false
	}
}

// stringKeysOfLiteral — строковые ключи одного литерала.
func stringKeysOfLiteral(lit *ast.CompositeLit, lineOf func(token.Pos) int) []AuditPayloadKey {
	var out []AuditPayloadKey
	for _, el := range lit.Elts {
		kv, ok := el.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		if name, ok := stringLiteralValue(kv.Key); ok {
			out = append(out, AuditPayloadKey{Name: name, Line: lineOf(kv.Pos())})
		}
	}
	return out
}

// stringKeysOfAnyMapLiterals — ключи ВСЕХ литералов `map[string]any` внутри узла.
func stringKeysOfAnyMapLiterals(n ast.Node, lineOf func(token.Pos) int) []AuditPayloadKey {
	var out []AuditPayloadKey
	ast.Inspect(n, func(x ast.Node) bool {
		lit, ok := x.(*ast.CompositeLit)
		if !ok || !isAnyMapType(lit.Type) {
			return true
		}
		out = append(out, stringKeysOfLiteral(lit, lineOf)...)
		return true
	})
	return out
}

// stringKeysOfIndexAssigns — ключи, добавленные присваиванием по индексу.
//
// Форма отдельная потому, что литеральный разбор её не видит: условный ключ
// (`if x != "" { p["ключ"] = x }`) в литерале не стоит вовсе, и без этой ветви
// он оказался бы вне наблюдения, оставаясь на вид покрытым.
func stringKeysOfIndexAssigns(n ast.Node, lineOf func(token.Pos) int) []AuditPayloadKey {
	var out []AuditPayloadKey
	ast.Inspect(n, func(x ast.Node) bool {
		as, ok := x.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for _, lhs := range as.Lhs {
			idx, ok := lhs.(*ast.IndexExpr)
			if !ok {
				continue
			}
			if name, ok := stringLiteralValue(idx.Index); ok {
				out = append(out, AuditPayloadKey{Name: name, Line: lineOf(idx.Pos())})
			}
		}
		return true
	})
	return out
}

// stringKeysOfBinding — ключи литерала `map[string]any`, привязанного к имени,
// и ОТДЕЛЬНО ключи, досланные тому же имени по индексу. Два возврата потому,
// что это две разные формы, и каждая обязана быть видна переписи своей строкой.
//
// Оба nil означают, что привязки в файле нет: тогда место непрозрачно, и разбор
// обязан сказать это, а не молчать.
func stringKeysOfBinding(f *ast.File, name string, lineOf func(token.Pos) int) (
	fromLiteral, byIndex []AuditPayloadKey,
) {
	ast.Inspect(f, func(x ast.Node) bool {
		as, ok := x.(*ast.AssignStmt)
		if !ok {
			return true
		}
		for i, lhs := range as.Lhs {
			// Привязка имени к литералу.
			if id, ok := lhs.(*ast.Ident); ok && id.Name == name && i < len(as.Rhs) {
				if lit, ok := as.Rhs[i].(*ast.CompositeLit); ok && isAnyMapType(lit.Type) {
					fromLiteral = append(fromLiteral, stringKeysOfLiteral(lit, lineOf)...)
				}
			}
			// Ключ, досланный тому же имени по индексу.
			if idx, ok := lhs.(*ast.IndexExpr); ok {
				if id, ok := idx.X.(*ast.Ident); ok && id.Name == name {
					if key, ok := stringLiteralValue(idx.Index); ok {
						byIndex = append(byIndex, AuditPayloadKey{Name: key, Line: lineOf(idx.Pos())})
					}
				}
			}
		}
		return true
	})
	return fromLiteral, byIndex
}

// stringLiteralValue — значение строкового литерала. Вычисляемый ключ строковым
// литералом не является и сюда не попадает: разбор судит то, что написано.
func stringLiteralValue(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
}
