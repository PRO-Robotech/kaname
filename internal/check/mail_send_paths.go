// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mail_send_paths.go — MAIL-47 приёмки ID-MAIL-1: путей отправки письма у нас
// РОВНО ОДИН, и отправляет он приглашение.
//
// # Предмет
//
// Видов письма в продукте три (подтверждение адреса, восстановление доступа,
// приглашение), а производители у них РАЗНЫЕ — решение Р23 приёмки. Два вида
// отправляет почтовый процесс поставщика личности: их предъявители принадлежат
// ему, и составляет письмо он. Приглашение отправляем МЫ, потому что предмет
// приглашения — строка в НАШЕЙ базе, и поставщику о ней не известно ничего.
//
// Отсюда два признака нарушения, и каждый сам по себе достаточен:
//
//   - ВТОРОЙ путь отправки того же вида нарушает Р1 («два способа доставить
//     одно и то же письмо, и какой сработает, решает порядок»);
//   - НАШ путь отправки ЧУЖОГО вида означает, что решение Р23 обойдено
//     реализацией: подтверждение адреса, отправленное нами, разойдётся с тем,
//     что о нём знает поставщик, и разойдётся молча.
//
// # Что здесь считается путём отправки — ДВЕ оси
//
//  1. ТРАНСПОРТ. Не-тестовый файл Go, импортирующий пакет, который говорит с
//     почтовым узлом. Список объявлен закрытым (`mailTransportTokens`), его
//     предпосылка проверяется: якорный пакет `net/smtp` обязан найтись в дереве
//     хотя бы раз, иначе ось судит пустоту и молчит по этой причине, а не по
//     существу.
//
//  2. СЛОВАРЬ ВИДОВ. Строковый литерал вида `mail.<вид>.send` — имя события
//     очереди писем, чей словарь закрыт CHECK'ом миграции. Вид, отличный от
//     приглашения, есть находка ГДЕ УГОДНО в не-тестовом дереве, даже без
//     транспорта рядом: расширить словарь молча нельзя, а расширенный словарь
//     означает второй вид письма, уехавший от нас.
//
// Вид письма, который отправляет путь, БЕРЁТСЯ ИЗ ЕГО ЖЕ ФАЙЛА — литералом оси
// 2. Путь, не назвавший вида, — находка: перепись обязана печатать ДВЕ
// величины, и вторая из воздуха не берётся.
//
// # Чего разбор НЕ видит — названо прямо
//
// Отправитель, написанный на голом сокете и говорящий по протоколу почты
// руками, осью 1 не опознаётся: он не импортирует ничего почтового. Границу
// закрывает ось 2 — такой отправитель всё равно обязан взять своё событие из
// очереди, а словарь очереди закрыт миграцией.
//
// Об отправителе, живущем в ЧУЖОМ процессе, гейт не утверждает НИЧЕГО (круг 6,
// В3): его в нашем дереве нет и быть не может, а проверка, требующая
// утверждения о непрочитанном, есть «ноль находок» без прочтения. Что письма
// подтверждения и восстановления действительно уходят, утверждают MAIL-01 и
// MAIL-04 на поднятом стенде, наблюдая письмо у приёмника. Здесь утверждается
// ЗЕРКАЛО: у нас их не отправляет никто — значит вида с двумя отправителями нет.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/PRO-Robotech/corelib/treecorpus"
)

// MailKindInvite — ЕДИНСТВЕННЫЙ вид письма, чей производитель — наш код (Р23).
const MailKindInvite = "invite"

// mailTransportAnchor — якорный пакет транспорта. Его присутствие в дереве и
// есть предпосылка оси 1: ноль его вхождений означает, что ось судит пустоту.
const mailTransportAnchor = "net/smtp"

// mailTransportTokens — ЗАКРЫТЫЙ список признаков импорта, говорящего с
// почтовым узлом. Совпадение ищется по СЕГМЕНТАМ пути импорта, а не подстрокой:
// подстрока `mail` совпала бы с собственным пакетом `invite_mail_outbox` и с
// любым внутренним каталогом, чьё имя несёт это слово, — то есть ось находила
// бы своё же хранилище очереди и звала его транспортом.
var mailTransportTokens = []string{
	"smtp",     // net/smtp, github.com/emersion/go-smtp
	"gomail",   // gopkg.in/gomail.v2
	"go-mail",  // github.com/wneessen/go-mail, github.com/go-mail/mail
	"sendgrid", // github.com/sendgrid/sendgrid-go
	"mailgun",  // github.com/mailgun/mailgun-go
	"postmark", // github.com/keighl/postmark
	"resend",   // github.com/resend/resend-go
	"ses",      // aws sdk .../service/ses
	"sesv2",    // aws sdk .../service/sesv2
}

// СЛОВА `mail` ЗДЕСЬ НЕТ НАМЕРЕННО. Сегмент `mail` несёт `net/mail` — разбор
// адреса, а не транспорт, — и признак, включивший это слово, объявил бы
// транспортом всякий пакет, который всего лишь читает заголовок письма.

// mailKindLiteralRe — имя события очереди писем. Привязано к ОБОИМ концам:
// проза об этом же предмете несёт те же слова посреди предложения, и образец
// без привязки краснел бы на собственном объяснении.
var mailKindLiteralRe = regexp.MustCompile(`^mail\.([a-z][a-z0-9_-]*)\.send$`)

// MailSendPath — координата пути отправки.
type MailSendPath struct {
	// File — путь от корня модуля, через косую черту.
	File string
	// Line — строка импорта транспорта.
	Line int
	// Import — сам импорт, дословно.
	Import string
	// Kinds — виды письма, названные литералами ЭТОГО файла.
	Kinds []string
}

// MailKindSite — координата объявления вида письма.
type MailKindSite struct {
	File string
	Line int
	Kind string
}

// MailSendFinding — находка одной из двух осей.
type MailSendFinding struct {
	// Where — координата `файл:строка`; пусто у находки об ОТСУТСТВИИ пути.
	Where string
	// Axis — `transport` либо `vocabulary`.
	Axis string
	// What — что именно найдено.
	What string
	// Why — почему это дефект, дословно для текста находки.
	Why string
}

// MailSendCensus — объём осмотренного. Две несущие величины MAIL-47 —
// `Paths` и `Kinds`; остальные доказывают, что обход непуст.
type MailSendCensus struct {
	// Tracked — отслеживаемых файлов дерева всего.
	Tracked int
	// Read — не-тестовых файлов Go прочитано.
	Read int
	// Imports — импортов осмотрено.
	Imports int
	// Literals — строковых литералов осмотрено.
	Literals int
	// TransportAnchorHits — вхождений якорного пакета. Ноль означает, что
	// предпосылка оси 1 не выполняется.
	TransportAnchorHits int
	// Paths — путей отправки найдено (первая несущая величина).
	Paths int
	// Kinds — виды письма, которые эти пути отправляют (вторая несущая).
	Kinds []string
}

// String — перепись одной строкой, в форме, которую требует MAIL-47.
func (c MailSendCensus) String() string {
	kinds := "нет"
	if len(c.Kinds) > 0 {
		kinds = strings.Join(c.Kinds, ",")
	}
	return fmt.Sprintf(
		"перепись: путей отправки найдено %d · видов письма, которые они отправляют: %s "+
			"(отслеживаемых файлов %d, не-тестовых файлов Go прочитано %d, импортов осмотрено %d, "+
			"строковых литералов осмотрено %d, вхождений якорного транспорта %s: %d)",
		c.Paths, kinds, c.Tracked, c.Read, c.Imports, c.Literals,
		mailTransportAnchor, c.TransportAnchorHits)
}

// MailImportIsTransport — предикат оси 1: говорит ли этот импорт с почтовым
// узлом. Судит СЕГМЕНТЫ пути, а не подстроку.
func MailImportIsTransport(path string) bool {
	for _, seg := range strings.Split(path, "/") {
		// Сегмент сверяется В ДВУХ написаниях — как есть и без принятой у
		// библиотек Go окантовки (`go-smtp`, `sendgrid-go`, `gomail.v2`). Одного
		// написания мало: предикат, знающий только голое слово, не увидел бы
		// `github.com/emersion/go-smtp`, то есть целую законную форму записи
		// предмета, и молчал бы на ней — ни красного, ни зелёного.
		for _, form := range []string{seg, mailTrimLibraryTrappings(seg)} {
			for _, tok := range mailTransportTokens {
				if form == tok {
					return true
				}
			}
		}
	}
	return false
}

// mailTrimLibraryTrappings снимает окантовку имени библиотеки Go: приставку
// `go-`, окончание `-go` и суффикс мажорной версии.
func mailTrimLibraryTrappings(seg string) string {
	if i := strings.LastIndexByte(seg, '.'); i > 0 {
		if v := seg[i+1:]; len(v) > 1 && v[0] == 'v' {
			seg = seg[:i]
		}
	}
	seg = strings.TrimPrefix(seg, "go-")
	seg = strings.TrimSuffix(seg, "-go")
	return seg
}

// MailKindOfLiteral — вид письма, названный литералом. Второе значение — был ли
// литерал именем события очереди вообще.
func MailKindOfLiteral(lit string) (string, bool) {
	m := mailKindLiteralRe.FindStringSubmatch(lit)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// ScanMailSendFile разбирает ОДИН файл: импорты транспорта и объявления вида.
func ScanMailSendFile(rel string, src []byte) (paths []MailSendPath, kinds []MailKindSite, census MailSendCensus, err error) {
	fset := token.NewFileSet()
	f, perr := parser.ParseFile(fset, rel, src, 0)
	if perr != nil {
		return nil, nil, MailSendCensus{}, perr
	}

	var transportLine int
	var transportImport string
	for _, imp := range f.Imports {
		census.Imports++
		p, uerr := strconv.Unquote(imp.Path.Value)
		if uerr != nil {
			continue
		}
		if p == mailTransportAnchor {
			census.TransportAnchorHits++
		}
		if MailImportIsTransport(p) && transportImport == "" {
			transportImport = p
			transportLine = fset.Position(imp.Pos()).Line
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			return true
		}
		census.Literals++
		u, uerr := strconv.Unquote(lit.Value)
		if uerr != nil {
			return true
		}
		kind, isKind := MailKindOfLiteral(u)
		if !isKind {
			return true
		}
		kinds = append(kinds, MailKindSite{
			File: rel, Line: fset.Position(lit.Pos()).Line, Kind: kind,
		})
		return true
	})

	if transportImport != "" {
		seen := map[string]bool{}
		var own []string
		for _, k := range kinds {
			if !seen[k.Kind] {
				seen[k.Kind] = true
				own = append(own, k.Kind)
			}
		}
		sort.Strings(own)
		paths = append(paths, MailSendPath{
			File: rel, Line: transportLine, Import: transportImport, Kinds: own,
		})
		census.Paths = 1
	}
	return paths, kinds, census, nil
}

// AdjudicateMailSendPaths — ВЕРДИКТ по обеим осям. Отделён от обхода намеренно:
// инъекция подаёт ему синтетику напрямую и не поднимает дерева.
func AdjudicateMailSendPaths(paths []MailSendPath, kinds []MailKindSite) []MailSendFinding {
	var out []MailSendFinding

	// Ось 1. Путь без названного вида; путь чужого вида; второй путь одного вида.
	byKind := map[string][]MailSendPath{}
	for _, p := range paths {
		if len(p.Kinds) == 0 {
			out = append(out, MailSendFinding{
				Where: fmt.Sprintf("%s:%d", p.File, p.Line),
				Axis:  "transport",
				What:  "путь отправки (" + p.Import + ") не называет вида письма",
				Why: "Перепись MAIL-47 печатает ДВЕ величины, и вторая берётся из имени " +
					"события очереди (`mail.<вид>.send`) в том же файле. Путь без вида " +
					"означает письмо без объявленного предмета: какой вид он отправляет, " +
					"из дерева не читается.",
			})
			continue
		}
		for _, k := range p.Kinds {
			byKind[k] = append(byKind[k], p)
			if k == MailKindInvite {
				continue
			}
			out = append(out, MailSendFinding{
				Where: fmt.Sprintf("%s:%d", p.File, p.Line),
				Axis:  "transport",
				What:  "наш путь отправки отправляет вид письма `" + k + "`",
				Why: "Решение Р23 приёмки ID-MAIL-1 отдаёт этот вид почтовому процессу " +
					"поставщика личности: его предъявитель принадлежит ему, и составляет " +
					"письмо он. Наш отправитель того же вида есть ВТОРОЙ отправитель одного " +
					"письма — что доедет до адресата, решает порядок, а не решение.",
			})
		}
	}
	for kind, ps := range byKind {
		if len(ps) < 2 {
			continue
		}
		var where []string
		for _, p := range ps {
			where = append(where, fmt.Sprintf("%s:%d", p.File, p.Line))
		}
		sort.Strings(where)
		out = append(out, MailSendFinding{
			Where: strings.Join(where, " · "),
			Axis:  "transport",
			What:  fmt.Sprintf("путей отправки вида `%s` — %d", kind, len(ps)),
			Why: "Два способа доставить ОДНО И ТО ЖЕ письмо, и какой сработает — решает " +
				"порядок (Р1). Координаты названы обе: у дефекта нет «главного» места.",
		})
	}

	// Ось 1, обратная сторона: пути нет вовсе. Вид письма без производителя —
	// §12 п. 3а приёмки, и это находка, а не молчание.
	if _, ok := byKind[MailKindInvite]; !ok {
		out = append(out, MailSendFinding{
			Axis: "transport",
			What: "путей отправки вида `" + MailKindInvite + "` — ноль",
			Why: "Приглашение отправляет НАШ код (Р23): предмет приглашения — строка в " +
				"нашей базе, и поставщику о ней не известно ничего. Ноль путей означает " +
				"обещание без производителя: приглашение создаётся успешно, письма нет.",
		})
	}

	// Ось 2. Словарь видов. Вид, отличный от приглашения, — находка где угодно.
	for _, k := range kinds {
		if k.Kind == MailKindInvite {
			continue
		}
		out = append(out, MailSendFinding{
			Where: fmt.Sprintf("%s:%d", k.File, k.Line),
			Axis:  "vocabulary",
			What:  "словарь очереди писем назвал вид `" + k.Kind + "`",
			Why: "Словарь закрыт CHECK'ом миграции, и расширить его молча нельзя. Второй " +
				"вид письма в нашей очереди означает, что мы взялись отправлять то, чей " +
				"производитель объявлен чужим (Р23).",
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Where != out[j].Where {
			return out[i].Where < out[j].Where
		}
		return out[i].What < out[j].What
	})
	return out
}

// ScanMailSendPaths обходит не-тестовое дерево Go модуля.
func ScanMailSendPaths(root string) (paths []MailSendPath, kinds []MailKindSite, census MailSendCensus, err error) {
	tracked, terr := treecorpus.Under(root)
	if terr != nil {
		return nil, nil, census, fmt.Errorf("состав дерева: %w", terr)
	}
	census.Tracked = len(tracked)

	for _, abs := range tracked {
		rel, rerr := filepath.Rel(root, abs)
		if rerr != nil {
			return nil, nil, census, fmt.Errorf("путь %s: %w", abs, rerr)
		}
		slashed := filepath.ToSlash(rel)
		if !strings.HasSuffix(slashed, ".go") || strings.HasSuffix(slashed, "_test.go") {
			continue
		}
		raw, berr := os.ReadFile(abs) // #nosec G304 -- путь из индекса git ЭТОГО дерева
		if berr != nil {
			return nil, nil, census, fmt.Errorf("чтение %s: %w", slashed, berr)
		}
		census.Read++

		p, k, c, serr := ScanMailSendFile(slashed, raw)
		if serr != nil {
			return nil, nil, census, fmt.Errorf("разбор %s: %w", slashed, serr)
		}
		census.Imports += c.Imports
		census.Literals += c.Literals
		census.TransportAnchorHits += c.TransportAnchorHits
		census.Paths += c.Paths
		paths = append(paths, p...)
		kinds = append(kinds, k...)
	}

	seen := map[string]bool{}
	for _, p := range paths {
		for _, k := range p.Kinds {
			if !seen[k] {
				seen[k] = true
				census.Kinds = append(census.Kinds, k)
			}
		}
	}
	sort.Strings(census.Kinds)
	return paths, kinds, census, nil
}
