// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// invite_mail_page_test.go — КЛИЕНТСКАЯ страница не вправе отрицать механизм,
// который дерево несёт (#2525).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Страница — единственный артефакт, по которому арендатор решает, ждать ли
// письма. Фраза «автоотправка email не интегрирована» есть утверждение о
// ДЕРЕВЕ, и утверждение это не компилируется: полосу заводят, а фраза остаётся.
//
// Цена не косметическая и приходит арендатору дважды. Прочитав страницу,
// оператор не станет объявлять почтовый узел вовсе — и получит ровно то
// поведение, которое страница обещает, но ПО ДРУГОЙ ПРИЧИНЕ: письмо не уходит,
// потому что узел не назван, а не потому, что отправлять некому. Второе:
// админ продолжит передавать ссылку руками, не зная, что этого можно не делать.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЖИВОСТЬ ПОЛОСЫ УСТАНАВЛИВАЕТСЯ ЗАМЕРОМ, А НЕ ДОПУЩЕНИЕМ
//
// Отрицание на странице законно ровно тогда, когда полосы в дереве НЕТ. Поэтому
// проверка сперва спрашивает дерево — тремя независимыми производителями, — и
// лишь затем судит страницы. Мир, где полосы нет, а страница её отрицает,
// молчит: это законный близнец, и он проверен инъекцией.
//
// Производители спрашиваются ЛИТЕРАЛАМИ разобранного исходника, а не поиском
// слова: имя очереди и имя ряда встречаются и в прозе, и в комментариях, и
// поиск словом принял бы за производителя собственное объяснение.
//
// ─────────────────────────────────────────────────────────────────────────────
// СУДИТСЯ ОТРИЦАНИЕ СУЩЕСТВОВАНИЯ, А НЕ УСЛОВНАЯ ФРАЗА — И ЭТО ГРАНИЦА
//
// Словарь отрицаний закрыт и содержит только формы «механизма нет»
// (`не интегрирован`, `not implemented`, …). Условная фраза — «пока почтовый
// узел не объявлен, письмо не уходит» — ЗАКОННА и намеренно вне наблюдения: она
// описывает настройку, а не отсутствие механизма. Отличить их машинно в общем
// случае нельзя, поэтому проверка берёт узкую полосу и называет её вслух;
// широкий словарь краснел бы на правдивом тексте, и его сняли бы первым.
//
// Корпус ДВУЯЗЫЧНЫЙ, поэтому оба словаря несут русскую и английскую форму:
// предикат на одном языке недобирает МОЛЧА.
//
// Способность упасть и смолчать доказана инъекцией — invite_mail_page_injection_test.go.
package supplyhygiene

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// clientPagesDir — то, что арендатор ЧИТАЕТ, относительно корня службы.
// Инженерные страницы сайт не служит, и у поставившего продукт их нет.
const clientPagesDir = "docs/content"

// inviteMailLaneMarkers — производители почтовой полосы: имя очереди, объявление
// полосы живым процессом при старте и ряд исходов отправки. Три независимых
// предмета, и все три обязаны быть литералами не-тестового исходника.
var inviteMailLaneMarkers = []string{
	"kaname.invite_mail_outbox",
	"kaname invite mail drainer starting",
	"kaname_invite_mail_outcomes_total",
}

// subjectPatterns — как страница называет ПРЕДМЕТ (отправку письма за админа).
//
// ВЫРАЖЕНИЯ, а не подстроки, и это НЕ украшение. Русский корпус предмет
// СКЛОНЯЕТ: фиксированная форма «автоматическая отправка» не совпадает с
// «автоматической отправки», и страница, написанная в родительном падеже,
// оказывается вне наблюдения ЦЕЛИКОМ — не находкой и не чистой, а невидимой.
// Ровно это и случилось: словарь из фиксированных форм осматривал 3 вхождения
// из 5, а две лживые строки одной страницы не читал ни разу (#2525, второй
// заход).
var subjectPatterns = []*regexp.Regexp{
	regexp.MustCompile(`автоотправк\p{L}*`),
	regexp.MustCompile(`автоматическ\p{L}*\s+отправк\p{L}*`),
	regexp.MustCompile(`автоматически\s+отправ\p{L}*`),
	regexp.MustCompile(`auto-?send\w*`),
	regexp.MustCompile(`automatic\w*\s+e-?mail\w*`),
	regexp.MustCompile(`automatically\s+sends?`),
}

// existenceDenials — закрытый словарь ОДНОЗНАЧНОГО отрицания существования.
// Условные формы («не уходит», «не отправляется, пока …») сюда не входят
// намеренно: см. шапку. Читаются в ШИРОКОМ окне: «не интегрирован» не бывает
// правдой о живом механизме, на каком бы расстоянии от предмета ни стояло.
var existenceDenials = []string{
	"не интегрирован", "не реализован", "не поддерживается", "не предусмотрен",
	"not integrated", "not implemented", "not supported",
}

// bareNegations — ГОЛОЕ отрицание. Это то же слово, что и в правдивом тексте,
// поэтому оно читается в УЗКОМ окне: засчитывается, только когда управляет
// предметом («автоматической отправки письма … нет»), а не когда просто попало
// в тот же абзац.
//
// Граница не выбрана на глаз, а ЗАМЕРЕНА по корпусу — расстояние от предмета до
// ближайшего голого «нет». Единица — БАЙТ, потому что окно берётся по байтам
// (кириллица занимает два, и мерить это знаками значило бы называть не ту
// величину):
//
//	лживые (до правки)  first-credential.mdx:26  →   33 · :237 →   29
//	правдивые           first-credential.mdx:240 →  139
//	                    getting-started.mdx:233  →  706
//	                    api/user.mdx:189         → 2263
//	                    architecture/identity.mdx:60 → голого «нет» нет вовсе
//
// Окно 60 стоит в коридоре между полосами: вдвое шире самой далёкой лжи и вдвое
// уже самой близкой правды. Ближайшая правда — абзац в разделе «Чего в продукте
// нет»: там отрицания густы by construction, и это худший случай корпуса, а не
// средний.
//
// Границы слова — через класс «не-буква»: RE2 не знает ретроспективных проверок,
// а `\b` в Go считает словом только ASCII, то есть на кириллице молчал бы. Без
// этого «нет» нашлось бы внутри «интернет».
var bareNegations = []*regexp.Regexp{
	regexp.MustCompile(`(?:^|[^\p{L}])нет(?:[^\p{L}]|$)`),
	regexp.MustCompile(`there\s+(?:is|are)\s+no\b`),
	regexp.MustCompile(`there'?s\s+no\b`),
	regexp.MustCompile(`does\s*n[o']?t\s+send\b`),
}

// denialWindow — сколько знаков вокруг предмета читается в поисках ОДНОЗНАЧНОГО
// отрицания. Фраза переносится по строкам, поэтому окно берётся по ТЕКСТУ
// страницы, а не по строке: судить строку значило бы не видеть перенос.
const denialWindow = 220

// bareNegationWindow — то же для ГОЛОГО отрицания, и оно на порядок уже: см.
// замер у bareNegations. Широкое окно здесь краснело бы на правдивом тексте,
// и такой держатель сняли бы первым.
const bareNegationWindow = 60

// absenceClaim — страница, отрицающая существование предмета.
type absenceClaim struct {
	Page   string
	Line   int
	Denial string
}

// pageAbsenceCensus — объём осмотренного. Печатается ВСЕГДА: «ноль находок»
// обязано быть отличимо от «ноль прочитанного».
type pageAbsenceCensus struct {
	Pages    int
	Subjects int // вхождений предмета осмотрено
	Claims   int
}

// findAbsenceClaims разбирает ПРОИЗВОЛЬНЫЙ корпус страниц (путь → содержимое):
// настоящее дерево и синтетический мир инъекции проходят одну функцию, поэтому
// доказанное на втором верно для первого.
func findAbsenceClaims(pages map[string][]byte) ([]absenceClaim, pageAbsenceCensus) {
	census := pageAbsenceCensus{Pages: len(pages)}
	var out []absenceClaim

	paths := make([]string, 0, len(pages))
	for p := range pages {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, path := range paths {
		text := strings.ToLower(string(pages[path]))
		for _, at := range subjectOccurrences(text) {
			census.Subjects++
			if denial, ok := denialNear(text, at.start, at.end-at.start); ok {
				census.Claims++
				out = append(out, absenceClaim{
					Page: path, Line: lineOf(text, at.start), Denial: denial,
				})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Page != out[j].Page {
			return out[i].Page < out[j].Page
		}
		return out[i].Line < out[j].Line
	})
	return out, census
}

// span — вхождение предмета в тексте страницы.
type span struct{ start, end int }

// subjectOccurrences — все вхождения предмета, БЕЗ двойного счёта. Выражения
// перекрываются (одна и та же фраза попадает под два образца), а перепись
// объявлена «объёмом осмотренного»: сосчитав вхождение дважды, держатель
// отчитался бы о работе, которой не делал.
func subjectOccurrences(text string) []span {
	var all []span
	for _, re := range subjectPatterns {
		for _, m := range re.FindAllStringIndex(text, -1) {
			all = append(all, span{start: m[0], end: m[1]})
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].start != all[j].start {
			return all[i].start < all[j].start
		}
		return all[i].end > all[j].end
	})
	out := make([]span, 0, len(all))
	for _, s := range all {
		if n := len(out); n > 0 && s.start < out[n-1].end {
			continue // поглощено предыдущим — то же вхождение, другой образец
		}
		out = append(out, s)
	}
	return out
}

// windowAround — окно заданной ширины вокруг предмета.
func windowAround(text string, at, width, radius int) string {
	lo := at - radius
	if lo < 0 {
		lo = 0
	}
	hi := at + width + radius
	if hi > len(text) {
		hi = len(text)
	}
	return text[lo:hi]
}

// denialNear — стоит ли рядом с предметом отрицание его существования. Полос
// две, и у каждой СВОЁ окно: однозначная фраза читается широко, голое
// отрицание — узко (см. замер у bareNegations).
func denialNear(text string, at, width int) (string, bool) {
	wide := windowAround(text, at, width, denialWindow)
	for _, denial := range existenceDenials {
		if strings.Contains(wide, denial) {
			return denial, true
		}
	}
	tight := windowAround(text, at, width, bareNegationWindow)
	for _, re := range bareNegations {
		if m := re.FindString(tight); m != "" {
			return strings.TrimSpace(m), true
		}
	}
	return "", false
}

// lineOf — номер строки смещения; координата находки, а не украшение.
func lineOf(text string, at int) int {
	return 1 + strings.Count(text[:at], "\n")
}

// inviteMailLaneProducers — какие маркеры полосы дерево ПРОИЗВОДИТ. Второе
// возвращаемое — файлов разобрано: ноль означает, что обход не состоялся, и
// «полосы нет» тогда значит «не искали».
func inviteMailLaneProducers(root string) (map[string]string, int, error) {
	found := map[string]string{}
	filesRead := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") || strings.HasSuffix(p, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, p, nil, 0)
		if perr != nil {
			// Неразбираемый исходник — предмет компилятора, не этого разбора.
			return nil
		}
		filesRead++
		rel, rerr := filepath.Rel(root, p)
		if rerr != nil {
			rel = p
		}
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			value, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			for _, marker := range inviteMailLaneMarkers {
				if strings.Contains(value, marker) {
					if _, seen := found[marker]; !seen {
						found[marker] = filepath.ToSlash(rel)
					}
				}
			}
			return true
		})
		return nil
	})
	return found, filesRead, err
}

// clientPageCorpus — страницы, которые арендатор читает.
func clientPageCorpus(t *testing.T, root string) map[string][]byte {
	t.Helper()
	corpus := map[string][]byte{}
	dir := filepath.Join(root, filepath.FromSlash(clientPagesDir))
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if !strings.HasSuffix(p, ".mdx") && !strings.HasSuffix(p, ".md") {
			return nil
		}
		body, rerr := os.ReadFile(p) // #nosec G304 -- путь из обхода своего дерева
		if rerr != nil {
			return rerr
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return relErr
		}
		corpus[filepath.ToSlash(rel)] = body
		return nil
	})
	require.NoErrorf(t, err, "обход клиентских страниц %s", clientPagesDir)
	return corpus
}

// TestClientPagesDoNotDenyTheInviteMailLane — ни одна клиентская страница не
// отрицает существования почтовой полосы, пока дерево её производит.
func TestClientPagesDoNotDenyTheInviteMailLane(t *testing.T) {
	t.Parallel()

	producers, filesRead, err := inviteMailLaneProducers(serviceRoot)
	require.NoError(t, err, "обход исходников службы")
	require.NotZerof(t, filesRead, "не разобрано ни одного исходника службы — "+
		"«полосы нет» здесь означало бы «не искали», и вердикт был бы вакуумным")

	missing := make([]string, 0, len(inviteMailLaneMarkers))
	for _, marker := range inviteMailLaneMarkers {
		if _, ok := producers[marker]; !ok {
			missing = append(missing, marker)
		}
	}

	pages := clientPageCorpus(t, serviceRoot)
	claims, census := findAbsenceClaims(pages)

	t.Logf("перепись: исходников разобрано %d · производителей полосы %d из %d · "+
		"страниц прочитано %d · вхождений предмета осмотрено %d · отрицаний найдено %d",
		filesRead, len(producers), len(inviteMailLaneMarkers),
		census.Pages, census.Subjects, census.Claims)
	for _, marker := range inviteMailLaneMarkers {
		if at, ok := producers[marker]; ok {
			t.Logf("производитель %q — %s", marker, at)
		}
	}

	require.NotZerof(t, census.Pages, "клиентских страниц не прочитано ни одной — "+
		"каталог %s переехал, и «отрицаний нет» означает «не читали»", clientPagesDir)
	require.NotZerof(t, census.Subjects, "предмет не встретился на страницах ни разу — "+
		"словарь предмета ослеп либо страницы перестали говорить об отправке письма; "+
		"в обоих случаях молчание проверки ничего не утверждает")

	if len(missing) > 0 {
		// Полоса СНЯТА — тогда отрицание на страницах законно, а этот держатель
		// потерял предмет и снимается ВМЕСТЕ с ней.
		t.Fatalf("производителей полосы не нашлось: %v — либо полоса снята из дерева "+
			"(тогда снимите этот держатель вместе с ней и верните страницам их "+
			"отрицание), либо распознаватель производителей ослеп. Различает это "+
			"человек, а не проба.", missing)
	}

	for _, c := range claims {
		t.Errorf("%s:%d — страница отрицает существование автоотправки (%q), "+
			"а дерево её производит: очередь, объявление полосы живым процессом и ряд "+
			"исходов отправки. Скажите фактическое состояние: отправка есть, полоса "+
			"объявляется ключами inviteMail.* (INSTALL.md, глава про почтовую полосу), "+
			"необъявленный узел означает, что письмо не отправляется, и наблюдаемо это "+
			"счётчиком исходов.", c.Page, c.Line, c.Denial)
	}
}
