// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// own_minting_claim_test.go — УТВЕРЖДЕНИЕ «ПЛАТФОРМА НЕ ЧЕКАНИТ НИЧЕГО» НЕ
// ВПРАВЕ СТОЯТЬ В ДЕРЕВЕ, КОТОРОЕ НЕСЁТ СВОЕГО ПОДПИСАНТА И ПУБЛИКУЕТ ЕГО
// НАБОР КЛЮЧЕЙ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ, ИЗМЕРЕННЫЙ ДО РАБОТЫ
//
// Шапка настройки публикатора набора ключей объявляла: прежний провайдер
// остаётся издателем и подписантом, а платформа не чеканит ничего. В ТОМ ЖЕ
// дереве композиционный корень публикует ВТОРУЮ запись набора, источник которой
// — наша ключница, а докерную полосу выдачи обслуживает наш подписант.
//
// Существенно не то, что фраза устарела. Существенно, ГДЕ она стоит: её читают
// при всяком разборе выдачи — и по ней ищут причину не там. Комментарий не
// компилируется, документ не исполняется; красным не станет ни один прогон.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ИМЕННО ЗАПРЕЩЕНО — И ПОЧЕМУ НЕ ШИРЕ
//
// Запрещено утверждение ИСКЛЮЧИТЕЛЬНОСТИ О НАС: «платформа не чеканит ничего»,
// «своего набора ключей у неё нет», «единственный подписант — он».
//
// НЕ запрещено утверждение о ПРОВАЙДЕРЕ как об издателе: он им остаётся — для
// интерактивного входа человека и для удостоверений прежнего выпуска. Гейт,
// красневший бы на «провайдер — издатель и подписант», объявлял бы находкой
// верное: руководство дежурного говорит это про ЗАПИСЬ ЗЕРКАЛА, и говорит
// правду. Проверка, отвергающая верное, отключается первой.
//
// ─────────────────────────────────────────────────────────────────────────────
// ИСТИНА ВЫВОДИТСЯ ИЗ ИСПОЛНЯЕМОГО, А НЕ ИЗ ВТОРОГО ПЕРЕЧНЯ
//
// Опровергают утверждение ЯКОРЯ — вызовы в композиционном корне, найденные
// РАЗБОРОМ синтаксического дерева, а не поиском слова: имя вызова встречается и
// в комментариях, и поиск словом принял бы за якорь собственное объяснение.
// Второй перечень («вот здесь мы чеканим») был бы третьим местом об одном
// предмете и разошёлся бы с первыми двумя молча.
//
// Отсюда обратная сторона, и она несущая: снимут якоря — гейт ЗАМОЛЧИТ, потому
// что запрещённое утверждение станет верным. Он судит существо, а не слово.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ БЛОКАМИ, А НЕ СТРОКАМИ
//
// Разборщик, читающий по строке, слеп к переносу — и слеп он был бы ровно на
// том файле, ради которого гейт заведён: там «(iam mints» стоит в конце одной
// строки, а «nothing)» открывает следующую. Форма, о которой разборщик не знает,
// даёт не красное и не зелёное, а МОЛЧАНИЕ. Поэтому строки склеиваются в блок
// (маркеры комментария снимаются), и образец судит блок.
//
// ─────────────────────────────────────────────────────────────────────────────
// КОРПУС ДВУЯЗЫЧНЫЙ
//
// Одно и то же утверждение записано здесь по-английски и по-русски. Предикат на
// одном языке недобирает МОЛЧА, поэтому образцов два набора, и перепись печатает
// попадания по каждому.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ГЕЙТ НЕ ЗАКРЫВАЕТ — сказано прямо
//
// Он судит ОДНО названное утверждение. Страница вправе солгать о выдаче иначе —
// например, нарисовать поток через провайдера, не сказав ни слова про чеканку;
// такую ложь он не увидит и увидеть не может: «текст говорит правду» — не
// предикат. Эта половина держится вниманием и обзором.
package supplyhygiene

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/gitenv"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// mintingAnchors — вызовы, ОПРОВЕРГАЮЩИЕ утверждение исключительности. Каждый
// назван парой «пакет.имя», потому что судится узел вызова, а не строка.
var mintingAnchors = []struct {
	Pkg, Fun string
	// Refutes — чем именно этот якорь опровергает утверждение. Запись без
	// причины через полгода неотличима от вкусовщины.
	Refutes string
}{
	{"jwksproxyhttp", "NewKeySetHandler",
		"композиционный корень публикует ВТОРУЮ запись набора, источник которой — наша ключница"},
	{"registrytokenwire", "NewLocalMinter",
		"докерную полосу выдачи обслуживает НАШ подписант"},
}

// mintingAnchorRoots — где ищутся якоря: места СБОРКИ. Решение «чеканим ли мы»
// принимается провязкой, а не use-case'ом.
//
// Каталогов два, и второй добавлен ЗАМЕРОМ, а не догадкой: первая редакция
// перечисляла только композиционный корень, и объявленный якорь докерной полосы
// не находился НИ РАЗУ — то есть был мёртвым объявлением, ровно тем классом,
// который корпус запрещает в продовом коде. Видно это стало из переписи
// («якорей 1» при двух объявленных), а не из чтения.
var mintingAnchorRoots = []string{
	"services/iam/cmd/kaname",
	"services/iam/internal/registrytokenwire",
}

// retiredExclusivityClaim — утверждение исключительности О НАС. Оба языка.
//
// ПОДЛЕЖАЩЕЕ СВЯЗАНО ОБРАЗЦОМ, и это не педантизм, а замер. Первая редакция
// искала «не чеканит ничего» без подлежащего и дала 15 находок, из которых
// ПЯТЬ были ложны: «отвергнутое создание ничего не чеканит», «анонимная
// мутация ничего не чеканит», «отключённая служебная учётка ничего не
// чеканит» — верные фразы о СОВСЕМ ДРУГОМ предмете. Треть ложных достаточно,
// чтобы прибор перестали читать; перестав читать его, возвращаются к тому, что
// он заменил.
//
// Поэтому образец требует НАШЕГО имени в окне перед утверждением. Окно узкое
// (80 знаков): широкое вернуло бы ровно те ложные находки, ради которых оно и
// сужено.
var retiredExclusivityClaim = []struct {
	Pattern *regexp.Regexp
	Lang    string
	Why     string
}{
	{regexp.MustCompile(`(?i)\b(?:iam|kaname)\b.{0,80}?\bmints?\s+nothing\b`), "en",
		"«платформа не чеканит ничего»"},
	{regexp.MustCompile(`(?i)\b(?:iam|kaname)\b.{0,80}?\b(?:has|have|own|owns)\s+no\s+keyset\b`), "en",
		"«своего набора ключей у платформы нет»"},
	{regexp.MustCompile(`(?i)\b(?:iam|kaname)\b.{0,80}?\bno\s+keyset\s+of\s+(?:its|our)\s+own\b`), "en",
		"«своего набора ключей у платформы нет»"},
	{regexp.MustCompile(`(?i)(?:\biam\b|\bkaname\b|платформ\p{Cyrillic}*).{0,80}?ключ(?:и|ей)\s+не\s+чеканит`), "ru",
		"«платформа ключей не чеканит»"},
	{regexp.MustCompile(`(?i)(?:\biam\b|\bkaname\b|платформ\p{Cyrillic}*).{0,80}?ничего\s+не\s+чеканит`), "ru",
		"«платформа не чеканит ничего»"},
	{regexp.MustCompile(`(?i)единственн(?:ым|ый|ого)\s+подписант`), "ru",
		"«единственный подписант — прежний провайдер»"},
}

// quotedSpan — ЦИТАТА в русских кавычках-ёлочках. Снимается ДО сверки образцом.
//
// ПОЧЕМУ ЭТО НЕОБХОДИМО. Правильная починка утверждения, пережившего свой
// предмет, называет снятое дословно — «здесь стояло …», — иначе следующий
// читатель вносит его обратно, не зная, что оно уже было и почему снято. Гейт,
// не отличающий УТВЕРЖДЕНИЕ от ЦИТАТЫ утверждения, краснеет на собственной
// починке: ровно это и произошло — после правки восьми мест он дал восемь
// находок, и все восемь были прозой О снятом.
//
// Тот же приём, каким корпус развязывает гейт отложенной работы: предикат ловит
// ФОРМУ ОБРАЩЕНИЯ, а не слово, поэтому проза о самих маркерах под него не
// подпадает.
//
// РАЗМЕН НАЗВАН ПРЯМО. Ёлочки можно употребить и для того, чтобы спрятать живое
// утверждение. Ценой этого будет прямая ложь в прозе — читатель увидит цитату
// там, где её нет, — и обзор такое ловит; гейт же, не умеющий цитаты, снимут на
// первой же честной починке. Обратные кавычки и ASCII-кавычки НЕ снимаются
// намеренно: ими в этом дереве оформляют координаты и значения, а не выдержки.
var quotedSpan = regexp.MustCompile(`«[^»]*»`)

// emphasisMarkup — парные знаки выделения. Снимаются ДО сверки образцом:
// «**единственным** подписантом» иначе уходит из-под наблюдения — образец ждёт
// пробела между словами, а там стоят звёздочки. Слепота этого рода не даёт ни
// красного, ни зелёного, она МОЛЧИТ.
var emphasisMarkup = regexp.MustCompile(`\*\*|__|\*`)

// mintingScanExt — виды файлов под обходом. Утверждение живёт и в коде
// (комментарий), и в опубликованной странице, и в профиле развёртывания, и в
// скрипте гейта: обход по одному виду недобирал бы молча.
var mintingScanExt = map[string]bool{
	".go": true, ".md": true, ".mdx": true,
	".yaml": true, ".yml": true, ".sh": true, ".py": true,
}

// mintingSelfFiles — СОБСТВЕННЫЕ файлы гейта: они цитируют запрещённые фразы в
// своём объяснении и в фикстурах инъекции, и без изъятия гейт краснел бы на
// самом себе — на том самом классе, который ловит.
//
// Изъятие ИСТЕКАЕТ САМО по ПРИСУТСТВИЮ: файла нет в обходе — находка, а не
// молчание. Это ловит настоящий риск изъятия — переименование и снос, после
// которых запись остаётся прощать несуществующее.
//
// СПОСОБНОСТЬ ОБРАЗЦА СОВПАДАТЬ здесь НЕ проверяется намеренно. Держать
// контролем собственную прозу значило бы сделать её несущей: любая правка
// заголовка давала бы красное о дереве, в котором ничего не менялось. Контроль
// на КАЖДЫЙ образец стоит там, где ему место, — в инъекции.
var mintingSelfFiles = []string{
	"own_minting_claim_test.go",
	"own_minting_claim_injection_test.go",
}

// mintingCensus — объём осмотренного одним обходом.
type mintingCensus struct {
	filesRead    int             // прочитано отслеживаемых файлов
	blocks       int             // склеено блоков
	byLang       map[string]int  // попаданий по языку образца
	anchorsFound []string        // якоря, найденные разбором
	anchorFiles  int             // прочитано файлов композиционного корня
	selfSeen     map[string]bool // изъятые файлы, ВСТРЕЧЕННЫЕ обходом
	selfSkipped  map[string]int  // изъятые файлы → сколько попаданий изъято
}

// mintingFinding — одна находка с координатой.
type mintingFinding struct {
	Path string
	Line int
	Why  string
	Text string
}

func (f mintingFinding) String() string {
	return fmt.Sprintf("%s:%d: %s\n      блок: %s", f.Path, f.Line, f.Why, f.Text)
}

// claimBlock — склеенный блок и карта «смещение в тексте → строка файла».
//
// Карта несущая: без неё находка называет координату НАЧАЛА блока, а не строку
// утверждения. Первая редакция так и делала — и на профиле развёртывания
// назвала строку 1197 при утверждении на строке 1380, в ста восьмидесяти трёх
// строках ниже. Находка, посылающая читателя не туда, тратит прогон и потом
// снимается как непонятная.
type claimBlock struct {
	Text string
	// Claimed — тот же текст, из которого ВЫРЕЗАНЫ цитаты: по нему судит
	// образец. Длина сохраняется (цитата заменяется пробелами), поэтому карта
	// смещений остаётся годна для обоих.
	Claimed string
	Line    int   // первая строка блока
	marks   []int // marks[i] — строка файла, которой принадлежит смещение
}

// lineAt — строка файла, которой принадлежит смещение в склеенном тексте.
func (b claimBlock) lineAt(off int) int {
	if off < 0 || len(b.marks) == 0 {
		return b.Line
	}
	if off >= len(b.marks) {
		return b.marks[len(b.marks)-1]
	}
	return b.marks[off]
}

// commentMarker — начало строки-комментария. Судится ВИД строки, а не язык
// файла: один и тот же профиль несёт и комментарий, и объявление.
var commentMarker = regexp.MustCompile(`^\s*(?://+|#+|\*+)`)

// joinBlocks режет текст на БЛОКИ и склеивает строки блока в одну.
//
// Блок — АБЗАЦ, а не «всё до пустой строки»: он рвётся на пустой строке, на
// строке из одних маркеров комментария и на переходе «комментарий ↔
// объявление». Без последних двух условий раздел профиля развёртывания
// склеивается в блок на сто восемьдесят строк, и окно образца начинает
// перекидываться между фразами, друг к другу не относящимися, — то есть даёт
// ложные находки ровно там, где сужение и заведено.
//
// Маркеры комментария снимаются, отступы схлопываются: перенос ВНУТРИ фразы не
// должен уводить её из-под наблюдения. Абзац при этом не рвётся посередине
// предложения ни при какой вёрстке — перенос случается внутри абзаца, а не
// через его границу.
func joinBlocks(body string) []claimBlock {
	var out []claimBlock
	var text strings.Builder
	var marks []int
	first := 0
	prevComment := false
	havePrev := false

	flush := func() {
		if text.Len() == 0 {
			return
		}
		joined := text.String()
		out = append(out, claimBlock{
			Text:    joined,
			Claimed: blankQuotes(joined),
			Line:    first,
			marks:   marks,
		})
		text.Reset()
		marks = nil
		havePrev = false
	}

	for i, raw := range strings.Split(body, "\n") {
		lineNo := i + 1
		isComment := commentMarker.MatchString(raw)
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			flush()
			continue
		}
		stripped := strings.TrimLeft(trimmed, "/#*-> \t")
		// Выделение — разметка, а не фраза.
		stripped = emphasisMarkup.ReplaceAllString(stripped, " ")
		stripped = strings.Join(strings.Fields(stripped), " ")
		if stripped == "" {
			// Строка из одних маркеров — граница абзаца внутри комментария.
			flush()
			continue
		}
		if havePrev && isComment != prevComment {
			flush()
		}
		if text.Len() == 0 {
			first = lineNo
		} else {
			text.WriteByte(' ')
			marks = append(marks, lineNo)
		}
		for range stripped {
			marks = append(marks, lineNo)
		}
		// marks считает БАЙТЫ смещения, а руны — разной длины: карта обязана
		// сходиться с индексом, который вернёт образец.
		for len(marks) < text.Len()+len(stripped) {
			marks = append(marks, lineNo)
		}
		text.WriteString(stripped)
		marks = marks[:text.Len()]
		prevComment = isComment
		havePrev = true
	}
	flush()
	return out
}

// blankQuotes заменяет цитату пробелами той же длины: образец её не видит, а
// карта «смещение → строка» продолжает сходиться.
func blankQuotes(s string) string {
	return quotedSpan.ReplaceAllStringFunc(s, func(m string) string {
		return strings.Repeat(" ", len(m))
	})
}

// findMintingAnchors — якоря, найденные РАЗБОРОМ синтаксического дерева.
func findMintingAnchors(root string, dirs []string) ([]string, int, error) {
	seen := map[string]bool{}
	files := 0
	for _, d := range dirs {
		abs := filepath.Join(root, filepath.FromSlash(d))
		entries, err := os.ReadDir(abs)
		if err != nil {
			return nil, 0, fmt.Errorf("композиционный корень %s не прочитан: %w", d, err)
		}
		fset := token.NewFileSet()
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
				continue
			}
			p := filepath.Join(abs, e.Name())
			f, perr := parser.ParseFile(fset, p, nil, 0)
			if perr != nil {
				return nil, 0, fmt.Errorf("%s не разобран: %w", p, perr)
			}
			files++
			// ФОРМ ВЫЗОВА ДВЕ, и вторая — не редкость.
			//
			// Вне пакета якорь пишется `pkg.Fun`; ВНУТРИ своего пакета — голым
			// именем, без квалификатора. Первая редакция знала только первую
			// форму, и объявленный якорь докерной полосы не находился ни разу:
			// его единственный вызов живёт в том же пакете, где он объявлен.
			// Форма, о которой разборщик не знает, даёт не красное и не
			// зелёное, а МОЛЧАНИЕ.
			pkgName := ""
			if f.Name != nil {
				pkgName = f.Name.Name
			}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				switch fun := call.Fun.(type) {
				case *ast.SelectorExpr:
					pkg, ok := fun.X.(*ast.Ident)
					if !ok {
						return true
					}
					for _, a := range mintingAnchors {
						if pkg.Name == a.Pkg && fun.Sel.Name == a.Fun {
							seen[a.Pkg+"."+a.Fun] = true
						}
					}
				case *ast.Ident:
					// Голый вызов засчитывается ТОЛЬКО в пакете, которому якорь
					// объявлен: одноимённая функция в чужом пакете якорем не
					// является.
					for _, a := range mintingAnchors {
						if pkgName == a.Pkg && fun.Name == a.Fun {
							seen[a.Pkg+"."+a.Fun] = true
						}
					}
				}
				return true
			})
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, files, nil
}

// trackedScanFiles — отслеживаемые файлы под обходом. Единица счёта —
// ОТСЛЕЖИВАЕМЫЙ элемент git, а не то, что лежит на диске: иначе объявление,
// `.gitignore` и поведение разъезжаются молча.
func trackedScanFiles(root string) ([]string, error) {
	// Помощник, а НЕ exec.Command напрямую: `cmd.Dir` не выбирает репозиторий,
	// когда в окружении есть GIT_DIR — переменная сильнее рабочего каталога, и
	// обход ушёл бы читать состав ТОГО дерева, из которого запущен прогон.
	// Свойство держит гейт платформы TestGitCommandsRunWithScrubbedEnvironment,
	// и он же поймал здесь первую редакцию.
	out, err := gitenv.Command(root, "ls-files", "-z").Output()
	if err != nil {
		return nil, fmt.Errorf("перечень отслеживаемых не получен: %w", err)
	}
	var paths []string
	for _, p := range strings.Split(string(out), "\x00") {
		if p == "" {
			continue
		}
		if mintingScanExt[strings.ToLower(filepath.Ext(p))] {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)
	return paths, nil
}

// scanOwnMintingClaims — ОДИН обход: перепись, якоря, находки.
//
// Находки возвращаются ТОЛЬКО когда якорь найден: без него запрещённое
// утверждение верно, и объявлять его находкой значило бы судить слово.
func scanOwnMintingClaims(root string, anchorDirs []string) (mintingCensus, []mintingFinding, error) {
	census := mintingCensus{
		byLang:      map[string]int{},
		selfSeen:    map[string]bool{},
		selfSkipped: map[string]int{},
	}

	anchors, anchorFiles, err := findMintingAnchors(root, anchorDirs)
	if err != nil {
		return census, nil, err
	}
	census.anchorsFound, census.anchorFiles = anchors, anchorFiles

	paths, err := trackedScanFiles(root)
	if err != nil {
		return census, nil, err
	}

	self := map[string]bool{}
	for _, s := range mintingSelfFiles {
		self[s] = true
	}

	var findings []mintingFinding
	for _, rel := range paths {
		body, rerr := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if rerr != nil {
			return census, nil, fmt.Errorf("%s не прочитан: %w", rel, rerr)
		}
		census.filesRead++
		isSelf := self[filepath.Base(rel)]
		if isSelf {
			census.selfSeen[filepath.Base(rel)] = true
		}
		for _, b := range joinBlocks(string(body)) {
			census.blocks++
			_ = b.Line
			// ЕДИНИЦА СЧЁТА — БЛОК, а не совпадение. Образцы перекрываются
			// намеренно (одна и та же мысль записывается по-разному), и без
			// этого «одна фраза» считалась бы двумя находками — число, которое
			// нельзя ни повторить, ни сверить.
			matched := false
			for _, c := range retiredExclusivityClaim {
				if matched {
					continue
				}
				loc := c.Pattern.FindStringIndex(b.Claimed)
				if loc == nil {
					continue
				}
				matched = true
				census.byLang[c.Lang]++
				if isSelf {
					census.selfSkipped[filepath.Base(rel)]++
					continue
				}
				if len(anchors) == 0 {
					continue
				}
				findings = append(findings, mintingFinding{
					Path: rel, Line: b.lineAt(loc[0]), Why: c.Why, Text: trimBlock(b.Text),
				})
			}
		}
	}
	return census, findings, nil
}

// trimBlock — блок в находке печатается целиком до разумного предела: находка,
// называющая симптом вместо предмета, посылает читателя искать не там.
func trimBlock(s string) string {
	const cap = 220
	if len(s) <= cap {
		return s
	}
	return s[:cap] + "…"
}

// TestPlatformMintingClaimIsNotDeniedByTheTreeThatMintsIt — гейт по дереву.
func TestPlatformMintingClaimIsNotDeniedByTheTreeThatMintsIt(t *testing.T) {
	t.Parallel()
	root := platformtree.Require(t)

	census, findings, err := scanOwnMintingClaims(root, mintingAnchorRoots)
	require.NoError(t, err)

	// ПРЕДПОСЫЛКА. Пустой обход — не «ноль находок», а «ноль прочитанного».
	require.NotZero(t, census.filesRead, "обход пуст: о дереве не прочитано ничего — вердикта нет")
	require.NotZero(t, census.blocks, "склеено ноль блоков: разборщик не читает — вердикта нет")
	require.NotZero(t, census.anchorFiles, "композиционный корень не прочитан — якорь искать негде")
	// КАЖДЫЙ объявленный якорь обязан быть НАЙДЕН. Объявление, которое не
	// находится, — мёртвое: оно создаёт вид опоры, которой нет, и «якорей 1 при
	// двух объявленных» никого не роняет.
	//
	// Снимут полосу выдачи — снимут и её якорь ТЕМ ЖЕ изменением; красное здесь
	// говорит, что этого не сделали либо что якорь переименовали, а гейт ослеп бы
	// молча.
	found := map[string]bool{}
	for _, a := range census.anchorsFound {
		found[a] = true
	}
	for _, a := range mintingAnchors {
		require.Truef(t, found[a.Pkg+"."+a.Fun],
			"объявленный якорь %s.%s не найден разбором в %v.\n"+
				"  он опровергает утверждение тем, что %s\n"+
				"  либо полосу сняли (снимите якорь тем же изменением), либо её переименовали",
			a.Pkg, a.Fun, mintingAnchorRoots, a.Refutes)
	}

	// ИЗЪЯТИЕ ИСТЕКАЕТ САМО: прощаемый файл обязан существовать в обходе.
	// Запись, прощающая несуществующее, — слепая зона, которую унаследует
	// следующий.
	for _, s := range mintingSelfFiles {
		require.Truef(t, census.selfSeen[s],
			"изъятие %s потеряло предмет: файла нет в обходе (переименован или снесён). "+
				"Запись, которой нечего изымать, — находка: снимите её вместе с предметом", s)
	}

	if len(findings) > 0 {
		var b strings.Builder
		for _, f := range findings {
			b.WriteString("  · " + f.String() + "\n")
		}
		t.Fatalf(
			"утверждение исключительности стоит в дереве, которое его ОПРОВЕРГАЕТ.\n"+
				"  опровергают якоря: %s\n"+
				"  находок: %d\n%s"+
				"  осмотрено: файлов %d · блоков %d · попаданий en %d · ru %d · изъято своих %v",
			strings.Join(census.anchorsFound, ", "), len(findings), b.String(),
			census.filesRead, census.blocks, census.byLang["en"], census.byLang["ru"], census.selfSkipped)
	}

	t.Logf("осмотрено: файлов %d · блоков %d · якорей %d (%s) · попаданий en %d · ru %d · изъято своих %v",
		census.filesRead, census.blocks, len(census.anchorsFound),
		strings.Join(census.anchorsFound, ", "), census.byLang["en"], census.byLang["ru"], census.selfSkipped)
}
