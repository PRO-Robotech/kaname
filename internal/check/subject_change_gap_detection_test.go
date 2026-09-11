// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// subject_change_gap_detection_test.go — держатель `TestSubjectChangeJournalDetectsAGapOnBothSides`
// (порт-ЗЕРКАЛО, СУЖЕННЫЙ ДО СВОЕЙ СТОРОНЫ ШВА, с монорепо
// `internal/repohygiene/subjectchangegapdetection.go`/`_test.go`, снят
// вынесением службы доступа — `kacho#2597`; задача продукта #1712).
//
// Имя держателя сохранено ДОСЛОВНО: `docs/engineering/architecture/
// journal-retention-is-a-policy.md` (живёт в дереве kaname) цитирует его как
// «чем держится» — цитата была бы координатой в никуда без этого файла.
//
// # Шов теперь пересекает ГРАНИЦУ РЕПОЗИТОРИЯ — и это меняет, что можно судить
//
// Монорепошный предок обходил ВСЁ дерево платформы и судил ОДНИМ прогоном три
// звена: ПОЛ (владелец спрашивает нижнюю границу) · ОТКАЗ (производится вне
// пакета читателя) · ОТВЕТ (разбирается ВНУТРИ пакета читателя,
// `pkg/subjectchange`). Разрез развёл звенья по двум репозиториям: ПОЛ и ОТКАЗ
// живут целиком в дереве kaname (владелец журнала); ОТВЕТ живёт в
// `pkg/subjectchange/watcher.go` — общем фундаменте платформы, который в
// kaname НЕ переезжает и там же продолжает нести свои пробы
// (`pkg/subjectchange/positionlost_test.go`, `readerpositionlost_test.go`).
//
// Судить звено ОТВЕТ отсюда значило бы читать чужой репозиторий чтением
// диска — вердикт стал бы свойством того, что случайно лежит в модульном кеше
// на машине прогона, а не свойством коммита ни одного из двух деревьев
// (`treecorpus`, тот же довод, что против обхода диска вместо индекса git).
// Поэтому эта проба судит ДВА звена из трёх — ПОЛ и ОТКАЗ, — а третье остаётся
// за платформенным пакетом: его молчаливый разрыв (реализация есть, а пробы
// нет) — предмет ЕГО репозитория, не этого.
//
// Собственная шапка предка (перенесена в комментарии ниже дословно по смыслу)
// прямо запрещает судить звенья порознь: «звенья порознь дают зелёные гейты над
// неработающим механизмом». Здесь это разрешение вынуждено СТРУКТУРОЙ РАЗРЕЗА,
// а не удобством — судить оба звена СРАЗУ и в одном прогоне сегодня возможно
// только там, где оба лежат: то есть только здесь, для пары «пол+отказ».
//
// Способность гейта упасть доказана инъекцией —
// subject_change_gap_detection_injection_test.go.
//
// # Предмет — РАЗРЫВ, невидимый ни с одной стороны по отдельности
//
// Журнал `kaname.subject_change_outbox` читается окном `id > since AND
// id <= settled`. Снятая строка в такое окно не попадает: курсор переезжает
// через неё по последней прочитанной позиции, и «строк не было» становится
// НЕОТЛИЧИМО от «строки убрали». Полоса fail-open by design — пропущенная
// строка означает непогашенный кэш вердиктов края, то есть неприменённый
// отзыв доступа, молча.
//
// # Порядок — вторая половина защиты пола, и без неё первая ничего не доказывает
//
// Пол и страница — ДВА запроса; между ними уборка вправе зафиксироваться. Пол,
// спрошенный РАНЬШЕ страницы, описывает журнал, которого к моменту чтения уже
// нет, и отказ не производится — software check-then-act (ban #10). Порядок
// «после» делает вывод доказуемым: нижняя строка непустого журнала монотонна,
// поэтому пол, взятый не раньше страницы, не может занизиться.
package check_test

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// subjectChangeJournalTable — имя журнала, как оно стоит в запросе.
const subjectChangeJournalTable = "subject_change_outbox"

// subjectChangeReasonToken — машинный признак полосы, как он стоит У ПРОДУКТА
// (`pkg/subjectchange.ReasonPositionLost`). Значение — данность контракта, не
// вкус: изменится оно там, разойдётся здесь, и разбор это заметит нулём
// найденных производителей, а не молчаливым мимо.
const subjectChangeReasonToken = "SUBJECT_CHANGE_POSITION_LOST"

const (
	floorSelector        = "Floor"
	observeFloorSelector = "ObserveFloor"
	positionLostProducer = "PositionLost"
	observedFloorMarker  = "<наблюдение>"
)

// floorObservers — ДВЕ законные формы наполнить нижнюю границу свежим числом
// (см. годок предка: `Advance` — полное наблюдение одним запросом,
// `RefreshEarliest` — узкий вопрос там, где полного не происходит).
var floorObservers = []string{"Advance", "RefreshEarliest"}

// subjectChangeGapCensus — объём осмотренного по каждой полосе. Печатается
// всегда: «ноль находок» обязано быть отличимо от «ноль прочитанного».
type subjectChangeGapCensus struct {
	GoFiles         int
	JournalLiterals int
	Windows         []string
	WindowsAskFloor []string
	Producers       []string
	TokenDuplicates []string
}

type subjectChangeGapFinding struct{ What string }

// auditSubjectChangeGapDetection обходит непробное дерево kaname и судит два
// звена шва, которые лежат в этом репозитории.
func auditSubjectChangeGapDetection(files []string, root string) ([]subjectChangeGapFinding, subjectChangeGapCensus, error) {
	var (
		findings []subjectChangeGapFinding
		census   subjectChangeGapCensus
	)
	for _, abs := range files {
		if strings.HasSuffix(abs, "_test.go") {
			continue
		}
		body, rerr := os.ReadFile(abs) // #nosec G304 -- путь взят из состава дерева этого модуля
		if rerr != nil {
			return nil, census, rerr
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, abs, body, 0)
		if perr != nil {
			return nil, census, fmt.Errorf("разбор %s: %w", abs, perr)
		}
		census.GoFiles++
		rel, _ := filepath.Rel(root, abs)
		rel = filepath.ToSlash(rel)
		at := func(p token.Pos) string { return fmt.Sprintf("%s:%d", rel, fset.Position(p).Line) }

		// ── ТОКЕН: раздублирован ли признак полосы литералом ────────────────
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, uerr := strconv.Unquote(lit.Value)
			if uerr != nil {
				return true
			}
			if s == subjectChangeReasonToken {
				census.TokenDuplicates = append(census.TokenDuplicates, at(lit.Pos()))
			}
			if strings.Contains(s, subjectChangeJournalTable) {
				census.JournalLiterals++
			}
			return true
		})

		// ── ПОЛ и ОТКАЗ: окна чтения и вызовы своей стороны шва ──────────────
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			var (
				sql       strings.Builder
				asks      = map[string]bool{}
				producers []token.Pos
				windowAt  token.Pos
				floorAt   token.Pos
				floorLine int
			)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				switch node := n.(type) {
				case *ast.BasicLit:
					if node.Kind == token.STRING {
						if s, uerr := strconv.Unquote(node.Value); uerr == nil {
							sql.WriteString(" ")
							sql.WriteString(s)
							if readsSubjectChangeJournalByWindow(s) && !windowAt.IsValid() {
								windowAt = node.Pos()
							}
						}
					}
				case *ast.CallExpr:
					name := subjectChangeCalledName(node.Fun)
					if name == "" {
						return true
					}
					switch name {
					case floorSelector:
						asks[floorSelector] = true
						if !floorAt.IsValid() || node.Pos() < floorAt {
							floorAt, floorLine = node.Pos(), fset.Position(node.Pos()).Line
						}
					case observeFloorSelector:
						asks[floorSelector], asks[observedFloorMarker] = true, true
						if !floorAt.IsValid() || node.Pos() < floorAt {
							floorAt, floorLine = node.Pos(), fset.Position(node.Pos()).Line
						}
					case positionLostProducer:
						producers = append(producers, node.Pos())
					}
					for _, observer := range floorObservers {
						if name == observer {
							asks[observedFloorMarker] = true
						}
					}
				}
				return true
			})

			for _, p := range producers {
				census.Producers = append(census.Producers, at(p))
			}

			if !readsSubjectChangeJournalByWindow(sql.String()) {
				continue
			}
			where := at(fn.Pos()) + " " + fn.Name.Name
			census.Windows = append(census.Windows, where)
			if asks[floorSelector] && asks[observedFloorMarker] {
				if windowAt.IsValid() && floorAt.IsValid() && floorAt < windowAt {
					findings = append(findings, subjectChangeGapFinding{
						What: where + " — пол берётся РАНЬШЕ страницы (строка " +
							strconv.Itoa(floorLine) + "). Между двумя запросами уборка " +
							"вправе зафиксироваться: страница придёт без снятых строк, " +
							"пол о них ещё не знает, отказа не будет — и вызывающий " +
							"получит страницу с дырой как полную. Пол обязан браться НЕ " +
							"РАНЬШЕ страницы, иначе доказывает он только расписание",
					})
					continue
				}
				census.WindowsAskFloor = append(census.WindowsAskFloor, where)
				continue
			}
			findings = append(findings, subjectChangeGapFinding{
				What: where + " — журнал смены субъекта читается ОКНОМ по позиции, а нижняя " +
					"удержанная граница не спрашивается (нужен вызов " + floorSelector +
					" и наблюдение, его наполняющее: " + strings.Join(floorObservers, " либо ") +
					"). Снятая строка в такое окно не попадает вовсе: курсор переезжает через " +
					"неё, и «строк не было» становится неотличимо от «строки убрали» — то есть " +
					"отзыв доступа не применён, и об этом не узнает никто",
			})
		}
	}
	return findings, census, nil
}

// subjectChangeCalledName — имя вызываемого: последний идентификатор
// выражения. Обе формы обращения (голым именем и через пакет) обязаны
// считаться — распознаватель, знающий одну, объявляет вторую отсутствующей.
func subjectChangeCalledName(fun ast.Expr) string {
	switch f := fun.(type) {
	case *ast.Ident:
		return f.Name
	case *ast.SelectorExpr:
		return f.Sel.Name
	case *ast.IndexExpr:
		return subjectChangeCalledName(f.X)
	case *ast.IndexListExpr:
		return subjectChangeCalledName(f.X)
	case *ast.ParenExpr:
		return subjectChangeCalledName(f.X)
	}
	return ""
}

// readsSubjectChangeJournalByWindow — читает ли этот запрос журнал ОКНОМ по
// позиции: пара сравнений, строго больше курсора и не больше границы.
func readsSubjectChangeJournalByWindow(sql string) bool {
	flat := strings.Join(strings.Fields(sql), " ")
	if !strings.Contains(flat, subjectChangeJournalTable) {
		return false
	}
	upper := strings.ToUpper(flat)
	if !strings.Contains(upper, "SELECT") || !strings.Contains(upper, "WHERE") {
		return false
	}
	return subjectChangeWindowCmp(flat, ">") && subjectChangeWindowCmp(flat, "<=")
}

func subjectChangeWindowCmp(flat, op string) bool {
	needle := "id " + op + " "
	for i := 0; i < len(flat); {
		j := strings.Index(flat[i:], needle)
		if j < 0 {
			return false
		}
		at := i + j
		if at == 0 || !subjectChangeIsIdentByte(flat[at-1]) {
			return true
		}
		i = at + 1
	}
	return false
}

func subjectChangeIsIdentByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// TestSubjectChangeJournalDetectsAGapOnBothSides — сам гейт, над СВОЕЙ
// стороной шва (см. шапку файла — почему не над обеими).
func TestSubjectChangeJournalDetectsAGapOnBothSides(t *testing.T) {
	t.Parallel()
	root, prefix := platformtree.RequireCorpus(t)
	dir := root
	if prefix != "" {
		dir = filepath.Join(root, filepath.FromSlash(prefix))
	}
	files, err := treecorpus.UnderWithSuffix(dir, ".go")
	if err != nil {
		t.Fatalf("состав дерева модуля: %v — вердикт беспредметен", err)
	}

	findings, census, err := auditSubjectChangeGapDetection(files, dir)
	if err != nil {
		t.Fatalf("обход дерева: %v", err)
	}

	t.Logf("перепись: файлов Go %d, литералов, называющих журнал %d; окон чтения %d, из "+
		"них спрашивают пол %d; производителей отказа %d; литералов-дублей признака полосы %d",
		census.GoFiles, census.JournalLiterals, len(census.Windows), len(census.WindowsAskFloor),
		len(census.Producers), len(census.TokenDuplicates))

	if census.GoFiles == 0 {
		t.Fatalf("обход не прочитал ни одного файла Go — вердикт был бы беспредметен")
	}
	if len(census.Windows) == 0 {
		t.Fatalf("ни одного чтения журнала %s окном по позиции не найдено при %d "+
			"прочитанных файлах и %d литералах, называющих журнал: либо предмет гейта "+
			"снят целиком (тогда снимите гейт вместе с ним), либо разбор ослеп",
			subjectChangeJournalTable, census.GoFiles, census.JournalLiterals)
	}
	if len(census.Producers) == 0 {
		t.Errorf("отказ «позиция утрачена» НЕ ПРОИЗВОДИТСЯ нигде в дереве (вызовов %s — "+
			"ноль), хотя окно чтения найдено: пол может спрашиваться исправно, а сказать о "+
			"его исходе нечем", positionLostProducer)
	}
	for _, dup := range census.TokenDuplicates {
		t.Errorf("%s — признак полосы %q продублирован строковым литералом вместо ссылки "+
			"на pkg/subjectchange.ReasonPositionLost: две сборки одного признака расходятся "+
			"МОЛЧА", dup, subjectChangeReasonToken)
	}
	for _, f := range findings {
		t.Errorf("НАХОДКА: %s", f.What)
	}
}
