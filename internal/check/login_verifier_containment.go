// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// login_verifier_containment.go — ЯДРО гейта: проверочный материал способа входа
// выходит из своего типа ТОЛЬКО там, где он нужен по существу (фаза Ф2,
// `kacho#1268`).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Материал пароля живёт в типе `domain.LoginVerifier`, который не печатается, не
// пишется в журнал и не сериализуется: каждый общий путь вывода отдаёт
// заглушку либо отказ (`internal/domain/login_method_test.go`). Выход у
// материала ОДИН — метод `Reveal`, — и он нужен ровно тем, кто кладёт материал в
// базу и сверяет с ним предъявленное.
//
// Значит утечка из кода Go имеет две и только две формы:
//
//  1. ВЫЗОВ ВЫХОДА вне разрешённого места — материал достан строкой и дальше
//     ничем не защищён: его можно положить в поле контракта, в нагрузку аудита,
//     в журнал;
//  2. ВТОРОЙ ЧИТАТЕЛЬ КОЛОНКИ — оператор, называющий таблицу секрета мимо её
//     адаптера, читает материал строкой, не проходя через тип вовсе.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СУДИТСЯ И КАК
//
// Судится РАЗБОРОМ, а не текстом: комментарий, объясняющий выход, и строка с
// его именем законны и обязаны остаться — гейт, краснеющий на собственном
// объяснении, снимают первым.
//
//   - выход: всякое обращение к селектору с именем выхода — вызов, значение
//     метода и выражение метода записываются одной синтаксической формой, и
//     распознаватель знает её одну, потому что других нет;
//   - таблица: строковый литерал, в котором имя таблицы стоит ЦЕЛЫМ словом.
//     Имена ограничений таблицы (`<таблица>_pkey`) им не являются — «слово»
//     здесь в смысле идентификатора SQL, где подчёркивание часть имени.
//
// Объявление предмета (имя выхода, файл и тип, где он объявлен, имя таблицы,
// разрешённые места) приходит ПАРАМЕТРОМ из файла пробы. Причина — не вкус:
// литерал имени таблицы в этом файле сделал бы гейт своей же первой находкой,
// а файл пробы в корпус не входит by construction.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕМИСЫ — ОТКАЗ, А НЕ МОЛЧАНИЕ
//
//   - выход объявлен РОВНО ОДИН раз, в названном файле, на названном типе.
//     Иначе селектор с тем же именем означает не этот выход, и перепись мерит
//     чужой метод;
//   - файл-владелец таблицы называет её хоть раз: иначе второе правило ослепло;
//   - каждое разрешённое место выход ИСПОЛЬЗУЕТ: разрешение без предмета —
//     место, куда вызов вносят незамеченным (послабление обязано истекать само).
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦЫ, НАЗВАННЫЕ ВСЛУХ
//
//  1. ФАЙЛЫ ПРОБ НЕ СУДЯТСЯ: пробе законно достать материал, чтобы сверить его
//     побайтово, а фикстуре инъекции — написать форму дефекта.
//  2. СКЛЕЙКА ИМЕНИ ТАБЛИЦЫ НЕ УЗНАЁТСЯ: литерал, собранный сложением частей,
//     под предикат не подпадает. В дереве такой формы нет; появится — гейт
//     промолчит, и это его граница, а не чистота.
//  3. ОТРАЖЕНИЕ НЕ УЗНАЁТСЯ: доступ к неэкспортированному полю через `reflect`
//     либо `unsafe` синтаксического следа выхода не оставляет.
//  4. ПУТЬ ВНЕ ГО НЕ СУДИТСЯ: базу судит соседний гейт схемы
//     `internal/repo/kaname/pg` `TestLoginVerifierStaysInsideTheSchema`.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// LoginVerifierSpec — объявление предмета гейта.
type LoginVerifierSpec struct {
	// Accessor — имя единственного выхода материала.
	Accessor string
	// DeclRel — файл, где выход объявлен; DeclType — тип-получатель.
	DeclRel, DeclType string
	// Table — таблица секрета; TableOwnerRel — единственный файл, который её называет.
	Table, TableOwnerRel string
	// Allowed — каталог пакета → причина, по которой материал ему нужен. Причина
	// уезжает в перепись: разрешение без названной причины снимается следующим.
	Allowed map[string]string
}

// LoginVerifierCensus — объём осмотренного по каждой оси.
type LoginVerifierCensus struct {
	FilesRead, FilesParsed int
	AccessorDecls          int
	AccessorUses           int
	AllowedUses            map[string]int
	TableLiterals          int
	OwnerTableLiterals     int
}

func (c LoginVerifierCensus) String() string {
	dirs := make([]string, 0, len(c.AllowedUses))
	for d, n := range c.AllowedUses {
		dirs = append(dirs, fmt.Sprintf("%s=%d", d, n))
	}
	sort.Strings(dirs)
	return fmt.Sprintf("перепись: не-тестовых файлов Go прочитано %d (разобрано %d) · объявлений выхода %d · "+
		"обращений к выходу %d, из них в разрешённых местах [%s] · литералов с именем таблицы %d, "+
		"из них у владельца %d",
		c.FilesRead, c.FilesParsed, c.AccessorDecls, c.AccessorUses, strings.Join(dirs, " "),
		c.TableLiterals, c.OwnerTableLiterals)
}

// AuditLoginVerifierContainment — находки и перепись по корпусу не-тестовых
// файлов. Корпус и объявление приходят ПАРАМЕТРАМИ: инъекция обязана подать
// разбору синтетику, а не это дерево.
func AuditLoginVerifierContainment(corpus TreeCorpus, spec LoginVerifierSpec) ([]string, LoginVerifierCensus, error) {
	c := LoginVerifierCensus{AllowedUses: map[string]int{}}
	for dir := range spec.Allowed {
		c.AllowedUses[dir] = 0
	}
	if spec.Accessor == "" || spec.Table == "" || spec.DeclRel == "" || spec.DeclType == "" || spec.TableOwnerRel == "" {
		return nil, c, fmt.Errorf("объявление предмета неполно (%+v) — судить нечего", spec)
	}
	tableWord, err := regexp.Compile(`(^|[^A-Za-z0-9_])` + regexp.QuoteMeta(spec.Table) + `($|[^A-Za-z0-9_])`)
	if err != nil {
		return nil, c, fmt.Errorf("имя таблицы %q не образует предиката: %w", spec.Table, err)
	}

	var findings []string
	var declWhere []string
	for _, rel := range corpus.Rels() {
		c.FilesRead++
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, rel, corpus[rel], parser.ParseComments)
		if perr != nil {
			return nil, c, fmt.Errorf("разбор %s: %w — гейт не вправе судить файл, которого он не разобрал", rel, perr)
		}
		c.FilesParsed++
		dir := path.Dir(rel)

		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Name.Name != spec.Accessor {
				continue
			}
			c.AccessorDecls++
			// Разбор получателя — общий с соседним гейтом (`provider_road_wire_guard.go`):
			// вторая копия одного разбора разошлась бы с первой молча.
			recvType, _ := receiverTypeName(fn)
			declWhere = append(declWhere, fmt.Sprintf("%s (получатель %s)", rel, recvType))
		}

		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.SelectorExpr:
				if node.Sel.Name != spec.Accessor {
					return true
				}
				c.AccessorUses++
				if _, ok := spec.Allowed[dir]; ok {
					c.AllowedUses[dir]++
					return true
				}
				findings = append(findings, fmt.Sprintf(
					"%s:%d: материал способа входа выведен из своего типа обращением к `%s` вне "+
						"разрешённых мест. Дальше он строка, и её ничто не мешает положить в поле "+
						"контракта, нагрузку аудита либо журнал. Разрешение даётся ПАКЕТУ с названной "+
						"причиной и держится этим гейтом",
					rel, fset.Position(node.Pos()).Line, spec.Accessor))
			case *ast.BasicLit:
				if node.Kind != token.STRING {
					return true
				}
				value, uerr := strconv.Unquote(node.Value)
				if uerr != nil || !tableWord.MatchString(value) {
					return true
				}
				c.TableLiterals++
				if rel == spec.TableOwnerRel {
					c.OwnerTableLiterals++
					return true
				}
				findings = append(findings, fmt.Sprintf(
					"%s:%d: таблица секрета `%s` названа мимо её адаптера (%s). Второй читатель "+
						"колонки получает материал строкой, не проходя через тип, — и первое правило "+
						"гейта его не увидит",
					rel, fset.Position(node.Pos()).Line, spec.Table, spec.TableOwnerRel))
			}
			return true
		})
	}

	switch {
	case c.FilesRead == 0:
		return nil, c, fmt.Errorf("%w — «находок ноль» здесь означало бы «прочитано ноль»", ErrEmptyTraversal)
	case c.AccessorDecls != 1:
		return nil, c, fmt.Errorf("выход материала `%s` объявлен %d раз (%s) — премиса «один выход» "+
			"не держится, и селектор с этим именем может означать чужой метод",
			spec.Accessor, c.AccessorDecls, strings.Join(declWhere, "; "))
	case !strings.HasPrefix(declWhere[0], spec.DeclRel+" ") ||
		!strings.HasSuffix(declWhere[0], "получатель "+spec.DeclType+")"):
		return nil, c, fmt.Errorf("выход материала объявлен не там: %s, ожидалось %s на типе %s",
			declWhere[0], spec.DeclRel, spec.DeclType)
	case c.OwnerTableLiterals == 0:
		return nil, c, fmt.Errorf("владелец таблицы %s не называет её ни разу (литералов с её именем "+
			"по дереву %d) — правило второго читателя ослепло, не покраснев", spec.TableOwnerRel, c.TableLiterals)
	}
	dirs := make([]string, 0, len(spec.Allowed))
	for dir := range spec.Allowed {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		if c.AllowedUses[dir] == 0 {
			findings = append(findings, fmt.Sprintf(
				"разрешение пакету %s («%s») без предмета: выход там не используется ни разу. "+
					"Разрешение, которому нечего разрешать, есть место, куда вызов вносят "+
					"незамеченным, — снимается вместе с предметом",
				dir, spec.Allowed[dir]))
		}
	}
	sort.Strings(findings)
	return findings, c, nil
}
