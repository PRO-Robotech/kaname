// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// injection_named_exists.go — разбор: доказательство способности упасть,
// НАЗВАННОЕ пробой, обязано существовать (#2479).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Проба, чья шапка говорит «способность упасть доказана инъекцией — такой-то
// файл», делает утверждение о ДЕРЕВЕ. Утверждение это не компилируется и никем
// не сверяется: файл переименовали, унесли вместе с рефакторингом либо не
// написали вовсе — а шапка продолжает обещать доказательство. Гейт, потерявший
// способность краснеть, на чистом дереве выглядит РОВНО ТАК ЖЕ, как исправный,
// поэтому обещание доказательства читается как само доказательство.
//
// Замер, из которого разбор выведен: на ревизии заведения упоминаний в
// комментариях было 122, не резолвилось ОДНО — шапка гейта осей адреса называла
// файл, которого в дереве не было с первого её дня.
//
// ─────────────────────────────────────────────────────────────────────────────
// У ЭТОГО РАЗБОРА ЕСТЬ БЛИЗНЕЦ В ПЛАТФОРМЕ — И ЭТО НАЗВАНО, А НЕ УМОЛЧАНО
//
// Тот же разбор, поднятый до корня МОНОРЕПО, живёт в `tools/injectionproofgate`
// (задача #2519): этот обходит корень своего модуля и о платформе не
// высказывается — в самостоятельном клоне службы монорепо нет вовсе. Обещания
// соседних модулей платформы этому модулю не принадлежат.
//
// Свести обе реализации в одну сегодня НЕЛЬЗЯ: модуль службы пинит платформу
// псевдоверсией, поэтому импортировать пакет, которого в пинованной ревизии ещё
// нет, он не может. Предикат сведения: пин указывает на ревизию, где тот пакет
// существует; до этого две реализации об одном предмете живут рядом осознанно.
//
// ─────────────────────────────────────────────────────────────────────────────
// СУДЯТСЯ КОММЕНТАРИИ, И ЭТО РЕШЕНИЕ, А НЕ УПРОЩЕНИЕ
//
// Координата доказательства пишется ПРОЗОЙ — это её законное место, и разбор
// читает разобранные группы комментариев, а не сырой текст файла. Строковые
// литералы намеренно НЕ судятся: в них живут синтетические имена, которые
// инъекции кладут во временные каталоги, и дерева они не называют вовсе. Судить
// их значило бы краснеть на чужой фикстуре — то есть на собственном
// доказательстве.
//
// Величина «в строках» всё равно печатается переписью: молчание о целом виде
// вхождений неотличимо от их отсутствия.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАКОННЫХ ФОРМ КООРДИНАТЫ ТРИ, И РАСПОЗНАВАТЕЛЬ ЗНАЕТ ВСЕ ТРИ
//
// Форма, о которой он не знает, даёт не красное и не зелёное, а МОЛЧАНИЕ.
// Измерено на этом дереве: наивный резолвер («имя рядом с называющим») дал 4
// непопадания из 138, и все четыре оказались ЗАКОННЫМИ формами, а не находками.
//
//	СОСЕД        `<имя>_injection_test.go` — файл в каталоге называющего;
//	ПО МОДУЛЮ    то же имя, но доказательство лежит в ДРУГОМ пакете модуля
//	             (проба одного пакета ссылается на инъекцию соседнего);
//	КООРДИНАТОЙ  `internal/<пакет>/<имя>_injection_test.go` — путь от корня
//	             МОДУЛЯ службы, а не от корня монорепо: в самостоятельном клоне
//	             приставки `services/iam/` нет, и счёт от неё указывал бы наружу
//	             дерева.
//
// Имя в примерах — ОБРАЗЕЦ с угловыми скобками, а не координата, и это не
// подгонка текста под инструмент: координата, названная в прозе, есть
// утверждение о дереве, и выдуманная — ложное. Разбор судит объявленные
// координаты, поэтому пример обязан не выглядеть ею.
package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// injectionCoordinate — имя файла-доказательства.
//
// Собирается СКЛЕЙКОЙ намеренно: записанный одним литералом образец нашёл бы сам
// себя в этом же файле, и разбор судил бы собственное объяснение.
var injectionCoordinate = regexp.MustCompile(
	`[A-Za-z0-9_./-]*[a-z0-9_]` + `_injection` + `(?:_internal)?` + `_test` + `\.go`)

// InjectionCensus — объём осмотренного. Печатается ВСЕГДА: «ноль находок»
// обязано быть отличимо от «ноль прочитанного».
type InjectionCensus struct {
	// GoFiles — исходников модуля разобрано.
	GoFiles int
	// NamingFiles / InComments — файлов, называющих доказательство, и самих
	// упоминаний В КОММЕНТАРИЯХ (судимая полоса).
	NamingFiles int
	InComments  int
	// InStrings — упоминаний в строковых литералах (полоса НЕ судимая; названа,
	// чтобы её отсутствие в вердикте не приняли за отсутствие вхождений).
	InStrings int
	// Resolved — из судимых упоминаний нашли свой файл.
	Resolved int
}

// InjectionFinding — упоминание, у которого нет предмета.
type InjectionFinding struct {
	NamedBy    string // координата называющего, от корня обхода
	Coordinate string // что названо
}

// AuditNamedInjections обходит дерево модуля от root и возвращает находки с
// переписью.
//
// Обращения к пробе здесь нет намеренно: разбор, роняющий её изнутри, инъекции
// не поддаётся — синтетическому дереву некуда было бы подать вход.
func AuditNamedInjections(root string) ([]InjectionFinding, InjectionCensus, error) {
	var (
		census   InjectionCensus
		findings []InjectionFinding
	)

	// Указатель имён всех проб модуля: форма «по модулю» резолвится по нему.
	byBase := map[string]bool{}
	walkErr := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, "_test.go") {
			byBase[filepath.Base(p)] = true
		}
		return nil
	})
	if walkErr != nil {
		return nil, census, walkErr
	}

	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, ".go") {
			return nil
		}
		fset := token.NewFileSet()
		file, perr := parser.ParseFile(fset, p, nil, parser.ParseComments)
		if perr != nil {
			// Неразбираемый исходник — не находка ЭТОГО разбора и не тишина:
			// о нём высказывается компилятор, а перепись недосчитает его вслух.
			return nil
		}
		census.GoFiles++

		named := false
		for _, group := range file.Comments {
			for _, coord := range injectionCoordinate.FindAllString(group.Text(), -1) {
				census.InComments++
				named = true
				if injectionExists(root, filepath.Dir(p), coord, byBase) {
					census.Resolved++
					continue
				}
				rel, rerr := filepath.Rel(root, p)
				if rerr != nil {
					rel = p
				}
				findings = append(findings, InjectionFinding{
					NamedBy: filepath.ToSlash(rel), Coordinate: coord,
				})
			}
		}
		if named {
			census.NamingFiles++
		}

		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if ok && lit.Kind == token.STRING {
				census.InStrings += len(injectionCoordinate.FindAllString(lit.Value, -1))
			}
			return true
		})
		return nil
	})
	if err != nil {
		return nil, census, err
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].NamedBy != findings[j].NamedBy {
			return findings[i].NamedBy < findings[j].NamedBy
		}
		return findings[i].Coordinate < findings[j].Coordinate
	})
	return findings, census, nil
}

// injectionExists — резолв по всем трём законным формам.
func injectionExists(root, dir, coord string, byBase map[string]bool) bool {
	if strings.Contains(coord, "/") {
		// КООРДИНАТОЙ: путь от корня модуля службы.
		return statFile(filepath.Join(root, filepath.FromSlash(coord)))
	}
	// СОСЕД.
	if statFile(filepath.Join(dir, coord)) {
		return true
	}
	// ПО МОДУЛЮ.
	return byBase[coord]
}

// statFile — существует ли ОБЫЧНЫЙ файл по пути. Каталог с таким именем
// доказательством не является.
func statFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}
