// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// derived_id_single_source.go — разбор объявлений деривации детерминированного
// идентификатора (приёмка `docs/engineering/acceptance/roles-come-as-data-not-migrations.md`
// §3.3; приёмка `seed-identity-names-its-own-service.md` §6, держатель
// `TestDeterministicIDDerivationIsDeclaredOnce`).
//
// # Предмет
//
// Идентификатор системной роли, служебной учётки модуля и связки OAuth есть
// функция ИМЕНИ: применённые миграции адресуют строки выражением
// `'<префикс>' || substr(md5('<имя>'), 1, 17)`, и на эти идентификаторы
// ссылаются выданные права. Вторая копия формулы разойдётся с первой МОЛЧА — и
// разойдётся ровно там, где обе отвечают «идентификатор вычислен»: полученное
// значение остаётся синтаксически верным и перестаёт находить строку.
// Наблюдаемо это только по отказу в доступе у арендатора, у которого право не
// отзывали.
//
// Порт с монорепо (`internal/repohygiene/derivedidsinglesource.go`, снят
// вынесением службы — `kacho#2597`): формула не переехала с кодом целиком, а
// была написана заново рядом с единственным домом — `internal/domain/derived_id.go`,
// чей собственный комментарий уже называет этот гейт держателем и ожидает его
// присутствия. До этой правки объявление не охранялось ничем: единственность
// была фактом дня, а не удержанным свойством.
//
// # Что здесь считается ОБЪЯВЛЕНИЕМ
//
// Файл прод-дерева, импортирующий `crypto/md5`. Иных потребителей MD5 в этом
// продукте нет и быть не должно: как примитив защиты MD5 запрещён (сам импорт
// в доме несёт отметку `#nosec G501`), а как контрольная сумма он здесь не
// применяется — значит всякое его вычисление есть деривация идентификатора.
//
// # Распознаватель знает ВСЕ формы импорта by construction
//
// Он читает ПУТЬ импорта из разобранного дерева, а не имя пакета в тексте,
// поэтому псевдоним (`md5b "crypto/md5"`), точечный (`. "crypto/md5"`) и
// пустой (`_ "crypto/md5"`) импорты опознаются одинаково. Упоминание пути в
// комментарии или в строковом литерале импортом НЕ является — разбор судит
// узел, а не подстроку.
//
// # Чего разбор НЕ видит — названо, а не спрятано
//
//  1. **своя реализация MD5 руками** — развёрнутый алгоритм без импорта. Это
//     другой класс, и ловит его обзор, а не этот гейт;
//  2. **вычисление на стороне базы** — `md5()` в тексте миграции. Это ВТОРАЯ
//     сторона равенства, а не вторая копия Go-функции, и этот гейт её не судит.
package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
)

// DerivedIDImportSite — координата импорта, вычисляющего MD5.
type DerivedIDImportSite struct {
	File string
	Line int
	// Form — форма импорта: `plain` · `alias` · `dot` · `blank`. Печатается
	// переписью, чтобы «ноль находок» было отличимо от «форму не узнали».
	Form string
}

// DerivedIDCensus — объём осмотренного одним файлом.
type DerivedIDCensus struct {
	// Imports — объявлений импорта прочитано.
	Imports int
}

// DerivedIDPackage — путь импорта, вычисляющий дайджест.
const DerivedIDPackage = "crypto/md5"

// ScanDerivedIDDeclarations разбирает один файл и возвращает импорты
// `crypto/md5` вместе с объёмом осмотренного.
func ScanDerivedIDDeclarations(path string, src []byte) (sites []DerivedIDImportSite, census DerivedIDCensus, err error) {
	fset := token.NewFileSet()
	f, perr := parser.ParseFile(fset, path, src, parser.ImportsOnly)
	if perr != nil {
		return nil, DerivedIDCensus{}, perr
	}
	for _, spec := range f.Imports {
		census.Imports++
		p, uerr := strconv.Unquote(spec.Path.Value)
		if uerr != nil || p != DerivedIDPackage {
			continue
		}
		sites = append(sites, DerivedIDImportSite{
			File: path,
			Line: fset.Position(spec.Pos()).Line,
			Form: derivedIDImportForm(spec),
		})
	}
	return sites, census, nil
}

// derivedIDImportForm — форма импорта. Различаются не ради красоты: пустой
// импорт (`_`) ничего не вычисляет, и перепись обязана это показывать, иначе
// находка «второе объявление» будет неотличима от находки «побочный эффект
// пакета».
func derivedIDImportForm(spec *ast.ImportSpec) string {
	switch {
	case spec.Name == nil:
		return "plain"
	case spec.Name.Name == ".":
		return "dot"
	case spec.Name.Name == "_":
		return "blank"
	default:
		return "alias"
	}
}
