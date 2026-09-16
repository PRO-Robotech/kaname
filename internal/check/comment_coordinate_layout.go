// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// comment_coordinate_layout.go — разбор комментария на ОДИН факт: называет ли он
// координату приставкой ЧУЖОЙ раскладки, когда та же координата лежит здесь.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Служба жила каталогом `services/iam/` внутри дерева платформы и переехала в
// свой репозиторий. Код переезд пережил — координаты в комментариях нет:
// шестьдесят с лишним мест продолжали называть файл приставкой, которой в этом
// дереве не существует.
//
// Читателя это отправляет в никуда, а замер делает недействительным: предикат,
// списанный из комментария, печатает пусто — и пусто читается как «находок нет»,
// а не как «искали не там».
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СЧИТАЕТСЯ НАХОДКОЙ — И ПОЧЕМУ НЕ ВСЯКОЕ УПОМИНАНИЕ ПРИСТАВКИ
//
// Находка — координата `<приставка>/<хвост>`, У КОТОРОЙ ХВОСТ РЕЗОЛВИТСЯ В ЭТОМ
// ДЕРЕВЕ. Это и есть «тот же файл, названный чужим адресом».
//
// Не находка, и всё это законно:
//
//	приставка БЕЗ хвоста — `git grep … -- services/iam`, `приставки services/iam/
//	                       в самостоятельном клоне нет`: проза О ПЕРЕЕЗДЕ и
//	                       указатель области в ЧУЖОМ дереве;
//	хвост с многоточием  — `services/iam/internal/…`: это не координата, а форма
//	                       записи класса путей;
//	хвост, не резолвящийся — назван файл, которого здесь нет: он либо чужой, либо
//	                       снят, и это ДРУГОЙ предмет (у него нет «того же файла
//	                       рядом», ради которого гейт и заведён).
//
// Сужение до резолвящегося хвоста не осторожность, а точность: без него гейт
// краснел бы на каждом объяснении собственного предмета — тот самый класс,
// который корпус ловит (`testing.md` §«Гейт на класс», п. 4).
//
// ─────────────────────────────────────────────────────────────────────────────
// РАЗБОР СУДИТ УЗЕЛ КОММЕНТАРИЯ, А НЕ СТРОКУ ФАЙЛА
//
// Строковый литерал с приставкой — ЗАКОННАЯ и действующая форма: `treeposture`
// резолвит координату платформы в обеих посадках by construction, и именно ею
// пользуются пробы объёма, отпечатки и обходчики. Гейт, судивший бы строки,
// потребовал бы снять работающий механизм.
package check

import (
	"go/parser"
	"go/token"
	"regexp"
	"strings"
)

// PlatformLayoutPrefix — приставка чужой раскладки, которую переезд оставил.
const PlatformLayoutPrefix = "services/iam"

// CommentCoordinate — координата, названная комментарием.
type CommentCoordinate struct {
	File string
	Line int
	// Text — координата целиком, как она записана.
	Text string
	// Tail — остаток после приставки.
	Tail string
}

// CommentCoordinateCensus — объём осмотренного одним файлом.
type CommentCoordinateCensus struct {
	// Comments — групп комментария прочитано.
	Comments int
	// Mentions — упоминаний приставки в них.
	Mentions int
	// WithTail — из них с непустым хвостом.
	WithTail int
}

var layoutCoordRe = regexp.MustCompile(regexp.QuoteMeta(PlatformLayoutPrefix) + `(/[A-Za-z0-9_./*-]+)?`)

// ScanCommentCoordinates разбирает один файл и возвращает координаты приставки,
// названные В КОММЕНТАРИЯХ, вместе с объёмом осмотренного. Отбор находок здесь
// НЕ делается: резолюция хвоста — свойство дерева, и её знает вызывающий.
func ScanCommentCoordinates(path string, src []byte) (out []CommentCoordinate, census CommentCoordinateCensus, err error) {
	fset := token.NewFileSet()
	f, perr := parser.ParseFile(fset, path, src, parser.ParseComments)
	if perr != nil {
		return nil, CommentCoordinateCensus{}, perr
	}
	for _, grp := range f.Comments {
		census.Comments++
		for _, c := range grp.List {
			for _, m := range layoutCoordRe.FindAllString(c.Text, -1) {
				census.Mentions++
				tail := strings.TrimPrefix(m, PlatformLayoutPrefix)
				tail = strings.TrimPrefix(tail, "/")
				tail = strings.TrimRight(tail, ".")
				if tail == "" {
					continue
				}
				census.WithTail++
				out = append(out, CommentCoordinate{
					File: path, Line: fset.Position(c.Pos()).Line, Text: m, Tail: tail,
				})
			}
		}
	}
	return out, census, nil
}
