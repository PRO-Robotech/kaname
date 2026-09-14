// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// guard_named_in_comment.go — разбор одного файла на ДВА РАЗНЫХ факта о защите:
// названа ли она КОММЕНТАРИЕМ и вызвана ли ВЫРАЖЕНИЕМ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Комментарий, противоречащий коду, — не косметика. В обычном случае следующий
// читатель «чинит» код под неверный комментарий. Здесь хуже: комментарий уже
// ОТВЕТИЛ на вопрос «закрыт ли этот сегмент защитой», поэтому читатель не идёт
// проверять, и пробел остаётся незамеченным ИМЕННО ПОТОМУ, что о нём написано.
//
// Класс наблюдался дважды и в двух разных видах. В монорепо: файл в пакете ролей
// утверждал, что сегмент глагола закрывается словарём домена, тогда как во всём
// пакете это имя встречалось РОВНО ОДИН раз — в самом этом комментарии. При
// выносе службы (kacho#2597): прод-код и приёмки службы продолжили называть
// держателями гейты монорепо, снятые вместе с каталогом, — то есть комментарий
// называл защиту, которой не существует ни в одном репозитории.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ УЗЕЛ РАЗБОРА, А НЕ ПОДСТРОКА
//
// Поиск по подстроке нашёл бы имя в комментарии, который эту же защиту
// ОБЪЯСНЯЕТ, и счёл бы её присутствующей — то есть гейт зеленел бы на
// собственном объяснении. Поэтому два факта читаются РАЗНЫМИ средствами:
//
//	упоминание — ТОЛЬКО из узла комментария (ast.CommentGroup);
//	наличие    — ТОЛЬКО из узла-идентификатора выражения (ast.Ident) и ТОЛЬКО
//	             из прод-кода: вызов защиты внутри пробы её в прод-коде не создаёт.
//
// Строковый литерал, несущий то же имя, наличием НЕ является: он узел
// ast.BasicLit, а не ast.Ident, и разбор его не засчитывает by construction.
//
// ─────────────────────────────────────────────────────────────────────────────
// ФОРМЫ ЗАПИСИ — ПЕРЕЧИСЛЕНЫ, А НЕ ПОДРАЗУМЕВАЮТСЯ
//
// Форма, о которой распознаватель не знает, даёт не красное и не зелёное, а
// МОЛЧАНИЕ. Поэтому обе стороны перечислены поимённо, и по каждой стоит
// утверждение инъекции.
//
// Формы показаны на ВЫМЫШЛЕННОМ имени GuardedCall, а не на записи
// действующего реестра, и это не стиль: godoc — тоже комментарий, и пример на
// живом имени сделал бы ЭТОТ ФАЙЛ находкой собственного гейта. Класс поймал
// себя сам при первом же прогоне после индексации (kacho#2597).
//
// Упоминание в комментарии — четыре формы:
//
//	bare       GuardedCall              — имя прозой
//	qualified  domain.GuardedCall       — имя с квалификатором пакета
//	call       GuardedCall()            — имя со скобками
//	backtick   `GuardedCall`            — имя в обратных кавычках
//
// Наличие в выражении — четыре формы, и все четыре суть узел ast.Ident:
//
//	GuardedCall(v, t)          прямой вызов
//	domain.GuardedCall(v, t)   вызов с квалификатором (Sel — тот же ast.Ident)
//	f := GuardedCall           значение функции
//	f := domain.GuardedCall    значение с квалификатором
//
// ─────────────────────────────────────────────────────────────────────────────
// ГРАНИЦА ИМЕНИ — НЕСУЩАЯ
//
// Совпадение считается по ГРАНИЦЕ идентификатора, а не по вхождению подстроки:
// иначе `GuardedCallStrict` засчитывался бы упоминанием `GuardedCall`, и
// находка приходила бы на имя, которого комментарий не называл.
package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
)

// GuardMentionForm — форма, в которой комментарий назвал защиту.
type GuardMentionForm string

// Формы упоминания. Печатаются переписью, чтобы «ноль находок» было отличимо
// от «форму не узнали».
const (
	GuardMentionBare      GuardMentionForm = "bare"
	GuardMentionQualified GuardMentionForm = "qualified"
	GuardMentionCall      GuardMentionForm = "call"
	GuardMentionBacktick  GuardMentionForm = "backtick"
)

// GuardMention — координата упоминания защиты в комментарии.
type GuardMention struct {
	Name string
	File string
	Line int
	Form GuardMentionForm
}

// GuardFileCensus — объём осмотренного одним файлом.
type GuardFileCensus struct {
	// Comments — узлов-комментариев прочитано.
	Comments int
	// Idents — узлов-идентификаторов прочитано.
	Idents int
}

// GuardFileScan — исход разбора одного файла.
type GuardFileScan struct {
	// Mentions — упоминания из комментариев.
	Mentions []GuardMention
	// Uses — имена, вызванные выражением прод-кода.
	Uses map[string]bool
	// Census — объём осмотренного.
	Census GuardFileCensus
}

// ScanGuardNaming разбирает один файл и возвращает упоминания защит в
// комментариях и их наличие в выражениях прод-кода.
//
// isTest несущий: наличие засчитывается ТОЛЬКО из прод-кода, потому что вызов
// защиты внутри пробы не делает её действующей в прод-пути. Упоминание при
// этом читается и из пробы — комментарий пробы, называющий защиту действующей,
// вводит читателя в то же заблуждение.
func ScanGuardNaming(path string, src []byte, isTest bool, names []string) (GuardFileScan, error) {
	out := GuardFileScan{Uses: map[string]bool{}}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		// Неразобранный файл НЕ трактуется как «упоминаний нет»: это третья
		// категория, и вызывающий обязан её увидеть.
		return GuardFileScan{}, err
	}

	// (а) наличие — только из выражения и только из прод-кода.
	ast.Inspect(f, func(n ast.Node) bool {
		id, ok := n.(*ast.Ident)
		if !ok {
			return true
		}
		out.Census.Idents++
		if isTest {
			return true
		}
		for _, name := range names {
			if id.Name == name {
				out.Uses[name] = true
			}
		}
		return true
	})

	// (б) упоминание — только из комментария.
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			out.Census.Comments++
			for _, name := range names {
				form, found := guardMentionForm(c.Text, name)
				if !found {
					continue
				}
				out.Mentions = append(out.Mentions, GuardMention{
					Name: name,
					File: path,
					Line: fset.Position(c.Pos()).Line,
					Form: form,
				})
			}
		}
	}
	return out, nil
}

// guardMentionForm ищет имя в тексте комментария ПО ГРАНИЦЕ идентификатора и
// называет форму записи.
//
// Возвращается форма ПЕРВОГО совпадения: предмет утверждения — «эта защита
// названа здесь», а не «сколькими способами». Перечень форм нужен, чтобы ни
// одна не выпала из наблюдения молча; кратность одной формы ничего не решает.
func guardMentionForm(text, name string) (GuardMentionForm, bool) {
	for i := 0; ; {
		j := strings.Index(text[i:], name)
		if j < 0 {
			return "", false
		}
		at := i + j
		end := at + len(name)
		if guardIsIdentByte(text, at-1) || guardIsIdentByte(text, end) {
			// Часть более длинного идентификатора: `GuardedCallStrict` —
			// не упоминание `GuardedCall`.
			i = at + 1
			continue
		}
		return guardFormAround(text, at, end), true
	}
}

// guardFormAround — форма по соседним знакам.
func guardFormAround(text string, at, end int) GuardMentionForm {
	before := byte(0)
	if at > 0 {
		before = text[at-1]
	}
	after := byte(0)
	if end < len(text) {
		after = text[end]
	}
	switch {
	case before == '`' || after == '`':
		return GuardMentionBacktick
	case before == '.':
		return GuardMentionQualified
	case after == '(':
		return GuardMentionCall
	default:
		return GuardMentionBare
	}
}

// guardIsIdentByte — знак принадлежит идентификатору Go.
func guardIsIdentByte(text string, i int) bool {
	if i < 0 || i >= len(text) {
		return false
	}
	c := text[i]
	return c == '_' ||
		(c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'z') ||
		(c >= 'A' && c <= 'Z')
}
