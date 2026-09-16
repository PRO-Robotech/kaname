// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// proto_comment_names_a_real_message.go — разбор комментариев контракта на ОДИН
// факт: существует ли сообщение, которое комментарий называет координатой.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Комментарий контракта читает КЛИЕНТ, и он не всегда может открыть дерево.
// Названная в обратных кавычках координата `Message.field` есть обещание поля:
// клиент идёт за ним в стабы, не находит и решает, что отстала его версия.
//
// Обещание переживает свой предмет МОЛЧА. Ни `buf lint`, ни `buf breaking`, ни
// генерация комментариев не читают: они судят объявления. Наблюдалось на
// привязке — комментарий обещал `Tuple.condition` при том, что сообщения `Tuple`
// в контрактах не было ни одного, а условия на кортеже своей формы на проводе не
// имеют вовсе (kaname#132).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СЧИТАЕТСЯ ССЫЛКОЙ — ФОРМА НАЗВАНА, А НЕ ПОДРАЗУМЕВАЕТСЯ
//
// Ссылкой считается токен В ОБРАТНЫХ КАВЫЧКАХ, несущий точку, у которого есть
// сегмент с заглавной первой буквой, а следом — сегмент со строчной:
//
//	`AccessBinding.scope_type`                     — короткая форма
//	`kaname.cloud.iam.v1.AccessBinding.scope_type` — полная форма
//	`AuthorizeService.CheckRequest.context`        — через службу
//
// Тип — ПОСЛЕДНИЙ сегмент с заглавной буквы: у полной формы перед ним стоит имя
// пакета, у формы через службу — имя службы, и оба сообщением не являются.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО РАЗБОР НЕ ВИДИТ — НАЗВАНО, А НЕ СПРЯТАНО
//
//  1. **ссылка без обратных кавычек**. Проза контракта называет типы и по-русски,
//     и мимоходом; принимать за координату всякое слово с заглавной значило бы
//     краснеть на собственном объяснении;
//  2. **существование ПОЛЯ** внутри названного сообщения. Гейт судит тип: поле
//     требует разбора тела сообщения вместе с вложенными и наследуемыми, а цена
//     этого не окупается — `Tuple` не существовал целиком, и это тот случай,
//     который встречается;
//  3. **чужие контракты вне дерева**. Набор известных типов строится по ВСЕМ
//     `*.proto` дерева, включая копии фундамента, — координата в контракт,
//     которого рядом нет, будет находкой, и это верно: клиент этого дерева его
//     тоже не откроет.
package check

import (
	"regexp"
	"strings"
)

// ProtoCommentRef — координата ссылки, названной комментарием контракта.
type ProtoCommentRef struct {
	File string
	Line int
	// Type — сообщение, которое ссылка называет.
	Type string
	// Text — токен целиком, как он записан.
	Text string
}

// ProtoCommentCensus — объём осмотренного одним файлом.
type ProtoCommentCensus struct {
	// Lines — строк прочитано.
	Lines int
	// Comments — из них строк комментария.
	Comments int
	// Refs — из них ссылок формы `Message.field`.
	Refs int
	// Decls — объявлений message/enum прочитано.
	Decls int
}

var (
	protoTickedRe = regexp.MustCompile("`([A-Za-z_][A-Za-z0-9_.]*\\.[A-Za-z_][A-Za-z0-9_]*)`")
	protoDeclRe   = regexp.MustCompile(`^\s*(?:message|enum)\s+([A-Za-z_][A-Za-z0-9_]*)`)
)

// ProtoTypeDecls — имена message и enum, объявленные одним файлом контракта.
func ProtoTypeDecls(src []byte) []string {
	var out []string
	for _, ln := range strings.Split(string(src), "\n") {
		if m := protoDeclRe.FindStringSubmatch(ln); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

// ScanProtoCommentRefs разбирает один файл контракта и возвращает ссылки
// комментариев вместе с объёмом осмотренного. Находки не отбираются здесь:
// отбор делает вызывающий, и тот же предикат зовёт инъекция.
func ScanProtoCommentRefs(path string, src []byte) (refs []ProtoCommentRef, census ProtoCommentCensus) {
	for i, ln := range strings.Split(string(src), "\n") {
		census.Lines++
		if protoDeclRe.MatchString(ln) {
			census.Decls++
		}
		t := strings.TrimSpace(ln)
		if !strings.HasPrefix(t, "//") {
			continue
		}
		census.Comments++
		for _, m := range protoTickedRe.FindAllStringSubmatch(t, -1) {
			typ, ok := protoRefType(m[1])
			if !ok {
				continue
			}
			census.Refs++
			refs = append(refs, ProtoCommentRef{File: path, Line: i + 1, Type: typ, Text: m[1]})
		}
	}
	return refs, census
}

// protoRefType — тип, который называет ссылка: ПОСЛЕДНИЙ сегмент с заглавной
// буквы, за которым идёт сегмент со строчной. Перед ним стоит имя пакета либо
// службы, и сообщением ни то, ни другое не является.
func protoRefType(tok string) (string, bool) {
	seg := strings.Split(tok, ".")
	for i := len(seg) - 2; i >= 0; i-- {
		c := seg[i][0]
		if c >= 'A' && c <= 'Z' {
			// Следом обязан идти сегмент со строчной: `Foo.Bar` — это вложенное
			// сообщение, а не поле, и обещания поля в нём нет.
			n := seg[i+1][0]
			if n >= 'a' && n <= 'z' || n == '_' {
				return seg[i], true
			}
			return "", false
		}
	}
	return "", false
}
