// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// published_key_private_half.go — разбор пары «хранимая форма ключа → публикуемая
// форма» (приёмка F1, сценарий F1-05).
//
// Предмет разбора: тип, которым подписной ключ ПУБЛИКУЕТСЯ, не имеет поля для
// приватной половины. Не «мы его не заполняем» — не имеет вовсе: форма «поле
// есть, но мы аккуратны» держится вниманием, отдельный тип держится
// компилятором.
//
// # Как пара находится — БЕЗ словаря имён
//
// Проекция опознаётся по СИНТАКСИСУ, а не по имени метода: метод со значимым
// приёмником именованного структурного типа, без параметров, возвращающий ровно
// один именованный структурный тип того же файла. Плюс условие, которое и делает
// разбор разбором про КЛЮЧИ, а не про любое приведение DTO: приёмник обязан
// нести поле, называющее приватный материал.
//
// Отсюда положительный близнец получается САМ, а не приписывается списком:
// найденная проекция — это и есть место, которое разбор ОБЯЗАН находить. Разбор,
// чей предмет — отсутствие, молчит одинаково и когда предмет исчез, и когда
// сломался он сам; здесь «сломался сам» наблюдаемо, потому что вместе с
// предметом пропадает и найденная пара.
//
// # Что считается «называет приватный материал»
//
// Имя поля разбирается на слова по границам регистра, и слово сверяется с
// закрытым словарём (private, priv, secret, wrapped, seed). Разбор по ПОДСТРОКЕ
// дал бы ложное срабатывание на законном соседе, а разбор по словам различает
// PrivateKeyWrapped и PublicKeyPEM без единого исключения.
//
// Тип поля сверяется отдельно: значение бывает названо нейтрально и при этом
// БЫТЬ приватным ключом (crypto.Signer, ed25519.PrivateKey).
//
// # Чего разбор НЕ видит — названо, а не спрятано
//
// Приватная половина, спрятанная в поле интерфейсного типа, за указателем на
// неэкспортируемый тип другого файла или в карте байтовых значений, разбору не
// видна: это потребовало бы разрешения типов, чего он не делает. Радиус
// ограничен намеренно и назван здесь, чтобы следующий читатель не принял
// молчание за доказательство.//
// # Откуда разбор пришёл
//
// Перенесён из корпуса монорепо (`internal/repohygiene/publishedkeyprivatehalf.go`),
// снятого вместе с выносом службы (kacho#2597). Предмет — пара форм подписного
// ключа — живёт целиком здесь: `internal/domain/signing_key.go`,
// `SigningKeyRecord.Published() PublishedKey`. Разбор перенесён БЕЗ изменения
// предиката: он не разрешает типы и обходится одним файлом, поэтому дерева
// платформы ему не требуется ни в одной посадке.

package check

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strings"
	"unicode"
)

// KeyField — одно поле разбираемого типа.
type KeyField struct {
	Name string // имя поля; пустое у встроенного
	Type string // текст типа, как он написан
	Line int
}

// KeyProjection — найденная пара форм ключа.
//
// StoredType — та, что несёт приватную половину (положительный близнец);
// PublishedType — та, в которую она проецируется. PrivateInPublished непусто
// ровно тогда, когда публикуемая форма приватный материал всё-таки несёт, — это
// и есть находка.
type KeyProjection struct {
	File               string
	Line               int
	Method             string
	StoredType         string
	PublishedType      string
	StoredPrivate      []KeyField // почему приёмник опознан хранимой формой
	PrivateInPublished []KeyField // НАХОДКА: приватное в публикуемой форме
	SameType           bool       // НАХОДКА: публикуемая форма не отделена от хранимой
	FieldsInspected    int
}

// KeyTypeCensus — объём осмотренного одним файлом.
type KeyTypeCensus struct {
	TypesInspected  int
	FieldsInspected int
}

// keyPrivateWords — закрытый словарь слов, называющих приватный материал.
//
// Словарь, а не регулярка: перечень обязан быть читаемым и опровергаемым.
// Сокращённая форма priv оставлена отдельно от private намеренно — она
// встречается в коде вокруг ключей (privPEM, privDER), а разбор по словам не
// спутает её с Privileged, потому что сверяет слово целиком.
var keyPrivateWords = map[string]bool{
	"private": true,
	"priv":    true,
	"secret":  true,
	"wrapped": true,
	"seed":    true,
}

// keyPrivateTypes — тексты типов, которые ЕСТЬ приватный ключ независимо от
// того, как названо поле. Имя поля бывает нейтральным, значение — нет.
var keyPrivateTypes = []string{
	"PrivateKey",
	"crypto.Signer",
	"crypto.Decrypter",
}

// ScanKeyProjections разбирает один файл и возвращает найденные пары форм ключа
// вместе с объёмом осмотренного.
//
// Перепись возвращается ВСЕГДА, включая случай «пар не найдено»: без неё «ноль
// находок» неотличимо от «ноль прочитанного».
func ScanKeyProjections(path string, src []byte) ([]KeyProjection, KeyTypeCensus, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, KeyTypeCensus{}, err
	}

	var census KeyTypeCensus
	structs := map[string][]KeyField{}
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return true
		}
		census.TypesInspected++
		fields := make([]KeyField, 0, len(st.Fields.List))
		for _, fld := range st.Fields.List {
			typeText := keyExprText(fld.Type)
			if len(fld.Names) == 0 { // встроенное поле
				census.FieldsInspected++
				fields = append(fields, KeyField{Type: typeText, Line: fset.Position(fld.Pos()).Line})
				continue
			}
			for _, nm := range fld.Names {
				census.FieldsInspected++
				fields = append(fields, KeyField{
					Name: nm.Name, Type: typeText, Line: fset.Position(nm.Pos()).Line,
				})
			}
		}
		structs[ts.Name.Name] = fields
		return true
	})

	var out []KeyProjection
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || len(fn.Recv.List) != 1 {
			continue
		}
		// Приёмник — ЗНАЧИМЫЙ именованный тип этого файла. Указательный
		// приёмник сюда не попадает: проекция, меняющая приёмник, проекцией не
		// является, и разбор о ней ничего не утверждает.
		recvName, ok := keyIdentName(fn.Recv.List[0].Type)
		if !ok {
			continue
		}
		stored, ok := structs[recvName]
		if !ok {
			continue
		}
		if fn.Type.Params != nil && len(fn.Type.Params.List) != 0 {
			continue
		}
		if fn.Type.Results == nil || len(fn.Type.Results.List) != 1 {
			continue
		}
		resName, ok := keyIdentName(fn.Type.Results.List[0].Type)
		if !ok {
			continue
		}
		published, ok := structs[resName]
		if !ok {
			continue
		}
		// Условие, делающее разбор разбором ПРО КЛЮЧИ: хранимая форма несёт
		// приватный материал. Без него сюда попало бы любое приведение DTO.
		storedPrivate := keyPrivateFields(stored)
		if len(storedPrivate) == 0 {
			continue
		}
		out = append(out, KeyProjection{
			File:               path,
			Line:               fset.Position(fn.Pos()).Line,
			Method:             fn.Name.Name,
			StoredType:         recvName,
			PublishedType:      resName,
			StoredPrivate:      storedPrivate,
			PrivateInPublished: keyPrivateFields(published),
			SameType:           recvName == resName,
			FieldsInspected:    len(stored) + len(published),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out, census, nil
}

// keyPrivateFields — поля, называющие приватный материал именем либо типом.
func keyPrivateFields(fields []KeyField) []KeyField {
	var out []KeyField
	for _, f := range fields {
		if keyFieldNamesPrivate(f) {
			out = append(out, f)
		}
	}
	return out
}

// keyFieldNamesPrivate — предикат «поле называет приватный материал».
func keyFieldNamesPrivate(f KeyField) bool {
	for _, w := range keySplitWords(f.Name) {
		if keyPrivateWords[w] {
			return true
		}
	}
	for _, t := range keyPrivateTypes {
		if strings.Contains(f.Type, t) {
			return true
		}
	}
	return false
}

// keySplitWords разбивает имя на слова по границам регистра и разделителям.
//
// Разбор ПО СЛОВАМ, а не по подстроке: PublicKeyPEM даёт [public key pem], и ни
// одно слово словарю не принадлежит; PrivateKeyWrapped даёт
// [private key wrapped] — принадлежат два. Подстрочный разбор не различил бы эти
// два случая ничем.
func keySplitWords(name string) []string {
	var words []string
	var cur []rune
	flush := func() {
		if len(cur) > 0 {
			words = append(words, strings.ToLower(string(cur)))
			cur = nil
		}
	}
	runes := []rune(name)
	for i, r := range runes {
		switch {
		case r == '_' || r == '-' || r == '.':
			flush()
		case unicode.IsUpper(r):
			// Граница слова — только если предыдущий символ строчный либо
			// следующий строчный: иначе аббревиатура PEM распалась бы на три.
			if i > 0 && (unicode.IsLower(runes[i-1]) ||
				(i+1 < len(runes) && unicode.IsLower(runes[i+1]))) {
				flush()
			}
			cur = append(cur, r)
		default:
			cur = append(cur, r)
		}
	}
	flush()
	return words
}

// keyIdentName — имя типа для голого идентификатора; для всего прочего
// (указатель, обобщение, чужой пакет) — отказ: разбор не разрешает типы и об
// этом честно молчит.
func keyIdentName(e ast.Expr) (string, bool) {
	id, ok := e.(*ast.Ident)
	if !ok {
		return "", false
	}
	return id.Name, true
}

// keyExprText — текст выражения типа, как он написан в исходнике.
func keyExprText(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return keyExprText(v.X) + "." + v.Sel.Name
	case *ast.StarExpr:
		return "*" + keyExprText(v.X)
	case *ast.ArrayType:
		return "[]" + keyExprText(v.Elt)
	case *ast.MapType:
		return "map[" + keyExprText(v.Key) + "]" + keyExprText(v.Value)
	case *ast.InterfaceType:
		return "interface{}"
	default:
		return ""
	}
}
