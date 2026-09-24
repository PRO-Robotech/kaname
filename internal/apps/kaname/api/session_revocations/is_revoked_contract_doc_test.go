// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_revocations

// is_revoked_contract_doc_test.go — текст КОНТРАКТА `IsRevoked` называет каждый
// источник, по которому судит ответ, и не называет того, по которому не судит.
//
// # Предмет (kaname#319)
//
// Ответ `IsRevoked` расширился: признак покрывает запись отзыва по
// идентификатору ЛИБО отзыв семейства, которому выпуск принадлежит. Контракт
// при этом сначала остался прежним — признак описывался только строкой в
// `session_revocations`, источниками отзыва назывались только выход и
// принудительный выход. Интегратор, читающий контракт, ждал бы
// `revoked_at`/`reason` у каждого отозванного — а у отзыва семейства их нет.
//
// # Класс, а не экземпляр
//
// Ответ судит источники, контракт их перечисляет — два места об одном предмете.
// Гейт сверяет их в ОБЕ стороны: источник, по которому ответ судит, а контракт
// молчит, — находка; источник, который контракт называет, а ответ не судит, —
// тоже. Вторая сторона ловит обратный дрейф: судить семейство перестали, а
// контракт обещает.
//
// # Что читается и почему так
//
//   - Источники ответа — разбором тела метода `IsRevoked` хендлера: узлы вызова
//     `IsRevoked` (запись по идентификатору) и `FamilyRevoked` (семейство). Не
//     поиском по тексту: упоминание в комментарии источником не является.
//   - Тексты контракта — комментарии ПОРОЖДЁННЫХ заглушек, привязанные к узлу:
//     шапка клиентского интерфейса службы, метод `IsRevoked` в нём, поля
//     `IsRevokedResponse`. Заглушки порождаются из `.proto` и сверяются с ним
//     целью `proto-gen-diff`, поэтому их текст — текст контракта; разбирать
//     `.proto` здесь нечем, а Go-разбор привязывает текст к узлу, а не к строке.
//
// # Граница
//
// Маркер источника — слово в прозе. Гейт отличает «назван» от «не назван», но
// не отличает «назван верно» от «назван в отрицании». Верность формулировки
// держит ревью; гейт держит то, что отставание контракта от ответа не пройдёт
// молча.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// Источники ответа `IsRevoked`.
const (
	sourceRecord = "record" // запись отзыва по идентификатору
	sourceFamily = "family" // отзыв семейства выпуска
)

// sourceCallee — имя вызываемого метода, по которому источник опознаётся в теле
// хендлера.
var sourceCallee = map[string]string{
	sourceRecord: "IsRevoked",
	sourceFamily: "FamilyRevoked",
}

// sourceMarker — как источник назван в прозе контракта.
var sourceMarker = map[string]*regexp.Regexp{
	sourceRecord: regexp.MustCompile(`\bsession_revocations\b`),
	sourceFamily: regexp.MustCompile(`(?i)\bfamil(y|ies)\b`),
}

// Тексты контракта, которые судит гейт.
const (
	textService   = "service InternalSessionRevocationsService"
	textRPC       = "rpc IsRevoked"
	textRevoked   = "IsRevokedResponse.revoked"
	textRevokedAt = "IsRevokedResponse.revoked_at"
	textReason    = "IsRevokedResponse.reason"
)

// contractClaims — какой текст обязан называть какой источник. Сверка в обе
// стороны по каждой паре.
//
// Запись по идентификатору судится только у метода и признака: шапка службы
// называет таблицу и как предмет записи `Revoke`, то есть её упоминание там не
// утверждение об ответе. Семейство судится везде: шапка перечисляет источники
// отзыва, а `revoked_at`/`reason` обязаны сказать, что у отзыва семейства они
// пусты.
var contractClaims = map[string][]string{
	textService:   {sourceFamily},
	textRPC:       {sourceRecord, sourceFamily},
	textRevoked:   {sourceRecord, sourceFamily},
	textRevokedAt: {sourceFamily},
	textReason:    {sourceFamily},
}

// isRevokedContractFacts — вход предиката; собран так, чтобы предикат гонялся
// инъекцией без правки дерева.
type isRevokedContractFacts struct {
	// Judged — источники, по которым судит ответ (разбор тела хендлера).
	Judged map[string]bool
	// Texts — имя текста контракта → его проза.
	Texts map[string]string
}

// auditIsRevokedContract — находки; пусто = контракт и ответ согласны.
func auditIsRevokedContract(f isRevokedContractFacts) []string {
	var found []string
	names := make([]string, 0, len(contractClaims))
	for name := range contractClaims {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		text := f.Texts[name]
		for _, src := range contractClaims[name] {
			named := sourceMarker[src].MatchString(text)
			switch {
			case f.Judged[src] && !named:
				found = append(found, name+": ответ судит источник «"+src+
					"», а контракт его не называет")
			case !f.Judged[src] && named:
				found = append(found, name+": контракт называет источник «"+src+
					"», а ответ по нему не судит")
			}
		}
	}
	return found
}

// judgedSources — источники, по которым судит тело метода `IsRevoked` с
// получателем, разбором исходника.
func judgedSources(t *testing.T, filename string, src any) (map[string]bool, bool) {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, 0)
	require.NoErrorf(t, err, "разбор %s", filename)
	judged := map[string]bool{}
	seen := false
	for _, d := range f.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Recv == nil || fn.Name.Name != "IsRevoked" || fn.Body == nil {
			continue
		}
		seen = true
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			for s, callee := range sourceCallee {
				if sel.Sel.Name == callee {
					judged[s] = true
				}
			}
			return true
		})
	}
	return judged, seen
}

// contractTexts — тексты контракта из порождённых заглушек, по узлам.
func contractTexts(t *testing.T, sources map[string]any) map[string]string {
	t.Helper()
	out := map[string]string{}
	fset := token.NewFileSet()
	names := make([]string, 0, len(sources))
	for name := range sources {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, filename := range names {
		f, err := parser.ParseFile(fset, filename, sources[filename], parser.ParseComments)
		require.NoErrorf(t, err, "разбор %s", filename)
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				ts := spec.(*ast.TypeSpec)
				switch ts.Name.Name {
				case "InternalSessionRevocationsServiceClient":
					out[textService] = gd.Doc.Text()
					if it, ok := ts.Type.(*ast.InterfaceType); ok {
						for _, m := range it.Methods.List {
							if len(m.Names) == 1 && m.Names[0].Name == "IsRevoked" {
								out[textRPC] = m.Doc.Text()
							}
						}
					}
				case "IsRevokedResponse":
					st, ok := ts.Type.(*ast.StructType)
					if !ok {
						continue
					}
					for _, fld := range st.Fields.List {
						if len(fld.Names) != 1 {
							continue
						}
						switch fld.Names[0].Name {
						case "Revoked":
							out[textRevoked] = fld.Doc.Text()
						case "RevokedAt":
							out[textRevokedAt] = fld.Doc.Text()
						case "Reason":
							out[textReason] = fld.Doc.Text()
						}
					}
				}
			}
		}
	}
	return out
}

// stubFiles — порождённые заглушки контракта службы, от корня модуля.
var stubFiles = []string{
	"pkg/api/kaname/cloud/iam/v1/session_revocations_service.pb.go",
	"pkg/api/kaname/cloud/iam/v1/session_revocations_service_grpc.pb.go",
}

func treeContractFacts(t *testing.T) isRevokedContractFacts {
	t.Helper()
	root := platformtree.Require(t)
	judged, seen := judgedSources(t, "handler.go", nil)
	require.True(t, seen, "в handler.go не найден метод IsRevoked с получателем — "+
		"предпосылка сломана, судить нечего")
	sources := map[string]any{}
	for _, rel := range stubFiles {
		sources[filepath.Join(root, filepath.FromSlash(rel))] = nil
	}
	return isRevokedContractFacts{Judged: judged, Texts: contractTexts(t, sources)}
}

// TestIsRevokedContractNamesEverySourceTheAnswerJudges — гейт на дереве.
func TestIsRevokedContractNamesEverySourceTheAnswerJudges(t *testing.T) {
	facts := treeContractFacts(t)

	// ПРЕДПОСЫЛКИ: «ноль находок» обязано быть отличимо от «ноль прочитанного».
	require.True(t, facts.Judged[sourceRecord], "разбор тела IsRevoked не нашёл "+
		"вызова записи по идентификатору — перепись меряет не то")
	for name := range contractClaims {
		require.NotEmptyf(t, strings.TrimSpace(facts.Texts[name]),
			"текст контракта %q не прочитан: узел заглушки не найден либо без комментария", name)
	}

	found := auditIsRevokedContract(facts)
	require.Emptyf(t, found, "контракт IsRevoked расходится с ответом:\n  %s\n"+
		"Правится комментарий в proto/kaname/cloud/iam/v1/session_revocations_service.proto "+
		"и перегенерируются заглушки (make proto-gen).", strings.Join(found, "\n  "))

	judged := make([]string, 0, len(facts.Judged))
	for s := range facts.Judged {
		judged = append(judged, s)
	}
	sort.Strings(judged)
	t.Logf("осмотрено: тело IsRevoked (handler.go), источников ответа %d (%s); "+
		"текстов контракта %d, пар «текст — источник» %d",
		len(judged), strings.Join(judged, ", "), len(facts.Texts), claimPairs())
}

func claimPairs() int {
	n := 0
	for _, srcs := range contractClaims {
		n += len(srcs)
	}
	return n
}
