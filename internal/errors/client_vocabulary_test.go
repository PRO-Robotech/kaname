// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package errors_test

// client_vocabulary_test.go — гейт: текст, который читает АРЕНДАТОР, не
// называет внутренних слоёв кода.
//
// ПРЕДМЕТ. Арендатор читает слово, которого нет ни в одном нашем документе, и
// сделать по нему не может ничего. Хуже, когда слово называет СТОРОННЮЮ
// систему: тогда отказ рассказывает об устройстве платформы вместо того, чтобы
// говорить, что делать дальше.
//
// ЧТО СЧИТАЕТСЯ ТЕКСТОМ ДЛЯ АРЕНДАТОРА — определено по ТРАКТУ, а не на глаз:
//
//  1. литерал сообщения в `status.Error/Errorf/New` — такой статус уходит на
//     провод как есть: `shared.MapRepoErr` пропускает готовый статус сквозь
//     себя (ветвь pass-through), то есть схлопывание в фиксированный текст его
//     НЕ касается;
//  2. литерал в `Wrapf(<признак>, …)` для тех признаков, чей текст доезжает
//     до провода (`passThroughSentinels`): `MapRepoErr` либо переводчик своей
//     полосы кладёт в статус `StripSentinel`.
//
// Признаки полос ФИКСИРОВАННОГО текста (`fixedTextSentinels`) в перечень НЕ
// входят: написанное в их обёртке адресовано журналу, и включить их значило бы
// краснеть на строках, которых арендатор не увидит.
//
// ЭТО ПРЕДПОСЫЛКА, И ГЕЙТ ЕЁ ПРОВЕРЯЕТ, а не объявляет. Исключение верно ровно
// пока КАЖДЫЙ переводчик отдаёт на этих полосах фиксированный текст; перестанет —
// и литералы обёрток уедут на провод, выведенные из наблюдения этим же гейтом.
// Прежде предпосылка стояла здесь прозой и разошлась с деревом молча (задачи
// PRO-Robotech/kacho#2464, #2478): гейт был зелён, пока она была ложна. Теперь
// `collectClientTexts` сперва спрашивает разбор `check.ScanFixedRefusalTexts` —
// того же производителя, что у гейта дерева, на том же корпусе, — и отказывает,
// если хоть одна конструкция на этих полосах не доказана фиксированной либо если
// судить было не о чем.
//
// Корпус предпосылки — прод-код МОДУЛЯ, а не только `internal/`: переводчик,
// решающий судьбу текста, вправе жить и в композиционном корне, и корпус более
// узкий, чем процесс, был бы слеп ровно к нему. Переводчики зависимостей
// (фундамент) в корпус не входят by construction — это граница, а не покрытие.
//
// Предпосылка судится по КОДУ статуса, а не по признаку: разбор без типов
// цепочки признака не видит. Связь «признак → код полосы» названа в
// `fixedTextSentinels` и держится инъекцией на каноническом переводчике —
// `TestClientVocabularyPremiseInjection`. ГРАНИЦА, названная явно: в копиях
// переводчика эту связь не держит ничто — копия, отдающая на ветви признака
// недоступности код ЧУЖОЙ полосы, выведет его текст из-под обеих проверок.
//
// Вторая ось той же предпосылки — РАЗБИЕНИЕ: каждый признак, который пакет
// объявляет, отнесён ровно к одному перечню (`sentinelPartition`). Проверка
// кода доказывает, что полосы фиксированы, но не то, что исключены ИМЕННО их
// признаки: признак вне обоих перечней выпадает из наблюдения молча.
//
// ГРАНИЦА, названная явно: адресат различает, а не слово. Тексты внутреннего
// слушателя обращены к МОДУЛЮ и его оператору — они называют механизм
// намеренно. Их пакеты перечислены в `operatorAddressed`, и перечень
// САМОИСТЕКАЕТ: запись, у которой не осталось ни одного попадания, — находка.
//
// Способность падать и молчать доказана инъекцией —
// `TestClientVocabularyGateInjection` (словарь) и
// `TestClientVocabularyPremiseInjection` (предпосылка).

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/gitenv"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// serviceRoot — корень дерева службы относительно этого пакета.
const serviceRoot = "../.."

// passThroughSentinels — признаки, чей текст доезжает до провода дословно:
// сам — через `shared.MapRepoErr` → `status.Error(code, StripSentinel(err))`, —
// либо через переводчик своей полосы, который кладёт в статус тот же
// `StripSentinel`. Критерий один — ДОЕЗЖАЕТ ЛИ текст обёртки, а не каким путём.
//
// Разбиение «каждый объявленный признак — ровно в одном перечне» держит
// `sentinelPartition`: признак вне обоих перечней прежде выпадал отсюда молча —
// так выпадали четыре последние записи ниже, пока проверки не было (задача
// PRO-Robotech/kacho#2478).
var passThroughSentinels = map[string]bool{
	"ErrNotFound":            true,
	"ErrAlreadyExists":       true,
	"ErrPermissionDenied":    true,
	"ErrUnauthenticated":     true,
	"ErrFailedPrecondition":  true,
	"ErrInvalidArg":          true,
	"ErrAborted":             true,
	"ErrQuotaExceeded":       true,
	"ErrQuotaNotProvisioned": true,
	"ErrQuotaRateExceeded":   true,
	"ErrReferenceMissing":    true,
	"ErrReferenceInUse":      true,
	// Снятие права администратора кластера перевёртывает оба признака в
	// предусловие с их же текстом (`cluster/revoke_admin.go`); что текст на
	// проводе, утверждает интеграционная проба той же полосы.
	"ErrSelfRevoke": true,
	"ErrLastAdmin":  true,
	// Полоса «членство несёт права» собирает статус из `StripSentinel(err)`
	// (`shared.membershipRefusal`).
	"ErrMembershipCarriesRights": true,
	// Частный случай неверного аргумента: регистрация ресурса отдаёт его текст
	// отказом по полю (`shared.InvalidArg("object", StripSentinel(err))`), а
	// общая ветвь канонического переводчика — как любой неверный аргумент.
	"ErrUnknownResourceType": true,
	// Срок строки приглашения: текст обёртки («попросите пригласить заново»)
	// доезжает до вызывающего как предусловие — он вложен в
	// `ErrFailedPrecondition`, и канонический переводчик отдаёт его текст.
	// Клиенту он и адресован: без следующего шага отказ оставляет человека
	// перед закрытой дверью без ручки.
	"ErrInviteExpired": true,
}

// fixedTextSentinels — признаки, чей текст на провод НЕ доезжает: их полоса
// отдаёт фиксированный текст. Каждому назван КОД полосы — по коду судит разбор
// `check.ScanFixedRefusalTexts`, и именно пара «признак → код» делает проверку
// кода проверкой признака. Держит её инъекция на каноническом переводчике: для
// каждой записи она находит ветвь признака, сверяет код и требует красного на
// тексте цепочки.
var fixedTextSentinels = map[string]string{
	"ErrInternal":    "Internal",
	"ErrUnavailable": "Unavailable",
}

// premiseOutcome — исход проверки предпосылки. Исходов ТРИ: «не проверена»
// отдельна от «ложна», потому что чинятся они в разных местах — первая в
// распознавателе или корпусе, вторая в переводчике.
type premiseOutcome int

const (
	premiseHolds     premiseOutcome = iota // каждая конструкция на полосах доказана фиксированной
	premiseFalse                           // хоть одна не доказана — исключение признаков не обосновано
	premiseUnchecked                       // судить не о чем — «держится» было бы «не смотрели»
)

// judgePremise — ЧИСТЫЙ судья предпосылки над переписью разбора. Выделен ради
// инъекции: доказывать способность падать на живой находке нельзя — такая проба
// исчезает вместе с находкой, то есть ровно тогда, когда дерево починено.
//
// Возвращает исход и текст отказа; на `premiseHolds` текст пуст.
func judgePremise(census check.RefusalTextCensus, findings []check.RefusalTextFinding) (premiseOutcome, string) {
	lanes := fixedTextLanes()
	switch {
	case census.Files == 0:
		return premiseUnchecked, fmt.Sprintf(
			"предпосылка гейта словаря НЕ ПРОВЕРЕНА: обход не разобрал ни одного файла Go — "+
				"исключение признаков полос %s ничем не обосновано, вердикт словаря беспредметен", lanes)
	case census.Population == 0:
		return premiseUnchecked, fmt.Sprintf(
			"предпосылка гейта словаря НЕ ПРОВЕРЕНА: на полосах %s ноль конструкций при %d "+
				"разобранных файлах и %d конструкциях статуса — распознаватель перестал их узнавать, "+
				"и «предпосылка держится» было бы неотличимо от «не смотрели»",
			lanes, census.Files, census.Constructions)
	case census.Population != census.Fixed:
		var b strings.Builder
		broken := map[string]bool{}
		for _, f := range findings {
			fmt.Fprintf(&b, "\n  %s:%d — codes.%s, текст: %s", f.File, f.Line, f.Code, f.Expr)
			for s, code := range fixedTextSentinels {
				if code == f.Code {
					broken[s] = true
				}
			}
		}
		return premiseFalse, fmt.Sprintf(
			"предпосылка гейта словаря ЛОЖНА: на полосах %s текст не доказан фиксированным — "+
				"конструкций %d из %d:%s\n\n"+
				"Литералы в обёртках признаков %s уезжают на провод, а гейт выводит их из наблюдения. "+
				"Чинится переводчик: текст полосы — у канонического (shared.UnavailableMessage) либо "+
				"свой литерал; гейт дерева TestRefusalTextOnForeignCauseLanesIsFixed называет то же место. "+
				"Если же текст на этой полосе решено доносить — признак переезжает в passThroughSentinels, "+
				"и его обёртки становятся судимы.",
			lanes, census.Population-census.Fixed, census.Population, b.String(),
			strings.Join(sortedKeys(broken), ", "))
	}
	return premiseHolds, ""
}

// fixedTextLanes — коды полос фиксированного текста для текста отказа.
func fixedTextLanes() string {
	codes := make([]string, 0, len(fixedTextSentinels))
	for _, c := range fixedTextSentinels {
		codes = append(codes, c)
	}
	sort.Strings(codes)
	return strings.Join(codes, "/")
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sentinelPartition — ЧИСТЫЙ судья разбиения: каждый объявленный признак
// отнесён РОВНО к одному перечню, и каждая запись перечня называет объявленный
// признак. Запись без признака — находка по той же причине, что послабление без
// предмета: она переживёт свою причину и достанется следующей слепой зоне.
func sentinelPartition(declared []string, pass map[string]bool, fixed map[string]string) (premiseOutcome, []string) {
	if len(declared) == 0 {
		return premiseUnchecked, []string{"признаков объявлено 0 — распознаватель разошёлся с пакетом, " +
			"и «каждый отнесён» было бы неотличимо от «не смотрели»"}
	}
	isDeclared := map[string]bool{}
	var findings []string
	for _, s := range declared {
		isDeclared[s] = true
		_, inFixed := fixed[s]
		switch {
		case pass[s] && inFixed:
			findings = append(findings, "признак "+s+" отнесён к обоим перечням сразу — "+
				"его обёртки одновременно судимы и объявлены невидимыми арендатору")
		case !pass[s] && !inFixed:
			findings = append(findings, "признак "+s+" не отнесён ни к доходящим до провода "+
				"(passThroughSentinels), ни к полосам фиксированного текста (fixedTextSentinels) — "+
				"литералы его обёрток выпадают из наблюдения молча")
		}
	}
	for _, s := range sortedKeys(pass) {
		if !isDeclared[s] {
			findings = append(findings, "запись "+s+" в passThroughSentinels называет признак, "+
				"которого пакет не объявляет — снимите её")
		}
	}
	for _, s := range sortedKeys(fixed) {
		if !isDeclared[s] {
			findings = append(findings, "запись "+s+" в fixedTextSentinels называет признак, "+
				"которого пакет не объявляет — снимите её")
		}
	}
	sort.Strings(findings)
	if len(findings) > 0 {
		return premiseFalse, findings
	}
	return premiseHolds, nil
}

// declaredSentinelsIn — имена признаков, объявленных исходниками пакета:
// экспортируемые переменные ПАКЕТНОГО уровня с приставкой `Err`.
//
// Форма правой части НЕ судится намеренно: пакет объявляет признак тремя
// способами (`stderrors.New`, `fmt.Errorf` поверх соседа, частный случай с
// явным типом), и распознаватель, знающий их по форме, пропустил бы четвёртую
// не нарушением, а невидимостью.
func declaredSentinelsIn(srcs ...[]byte) ([]string, error) {
	fset := token.NewFileSet()
	seen := map[string]bool{}
	for i, src := range srcs {
		f, err := parser.ParseFile(fset, "src"+strconv.Itoa(i)+".go", src, 0)
		if err != nil {
			return nil, err
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				continue
			}
			for _, sp := range gd.Specs {
				vs, ok := sp.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for _, n := range vs.Names {
					if strings.HasPrefix(n.Name, "Err") && n.IsExported() {
						seen[n.Name] = true
					}
				}
			}
		}
	}
	return sortedKeys(seen), nil
}

// sentinelPackageRel — пакет, объявляющий признаки.
const sentinelPackageRel = "internal/errors"

// requireSentinelPartition — разбиение на живом дереве.
func requireSentinelPartition(t *testing.T) {
	t.Helper()
	out, err := gitenv.Command(serviceRoot, "ls-files", "-z", "--", sentinelPackageRel).Output()
	if err != nil {
		t.Fatalf("разбиение признаков НЕ ПРОВЕРЕНО: состав пакета не получен: %v", err)
	}
	var srcs [][]byte
	for _, rel := range strings.Split(string(out), "\x00") {
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			continue
		}
		b, rerr := os.ReadFile(path.Join(serviceRoot, rel))
		if rerr != nil {
			t.Fatalf("разбиение признаков НЕ ПРОВЕРЕНО: %s не прочитан: %v", rel, rerr)
		}
		srcs = append(srcs, b)
	}
	declared, err := declaredSentinelsIn(srcs...)
	if err != nil {
		t.Fatalf("разбиение признаков НЕ ПРОВЕРЕНО: разбор пакета отказал: %v", err)
	}
	t.Logf("разбиение: файлов пакета признаков %d · признаков объявлено %d · доходят до провода %d · "+
		"полосы фиксированного текста %d", len(srcs), len(declared), len(passThroughSentinels), len(fixedTextSentinels))
	if outcome, findings := sentinelPartition(declared, passThroughSentinels, fixedTextSentinels); outcome != premiseHolds {
		t.Fatalf("предпосылка гейта словаря: разбиение признаков не держится (%d):\n  %s",
			len(findings), strings.Join(findings, "\n  "))
	}
}

// requireClientTextPremise — проверка предпосылки на живом дереве, обе оси:
// разбиение признаков и фиксированность полос. Зовётся из
// `collectClientTexts`, потому что предпосылка принадлежит ОПРЕДЕЛЕНИЮ
// клиентского текста, а им пользуются оба гейта пакета: словарь и перепись
// машинного признака. Вызов из одного теста оставил бы второй на непроверенной
// посылке, а прогон `-run` по одному имени — без неё вовсе.
func requireClientTextPremise(t *testing.T) {
	t.Helper()
	requireSentinelPartition(t)

	// Корпус — индекс git модуля целиком: тот же, что обходит гейт дерева.
	out, err := gitenv.Command(serviceRoot, "ls-files", "-z", "--", "*.go").Output()
	if err != nil {
		t.Fatalf("предпосылка гейта словаря НЕ ПРОВЕРЕНА: состав модуля не получен: %v", err)
	}
	var files []string
	for _, rel := range strings.Split(string(out), "\x00") {
		if rel != "" {
			files = append(files, path.Join(serviceRoot, rel))
		}
	}
	census, findings, err := check.ScanFixedRefusalTexts(serviceRoot, files)
	if err != nil {
		t.Fatalf("предпосылка гейта словаря НЕ ПРОВЕРЕНА: разбор корпуса отказал: %v", err)
	}
	// Перепись — ДО вердикта и независимо от него.
	t.Log("предпосылка: " + census.String())
	if outcome, text := judgePremise(census, findings); outcome != premiseHolds {
		t.Fatal(text)
	}
}

// internalVocabulary — закрытый словарь имён внутренних слоёв. Перечень
// закрытый намеренно: широкий («любое английское техническое слово») краснел бы
// на контракт-тоне, который менять нельзя.
var internalVocabulary = []struct {
	word string
	why  string
}{
	{"marshal", "имя операции сериализации — слой кода, а не предмет арендатора"},
	{"unmarshal", "то же"},
	{"serializ", "уровень изоляции СУБД / операция сериализации"},
	{"hydra", "имя стороннего поставщика — арендатору о нём знать не полагается"},
	{"openfga", "имя стороннего хранилища отношений"},
	{"pgx", "имя драйвера СУБД"},
	{"sqlstate", "код состояния СУБД"},
	{"goroutine", "устройство исполнения"},
	{"read committed", "уровень изоляции СУБД"},
	{"repeatable read", "уровень изоляции СУБД"},
}

// operatorAddressed — пакеты, чьи отказы обращены к МОДУЛЮ и его оператору, а
// не к арендатору: они живут на внутреннем слушателе (:9091), куда арендатор не
// дозванивается by construction. Слово механизма там законно и снимать его
// нельзя.
//
// Перечень самоистекает: запись без единого попадания — находка, потому что
// послабление без предмета переживёт свою причину.
// Сегодня перечень ПУСТ, и это состояние, а не недосмотр: ни один клиентский
// текст словаря не оказался адресован оператору. Пустая ведомость — цель, а не
// поломка, поэтому гейт на ней проходит; заводить запись «про запас» нельзя —
// она станет слепой зоной, выданной вперёд.
var operatorAddressed = map[string]string{}

type clientText struct {
	pkg  string
	pos  string
	text string
	// producer — как отказ построен: имя признака (`ErrNotFound`, …) для
	// `Wrapf` либо имя кода (`PermissionDenied`, …) для `status.*`. По нему
	// перепись `client_refusal_reason_coverage_test.go` решает, несёт ли отказ
	// машинный признак полосы.
	producer string
}

func collectClientTexts(t *testing.T) []clientText {
	t.Helper()
	// Сперва предпосылка: без неё отбор ниже выводил бы из наблюдения тексты,
	// которые арендатор читает.
	requireClientTextPremise(t)

	out, err := gitenv.Command(serviceRoot, "ls-files", "internal").Output()
	if err != nil {
		t.Fatalf("перечень файлов службы не получен: %v", err)
	}
	var texts []clientText
	fset := token.NewFileSet()
	files := 0
	for _, rel := range strings.Fields(string(out)) {
		if !strings.HasSuffix(rel, ".go") || strings.HasSuffix(rel, "_test.go") {
			continue
		}
		files++
		f, perr := parser.ParseFile(fset, path.Join(serviceRoot, rel), nil, 0)
		if perr != nil {
			t.Fatalf("%s не разобран: %v", rel, perr)
		}
		pkgDir := path.Dir(rel)
		ast.Inspect(f, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			var msgArg ast.Expr
			producer := ""
			switch sel.Sel.Name {
			case "Error", "Errorf", "New":
				// status.Error(codes.X, "…") — подлежащее обязано быть `status`.
				pkgIdent, ok := sel.X.(*ast.Ident)
				if !ok || pkgIdent.Name != "status" || len(call.Args) < 2 {
					return true
				}
				if code, ok := call.Args[0].(*ast.SelectorExpr); ok {
					producer = "codes." + code.Sel.Name
				}
				msgArg = call.Args[1]
			case "Wrapf":
				// Wrapf(<признак>, "…") — только признаки, чей текст доезжает.
				s, ok := call.Args[0].(*ast.SelectorExpr)
				if !ok || !passThroughSentinels[s.Sel.Name] || len(call.Args) < 2 {
					return true
				}
				producer = s.Sel.Name
				msgArg = call.Args[1]
			default:
				return true
			}
			lit, ok := msgArg.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			v, uerr := strconv.Unquote(lit.Value)
			if uerr != nil || strings.TrimSpace(v) == "" || v == "%s" || v == "%v" {
				return true
			}
			texts = append(texts, clientText{
				pkg: pkgDir, pos: fset.Position(lit.Pos()).String(), text: v, producer: producer,
			})
			return true
		})
	}
	if files == 0 {
		t.Fatal("прод-файлов службы прочитано 0 — вердикт беспредметен")
	}
	t.Logf("перепись: прод-файлов %d · клиентских текстов %d", files, len(texts))
	return texts
}

func TestClientRefusalTextNamesNoInternalLayer(t *testing.T) {
	texts := collectClientTexts(t)
	if len(texts) == 0 {
		t.Fatal("клиентских текстов прочитано 0 — разбор разошёлся с деревом")
	}

	findings, exempted := vocabularyFindings(texts, operatorAddressed)

	// Самоистечение послабления: запись, которой больше нечего исключать,
	// переживёт свою причину и достанется следующей слепой зоне.
	var stale []string
	for pkg := range operatorAddressed {
		if exempted[pkg] == 0 {
			stale = append(stale, pkg)
		}
	}
	sort.Strings(stale)

	t.Logf("перепись: клиентских текстов %d · с именем внутреннего слоя %d · прощено адресату-оператору %d",
		len(texts), len(findings), len(exempted))

	if len(stale) > 0 {
		t.Errorf("послабление потеряло предмет — %d записей нечего исключать: %s\n"+
			"Снимите запись: она достанется следующей слепой зоне.", len(stale), strings.Join(stale, ", "))
	}
	if len(findings) > 0 {
		t.Fatalf("клиентский текст называет внутренний слой в %d местах:\n  %s\n"+
			"На месте каждого обязан стоять текст, называющий следующий шаг клиента, а не причину внутри.",
			len(findings), strings.Join(findings, "\n  "))
	}
}

// vocabularyFindings — ЧИСТЫЙ предикат гейта. Выделен ради инъекции: доказывать
// способность падать на живой находке нельзя — такая проба исчезает вместе с
// находкой, то есть ровно тогда, когда дерево починено.
func vocabularyFindings(texts []clientText, ledger map[string]string) ([]string, map[string]int) {
	var findings []string
	exempted := map[string]int{}
	for _, ct := range texts {
		low := strings.ToLower(ct.text)
		for _, w := range internalVocabulary {
			if !strings.Contains(low, w.word) {
				continue
			}
			if _, ok := ledger[ct.pkg]; ok {
				exempted[ct.pkg]++
				continue
			}
			findings = append(findings, ct.pos+" — "+strconv.Quote(ct.text)+": "+w.why)
		}
	}
	sort.Strings(findings)
	return findings, exempted
}
