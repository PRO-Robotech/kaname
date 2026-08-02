// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// metadata_coverage_test.go — гейт против операции, которую некому довести до
// терминального состояния.
//
// Резолвер — закрытый переключатель по типу метаданных операции. Тип, которого в
// нём нет, попадает в ветку по умолчанию и **пропускается**: осиротевшая операция
// (воркер умер между созданием строки и коммитом) навсегда остаётся незавершённой
// и переклеймливается каждым проходом. Вызывающий поллит ответ, который никогда
// не придёт.
//
// Забыть эту ветку легко и ничем не наказуемо: новый RPC, возвращающий Operation,
// собирается, проходит все свои тесты, попадает в каталог и в таблицу маршрутов —
// и единственное, чего у него нет, не проверяет никто. Ровно так и вышло с двумя
// действиями сервисного аккаунта: их добавили вместе с полным набором тестов, а
// резолвер узнал о них только на ревью.
//
// Гейт сверяет ОБЪЯВЛЕНИЕ (`metadata:` в опции операции доменного proto) с тем,
// что резолвер реально разбирает (разбор AST переключателя, не текстовый поиск —
// иначе строка в комментарии считалась бы реализацией). Реестр непокрытых —
// ПИН, а не разрешение: он обязан совпадать точно. Появился новый непокрытый тип
// — падает; покрыли старый — тоже падает, чтобы запись не пережила свой предмет.
package operationresolver

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
)

// resolverFile — файл, чей переключатель и есть предмет проверки.
const resolverFile = "resolver.go"

// protoGlob — доменное proto iam относительно корня репозитория.
const protoGlob = "proto/kacho/cloud/iam/v1/*.proto"

// metadataDeclRe — объявление метаданных в опции операции: `metadata: "XMetadata"`.
var metadataDeclRe = regexp.MustCompile(`metadata:\s*"([A-Za-z0-9_]+)"`)

// unresolvedMetadata — типы метаданных, которые резолвер сегодня НЕ разбирает.
//
// Это долг с числом, а не список прощённых. Каждая запись означает: у операции
// этого типа нет пути к терминальному состоянию, кроме успешного воркера. Для
// части из них это защитимо (операция создаётся и завершается синхронно в одном
// вызове, осиротеть ей негде), для части — нет, и разбирать это нужно по одной,
// в своём домене, а не заодно.
//
// Порядок закрытия записи: добавить ветку в переключатель резолвера с явным
// решением, разрешается ли ресурс как присутствующий (kindCreate/kindUpdate) или
// как отсутствующий (kindDelete), и убрать строку отсюда.
var unresolvedMetadata = []string{
	"AddGroupMemberMetadata",
	"DeleteUserMetadata",
	"ForceLogoutMetadata",
	"GrantClusterAdminMetadata",
	"InviteUserMetadata",
	"IssueSAKeyMetadata",
	"IssueUserTokenMetadata",
	"OnRecoveryCompletedMetadata",
	"RemoveGroupMemberMetadata",
	"RevokeClusterAdminMetadata",
	"RevokeMetadata",
	"RevokeSAKeyMetadata",
	"RevokeUserTokenMetadata",
	"UpsertFromIdentityMetadata",
	"WriteTuplesMetadata",
}

// TestEveryOperationMetadataIsResolvedOrPinned — объявленный тип метаданных либо
// разбирается резолвером, либо назван в реестре выше. Третьего исхода нет:
// «просто не добавили» — это операция, которая может зависнуть навсегда.
func TestEveryOperationMetadataIsResolvedOrPinned(t *testing.T) {
	root := repoRootForCoverage(t)

	declared, protoFiles := declaredOperationMetadata(t, root)
	// Предпосылка гейта: он обязан утверждать ОБЪЁМ осмотренного. «Ноль находок»
	// обязано быть отличимо от «ноль прочитанного».
	if len(protoFiles) == 0 {
		t.Fatalf("не прочитано ни одного proto-файла по шаблону %s — гейт беспредметен: "+
			"дерево proto переехало, и он молчал бы при любом дрейфе", protoGlob)
	}
	if len(declared) == 0 {
		t.Fatalf("в %d proto-файлах не найдено ни одного объявления `metadata: \"…\"` — "+
			"либо изменилась форма опции операции, либо разбор её больше не видит. "+
			"В обоих случаях гейт ниже объявил бы покрытым ВСЁ", len(protoFiles))
	}

	handled := resolverHandledMetadata(t, root)
	if len(handled) == 0 {
		t.Fatalf("в %s не найдено ни одной ветки `case *iamv1.…Metadata` — разбор перестал "+
			"видеть переключатель, и гейт объявил бы НЕПОКРЫТЫМИ все %d объявленных типов",
			resolverFile, len(declared))
	}

	var uncovered []string
	for _, name := range declared {
		if !slices.Contains(handled, name) {
			uncovered = append(uncovered, name)
		}
	}
	sort.Strings(uncovered)

	pinned := slices.Clone(unresolvedMetadata)
	sort.Strings(pinned)

	for _, name := range uncovered {
		if !slices.Contains(pinned, name) {
			t.Errorf("тип метаданных операции не разбирается резолвером и не внесён в реестр:\n"+
				"  %s\n\n"+
				"Осиротевшая операция этого типа НИКОГДА не станет терминальной: ветка по "+
				"умолчанию её пропускает, строка переклеймливается каждым проходом, вызывающий "+
				"поллит ответ, которого не будет. Исходы: добавить ветку в %s с явным решением "+
				"о разрешении ресурса / внести сюда с разбором, почему операция этого типа "+
				"осиротеть не может.", name, resolverFile)
		}
	}
	for _, name := range pinned {
		if !slices.Contains(uncovered, name) {
			t.Errorf("запись реестра пережила свой предмет: %s теперь разбирается резолвером.\n"+
				"Удали строку из unresolvedMetadata — иначе следующая слепая зона унаследует "+
				"это разрешение.", name)
		}
	}

	t.Logf("осмотрено: %d proto-файлов, %d объявленных типов метаданных, %d разбираемых "+
		"резолвером, %d непокрытых (все запинены)",
		len(protoFiles), len(declared), len(handled), len(uncovered))
}

// declaredOperationMetadata возвращает имена сообщений метаданных, объявленных в
// опции операции доменного proto, и список прочитанных файлов.
//
// Строчные комментарии снимаются до сопоставления: объявление живёт в коде, а
// закомментированный пример — нет, и считать его объявлением значило бы требовать
// ветку под то, чего не существует.
func declaredOperationMetadata(t *testing.T, root string) ([]string, []string) {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(root, protoGlob))
	if err != nil {
		t.Fatalf("обход %s: %v", protoGlob, err)
	}
	seen := map[string]struct{}{}
	for _, f := range files {
		raw, rerr := os.ReadFile(f)
		if rerr != nil {
			t.Fatalf("чтение %s: %v", f, rerr)
		}
		for _, line := range strings.Split(string(raw), "\n") {
			if i := strings.Index(line, "//"); i >= 0 {
				line = line[:i]
			}
			for _, m := range metadataDeclRe.FindAllStringSubmatch(line, -1) {
				seen[m[1]] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(seen))
	for k := range seen {
		out = append(out, k)
	}
	sort.Strings(out)
	return out, files
}

// resolverHandledMetadata разбирает переключатель резолвера по AST и возвращает
// имена типов, под которые в нём есть ветка.
//
// Именно AST, а не поиск по тексту: имя типа, упомянутое в комментарии рядом (а
// они там есть — ветка отзыва привязки объясняет своё решение в трёх строках
// прозы), текстовым поиском неотличимо от реализации, и гейт зеленел бы на
// объяснении вместо кода.
func resolverHandledMetadata(t *testing.T, root string) []string {
	t.Helper()
	path := filepath.Join(root, "services/iam/internal/apps/kacho/operationresolver", resolverFile)
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("разбор %s: %v", path, err)
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		cc, ok := n.(*ast.CaseClause)
		if !ok {
			return true
		}
		for _, expr := range cc.List {
			star, ok := expr.(*ast.StarExpr)
			if !ok {
				continue
			}
			sel, ok := star.X.(*ast.SelectorExpr)
			if !ok {
				continue
			}
			if strings.HasSuffix(sel.Sel.Name, "Metadata") {
				out = append(out, sel.Sel.Name)
			}
		}
		return true
	})
	sort.Strings(out)
	return slices.Compact(out)
}

// repoRootForCoverage поднимается от каталога этого файла до корня репозитория
// (первый каталог с go.mod).
func repoRootForCoverage(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("рабочий каталог: %v", err)
	}
	for i := 0; i < 12; i++ {
		if _, serr := os.Stat(filepath.Join(dir, "go.mod")); serr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("не найден корень репозитория (каталог с go.mod) над %s", dir)
	return ""
}
