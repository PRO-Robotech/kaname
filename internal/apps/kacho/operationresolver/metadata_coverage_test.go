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

	"github.com/PRO-Robotech/kacho/internal/treecorpus"
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
	// ApplyModuleMetadata — то же основание, что у пары ClusterAdmin выше, и
	// сильнее её: у применения каталога модулей воркера нет НЕ по стечению
	// обстоятельств, а по форме контракта. `InternalModuleService.Apply`
	// возвращает ТЕРМИНАЛЬНЫЙ конверт: строка операции сохраняется `done=false`
	// до мутации (чтобы её id был запрашиваем всегда), мутация исполняется
	// синхронно в одной транзакции, и вызывающий получает конверт уже с
	// `done=true`. Полла не требуется, а всякий отказ приходит СИНХРОННОЙ
	// gRPC-ошибкой, а не операцией с ошибкой внутри.
	//
	// Значит осиротеть операции этого типа негде, кроме гибели процесса между
	// двумя соседними стейтментами, — тот же остаток, что у девяти записей выше,
	// и не больший. Асинхронного исполнителя у iam нет вовсе, поэтому ветка
	// резолвера здесь не «забыта»: разрешать ей было бы нечего — применение не
	// заводит строки ресурса со своим id, его предмет есть МОДУЛЬ.
	//
	// Это ДОЛГ С ЧИСЛОМ — записей стало десять, — а не прощение.
	"ApplyModuleMetadata",
	"DeleteUserMetadata",
	"ForceLogoutMetadata",
	"GrantClusterAdminMetadata",
	// InteractiveClient{Create,Update,Delete}Metadata — то же основание, что у
	// пары ClusterAdmin рядом, и по той же причине: у этих операций НЕТ воркера.
	// Строка операции создаётся и переводится в терминальное состояние внутри
	// одного вызова RPC, поэтому осиротеть ей негде, кроме гибели процесса между
	// двумя соседними стейтментами. Ветку резолвера сюда не добавили не «потому
	// что забыли»: она потребовала бы внести ресурс в CQRS-корень Reader, тогда
	// как ресурс намеренно живёт отдельными адаптерами (кластерная админ-
	// поверхность, не тенантная). Это ДОЛГ С ЧИСЛОМ — три записи, — а не
	// прощение; закрывается вместе с парой ClusterAdmin, когда у админ-
	// поверхности появится общий путь разрешения.
	"CreateInteractiveClientMetadata",
	"UpdateInteractiveClientMetadata",
	"DeleteInteractiveClientMetadata",
	// Limit{Create,Update,Delete}Metadata — то же основание и та же цена, что у
	// трёх записей выше: у операций назначения, изменения и отзыва предела НЕТ
	// воркера. Строка операции создаётся и переводится в терминальное состояние
	// внутри одного вызова RPC (usecases.go: opsRepo.Create → запись → MarkDone
	// либо MarkError), поэтому осиротеть ей негде, кроме гибели процесса между
	// двумя соседними стейтментами. Ветка резолвера потребовала бы внести предел
	// в CQRS-корень Reader, тогда как ресурс намеренно живёт отдельным адаптером
	// (кластерная админ-поверхность, не тенантная).
	//
	// Это ДОЛГ С ЧИСЛОМ — записей стало шесть, — а не прощение: закрывается тем
	// же заходом, что пара ClusterAdmin и тройка InteractiveClient, когда у
	// админ-поверхности появится общий путь разрешения.
	"CreateLimitMetadata",
	"UpdateLimitMetadata",
	"DeleteLimitMetadata",
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
	// Здесь стояла `WriteTuplesMetadata`. Запись снята вместе со своим предметом
	// (#788): RPC `InternalAuthorizeService.WriteTuples` удалён с контракта, тип
	// метаданных перестал существовать — и перепись назвала запись истёкшей сама,
	// ровно как обещает её шапка. Это и есть самоистечение: разрешение не пережило
	// того, что им прощалось.
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
	files, err := treecorpus.Glob(filepath.Join(root, protoGlob))
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
