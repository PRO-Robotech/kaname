// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// exemptclaim_test.go — комментарий use-case не объявляет полосу `<exempt>`
// там, где контракт объявил `scope_filtered` (задача продукта #2047).
//
// # Предмет
//
// Комментарий описывает ПОЛОСУ АВТОРИЗАЦИИ, и потому его неправда дороже
// обычной: прочитавший «Get is `<exempt>`» заключит, что пообъектного гейта у
// единичного чтения роли нет, — и либо заведёт его второй раз, либо снимет тот,
// что стоит. Контракт при этом лежит рядом и сам объясняет, почему выбрана
// другая полоса (`role_service.proto`, шапки `rpc Get` и `rpc List`).
//
// # Премиса берётся из КОНТРАКТА, а не выписывается
//
// Гейт не утверждает «`<exempt>` в этом пакете запрещён навсегда». Он читает
// объявления `RoleService` и судит только при условии, что НИ ОДИН её rpc не
// объявлен `<exempt>`: тогда всякое такое слово в комментарии — заведомо ложь.
// Объявят какой-нибудь rpc действительно освобождённым — гейт отойдёт в сторону
// и скажет об этом переписью, вместо того чтобы краснеть на верном коде.
//
// Это и есть проверка собственной предпосылки (`testing.md` §«Гейт на класс»,
// п. 3): запрет обоснован фактом о контракте, факт может измениться, и гейт
// обязан заявить об этом сам.
//
// # Судится КОММЕНТАРИЙ, а не текст файла
//
// Слово `<exempt>` стоит и в строковых литералах контракта, и в прозе о самом
// гейте. Предикат по подстроке краснел бы на собственном объяснении
// (`testing.md` §«Гейт на класс», п. 4), поэтому суждение выносится по
// РАЗОБРАННЫМ комментариям — узлам дерева разбора, а не по строкам файла.
//
// # РАДИУС ВЗЯТ ПО МЕХАНИЗМУ, А НЕ ПО КАТАЛОГУ, ГДЕ ДЕФЕКТ ЗАМЕТИЛИ
//
// Прежняя редакция судила ОДИН каталог — тот, в котором дефект нашли. Класс это
// не закрыло: то же утверждение жило в `internal/authzfilter/visibility.go`,
// рядом с таблицей предикатов страницы, и пережило починку соседей на полторы
// недели (kacho#1922). Файл объявлял, что запись каталога для `RoleService/Get`
// освобождена, — тогда как контракт объявляет `scope_filtered` и САМ объясняет,
// чем это отличается: освобождённая полоса допускает вызов ВООБЩЕ БЕЗ
// ПРИНЦИПАЛА, а чтение, сужаемое по вызывающему, без принципала сужать не по
// кому.
//
// Поэтому судится ЗАКРЫТЫЙ НАБОР: каталог use-case плюс поимённо названные
// файлы вне его, чей предмет — та же полоса чтения роли. Исчезнувший файл
// набора — НАХОДКА, а не тишина: иначе переезд вывел бы утверждение из-под
// наблюдения, и заметить это было бы нечем.
//
// # Границы, названные честно
//
// Судятся только НЕ-ТЕСТОВЫЕ файлы, и это не забывчивость: слово стоит в шапке
// этого самого гейта и в его инъекции, поэтому охват на тестовое дерево сделал
// бы гейт красным на собственном объяснении — ровно тот класс, который он и
// ловит. Комментарии проб, называвшие ту же несуществующую полосу
// (`internal/authzfilter/read_parity_test.go`), поправлены тем же изменением
// ВРУЧНУЮ, и держателя у них нет; сказано, чтобы «ноль находок» не читалось
// шире, чем есть.
package role_test

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

const (
	// exemptToken — как полоса освобождения записывается в контракте и в прозе.
	exemptToken = "<exempt>"
	// roleContract — контракт, у которого живёт объявление полос. Координата от
	// корня МОДУЛЯ.
	//
	// ЗДЕСЬ СТОЯЛА КООРДИНАТА ОТ КОРНЯ ПЛАТФОРМЫ, И ГЕЙТ ИЗ-ЗА НЕЁ НЕ ИСПОЛНЯЛСЯ
	// НИ РАЗУ. Резолв от платформы отвечает «условие не создано» на всякий путь
	// вне поставки модуля, а контракты в неё когда-то не входили. Решением
	// владельца 2026-09-13 они переехали в репозиторий службы (kacho#2616):
	// `proto/` лежит в ЭТОМ модуле, и посылка резолва пережила свой предмет.
	// Пропуск при этом выглядит как успех — прогон зелёный, вердикта нет ни
	// одного.
	roleContract = "proto/kaname/cloud/iam/v1/role_service.proto"
	// roleUseCaseDir — каталог use-case, чьи комментарии судятся.
	roleUseCaseDir = "."
)

// roleLaneFilesOutsideTheUseCase — файлы ВНЕ каталога use-case, чей предмет — та
// же полоса чтения роли. Координаты от корня МОДУЛЯ.
//
// Набор ЗАКРЫТЫЙ и проверяется на существование: файл, которого нет, — находка,
// потому что молчание о переехавшем утверждении неотличимо от молчания о
// починенном.
var roleLaneFilesOutsideTheUseCase = []string{
	"internal/authzfilter/visibility.go",
}

// reExemptOption — объявление освобождённой полосы в контракте.
var reExemptOption = regexp.MustCompile(`permission\s*\)?\s*=\s*"` + regexp.QuoteMeta(exemptToken) + `"`)

type exemptCensus struct {
	ContractExempts int // rpc RoleService, объявленных `<exempt>`
	FilesRead       int // не-тестовых файлов use-case прочитано
	CommentBlocks   int // блоков комментария разобрано
	Claims          int // блоков, называющих `<exempt>`
}

func (c exemptCensus) String() string {
	return fmt.Sprintf("объявлений `%s` в контракте %d · файлов use-case прочитано %d · "+
		"блоков комментария разобрано %d · из них называют полосу %d",
		exemptToken, c.ContractExempts, c.FilesRead, c.CommentBlocks, c.Claims)
}

// auditExemptClaims судит комментарии при условии, что контракт освобождённых
// полос не объявляет. Оба входа принимаются параметром — инъекция подаёт
// синтетику, не трогая дерево.
func auditExemptClaims(contract string, sources map[string]string) ([]string, exemptCensus, error) {
	var (
		findings []string
		census   exemptCensus
	)
	census.ContractExempts = len(reExemptOption.FindAllString(contract, -1))
	if strings.TrimSpace(contract) == "" {
		return nil, census, fmt.Errorf("контракт пуст — премиса не прочитана, судить не по чему")
	}

	fset := token.NewFileSet()
	for name, src := range sources {
		f, err := parser.ParseFile(fset, name, src, parser.ParseComments)
		if err != nil {
			return nil, census, fmt.Errorf("%s не разобран: %w", name, err)
		}
		census.FilesRead++
		for _, group := range f.Comments {
			census.CommentBlocks++
			text := group.Text()
			if !strings.Contains(text, exemptToken) {
				continue
			}
			census.Claims++
			// Премиса: пока контракт не объявил ни одной освобождённой полосы,
			// такое слово в комментарии — заведомо ложь.
			if census.ContractExempts > 0 {
				continue
			}
			findings = append(findings, fmt.Sprintf(
				"%s:%d: комментарий называет полосу `%s`, а контракт RoleService не объявил "+
					"её НИ У ОДНОГО rpc — обе читающие полосы объявлены `scope_filtered`, и "+
					"контракт сам объясняет почему.\n"+
					"    читатель заключит, что пообъектного гейта нет, и либо заведёт его "+
					"второй раз, либо снимет тот, что стоит.\n"+
					"    отдельно: освобождённая полоса допускает вызов ВООБЩЕ БЕЗ ПРИНЦИПАЛА, "+
					"а чтение, сужаемое по вызывающему, без принципала сужать не по кому",
				name, fset.Position(group.Pos()).Line, exemptToken))
		}
	}
	return findings, census, nil
}

// collectRoleLaneSources — не-тестовые исходники каталога use-case ПЛЮС поимённо
// названные файлы полосы вне его.
//
// Чистая функция от двух корней: инъекция подаёт ей синтетическое дерево и
// доказывает, что исчезнувший файл набора даёт ОТКАЗ, а не тишину. Спрятав это
// в `t.Fatalf` внутри сборщика, свойство пришлось бы проверять чтением.
func collectRoleLaneSources(useCaseDir, moduleRoot string, extra []string) (map[string]string, error) {
	entries, err := os.ReadDir(useCaseDir)
	if err != nil {
		return nil, fmt.Errorf("каталог use-case не прочитан: %w", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, rerr := os.ReadFile(filepath.Join(useCaseDir, name)) // #nosec G304 -- обход своего каталога
		if rerr != nil {
			return nil, fmt.Errorf("файл %s не прочитан: %w", name, rerr)
		}
		out[name] = string(b)
	}
	for _, rel := range extra {
		b, rerr := os.ReadFile(filepath.Join(moduleRoot, filepath.FromSlash(rel))) // #nosec G304 -- координата-константа своего дерева
		if rerr != nil {
			return nil, fmt.Errorf("файл набора %s не прочитан: %w.\n"+
				"    Набор ЗАКРЫТЫЙ: исчезнувший файл — НАХОДКА, а не тишина. Переехал? "+
				"Поправьте координату ЗДЕСЬ — иначе утверждение уедет из-под наблюдения "+
				"вместе с ним, и заметить это будет нечем", rel, rerr)
		}
		out[rel] = string(b)
	}
	return out, nil
}

// roleLaneSources — тот же сбор против НАСТОЯЩЕГО дерева.
func roleLaneSources(t *testing.T) map[string]string {
	t.Helper()
	moduleRoot, merr := platformtree.ModuleRootFrom(mustWD(t))
	if merr != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не установлен: %v", merr)
	}
	out, err := collectRoleLaneSources(roleUseCaseDir, moduleRoot, roleLaneFilesOutsideTheUseCase)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return out
}

// mustWD — рабочий каталог либо ОТКАЗ: не установлен — судить не о чем.
func mustWD(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	return dir
}

// TestUseCaseDoesNotClaimAnExemptLaneTheContractNeverDeclared — вердикт о
// НАСТОЯЩЕМ дереве.
//
// Способность падать доказывает не этот прогон, а инъекция
// (`exemptclaim_injection_test.go`).
func TestUseCaseDoesNotClaimAnExemptLaneTheContractNeverDeclared(t *testing.T) {
	moduleRoot, merr := platformtree.ModuleRootFrom(mustWD(t))
	if merr != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не установлен: %v", merr)
	}
	contract, err := os.ReadFile(filepath.Join(moduleRoot, filepath.FromSlash(roleContract)))
	if err != nil {
		t.Fatalf("контракт не прочитан (%s): %v.\n"+
			"    Это НЕ «условие не создано»: контракты службы лежат в её собственном "+
			"модуле, поэтому отсутствие файла здесь — находка", roleContract, err)
	}
	findings, census, aerr := auditExemptClaims(string(contract), roleLaneSources(t))
	if aerr != nil {
		t.Fatalf("сверка не отработала: %v", aerr)
	}
	t.Logf("объём осмотренного: %s", census)

	// Премисы: «ноль находок» обязано быть отличимо от «ноль прочитанного».
	if census.FilesRead == 0 {
		t.Fatal("файлов use-case прочитано 0 — обход пуст, вердикт беспредметен")
	}
	if census.CommentBlocks == 0 {
		t.Fatal("блоков комментария разобрано 0 — разбор пуст, судить не по чему")
	}
	if census.ContractExempts > 0 {
		t.Logf("контракт объявил освобождённых полос %d — гейт отходит в сторону: "+
			"слово в комментарии перестало быть заведомой ложью", census.ContractExempts)
	}

	for _, f := range findings {
		t.Errorf("НАХОДКА: %s", f)
	}
}
