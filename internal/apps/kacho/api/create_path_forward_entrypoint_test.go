// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// create_path_forward_entrypoint_test.go — гейт на КЛАСС: путь СОЗДАНИЯ не вправе
// звать сторожевой вход быстрой материализации.
//
// # Предмет
//
// Пост-коммитный проход материализации существует затем, чтобы созданный объект был
// виден создателю раньше клиентского бюджета чтения-своих-записей. У него два входа:
//
//   - сторожевой (ReconcileObjectForward) — сперва читает, есть ли у объекта уже
//     материализованные члены; если есть, объект считается ПЕРЕсозданным и уводится на
//     ПОЛНЫЙ проход с ИСКЛЮЧИТЕЛЬНОЙ advisory-блокировкой биндинга;
//   - доказанный (ReconcileObjectForwardNoStale) — сторож снят, потому что вызывающий
//     располагает фактом, которого хранилище вывести не может: идентификатор выдан в
//     только что закоммиченной транзакции, то есть объекта раньше не существовало и
//     устареть на нём нечему.
//
// # Почему сторожевой вход на пути создания — это ХВОСТ, а не безопасная перестраховка
//
// Члены на брандновом объекте появляются штатно: путь создания сам делает ДВА прохода —
// сперва по биндингу, затем по нему же как по ОБЪЕКТУ, — и первый пишет член ровно на
// тот объект, который второй сейчас посмотрит. Сторож видит непустой набор и уводит
// объект на полный проход. А поскольку все объекты аккаунта делят ОДИН биндинг
// администратора аккаунта, эти полные проходы встают в очередь на одну блокировку.
// Замер этого же класса на живом стенде (он записан в шапке forward_no_stale_test.go):
// собственные кортежи субъекта приезжали за ~3 с, родительский указатель области — за
// ~61 с, пообъектные глаголы администратора аккаунта — за ~67 с при клиентском бюджете
// опроса 25 с. Отсюда наблюдаемое «шаг исчерпал бюджет повторов на скрытом отказе, а
// следующий запрос по тому же ресурсу прошёл сразу»: к нему очередь уже разошлась.
//
// # Почему это гейт, а не правка шести мест
//
// Класс уже один раз чинили ЭКЗЕМПЛЯРОМ: доказанный вход завели ради создания выдачи —
// и там его и оставили, хотя ровно та же двухпроходная форма стоит в приглашении
// пользователя, а брандновый идентификатор рождают ещё четыре пути создания. Правка без
// гейта воспроизведёт это на следующем созданном ресурсе.
//
// # Разбор синтаксисом, а не поиском подстроки
//
// Имя сторожевого входа встречается в godoc КАЖДОГО из этих файлов — в том числе там,
// где вызов уже правильный. Гейт по тексту считал бы такой комментарий нарушением и был
// бы снят первым же разбирающимся как ложный. Поэтому здесь разбирается дерево
// синтаксиса и рассматриваются ТОЛЬКО выражения вызова.
package api_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

const (
	guardedEntryPoint = "ReconcileObjectForward"
	provenEntryPoint  = "ReconcileObjectForwardNoStale"
)

// createPathFileNames / updatePathFileNames — по КАКОМУ имени файла узнаётся полоса.
// Сами файлы НЕ перечисляются: состав выводится из индекса отслеживаемых файлов, иначе
// назавтра заведённый `create.go` нового ресурса окажется вне гейта, и тот промолчит —
// не потому, что нарушения нет, а потому, что он о файле не знает. Закрытый перечень
// здесь был бы слепой зоной ровно того же рода, что ловит сам гейт.
//
// Предмет полосы, а не имя, решает: `create.go` и `invite.go` РОЖДАЮТ объект —
// идентификатор выдаётся в транзакции, которая коммитится перед пост-коммитным
// проходом, поэтому доказательство «объекта раньше не существовало» верно by
// construction. `update.go` — противоположный случай: перерегистрация могла ЗАМЕНИТЬ
// проекцию, и снятая метка обязана ОТОЗВАТЬ доступ, чего аддитивный проход не делает.
var (
	createPathFileNames = map[string]bool{"create.go": true, "invite.go": true}
	updatePathFileNames = map[string]bool{"update.go": true}
)

// TestCreatePathUsesProvenForwardEntryPoint — путь создания зовёт доказанный вход, а
// путь обновления сохраняет сторожевой.
func TestCreatePathUsesProvenForwardEntryPoint(t *testing.T) {
	apiDir := apiDirForForwardGate(t)
	files, err := treecorpus.UnderWithSuffix(apiDir, ".go")
	require.NoError(t, err, "индекс отслеживаемых файлов под api/")

	var createFiles, updateFiles []string
	for _, p := range files {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		base := filepath.Base(p)
		switch {
		case createPathFileNames[base]:
			createFiles = append(createFiles, p)
		case updatePathFileNames[base]:
			updateFiles = append(updateFiles, p)
		}
	}
	require.NotEmpty(t, createFiles, "путей создания не найдено — предпосылка гейта сломана")
	require.NotEmpty(t, updateFiles, "путей обновления не найдено — предпосылка гейта сломана")

	var offenders []string
	createChecked, createCalls := 0, 0
	for _, path := range createFiles {
		rel, rerr := filepath.Rel(apiDir, path)
		require.NoError(t, rerr)
		calls := forwardCallsIn(t, path)
		createChecked++
		createCalls += len(calls)
		for _, c := range calls {
			if c.name == guardedEntryPoint {
				offenders = append(offenders, rel+":"+c.pos)
			}
		}
		// Требования «хотя бы один вызов» здесь НЕТ намеренно: путь создания вправе не
		// материализовать объект синхронно вовсе (создание аккаунта материализует свою
		// выдачу другим портом). Предмет гейта обеспечен ниже — общим числом найденных
		// вызовов: ноль означал бы, что смотреть было не на что.
	}
	require.Positivef(t, createCalls,
		"на %d путях создания не найдено НИ ОДНОГО вызова пост-коммитного прохода. Либо "+
			"создание перестало материализовать созданное синхронно, либо гейт смотрит не "+
			"туда — и тогда его «ноль находок» ничего не значит", createChecked)
	sort.Strings(offenders)
	require.Emptyf(t, offenders,
		"путь СОЗДАНИЯ зовёт СТОРОЖЕВОЙ вход быстрой материализации: %v\n\n"+
			"Идентификатор выдан в только что закоммиченной транзакции, поэтому устареть на "+
			"объекте нечему, и читать «есть ли у него члены» незачем. Хуже того, члены там "+
			"штатно ЕСТЬ — их написал предыдущий проход того же создания, — поэтому сторож "+
			"уводит брандновый объект на ПОЛНЫЙ проход с исключительной блокировкой, общей для "+
			"всех объектов аккаунта. Это и есть хвост материализации. Нужен %q.",
		offenders, provenEntryPoint)

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: у обновления сторож обязан остаться.
	updChecked, updGuarded := 0, 0
	for _, path := range updateFiles {
		rel, rerr := filepath.Rel(apiDir, path)
		require.NoError(t, rerr)
		updChecked++
		for _, c := range forwardCallsIn(t, path) {
			if c.name == guardedEntryPoint {
				updGuarded++
			}
			require.NotEqualf(t, provenEntryPoint, c.name,
				"путь ОБНОВЛЕНИЯ %q зовёт доказанный вход (%s:%s). Перерегистрация могла "+
					"ЗАМЕНИТЬ проекцию объекта — снятая метка обязана ОТОЗВАТЬ выданный доступ, "+
					"а аддитивный проход не отзывает ничего. Снятие сторожа здесь — не ускорение, "+
					"а неприменённый отзыв.", rel, rel, c.pos)
		}
	}
	require.Positive(t, updGuarded,
		"ни один путь обновления не зовёт сторожевой вход — положительный контроль пуст, "+
			"значит гейт не отличает «сторож не нужен» от «сторожа нигде нет»")

	t.Logf("перепись: путей создания осмотрено %d (вызовов прохода %d); путей обновления %d "+
		"(сторожевых вызовов %d)", createChecked, createCalls, updChecked, updGuarded)
}

type forwardCall struct{ name, pos string }

// forwardCallsIn — ВЫЗОВЫ обоих входов в файле, по дереву синтаксиса. Комментарии и
// объявления port-интерфейсов не рассматриваются: предмет гейта — что код ДЕЛАЕТ.
func forwardCallsIn(t *testing.T, path string) []forwardCall {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0) // 0 ⇒ комментарии не разбираются вовсе
	require.NoErrorf(t, err, "разбор %q", path)

	var out []forwardCall
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		name := sel.Sel.Name
		if name != guardedEntryPoint && name != provenEntryPoint {
			return true
		}
		p := fset.Position(call.Pos())
		out = append(out, forwardCall{name: name, pos: strings.TrimPrefix(p.String(), path+":")})
		return true
	})
	return out
}

func apiDirForForwardGate(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	require.NoError(t, err)
	dir := wd
	// Корнем берётся САМЫЙ ВНЕШНИЙ `go.mod`, а не первый встречный: у службы
	// теперь СВОЙ модуль, и подъём «до первого» останавливался бы в её каталоге,
	// а пути ниже называют место В ДЕРЕВЕ МОНОРЕПО — от корня.
	outermost := ""
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			outermost = dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			if outermost != "" {
				return filepath.Join(outermost, "services", "iam", "internal", "apps", "kacho", "api")
			}
			t.Fatalf("корень монорепо (go.mod) не найден от %s", wd)
		}
		dir = parent
	}
}
