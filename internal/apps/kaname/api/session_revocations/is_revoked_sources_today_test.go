// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_revocations

// is_revoked_sources_today_test.go — перечень «источники отзыва, какими их
// производит дерево сегодня» в контракте службы называет отзыв семейства ровно
// тогда, когда дерево пишет запись выпуска, и говорит, собрана ли церемония на
// пути запроса (kaname#319, находки ревью GSR-319-4 и GSR-420-3).
//
// # Предмет
//
// Ответ `IsRevoked` судит семейство только у выпуска, чья запись лежит в таблице
// выпусков, а запись пишет выпуск церемонии вызовом писателя `RecordAccessToken`
// из адаптера порта выпуска (`internal/ceremonyport`, kaname#396). Пока в дереве
// нет ни одного не-тестового вызова писателя, ни один токен не принадлежит
// семейству, и отзыв семейства ни до одного ответа не доходит. Контракт,
// числящий его среди источников «сегодня», обещает источник, который не
// приходит, — ровно то, от чего шапка службы предостерегает на примере снятых
// приёмников.
//
// Вызова мало: адаптер пишет запись, только если его собирает процесс службы.
// Пока композиционный корень (`cmd/kaname`) церемонию не собирает (kaname#407),
// пункт о семействе правдив лишь с оговоркой «церемония на пути запроса ещё не
// собрана». Эта оговорка — такой же факт о дереве, и судится он так же.
//
// # В обе стороны, по каждой оси
//
//   - писатель не позван, а перечень «сегодня» называет семейство — находка;
//   - писатель позван, а перечень «сегодня» семейства не называет — тоже
//     находка: оговорка «на этой ревизии не производится» пережила свой предмет;
//   - писателя зовут только пакеты, которых корень не собирает, а перечень
//     называет семейство без оговорки о несобранной церемонии — находка;
//   - писателя зовёт пакет, который корень собирает, а оговорка осталась —
//     тоже находка: она пережила свой предмет.
//
// # Что читается
//
//   - вызовы писателя — перепись гейта `internal/check` (`check.FamilyVerdict`,
//     поле `WriterCalls`) над составом `check.ProdGoFiles`: у факта одна мерка,
//     своего обхода здесь нет;
//   - что собирает корень — замыкание по импортам не-тестовых файлов `cmd`,
//     `internal` и `pkg`, начиная с `cmd/kaname`. Корень без единого импорта
//     модуля — предпосылка сломана, а не «ничего не собрано»;
//   - перечень — строки шапки службы в порождённой заглушке от заголовка
//     перечня до первой пустой строки. Заголовок не найден — предпосылка
//     сломана, а не «перечень пуст».
//
// # Граница
//
// Гейт судит, В КАКОМ месте названо семейство — в перечне «сегодня» или вне
// его, — и есть ли в перечне оговорка, а не верность прочей прозы вне перечня.
// Условия сборки файла (`//go:build`) разбор импортов не исполняет: файл под
// чужой платформой засчитывается собранным. Порядок «запись до того, как токен
// уедет» на уровне адаптера держит
// `TestIssue_RecordsTheIssuanceInItsFamilyBeforeTheTokenLeaves`
// (`internal/ceremonyport`), на пути запроса — сборка церемонии (kaname#407),
// не этот гейт.

import (
	"fmt"
	"go/parser"
	"go/token"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// producedTodayHeading — заголовок перечня источников «сегодня» в шапке службы.
const producedTodayHeading = "Revocation sources, as the tree produces them today:"

// issuanceWriter — писатель записи выпуска; без его вызова семейству отвечать
// не о чем.
const issuanceWriter = "RecordAccessToken"

// serviceRoot — композиционный корень службы: пакет, который собирает её
// процесс.
const serviceRoot = "cmd/kaname"

// unmountedCaveat — оговорка перечня о том, что церемония на пути запроса
// службы ещё не собрана.
var unmountedCaveat = regexp.MustCompile(`(?i)\bnot\s+yet\s+mounted\b`)

// listItem — строка, открывающая пункт перечня.
var listItem = regexp.MustCompile(`^\s*- `)

// producedTodayList — строки перечня источников «сегодня»: от заголовка до
// первой пустой строки. ok=false — заголовка в тексте нет.
func producedTodayList(service string) (list string, ok bool) {
	lines := strings.Split(service, "\n")
	for i, l := range lines {
		if strings.TrimSpace(l) != producedTodayHeading {
			continue
		}
		var items []string
		for _, item := range lines[i+1:] {
			if strings.TrimSpace(item) == "" {
				break
			}
			items = append(items, item)
		}
		return strings.Join(items, "\n"), true
	}
	return "", false
}

// sourcesTodayFacts — вход предиката; собран так, чтобы предикат гонялся
// инъекцией без правки дерева.
type sourcesTodayFacts struct {
	// WriterCalls — не-тестовые вызовы писателя записи выпуска в дереве.
	WriterCalls int
	// WriterMounted — хотя бы один из этих вызовов лежит в пакете, который
	// собирает композиционный корень службы.
	WriterMounted bool
	// List — перечень источников «сегодня» из шапки службы.
	List string
}

// auditSourcesToday — находки; пусто = перечень и дерево согласны.
func auditSourcesToday(f sourcesTodayFacts) []string {
	listed := sourceMarker[sourceFamily].MatchString(f.List)
	caveat := unmountedCaveat.MatchString(f.List)
	switch {
	case listed && f.WriterCalls == 0:
		return []string{fmt.Sprintf("перечень «%s» называет отзыв семейства, а писателя записи "+
			"выпуска %s в дереве не зовёт ни один не-тестовый вызов: ни один токен семейству "+
			"не принадлежит, и этот источник до ответа IsRevoked не доходит",
			producedTodayHeading, issuanceWriter)}
	case !listed && f.WriterCalls > 0:
		return []string{fmt.Sprintf("писатель записи выпуска %s позван (%d), а перечень «%s» "+
			"отзыва семейства не называет: оговорка «на этой ревизии не производится» "+
			"пережила свой предмет", issuanceWriter, f.WriterCalls, producedTodayHeading)}
	case listed && !f.WriterMounted && !caveat:
		return []string{fmt.Sprintf("перечень «%s» называет отзыв семейства, а писателя записи "+
			"выпуска %s зовут только пакеты, которых корень %s не собирает, и оговорки о "+
			"несобранной церемонии нет: контракт обещает источник, который до ответа IsRevoked "+
			"не доходит", producedTodayHeading, issuanceWriter, serviceRoot)}
	case caveat && f.WriterMounted:
		return []string{fmt.Sprintf("писателя записи выпуска %s зовёт пакет, который корень %s "+
			"собирает, а перечень «%s» по-прежнему говорит, что церемония не собрана: "+
			"оговорка о несобранной церемонии пережила свой предмет",
			issuanceWriter, serviceRoot, producedTodayHeading)}
	}
	return nil
}

// treeSourcesToday — факты дерева и перепись для печати.
func treeSourcesToday(t *testing.T) (sourcesTodayFacts, check.FamilyVerdictCensus) {
	t.Helper()
	root := platformtree.Require(t)
	files, err := check.ProdGoFiles(root)
	require.NoError(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева не прочитан")
	census, err := check.FamilyVerdict(files)
	require.NoError(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: перепись не собрана")

	sources := map[string]any{}
	for _, rel := range stubFiles {
		sources[filepath.Join(root, filepath.FromSlash(rel))] = nil
	}
	list, ok := producedTodayList(contractTexts(t, sources)[textService])
	require.Truef(t, ok, "в шапке службы нет заголовка %q — предпосылка сломана: "+
		"судить, где назван источник, не по чему", producedTodayHeading)

	built := rootBuilds(t, root)
	// ПРЕДПОСЫЛКА замыкания: пакет, объявляющий писателя (хранилище службы),
	// корень собирает. Не дошло — замыкание слепо, и «не собирает» о вызовах
	// ниже ничего не значит.
	for _, d := range census.WriterDecls {
		require.Truef(t, built[path.Dir(d.File)], "проверка НЕ ИСПОЛНЯЛАСЬ: замыкание импортов корня %s "+
			"не дошло до пакета писателя %s (%s)", serviceRoot, issuanceWriter, d.File)
	}
	mounted := false
	for _, c := range census.WriterCalls {
		if built[path.Dir(c.File)] {
			mounted = true
		}
	}
	t.Logf("корень %s собирает каталогов модуля %d", serviceRoot, len(built))
	return sourcesTodayFacts{WriterCalls: len(census.WriterCalls), WriterMounted: mounted, List: list}, census
}

// moduleImportPrefix — префикс импорта пакетов этого модуля.
const moduleImportPrefix = "github.com/PRO-Robotech/kaname/"

// rootBuilds — каталоги модуля, которые собирает корень службы: замыкание по
// импортам не-тестовых файлов каталогов `cmd`, `internal` и `pkg`, начиная с
// корня. Каталог — путь относительно корня модуля в косой записи.
func rootBuilds(t *testing.T, root string) map[string]bool {
	t.Helper()
	imports := map[string]map[string]bool{}
	fset := token.NewFileSet()
	for _, d := range []string{"cmd", "internal", "pkg"} {
		paths, err := treecorpus.UnderWithSuffix(filepath.Join(root, d), ".go")
		require.NoError(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: состав %s не прочитан", d)
		for _, p := range paths {
			if strings.HasSuffix(p, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, p, nil, parser.ImportsOnly)
			require.NoError(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: импорты %s не разобраны", p)
			rel, err := filepath.Rel(root, filepath.Dir(p))
			require.NoError(t, err)
			dir := filepath.ToSlash(rel)
			if imports[dir] == nil {
				imports[dir] = map[string]bool{}
			}
			for _, spec := range f.Imports {
				ip, err := strconv.Unquote(spec.Path.Value)
				require.NoError(t, err)
				if dep, ok := strings.CutPrefix(ip, moduleImportPrefix); ok {
					imports[dir][dep] = true
				}
			}
		}
	}
	require.NotEmptyf(t, imports[serviceRoot], "проверка НЕ ИСПОЛНЯЛАСЬ: корень %s не прочитан либо "+
		"не импортирует ни одного пакета модуля — «не собирает» перестало что-либо значить", serviceRoot)
	return importClosure(imports, serviceRoot)
}

// importClosure — каталоги, достижимые из from по рёбрам импорта (from
// включительно).
func importClosure(imports map[string]map[string]bool, from string) map[string]bool {
	built := map[string]bool{}
	queue := []string{from}
	for len(queue) > 0 {
		dir := queue[0]
		queue = queue[1:]
		if built[dir] {
			continue
		}
		built[dir] = true
		for dep := range imports[dir] {
			queue = append(queue, dep)
		}
	}
	return built
}

// TestContractListsFamilyAsProducedTodayOnlyWhenIssuanceIsRecorded — гейт на
// дереве.
func TestContractListsFamilyAsProducedTodayOnlyWhenIssuanceIsRecorded(t *testing.T) {
	facts, census := treeSourcesToday(t)

	// ПРЕДПОСЫЛКИ: «ноль находок» обязано быть отличимо от «ноль прочитанного».
	require.NotZero(t, census.FilesParsed, "обход дал ноль файлов — это «не смотрели», а не «чисто»")
	require.NotEmptyf(t, census.WriterDecls, "объявления писателя %s в дереве нет: «вызовов ноль» "+
		"перестало что-либо значить", issuanceWriter)
	items := 0
	for _, l := range strings.Split(facts.List, "\n") {
		if listItem.MatchString(l) {
			items++
		}
	}
	require.NotZero(t, items, "перечень «сегодня» прочитан без единого пункта — читается не то")

	found := auditSourcesToday(facts)
	require.Emptyf(t, found, "перечень источников отзыва расходится с деревом:\n  %s\n"+
		"Правится комментарий в proto/kaname/cloud/iam/v1/session_revocations_service.proto "+
		"и перегенерируются заглушки (make proto-gen).", strings.Join(found, "\n  "))

	t.Logf("осмотрено: файлов %d, объявлений писателя %s %d, его вызовов %d (в пакетах, которые "+
		"собирает %s: %v); пунктов перечня «сегодня» %d, семейство в перечне: %v, оговорка о "+
		"несобранной церемонии: %v", census.FilesParsed, issuanceWriter,
		len(census.WriterDecls), facts.WriterCalls, serviceRoot, facts.WriterMounted, items,
		sourceMarker[sourceFamily].MatchString(facts.List), unmountedCaveat.MatchString(facts.List))
}
