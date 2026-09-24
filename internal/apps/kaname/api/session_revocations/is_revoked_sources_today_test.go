// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package session_revocations

// is_revoked_sources_today_test.go — перечень «источники отзыва, какими их
// производит дерево сегодня» в контракте службы называет отзыв семейства ровно
// тогда, когда дерево пишет запись выпуска (kaname#319, находка ревью
// GSR-319-4).
//
// # Предмет
//
// Ответ `IsRevoked` судит семейство только у выпуска, чья запись лежит в таблице
// выпусков, а запись пишет выпуск церемонии вызовом писателя `RecordAccessToken`
// (провязка — kaname#396). Пока в дереве нет ни одного не-тестового вызова
// писателя, ни один токен не принадлежит семейству, и отзыв семейства ни до
// одного ответа не доходит. Контракт, числящий его среди источников «сегодня»,
// обещает источник, который не приходит, — ровно то, от чего шапка службы
// предостерегает на примере снятых приёмников.
//
// # В обе стороны
//
//   - писатель не позван, а перечень «сегодня» называет семейство — находка;
//   - писатель позван, а перечень «сегодня» семейства не называет — тоже
//     находка: оговорка «на этой ревизии не производится» пережила свой предмет.
//
// # Что читается
//
//   - вызовы писателя — перепись гейта `internal/check` (`check.FamilyVerdict`,
//     поле `WriterCalls`) над составом `check.ProdGoFiles`: у факта одна мерка,
//     своего обхода здесь нет;
//   - перечень — строки шапки службы в порождённой заглушке от заголовка
//     перечня до первой пустой строки. Заголовок не найден — предпосылка
//     сломана, а не «перечень пуст».
//
// # Граница
//
// Гейт судит, В КАКОМ месте названо семейство — в перечне «сегодня» или вне
// его, — а не верность оговорки вне перечня. Порядок «запись до ответа клиенту»
// держит сквозная проба выпуска (kaname#396), не этот гейт.

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// producedTodayHeading — заголовок перечня источников «сегодня» в шапке службы.
const producedTodayHeading = "Revocation sources, as the tree produces them today:"

// issuanceWriter — писатель записи выпуска; без его вызова семейству отвечать
// не о чем.
const issuanceWriter = "RecordAccessToken"

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
	// List — перечень источников «сегодня» из шапки службы.
	List string
}

// auditSourcesToday — находки; пусто = перечень и дерево согласны.
func auditSourcesToday(f sourcesTodayFacts) []string {
	listed := sourceMarker[sourceFamily].MatchString(f.List)
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
	return sourcesTodayFacts{WriterCalls: len(census.WriterCalls), List: list}, census
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

	t.Logf("осмотрено: файлов %d, объявлений писателя %s %d, его вызовов %d; пунктов перечня "+
		"«сегодня» %d, семейство в перечне: %v", census.FilesParsed, issuanceWriter,
		len(census.WriterDecls), facts.WriterCalls, items,
		sourceMarker[sourceFamily].MatchString(facts.List))
}
