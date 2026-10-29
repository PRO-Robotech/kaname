// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package contracttext

// page_size_default_test.go — каждое поле `page_size` контракта называет то
// умолчание страницы, которое служба применяет на `0`, и только его (kaname#755).
//
// # Предмет
//
// Служба на каждом List применяет одно умолчание: `0` → 50 (общий помощник
// `shared.EffectiveListPageSize`, репозиторный `effectivePageSize`, у операций —
// `corevalidate.PageSize` фундамента). Контракт при этом говорил в одних
// сообщениях «Default value: 100», в других «0 selects the platform default
// (50)». Интегратор, читающий контракт, ждал бы сто строк и получал пятьдесят.
//
// # Класс, а не экземпляр
//
// Судится КАЖДОЕ поле `PageSize` каждого сообщения-запроса контракта, а не
// названные в задаче четыре файла: умолчание — одно на службу, и второе
// написание в любом сообщении — тот же дефект.
//
// # Граница
//
// Проба судит, что названное в прозе число — это умолчание службы, и что
// умолчание названо. Она не отличает «названо верно» от «названо в отрицании»
// («не 100, а 50» прошло бы, назвав 100) — верность формулировки держит ревью.

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	corevalidate "github.com/PRO-Robotech/corelib/validate"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
)

// pageSizeOwnDefault — поля, чей List применяет НЕ умолчание службы, и число,
// которое он применяет на деле. Число берётся из кода, а не выписывается:
// разойдись код и контракт — проба краснеет.
//
// Пустой перечень — цель, а не отказ: каждое поле судится умолчанием службы.
// Последняя запись (`ListSubjectsRequest.PageSize`, 500 из разбора модели)
// снята приёмкой kaname#615 (LSP-10): глагол применяет правило платформы, и
// его поле судится тем же числом, что прочие.
var pageSizeOwnDefault = map[string]int{}

// namedDefault — число, которое проза называет умолчанием: «Default value: N»,
// «default N», «platform default (N)».
var namedDefault = regexp.MustCompile(`(?i)\bdefault\b(?:\s+value)?\s*[:(]?\s*\(?(\d+)\)?`)

// pageSizeDefaultFindings — находки по полям `PageSize`; пусто = контракт
// называет ровно умолчание службы в каждом поле.
func pageSizeDefaultFindings(texts stubTexts, serviceDefault int, own map[string]int) (found []string, judged int) {
	keys := make([]string, 0, len(texts))
	for k := range texts {
		if strings.HasSuffix(k, "Request.PageSize") {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	for _, k := range keys {
		judged++
		want := serviceDefault
		if n, ok := own[k]; ok {
			want = n
		}
		text := oneLine(texts[k])
		ms := namedDefault.FindAllStringSubmatch(text, -1)
		if len(ms) == 0 {
			found = append(found, k+": умолчание страницы не названо")
			continue
		}
		for _, m := range ms {
			n, err := strconv.Atoi(m[1])
			if err != nil || n != want {
				found = append(found, fmt.Sprintf("%s: названо умолчание %s, служба применяет %d", k, m[1], want))
			}
		}
	}
	return found, judged
}

// TestPageSizeContractNamesTheDefaultTheServiceApplies — гейт на дереве.
func TestPageSizeContractNamesTheDefaultTheServiceApplies(t *testing.T) {
	// ПРЕДПОСЫЛКА: умолчание службы одно. Помощник службы и фундамент —
	// два написания одного числа; разойдись они, судить контракт было бы не по
	// чему.
	require.EqualValues(t, corevalidate.DefaultPageSize, shared.DefaultListPageSize,
		"умолчание страницы службы и фундамента разошлись — предпосылка пробы сломана")

	texts := readStubTexts(t)
	found, judged := pageSizeDefaultFindings(texts, shared.DefaultListPageSize, pageSizeOwnDefault)
	t.Logf("осмотрено полей page_size: %d", judged)
	require.Greater(t, judged, 0, "не прочитано ни одного поля page_size — перепись меряет не то")
	require.Emptyf(t, found, "контракт называет не то умолчание страницы:\n  %s\n"+
		"Правится комментарий поля в proto/kaname/cloud/iam/v1/*.proto, заглушки — регенерацией.",
		strings.Join(found, "\n  "))
}

// TestPageSizeDefaultPredicateInjection — предикат краснеет на дефекте и молчит
// на исправном тексте.
func TestPageSizeDefaultPredicateInjection(t *testing.T) {
	for _, tc := range []struct {
		name, text string
		red        bool
	}{
		{"чужое число", "The maximum number of results per page to return. Default value: 100.", true},
		{"не названо", "The maximum number of results per page to return.", true},
		{"два числа, одно чужое", "Default value: 50. Default 100 for old clients.", true},
		{"верное, форма Default value", "The maximum number of results per page to return. Default value: 50.", false},
		{"верное, форма platform default", "0 selects the platform default (50), max 1000.", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			found, judged := pageSizeDefaultFindings(stubTexts{"ListThingsRequest.PageSize": tc.text}, 50, nil)
			require.Equal(t, 1, judged)
			if tc.red {
				require.NotEmpty(t, found)
			} else {
				require.Empty(t, found)
			}
		})
	}
}

// TestPageSizeOwnDefaultIsJudgedAgainstItsOwnNumber — запись исключения судит
// поле по ЕГО числу, а не освобождает от суда: умолчание службы на таком поле —
// находка, своё число — нет.
func TestPageSizeOwnDefaultIsJudgedAgainstItsOwnNumber(t *testing.T) {
	own := map[string]int{"ListThingsRequest.PageSize": 500}
	found, _ := pageSizeDefaultFindings(stubTexts{"ListThingsRequest.PageSize": "Page size; default 50."}, 50, own)
	require.NotEmpty(t, found)
	found, _ = pageSizeDefaultFindings(stubTexts{"ListThingsRequest.PageSize": "Page size; default 500, max 1000."}, 50, own)
	require.Empty(t, found)
}
