// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

// seeded_id_exception_subject_test.go — у КАЖДОЙ записи закрытого перечня
// `domain.SeededResourceIDs()` обязан быть ПРЕДМЕТ. Гейт задачи #1808.
//
// # ЗАЧЕМ
//
// Перечень расширяет приём проверки формы: `shared.ValidateResourceID`
// принимает названный им литерал вопреки длине. Такое послабление обязано
// истекать САМО, иначе оно переживёт свой предмет и станет слепой зоной —
// следующий негодный посев уедет под чужую запись незамеченным.
//
// # ДВА УСЛОВИЯ, И КАЖДОЕ САМОСТОЯТЕЛЬНО
//
//  1. литерал ПОСЕЯН миграцией. Запись, которую больше не сеет ничто, называет
//     несуществующее — и снимается вместе с посевом;
//  2. чеканная форма его ОТВЕРГАЕТ. Запись про литерал, который форма и так
//     принимает, не прощает ничего — и снимается как лишняя.
//
// # ПОЧЕМУ ЭТО НЕ ВТОРОЕ МЕСТО ОБ ОДНОМ ПРЕДМЕТЕ
//
// У проверки пути запроса ДВА плеча: чеканная форма ЛИБО перечень посеянного.
// Здесь спрашивается ПЕРВОЕ плечо отдельно — вопрос, которого сам путь запроса
// не задаёт никогда. Настоящей функцией его задать нельзя by construction: она
// отвечает «принято» по второму плечу, то есть на другой вопрос.

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho/pkg/treecorpus"
)

// exceptionCensus — объём осмотренного.
type exceptionCensus struct {
	filesRead    int // файлов миграций прочитано
	seededValues int // значений колонки `id`, извлечённых из посевов
	pinned       int // записей перечня
	withSubject  int // из них с предметом по обоим условиям
}

// mintedFormRejects — судит литерал ПЕРВЫМ плечом: чеканной формой его
// префикса. Слитная форма — длина `domain.ShortIDLen`; разделительные — длина
// префикса плюс разделитель плюс тело.
func mintedFormRejects(lit string) (bool, string) {
	m, known := formOfPrefix(lit)
	if !known {
		return true, "семейство литерала не названо таблицей форм — идентификатором ресурса iam он не является"
	}
	if m.form == mintConcatenated {
		if len(lit) != domain.ShortIDLen {
			return true, fmt.Sprintf("длина %d при чеканных %d", len(lit), domain.ShortIDLen)
		}
		return false, ""
	}
	want := len(m.prefix) + len(m.form.separator()) + kac127BodyLen
	if len(lit) != want {
		return true, fmt.Sprintf("длина %d, а форма префикса %q требует %d", len(lit), m.prefix, want)
	}
	return false, ""
}

// auditSeededIDExceptions — чистое ядро обеих проб.
func auditSeededIDExceptions(migrations map[string]string, pinned []string) ([]string, exceptionCensus) {
	var findings []string
	c := exceptionCensus{filesRead: len(migrations), pinned: len(pinned)}

	// какие литералы дерево ДЕЙСТВИТЕЛЬНО сеет
	seeded := map[string]bool{}
	names := make([]string, 0, len(migrations))
	for n := range migrations {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		for _, m := range reSingleLineInsert.FindAllStringSubmatch(migrations[n], -1) {
			cols := strings.Split(m[2], ",")
			vals := splitSQLValues(m[3])
			if len(cols) != len(vals) {
				continue
			}
			for i, col := range cols {
				if strings.TrimSpace(col) != "id" {
					continue
				}
				raw := vals[i]
				if len(raw) < 2 || raw[0] != '\'' || raw[len(raw)-1] != '\'' {
					continue
				}
				c.seededValues++
				seeded[strings.ReplaceAll(raw[1:len(raw)-1], "''", "'")] = true
			}
		}
	}

	sorted := append([]string(nil), pinned...)
	sort.Strings(sorted)
	for _, lit := range sorted {
		ok := true
		if !seeded[lit] {
			findings = append(findings, fmt.Sprintf(
				"ЗАПИСИ НЕЧЕГО ПРОЩАТЬ: перечень посеянного называет %q, а ни одна миграция "+
					"его не сеет — запись пережила свой предмет и снимается", lit))
			ok = false
		}
		if rejected, why := mintedFormRejects(lit); !rejected {
			findings = append(findings, fmt.Sprintf(
				"ЗАПИСЬ ЛИШНЯЯ: %q принимается чеканной формой и без перечня — послабление "+
					"не прощает ничего и снимается", lit))
			ok = false
		} else {
			_ = why
		}
		if ok {
			c.withSubject++
		}
	}
	return findings, c
}

// TestSeededIDExceptionsHaveASubject — несущее утверждение по НАСТОЯЩЕМУ дереву.
func TestSeededIDExceptionsHaveASubject(t *testing.T) {
	root := monorepoRoot(t)
	paths, err := treecorpus.UnderWithSuffix(root+"/"+iamMigrationsDir, ".sql")
	require.NoError(t, err)

	migrations := map[string]string{}
	for _, p := range paths {
		raw, readErr := os.ReadFile(p) // #nosec G304 -- путь пришёл из индекса git каталога миграций
		require.NoError(t, readErr)
		migrations[p[strings.LastIndex(p, "/")+1:]] = string(raw)
	}

	findings, c := auditSeededIDExceptions(migrations, domain.SeededResourceIDs())

	t.Logf("перепись: файлов миграций %d · значений колонки id %d · записей перечня %d "+
		"(с предметом %d) · находок %d",
		c.filesRead, c.seededValues, c.pinned, c.withSubject, len(findings))

	require.NotZerof(t, c.filesRead, "обход миграций пуст — вердикт беспредметен (%s)", iamMigrationsDir)
	require.NotZero(t, c.seededValues,
		"ни одного посеянного идентификатора не извлечено — разбор перестал узнавать посев, "+
			"и «предмета нет» стало неотличимо от «не прочитано»")

	// ПУСТОЙ перечень — законная цель, а не поломка: он опустеет, когда посевы
	// станут чеканными. Поэтому непустоты перечня здесь НЕ требуется.
	require.Emptyf(t, findings, "запись перечня посеянного потеряла предмет:\n%s",
		strings.Join(findings, "\n"))
}
