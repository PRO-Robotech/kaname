// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain_test

// blocked_state_reachability_test.go — гейт на связку «запрет ↔ путь снятия».
//
// Восстановление пароля больше не снимает административную блокировку (это
// продуктовое решение: самостоятельное действие не отменяет административное).
// Решение полно ровно до тех пор, пока верна его предпосылка: **в продуктовом
// коде нет пути, который ставит BLOCKED**. Сегодня запрет ставится только
// прямым вмешательством оператора в базу — и у того же оператора есть обратное
// утверждение, поэтому запертых по построению нет.
//
// Предпосылка может измениться молча: кто-нибудь добавит администратору
// возможность заблокировать пользователя — и человек окажется заперт навсегда,
// потому что снимать запрет будет нечем. Этот гейт превращает такое изменение
// из открытия в упавшую сборку: появился писатель BLOCKED — в том же изменении
// обязан появиться административный путь снятия, а здесь обязана появиться
// строка, называющая его.
//
// Гейт проверяет СВОЮ предпосылку и объявляет объём осмотренного: если он не
// прочитал ни одного файла (переехало дерево, сменилось имя пакета), он падает
// — «ноль находок» обязано быть отличимо от «ноль прочитанного».

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// blockedWriters — известные и обоснованные места, которые упоминают BLOCKED
// как ЗАПИСЫВАЕМОЕ значение. Пусто: продуктового пути блокировки нет.
//
// Появится путь — сюда добавляется его файл ВМЕСТЕ со ссылкой на
// административный путь снятия. Запись без такой ссылки смысла не имеет:
// исключение живёт, пока у него есть предмет.
var blockedWriters = map[string]string{}

// scanRoots — поддеревья продуктового кода iam, в которых ищется писатель.
var scanRoots = []string{
	"../../internal",
	"../../cmd",
}

// blockedWriteMarkers — синтаксические формы, которыми состояние можно ЗАПИСАТЬ.
// Чтение (`invite_status = ANY(...)`, `IN ('ACTIVE','BLOCKED')`, сравнение с
// domain.InviteStatusBlocked) сюда не попадает — гейт ловит присваивание.
var blockedWriteMarkers = []string{
	"invite_status = 'BLOCKED'",
	"invite_status='BLOCKED'",
	"InviteStatus = domain.InviteStatusBlocked",
	"InviteStatus: domain.InviteStatusBlocked",
	"InviteStatus = InviteStatusBlocked",
	"InviteStatus: InviteStatusBlocked",
	"'BLOCKED')", // INSERT ... VALUES (..., 'BLOCKED')
}

func TestBlockedState_HasNoProductWriterWithoutALiftPath(t *testing.T) {
	var (
		scanned int
		found   []string
	)
	for _, root := range scanRoots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() {
				return nil
			}
			name := info.Name()
			isGo := strings.HasSuffix(name, ".go") && !strings.HasSuffix(name, "_test.go")
			isSQL := strings.HasSuffix(name, ".sql")
			if !isGo && !isSQL {
				return nil
			}
			body, rerr := os.ReadFile(path) //nolint:gosec // фиксированное дерево репозитория
			if rerr != nil {
				return rerr
			}
			scanned++
			text := string(body)
			for _, marker := range blockedWriteMarkers {
				if !strings.Contains(text, marker) {
					continue
				}
				rel := filepath.ToSlash(path)
				if _, ok := blockedWriters[rel]; ok {
					break // объявлено и обосновано
				}
				found = append(found, rel+" → "+marker)
				break
			}
			return nil
		})
		require.NoError(t, err, "обход %s", root)
	}

	// Перепись осмотренного — отдельное утверждение: «ноль находок» не должно
	// быть неотличимо от «ноль прочитанных файлов».
	require.Greater(t, scanned, 100,
		"гейт прочитал %d файлов — это не похоже на дерево iam; проверь scanRoots", scanned)

	require.Empty(t, found,
		"появился путь, ставящий BLOCKED: %v\n\n"+
			"Самостоятельное восстановление пароля запрет НЕ снимает (осознанное решение —\n"+
			"см. internal/apps/kacho/api/user/internal_on_recovery.go). Значит вместе с путём\n"+
			"блокировки в ТОМ ЖЕ изменении обязан появиться административный путь снятия,\n"+
			"иначе заблокированный оказывается заперт навсегда. Добавив его, впиши файл в\n"+
			"blockedWriters вместе со ссылкой на путь снятия.", found)
}

// TestBlockedState_GateSeesAnInjectedWriter — доказательство обратной стороны:
// гейт краснеет на настоящем писателе и молчит на чтении той же формы. Без этой
// пары он ловил бы форму, а не существо.
func TestBlockedState_GateSeesAnInjectedWriter(t *testing.T) {
	write := "	q := `UPDATE users SET invite_status = 'BLOCKED' WHERE id = $1`"
	read := "	q := `SELECT id FROM users WHERE invite_status = ANY($1)`"

	require.True(t, containsBlockedWrite(write), "гейт обязан увидеть запись состояния")
	require.False(t, containsBlockedWrite(read), "чтение того же поля находкой не является")
}

func containsBlockedWrite(text string) bool {
	for _, marker := range blockedWriteMarkers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}
