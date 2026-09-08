// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain_test

// blocked_state_reachability_test.go — гейт на связку «запрет ↔ путь снятия».
//
// Восстановление пароля не снимает административную блокировку (продуктовое
// решение: самостоятельное действие не отменяет административное). Решение полно
// ровно до тех пор, пока у запрета есть административный путь СНЯТИЯ: иначе
// заблокированный оказался бы заперт навсегда.
//
// ЧТО ИЗМЕНИЛОСЬ. Писатель запрета теперь СУЩЕСТВУЕТ — `UserService.Block` /
// `Unblock` (use-case `internal/apps/kaname/api/user/set_blocked.go`, запись
// `userWriter.SetInviteStatus`). Прежняя редакция этого комментария утверждала,
// что продуктового пути нет вовсе; с посадкой действий это стало бы ложью, а
// комментарий, противоречащий коду, — ловушка: следующий читатель «починит» код
// под неверное описание. Гейт с тех пор проверяет не «писателей нет», а «каждый
// писатель ОБЪЯВЛЕН и назвал путь снятия» — см. blockedWriters.
//
// Зачем это по-прежнему гейт: путей записи может появиться второй (групповая
// блокировка, импорт, административный сценарий в другом слое), и он способен
// приехать БЕЗ обратного направления. Тогда человек снова заперт. Гейт делает
// такое изменение упавшей сборкой, а не открытием.
//
// Форма, которую писатель обязан принять, посажена на машинном двойнике
// (`ServiceAccountService.Disable`/`Enable`) и повторена здесь: состояние доступа
// меняется ДЕЙСТВИЕМ, а не изменяемым полем. Довод переносится дословно — при
// пустой маске конвенция предписывает полную замену объекта, а enum в proto3
// неотличим от незаданного, поэтому клиент, не приславший поле, отключил бы
// личность тихо и массово. Действие вдобавок видно в аудите событием, несёт ярус
// повышенной аутентификации (это изменение постуры безопасности) и идемпотентно
// по построению, потому что аргумент — состояние, а не переход.
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

// blockedWriters — известные и обоснованные места, которые ЗАПИСЫВАЮТ состояние
// членства. Ключ — путь в форме, которую даёт filepath.Walk от scanRoots;
// значение — административный путь СНЯТИЯ, ради которого запись разрешена.
//
// Запись без такой ссылки смысла не имеет: гейт существует ровно для того, чтобы
// запрет и путь его снятия появлялись вместе.
var blockedWriters = map[string]string{
	"../../internal/repo/kaname/pg/user_repo.go": "UserService.Unblock — административное снятие " +
		"(use-case services/iam/internal/apps/kaname/api/user/set_blocked.go, " +
		"право identity_suspender@iam_user = админ аккаунта + каскад облака). Писатель — " +
		"userWriter.SetInviteStatus; тот же метод обслуживает и снятие, поэтому " +
		"односторонним контроль быть не может by construction.",
}

// scanRoots — поддеревья продуктового кода iam, в которых ищется писатель.
var scanRoots = []string{
	"../../internal",
	"../../cmd",
}

// blockedWriteMarkers — синтаксические формы, которыми состояние можно ЗАПИСАТЬ.
//
// ФОРМА ЗАПИСИ, А НЕ ТОЛЬКО ЗНАЧЕНИЕ (иначе гейт слеп ровно к тому писателю, для
// которого построен). Целевое состояние законно приходит bind-параметром
// (`SET invite_status = $2`), и тогда НИ ОДИН маркер по значению его не увидит:
// в файле нет ни литерала `'BLOCKED'`, ни константы рядом с присваиванием. Это не
// теория — так и вышло: писатель `userWriter.SetInviteStatus` уже жил в дереве, а
// гейт по маркерам-значениям печатал «при нуле писателей». Поэтому маркер
// `SET invite_status =` ловит саму запись колонки, независимо от того, откуда
// берётся значение.
//
// ЧТО ЭТИ МАРКЕРЫ ДЕЛАЮТ С ЧТЕНИЕМ — честно, без обещаний, которых код не даёт.
// Маркеры по значению — подстрочные, и подстрока `'BLOCKED')` встречается не
// только в записи: предикат-перечисление вида `IN ('ACTIVE','BLOCKED')` её
// содержит и БУДЕТ находкой. Прежняя редакция этого комментария утверждала
// обратное; утверждение никогда не исполнялось (такой формы в дереве не было) и
// стало бы ложью в момент посадки писателя. Следствие для продуктового кода:
// предикат состояния пишется через bind (`= ANY($1)`) либо через отрицание
// (`<> 'PENDING'`) — так он и написан. Чтение через сравнение с константой
// (`st == InviteStatusBlocked`) маркерам не подходит вовсе и находкой не является;
// именно его считает вторая проба ниже.
//
// Обе стороны — и слепая зона по bind-параметру, и молчание на честном чтении —
// доказаны инъекцией в TestBlockedState_GateSeesAnInjectedWriter.
var blockedWriteMarkers = []string{
	"SET invite_status =", // запись колонки; значение может быть bind-параметром
	"set invite_status =",
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
			body, rerr := os.ReadFile(path)
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
		"НЕОБЪЯВЛЕННЫЙ писатель состояния членства: %v\n\n"+
			"Самостоятельное восстановление пароля запрет НЕ снимает (осознанное решение —\n"+
			"см. internal/apps/kaname/api/user/internal_on_recovery.go). Значит у КАЖДОГО пути\n"+
			"записи обязан быть административный путь снятия, иначе заблокированный\n"+
			"оказывается заперт навсегда.\n\n"+
			"Форму бери с уже посаженной пары UserService.Block/Unblock\n"+
			"(services/iam/internal/apps/kaname/api/user/set_blocked.go): ДЕЙСТВИЕ с операцией,\n"+
			"а не поле маски; идемпотентно по состоянию, а не по переходу; событие в аудит;\n"+
			"ярус повышенной аутентификации. Затем впиши файл в blockedWriters вместе со\n"+
			"ссылкой на путь снятия — объявление и есть то, что этот гейт требует.", found)
}

// TestBlockedState_ReadersExistWhichIsWhyTheWriterMatters — число, а не память:
// у запрета есть читатели, решающие доступ, и это ровно то, что делает
// отсутствие писателя предметом, а не мелочью. Проба падает, если читатели
// исчезнут: тогда и весь этот гейт теряет предмет.
func TestBlockedState_ReadersExistWhichIsWhyTheWriterMatters(t *testing.T) {
	readers := 0
	scanned := 0
	for _, root := range scanRoots {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(info.Name(), ".go") ||
				strings.HasSuffix(info.Name(), "_test.go") {
				return nil
			}
			body, rerr := os.ReadFile(path)
			if rerr != nil {
				return rerr
			}
			scanned++
			if strings.Contains(string(body), "InviteStatusBlocked") {
				readers++
			}
			return nil
		})
		require.NoError(t, err)
	}
	require.Greater(t, scanned, 100, "прочитано %d файлов — дерево не то", scanned)
	require.Greater(t, readers, 0,
		"у BLOCKED не осталось ни одного читателя — тогда состояние вообще ни на что не влияет, "+
			"и связку «запрет ↔ путь снятия» надо пересматривать целиком")
	t.Logf("BLOCKED: файлов-читателей=%d; объявленных писателей=%d (все с названным путём "+
		"снятия — см. гейт выше); осмотрено файлов=%d", readers, len(blockedWriters), scanned)
}

// TestBlockedState_GateSeesAnInjectedWriter — доказательство в ОБЕ стороны: гейт
// краснеет на настоящем писателе (в том числе на том, чьё значение приходит
// bind-параметром) и молчит на честном чтении. Без второй половины он ловил бы
// форму, а не существо, и первый же ложный срабат его отключил бы.
func TestBlockedState_GateSeesAnInjectedWriter(t *testing.T) {
	writers := map[string]string{
		"литерал в UPDATE": "	q := `UPDATE users SET invite_status = 'BLOCKED' WHERE id = $1`",
		// Регрессия на реальную слепую зону: значение приходит параметром, поэтому
		// ни один маркер по значению его не видит. Ровно так живой писатель
		// проходил мимо гейта, пока тот печатал «при нуле писателей».
		"bind-параметр":       "	q := `UPDATE users SET invite_status = $2 WHERE id = $1`",
		"строчный SET":        "	q := `update users set invite_status = $2 where id = $1`",
		"литерал в INSERT":    "	q := `INSERT INTO users (id, invite_status) VALUES ($1, 'BLOCKED')`",
		"структура домена":    "	u.InviteStatus = domain.InviteStatusBlocked",
		"композитный литерал": "	u := domain.User{InviteStatus: domain.InviteStatusBlocked}",
	}
	for name, src := range writers {
		t.Run("находка/"+name, func(t *testing.T) {
			require.True(t, containsBlockedWrite(src),
				"гейт обязан увидеть запись состояния в форме %q", name)
		})
	}

	reads := map[string]string{
		"предикат через bind":    "	q := `SELECT id FROM users WHERE invite_status = ANY($1)`",
		"предикат-отрицание":     "	q := `UPDATE users SET labels = $2 WHERE invite_status <> 'PENDING'`",
		"сравнение с константой": "	if st == domain.InviteStatusBlocked { return errBlocked }",
		"switch по состоянию":    "	case domain.InviteStatusBlocked:",
	}
	for name, src := range reads {
		t.Run("молчание/"+name, func(t *testing.T) {
			require.False(t, containsBlockedWrite(src),
				"чтение состояния в форме %q находкой не является", name)
		})
	}

	// Предпосылка самого маркера-формы: он обоснован тем, что боевой писатель
	// действительно пишет колонку этой конструкцией. Переедет писатель на другую
	// форму — маркер станет мёртвым, а гейт снова слепым, и заметить это должен
	// он сам, а не следующий инцидент.
	body, err := os.ReadFile("../../internal/repo/kaname/pg/user_repo.go")
	require.NoError(t, err, "боевой писатель состояния обязан существовать по этому пути")
	require.Contains(t, string(body), "SET invite_status =",
		"маркер формы записи обоснован тем, что писатель пользуется именно этой "+
			"конструкцией; если он переехал — правь маркер вместе с ним")
}

func containsBlockedWrite(text string) bool {
	for _, marker := range blockedWriteMarkers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}
