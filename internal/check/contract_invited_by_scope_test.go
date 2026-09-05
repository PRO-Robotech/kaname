// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Два поля отвечают на вопрос «кто пригласил», и области у них РАЗНЫЕ.
//
// # ПРЕДМЕТ
//
// `User.invited_by` называет того, кто завёл ЛИЧНОСТЬ на платформе: значение
// пишется один раз и последующими приглашениями не меняется.
// `Membership.invited_by` называет того, кто позвал человека В ЭТОТ АККАУНТ, и у
// одного человека таких значений столько, сколько у него членств.
//
// Значения одного типа, одного имени и оба верны — различить их по ответу нельзя
// ничем. Кадровый контур прочтёт поле как «кто ввёл человека в организацию», а
// `User.invited_by` назовёт поручителя из ЧУЖОГО арендатора. Цена не в
// отображении: на такое поле ключуются согласование и отчётность, и ошибка
// проявится там, где её никто не ищет.
//
// # ЧТО ИМЕННО ТРЕБУЕТСЯ, И ПОЧЕМУ НЕ «ЕСТЬ КОММЕНТАРИЙ»
//
// Комментарий у обоих полей был и до правки — он просто не называл область.
// Поэтому гейт требует ТРЁХ вещей сразу, и ни одна не выводится из остальных:
//
//  1. область ОБЪЯВЛЕНА дословной приметой `ОБЛАСТЬ — <…>`;
//  2. объявленные области РАЗЛИЧАЮТСЯ — иначе «различие не объявлено» вернулось
//     бы в форме «объявлено одно и то же дважды». КАКОЕ именно слово стоит у
//     каждого поля, гейт не предписывает: он судит наличие объявления и его
//     различность, а не выбирает термин за автора;
//  3. каждый комментарий НАЗЫВАЕТ БЛИЗНЕЦА по полному имени — читатель, дошедший
//     до одного поля, обязан узнать о существовании второго, иначе объявление
//     области его ни от чего не спасает.
//
// # ГРАНИЦА
//
// Гейт судит ОБЪЯВЛЕНИЕ, а не его истинность: сказать «ОБЛАСТЬ — АККАУНТ» о
// платформенном поле он не помешает. Тот же предел, что у машинного чтения
// вердикта приёмки. Истинность держит запись пути: `memberships.invited_by`
// пишется значением ЭТОГО приглашения в строку ЭТОГО аккаунта, а
// `users.invited_by` в списке `SET` конфликтной ветки не назван вовсе.

// invitedByField — одно из двух полей и его ожидаемая примета.
type invitedByField struct {
	file string
	decl string
	twin string // полное имя близнеца, которое комментарий обязан назвать
}

const invitedByScopeMarker = "ОБЛАСТЬ — "

var invitedByFields = []invitedByField{
	{"user.proto", "string invited_by = 8;", "Membership.invited_by"},
	{"membership.proto", "string invited_by = 6;", "User.invited_by"},
}

// TestBothInvitedByFieldsDeclareTheirScope — несущее утверждение.
func TestBothInvitedByFieldsDeclareTheirScope(t *testing.T) {
	dir := filepath.Join(monorepoRoot(t), iamContractDir)
	read := func(name string) (string, error) {
		raw, err := os.ReadFile(filepath.Join(dir, name)) // #nosec G304 -- путь собран из корня собственного модуля
		return string(raw), err                           //nolint:wrapcheck // ошибка чтения возвращается вызывающему как есть
	}
	findings, inspected, scopes := auditInvitedByScopes(t, read, invitedByFields)
	require.NotZero(t, inspected, "не осмотрено ни одного поля — вердикт беспредметен")
	t.Logf("перепись: полей «кто пригласил» осмотрено %d · областей объявлено %d · находок %d",
		inspected, scopes, len(findings))
	require.Emptyf(t, findings, "область поля «кто пригласил» не названа:\n%s", strings.Join(findings, "\n"))
}

// auditInvitedByScopes — вердикт по набору полей. Вынесен, чтобы инъекция могла
// подать синтетический контракт, а не только настоящий.
func auditInvitedByScopes(
	t *testing.T, read func(string) (string, error), rows []invitedByField,
) (findings []string, inspected, scopes int) {
	t.Helper()
	seen := map[string]string{}
	for _, f := range rows {
		text, err := read(f.file)
		require.NoErrorf(t, err, "поля %s в дереве нет — вердикт беспредметен", f.file)
		comment, ok := leadingCommentOf(text, f.decl)
		require.Truef(t, ok, "%s: объявления %q не найдено — гейт судит не то поле", f.file, f.decl)
		inspected++

		got, declared := declaredScope(comment)
		switch {
		case !declared:
			findings = append(findings, fmt.Sprintf("%s: область поля не объявлена (нет приметы %q)",
				f.file, invitedByScopeMarker))
		default:
			if prev, dup := seen[got]; dup {
				findings = append(findings, fmt.Sprintf(
					"%s и %s объявляют ОДНУ область %q — различие так и не названо", prev, f.file, got))
			}
			seen[got] = f.file
		}
		if !strings.Contains(comment, f.twin) {
			findings = append(findings, fmt.Sprintf("%s: комментарий не называет близнеца %q", f.file, f.twin))
		}
	}
	return findings, inspected, len(seen)
}

// TestNoThirdInvitedByFieldSlippedIn — предпосылка таблицы: полей «кто пригласил»
// в контракте ровно столько, сколько названо. Третье появилось бы вне наблюдения.
func TestNoThirdInvitedByFieldSlippedIn(t *testing.T) {
	dir := filepath.Join(monorepoRoot(t), iamContractDir)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)

	found := map[string]int{}
	filesRead := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".proto") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(dir, e.Name())) // #nosec G304 -- путь собран из корня собственного модуля
		require.NoError(t, err)
		filesRead++
		for _, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue
			}
			if strings.Contains(trimmed, " invited_by = ") {
				found[e.Name()]++
			}
		}
	}
	require.NotZero(t, filesRead, "контракт iam не прочитан — вердикт беспредметен")

	declared := map[string]bool{}
	for _, f := range invitedByFields {
		declared[f.file] = true
	}
	for file := range found {
		require.Truef(t, declared[file],
			"поле «кто пригласил» появилось в %s и в таблице областей не названо", file)
	}
	require.Lenf(t, found, len(invitedByFields),
		"полей «кто пригласил» в контракте %d, а таблица знает %d", len(found), len(invitedByFields))
	t.Logf("перепись: файлов контракта %d · файлов с полем «кто пригласил» %d", filesRead, len(found))
}

// declaredScope — объявленная область из комментария поля.
func declaredScope(comment string) (string, bool) {
	i := strings.Index(comment, invitedByScopeMarker)
	if i < 0 {
		return "", false
	}
	rest := comment[i+len(invitedByScopeMarker):]
	end := len(rest)
	for j, r := range rest {
		if r < 'А' || r > 'Я' {
			end = j
			break
		}
	}
	scope := rest[:end]
	if scope == "" {
		return "", false
	}
	return scope, true
}

// leadingCommentOf — непрерывный блок `//`-строк непосредственно НАД объявлением.
func leadingCommentOf(text, decl string) (string, bool) {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if strings.TrimSpace(line) != decl {
			continue
		}
		var block []string
		for j := i - 1; j >= 0; j-- {
			trimmed := strings.TrimSpace(lines[j])
			if !strings.HasPrefix(trimmed, "//") {
				break
			}
			block = append([]string{strings.TrimPrefix(trimmed, "//")}, block...)
		}
		return strings.Join(block, "\n"), true
	}
	return "", false
}
