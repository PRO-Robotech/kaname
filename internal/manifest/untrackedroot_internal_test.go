// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest

import (
	"errors"
	"strings"
	"testing"
)

// TestUntrackedRootTextNamesEachOutcomeOfTheOwnerQuestion — у вопроса «чей это
// индекс» исходов ТРИ по разбору, и каждый даёт свой текст: корень внутри
// постороннего репозитория · корень сам репозиторий · git не назвал владельца.
//
// Третий исход на живой машине почти непредставим (git ответил на перечисление
// и не ответил на `rev-parse`), поэтому судится синтетикой: иначе ветка, о
// которой никто не знает, работает ли она, стояла бы в прод-коде молча.
// Непредусмотренная форма ответа обязана дать третий текст, а не догадку о
// первых двух.
func TestUntrackedRootTextNamesEachOutcomeOfTheOwnerQuestion(t *testing.T) {
	const root = "/корень/полоса"
	cases := []struct {
		name    string
		out     string
		err     error
		want    []string
		notWant []string
	}{
		{
			name: "корень внутри постороннего репозитория",
			out:  "/корень\nполоса/\n",
			want: []string{"внутри репозитория /корень", "путь в нём полоса/", "не отслеживается"},
		},
		{
			name:    "корень — сам репозиторий с пустым индексом",
			out:     "/корень/полоса\n\n",
			want:    []string{"сам репозиторий", "индексе нет ни одного файла"},
			notWant: []string{"внутри репозитория"},
		},
		{
			name:    "git не ответил",
			err:     errors.New("exit status 128"),
			want:    []string{"git не назвал", "exit status 128"},
			notWant: []string{"сам репозиторий", "внутри репозитория"},
		},
		{
			name:    "одна строка вместо двух",
			out:     "/корень\n",
			want:    []string{"непредусмотренной форме"},
			notWant: []string{"сам репозиторий", "внутри репозитория"},
		},
		{
			name:    "пустой корень рабочего дерева",
			out:     "\nполоса/\n",
			want:    []string{"непредусмотренной форме"},
			notWant: []string{"сам репозиторий", "внутри репозитория"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := untrackedRootText(root, []byte(tc.out), tc.err)
			t.Logf("текст: %s", got)
			if !strings.HasPrefix(got, root+": ") {
				t.Errorf("текст не начинается с корня обхода %q: %s", root, got)
			}
			if !strings.Contains(got, untrackedRootVerdict) {
				t.Errorf("текст не говорит, почему это находка, а не VOID: %s", got)
			}
			for _, w := range tc.want {
				if !strings.Contains(got, w) {
					t.Errorf("нет %q: %s", w, got)
				}
			}
			for _, w := range tc.notWant {
				if strings.Contains(got, w) {
					t.Errorf("текст догадывается о мире, которого ответ не называл (%q): %s", w, got)
				}
			}
		})
	}
}
