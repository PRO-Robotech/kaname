// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

import (
	"testing"

	"github.com/PRO-Robotech/corelib/ids"
	corevalidate "github.com/PRO-Robotech/corelib/validate"
)

// TestSessionIDPrefixIsInTheFoundationCanon — идентификатор записи сессии,
// который выдача чеканит (`IssueSession`), есть адрес: перечень своих сессий его
// называет, выход из выбранной его принимает (приёмка
// `own-sessions-are-listed-and-ended-by-their-owner.md`, DoD п.7). Приставка
// обязана стоять в каталоге дефис-приставок фундамента на выпуске пина службы —
// иначе валидатор фундамента отвергает корректный идентификатор, который служба
// сама и выдала (класс `ak`, `tfm`).
//
// Приставка спрашивается у каталога ЗНАЧЕНИЕМ, а не через экспортируемую
// константу фундамента: на выпуске без записи файл обязан собираться и падать
// утверждением, а не отказом сборки.
//
// Законный близнец — ключ доступа (`ak`): та же дефисная форма, тот же
// генератор и тот же валидатор; меняется ровно один факт — приставка.
func TestSessionIDPrefixIsInTheFoundationCanon(t *testing.T) {
	cases := []struct {
		name, kind, prefix string
	}{
		{name: "twin: access key prefix is in the canon", kind: "access key", prefix: ids.PrefixAccessKeyHyphen},
		{name: "human session prefix is in the canon", kind: "human session", prefix: sessionIDPrefix},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := ids.KnownHyphenPrefixes()[tc.prefix]; !ok {
				t.Errorf("приставка %q отсутствует в ids.KnownHyphenPrefixes() выпуска пина фундамента", tc.prefix)
			}
			id := ids.NewHyphenID(tc.prefix)
			if err := corevalidate.ResourceID(tc.kind, tc.prefix, id); err != nil {
				t.Errorf("validate.ResourceID отверг выданный службой идентификатор %q: %v", id, err)
			}
		})
	}
}
