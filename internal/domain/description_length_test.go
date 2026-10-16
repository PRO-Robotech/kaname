// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain_test

// description_length_test.go — предел описания считается в ЗНАКАХ, как его
// считает база (`length(description) <= 256`), а не в байтах (kaname#856:
// кириллическое описание роли модуля в 178 знаков / 329 байт роняло применение
// ролей на старте, хотя база и загрузчик манифеста его принимают).

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestDescriptionLimitIsCountedInCharacters(t *testing.T) {
	for _, c := range []struct {
		name string
		in   string
		ok   bool
	}{
		{"256 кириллических знаков (512 байт) — граница, принято", strings.Repeat("я", 256), true},
		{"257 кириллических знаков — отказ", strings.Repeat("я", 257), false},
		{"256 латинских знаков — граница, принято", strings.Repeat("a", 256), true},
		{"257 латинских знаков — отказ", strings.Repeat("a", 257), false},
	} {
		err := domain.Description(c.in).Validate()
		if c.ok && err != nil {
			t.Errorf("%s: отказ %v", c.name, err)
		}
		if !c.ok && (err == nil || err.Error() != "Illegal argument description: length must be <=256") {
			t.Errorf("%s: ожидался отказ с прежним текстом, получено %v", c.name, err)
		}
	}
}
