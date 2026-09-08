// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package restfront

import "testing"

// dialtarget_test.go — адрес привязки не годится как адрес соединения.

func TestDialTargetResolvesTheWildcardBindToTheLoopback(t *testing.T) {
	cases := []struct {
		name, listen, want string
	}{
		{"привязка ко всем интерфейсам, IPv4", "0.0.0.0:9090", "127.0.0.1:9090"},
		{"привязка ко всем интерфейсам, IPv6", "[::]:9091", "127.0.0.1:9091"},
		{"хост опущен — та же неопределённость", ":9098", "127.0.0.1:9098"},
		// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: названный хост не трогается. Без него проба
		// зеленела бы на переводе, подменяющем адрес ВСЕГДА, — то есть на фронте,
		// который ходит в петлю независимо от профиля.
		{"названный хост остаётся как есть", "10.0.0.7:9090", "10.0.0.7:9090"},
		{"имя остаётся как есть", "kaname.kacho.svc:9090", "kaname.kacho.svc:9090"},
		{"пустой адрес — фронт не поднят, соединяться не с чем", "", ""},
		{"неразбираемое отдаётся как есть: отказ назовёт адрес прямо", "не-адрес", "не-адрес"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := DialTarget(c.listen); got != c.want {
				t.Errorf("DialTarget(%q) = %q, ожидалось %q", c.listen, got, c.want)
			}
		})
	}
}
