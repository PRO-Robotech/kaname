// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package mailaddr_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/mailaddr"
)

func TestSenderDomain(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		from   string
		domain string
		ok     bool
	}{
		{"kacho@example.invalid", "example.invalid", true},
		{"Kachō <kacho@example.invalid>", "example.invalid", true},
		{"  kacho@sub.example.invalid  ", "sub.example.invalid", true},
		{"kacho", "", false},
		{"kacho@", "", false},
		{"Kachō <kacho@>", "", false},
		{"kacho@.example.invalid", "", false},
		{"kacho@example.invalid.", "", false},
		{"kacho@example..invalid", "", false},
		{"kacho@exa mple.invalid", "", false},
		{"kacho@[192.0.2.1]", "", false},
		{"kacho@example.invalid\r\nBcc: x", "", false},
	} {
		got, ok := mailaddr.SenderDomain(tc.from)
		if ok != tc.ok || got != tc.domain {
			t.Errorf("SenderDomain(%q) = (%q, %t), ожидалось (%q, %t)", tc.from, got, ok, tc.domain, tc.ok)
		}
	}
}

func TestAddressOnly(t *testing.T) {
	t.Parallel()
	for in, want := range map[string]string{
		"Kachō <a@b.invalid>": "a@b.invalid",
		" a@b.invalid ":       "a@b.invalid",
		"a@b.invalid":         "a@b.invalid",
	} {
		if got := mailaddr.AddressOnly(in); got != want {
			t.Errorf("AddressOnly(%q) = %q, ожидалось %q", in, got, want)
		}
	}
}
