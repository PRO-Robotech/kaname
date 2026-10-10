// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mail_single_enqueuer_injection_test.go — гейт `mail_single_enqueuer`
// краснеет на ссылке на Send* вне пакета mail и молчит на законных близнецах
// той же формы. Каждая инъекция — один файл со своей координатой; близнец
// меняет ровно один факт (каталог файла либо имя, на которое ссылаются).
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

const enqueuerModule = "github.com/PRO-Robotech/kaname"

// enqueuerFindings — находки гейта по одному синтетическому файлу.
func enqueuerFindings(t *testing.T, rel, src string) ([]check.EnqueuerSendRef, []check.EnqueuerFinding) {
	t.Helper()
	refs, _, err := check.ScanSingleEnqueuerFile(rel, []byte(src), enqueuerModule)
	if err != nil {
		t.Fatalf("разбор %s: %v", rel, err)
	}
	return refs, check.AdjudicateSingleEnqueuer(refs)
}

const enqueuerSendCall = `package %s

import (
	"context"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/mail/feedgen"
)

func put(ctx context.Context, tx pgx.Tx) error {
	_, err := feedgen.SendInvite(ctx, tx, feedgen.InviteAttrs{})
	return err
}
`

func pkgSrc(form, pkg string) string { return strings.Replace(form, "%s", pkg, 1) }

// TestMailSingleEnqueuerInjection_CallFromAPIUserIsFound — инъекция: вызов
// Send* из api/user — находка с координатой файла и строки и именем функции.
// Близнец — тот же текст в пакете mail — молчит.
func TestMailSingleEnqueuerInjection_CallFromAPIUserIsFound(t *testing.T) {
	const rel = "internal/apps/kaname/api/user/invite_mail.go"
	_, findings := enqueuerFindings(t, rel, pkgSrc(enqueuerSendCall, "user"))
	if len(findings) != 1 {
		t.Fatalf("находок %d, ожидалась 1: %v", len(findings), findings)
	}
	msg := findings[0].String()
	if !strings.Contains(msg, rel+":12") || !strings.Contains(msg, "feedgen.SendInvite") {
		t.Fatalf("находка %q не называет координату %s:12 и функцию feedgen.SendInvite", msg, rel)
	}

	// Близнец: тот же текст в пакете mail.
	refs, findings := enqueuerFindings(t, "internal/apps/kaname/mail/enqueue.go", pkgSrc(enqueuerSendCall, "mail"))
	if len(refs) != 1 || len(findings) != 0 {
		t.Fatalf("близнец в пакете mail: ссылок %d (ожидалась 1), находок %d (ожидалось 0): %v", len(refs), len(findings), findings)
	}
}

// TestMailSingleEnqueuerInjection_ConstantIsNotASend — близнец по имени:
// api/user читает экспорт лимита шаблона из feedgen (законно, З19) — ссылкой на
// Send* это не является.
func TestMailSingleEnqueuerInjection_ConstantIsNotASend(t *testing.T) {
	const src = `package user

import "github.com/PRO-Robotech/kaname/internal/apps/kaname/mail/feedgen"

const ceiling = feedgen.InviteRecipientPerDay
`
	refs, findings := enqueuerFindings(t, "internal/apps/kaname/api/user/limits.go", src)
	if len(refs) != 0 || len(findings) != 0 {
		t.Fatalf("экспорт лимита: ссылок %d, находок %d — ожидалось 0 и 0: %v", len(refs), len(findings), findings)
	}
}

// TestMailSingleEnqueuerInjection_EveryFormIsFound — каждая законная для Go
// форма ссылки на Send* вне mail — находка: импорт с псевдонимом, значение
// функции без вызова, импорт с точкой, подпакет mail.
func TestMailSingleEnqueuerInjection_EveryFormIsFound(t *testing.T) {
	cases := []struct {
		name, rel, src, want string
	}{
		{
			name: "псевдоним импорта",
			rel:  "internal/apps/kaname/api/user/alias.go",
			src: `package user

import fg "github.com/PRO-Robotech/kaname/internal/apps/kaname/mail/feedgen"

var _ = fg.SendRecovery
`,
			want: "fg.SendRecovery",
		},
		{
			name: "значение функции",
			rel:  "internal/apps/kaname/seed/value.go",
			src: `package seed

import "github.com/PRO-Robotech/kaname/internal/apps/kaname/mail/feedgen"

var send = feedgen.SendClusterAdminGranted
`,
			want: "feedgen.SendClusterAdminGranted",
		},
		{
			name: "импорт с точкой",
			rel:  "internal/apps/kaname/api/user/dot.go",
			src: `package user

import . "github.com/PRO-Robotech/kaname/internal/apps/kaname/mail/feedgen"

var _ = SendInvite
`,
			want: "импорт с точкой",
		},
		{
			name: "подпакет mail",
			rel:  "internal/apps/kaname/mail/inner/put.go",
			src:  pkgSrc(enqueuerSendCall, "inner"),
			want: "feedgen.SendInvite",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, findings := enqueuerFindings(t, c.rel, c.src)
			if len(findings) == 0 {
				t.Fatalf("форма %q вне mail не найдена", c.name)
			}
			msg := findings[0].String()
			if !strings.Contains(msg, c.rel+":") || !strings.Contains(msg, c.want) {
				t.Fatalf("находка %q не называет координату %s и %q", msg, c.rel, c.want)
			}
		})
	}
}

// TestMailSingleEnqueuerInjection_OtherModuleFeedgenIsNotOurs — пакет с тем же
// последним сегментом пути из другого модуля нашим каталогом шаблонов не
// является: признак — полный путь импорта, а не имя пакета.
func TestMailSingleEnqueuerInjection_OtherModuleFeedgenIsNotOurs(t *testing.T) {
	const src = `package user

import "example.org/other/feedgen"

var _ = feedgen.SendInvite
`
	refs, findings := enqueuerFindings(t, "internal/apps/kaname/api/user/other.go", src)
	if len(refs) != 0 || len(findings) != 0 {
		t.Fatalf("чужой feedgen: ссылок %d, находок %d: %v", len(refs), len(findings), findings)
	}
}
