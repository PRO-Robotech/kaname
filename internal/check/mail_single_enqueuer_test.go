// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mail_single_enqueuer_test.go — гейт `mail_single_enqueuer` по не-тестовому
// дереву kaname (замысел issue-2917 З1, И1, И28).
//
// Норма, формы ссылки и граница разбора — в шапке mail_single_enqueuer.go;
// способность упасть и смолчать — mail_single_enqueuer_injection_test.go.
package check_test

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// TestMailSingleEnqueuer — ссылок на порождённые feedgen.Send* вне пакета
// mail 0. Исход находки один: перенести постановку за mail.Enqueuer — письмо,
// поставленное мимо Enqueue, обходит флаг, окно адресата и лимит шаблона.
func TestMailSingleEnqueuer(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}
	refs, census, err := check.ScanSingleEnqueuer(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: обход дерева не состоялся: %v", err)
	}
	findings := check.AdjudicateSingleEnqueuer(refs)
	t.Logf("%s; находок %d", census, len(findings))

	// ПРЕДПОСЫЛКИ. Пустой обход молчит так же, как исправное дерево.
	if census.Read == 0 {
		t.Fatalf("прочитано ноль не-тестовых файлов Go при %d отслеживаемых — обход пуст", census.Tracked)
	}
	if census.DeclaredSends == 0 {
		t.Fatalf("в каталоге %s не найдено ни одной функции Send* — гейт судит не тот каталог", check.FeedgenDir)
	}
	if census.MailRefs == 0 {
		t.Fatalf("в пакете %s не найдено ни одной ссылки на Send* — законный вызывающий не виден, "+
			"и молчание о прочих значит «не узнал форму», а не «нет»", check.MailPackageDir)
	}

	for _, f := range findings {
		t.Errorf("%s", f)
	}
}
