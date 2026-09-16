// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mail_send_paths_test.go — ГЕЙТ MAIL-47 по не-тестовому дереву службы.
//
// Норма, состав обеих осей, граница разбора и то, чего гейт НЕ утверждает, — в
// шапке `mail_send_paths.go`; здесь они не пересказываются, чтобы два места об
// одном предмете не разошлись.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// mail_send_paths_injection_test.go.
package check_test

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// TestMAIL47MailSendPathsAreOneAndSendTheInvite — сам гейт.
//
// Что делать, если он сработал, — исходов три, четвёртого нет:
//
//  1. появился второй путь отправки приглашения → свести к одному: два способа
//     доставить одно письмо решают спор порядком, а не решением (Р1);
//  2. появился наш путь отправки чужого вида → решение Р23 отдаёт этот вид
//     почтовому процессу поставщика; либо решение пересматривается ПРИЁМКОЙ,
//     либо путь снимается. Правка гейта исходом не является;
//  3. единственный путь исчез → вид письма остался без производителя (§12
//     п. 3а): приглашение создаётся успешно, письма нет.
func TestMAIL47MailSendPathsAreOneAndSendTheInvite(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен: %v", err)
	}
	// Обход — по корню МОДУЛЯ службы: дерево платформы этому модулю не
	// принадлежит, и судить его отсюда значило бы краснеть на чужом.
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден: %v", err)
	}

	paths, kinds, census, err := check.ScanMailSendPaths(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: обход дерева не состоялся: %v", err)
	}

	findings := check.AdjudicateMailSendPaths(paths, kinds)
	t.Logf("%s; объявлений вида письма найдено %d; находок %d",
		census, len(kinds), len(findings))

	// ПРЕДПОСЫЛКИ ОБЕИХ ОСЕЙ. Пустой обход молчит так же, как исправное дерево,
	// поэтому молчание тут — отказ, а не проход.
	if census.Read == 0 {
		t.Fatalf("прочитано ноль не-тестовых файлов Go при %d отслеживаемых — "+
			"обход пуст, и вердикт беспредметен", census.Tracked)
	}
	if census.Imports == 0 {
		t.Fatalf("осмотрено ноль импортов при %d прочитанных файлах — разбирается не то дерево",
			census.Read)
	}
	if census.TransportAnchorHits == 0 {
		t.Fatalf("якорный пакет транспорта не найден в дереве ни разу: ось транспорта "+
			"судит пустоту, и её молчание означает «не искали», а не «нет». "+
			"Прочитано файлов %d, импортов %d", census.Read, census.Imports)
	}

	for _, f := range findings {
		where := f.Where
		if where == "" {
			where = "дерево целиком"
		}
		t.Errorf("%s — %s (ось %s). %s", where, f.What, f.Axis, f.Why)
	}
}
