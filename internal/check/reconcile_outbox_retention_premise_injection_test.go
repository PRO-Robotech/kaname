// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

// reconcile_outbox_retention_premise_injection_test.go — доказательство, что
// гейт предпосылки СПОСОБЕН упасть и способен смолчать.
//
// Инъекция подаёт синтетический корпус в ЧИСТЫЙ разбор (`redriveSitesOfTree`):
// на настоящем дереве ни того, ни другого не показать, не сломав его. Обе
// стороны по каждой оси, и мир каждого случая отличается от близнеца ОДНИМ
// названным фактом — иначе неизвестно, что дало красное.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeGoFixture кладёт синтетический прод-файл и возвращает его путь.
func writeGoFixture(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatalf("фикстура %s: %v", name, err)
	}
	return p
}

const redriveOverNeighbour = `package fixture

import "x/reconciler"

func wire(pool any) {
	rc, _ := reconciler.NewRedriveOnly(pool, reconciler.Config{
		Table:           clients.InviteMailTable,
		PartitionColumn: "recipient",
	})
	_ = rc
}
`

// Отличается от близнеца ВЫШЕ ровно одним фактом — названной таблицей.
const redriveOverThisQueue = `package fixture

import "x/reconciler"

func wire(pool any) {
	rc, _ := reconciler.NewRedriveOnly(pool, reconciler.Config{
		Table:           "kacho_iam.resource_reconcile_outbox",
		PartitionColumn: "object_id",
	})
	_ = rc
}
`

// Законный близнец второго рода: имя конструктора совпадает, но пакет ЧУЖОЙ.
// Без него разбор, судящий по одному лишь имени метода, прошёл бы за исправный.
const foreignNewRedriveOnly = `package fixture

import "x/mailer"

func wire(pool any) {
	rc, _ := mailer.NewRedriveOnly(pool, mailer.Config{
		Table: "kacho_iam.resource_reconcile_outbox",
	})
	_ = rc
}
`

func TestReconcileOutboxPremiseGateCanFailAndCanStaySilent(t *testing.T) {
	dir := t.TempDir()

	t.Run("оживитель над соседней очередью — молчание", func(t *testing.T) {
		f := writeGoFixture(t, dir, "neighbour.go", redriveOverNeighbour)
		sites, read, err := redriveSitesOfTree(dir, []string{f})
		if err != nil {
			t.Fatalf("разбор: %v", err)
		}
		if read != 1 {
			t.Fatalf("прочитано файлов %d, ожидался 1", read)
		}
		if len(sites) != 1 {
			t.Fatalf("мест построения %d, ожидалось 1 — разбор не узнаёт оживителя", len(sites))
		}
		if strings.Contains(sites[0].table, reconcileOutboxTable) {
			t.Fatalf("сосед принят за очередь сверки: таблица %q", sites[0].table)
		}
	})

	t.Run("оживитель над очередью сверки — находка", func(t *testing.T) {
		f := writeGoFixture(t, dir, "ours.go", redriveOverThisQueue)
		sites, _, err := redriveSitesOfTree(dir, []string{f})
		if err != nil {
			t.Fatalf("разбор: %v", err)
		}
		if len(sites) != 1 {
			t.Fatalf("мест построения %d, ожидалось 1", len(sites))
		}
		if !strings.Contains(sites[0].table, reconcileOutboxTable) {
			t.Fatalf("оживитель над очередью сверки НЕ распознан: таблица %q — гейт не способен упасть",
				sites[0].table)
		}
	})

	t.Run("чужой пакет с тем же именем конструктора — молчание", func(t *testing.T) {
		f := writeGoFixture(t, dir, "foreign.go", foreignNewRedriveOnly)
		sites, _, err := redriveSitesOfTree(dir, []string{f})
		if err != nil {
			t.Fatalf("разбор: %v", err)
		}
		if len(sites) != 0 {
			t.Fatalf("чужой пакет принят за оживителя очередей: %+v — гейт ловит имя, а не предмет", sites)
		}
	})

	t.Run("пробы в обход не берутся", func(t *testing.T) {
		f := writeGoFixture(t, dir, "ours_test.go", redriveOverThisQueue)
		sites, read, err := redriveSitesOfTree(dir, []string{f})
		if err != nil {
			t.Fatalf("разбор: %v", err)
		}
		if read != 0 || len(sites) != 0 {
			t.Fatalf("проба попала в обход: прочитано %d, мест %d — фикстура соседнего гейта стала бы находкой",
				read, len(sites))
		}
	})
}
