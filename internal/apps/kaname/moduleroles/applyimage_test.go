// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package moduleroles_test

// applyimage_test.go — применение ролей манифеста ОБРАЗА службы
// (`Applier.ApplyImage`, kaname#1003): заводит объявленные роли, которых в базе
// нет, и не трогает уже стоящие роли платформы. Их перевод под применитель —
// отдельное решение с ценой (приёмка `roles-come-as-data-not-migrations.md`
// §3.4; kaname#1006): правка роли платформы влечёт удаление на листе
// (`domain.PolicyOfRole`), и старт службы такую правку молча не делает.

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleroles"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
)

// imageManifest — манифест с двумя кластерными ролями: стоящей в базе (её
// объявление расходится со строкой) и новой.
func imageManifest(t *testing.T) *manifest.Manifest {
	t.Helper()
	doc := "apiVersion: iam/v1\nmodule: vpc\nroles:\n" +
		"  - id: vpc.network.admin\n" +
		"    description: Объявление расходится со строкой платформы.\n" +
		"    tier: {tierType: iam.cluster, tierId: cluster_root}\n" +
		"    rules:\n      - {module: vpc, resources: [network], classes: [list]}\n" +
		"  - id: vpc.network.reader\n" +
		"    description: Новая роль образа.\n" +
		"    tier: {tierType: iam.cluster, tierId: cluster_root}\n" +
		"    rules:\n      - {module: vpc, resources: [network], classes: [get]}\n"
	m, err := manifest.Load([]byte(doc))
	if err != nil {
		t.Fatalf("фикстура манифеста отвергнута: %v", err)
	}
	return m
}

func TestApplyImageAddsAbsentRolesAndLeavesPlatformRolesAsTheyStand(t *testing.T) {
	store := newStore()
	ap := applierUnderTest(t, store)

	// Дано: роль платформы стоит в базе строкой без владельца — так, как её
	// завела начальная миграция, и в форме, которая с объявлением образа НЕ
	// совпадает.
	if _, err := ap.ApplyImage(context.Background(), vpcManifest(t, "vpc.network.admin", "get"), moduleroles.BootActorID); err != nil {
		t.Fatalf("Дано: строка роли платформы не заведена: %v", err)
	}
	standing := domain.SystemRoleID("vpc.network.admin")
	before, ok := store.rows[standing]
	if !ok {
		t.Fatalf("Дано: строки роли платформы нет: %v", store.rows)
	}
	if before.OwnerModule != "" {
		t.Fatalf("Дано: строка образа заведена с владельцем %q, ждали роль платформы", before.OwnerModule)
	}
	beforeRules := string(mustEncode(before.Rules))
	callsBefore := store.calls

	rep, err := ap.ApplyImage(context.Background(), imageManifest(t), moduleroles.BootActorID)
	if err != nil {
		t.Fatalf("применение образа отвергнуто: %v", err)
	}
	t.Logf("перепись: %s", rep)

	after := store.rows[standing]
	if got := string(mustEncode(after.Rules)); got != beforeRules || after.Description != before.Description {
		t.Errorf("роль платформы приведена к объявлению образа: правила %s → %s, описание %q → %q",
			beforeRules, got, before.Description, after.Description)
	}
	if store.calls != callsBefore+1 {
		t.Errorf("писатель строки позван %d раз(а), ждали 1 — только новая роль", store.calls-callsBefore)
	}
	added := domain.SystemRoleID("vpc.network.reader")
	row, ok := store.rows[added]
	if !ok {
		t.Fatalf("новая роль образа не заведена: %v", store.rows)
	}
	if row.OwnerModule != "" {
		t.Errorf("новая роль образа заведена с владельцем %q, ждали роль платформы", row.OwnerModule)
	}
	if len(store.refs[added]) == 0 {
		t.Errorf("у новой роли образа не записана проекция сегментов")
	}
	if rep.Written != 1 || rep.Kept != 1 {
		t.Errorf("перепись применения образа не та: записано %d (ждали 1), оставлено %d (ждали 1): %s",
			rep.Written, rep.Kept, rep)
	}
}
