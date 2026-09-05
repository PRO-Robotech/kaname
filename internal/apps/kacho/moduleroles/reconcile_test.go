// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// reconcile_test.go — сверка «объявлено против живого» (приёмка §3.4;
// сценарии MOD-RD-19 и MOD-RD-20).
package moduleroles_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/moduleroles"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	"github.com/PRO-Robotech/kacho-iam/internal/manifest"
)

// liveSystemRole — живая строка системной роли с данным именем.
func liveSystemRole(name string) domain.Role {
	return domain.Role{
		ID:        domain.SystemRoleID(domain.RoleName(name)),
		ClusterID: domain.ClusterSingletonID,
		Name:      domain.RoleName(name),
		IsSystem:  true,
	}
}

// declaredRoles — объявление манифеста модуля из имён кластерных ролей.
func declaredRoles(names ...string) []manifest.Role {
	out := make([]manifest.Role, 0, len(names))
	for _, n := range names {
		out = append(out, manifest.Role{
			ID: n,
			Tier: &manifest.Tier{
				TierType: domain.ScopeTypeClusterDotted,
				TierID:   domain.ClusterSingletonID,
			},
		})
	}
	return out
}

// TestMODRD19UndeclaredLiveRoleIsNamedWithBothSides — MOD-RD-19.
func TestMODRD19UndeclaredLiveRoleIsNamedWithBothSides(t *testing.T) {
	live := []domain.Role{
		liveSystemRole("vpc.network.admin"),
		liveSystemRole("vpc.network.view"),
		liveSystemRole("vpc.subnet.admin"),
	}
	found, census := moduleroles.Reconcile("vpc", declaredRoles("vpc.network.admin"), live)

	t.Logf("перепись сверки: %s", census)
	if census.LiveExamined != 3 || census.Declared != 1 {
		t.Fatalf("перепись не описывает осмотренного: %s", census)
	}
	if len(found) != 2 {
		t.Fatalf("расхождений найдено %d при двух живых необъявленных: %v\n"+
			"«Расхождений нет» обязано быть отличимо от «половину не смотрели»", len(found), found)
	}
	for _, d := range found {
		if d.Kind != moduleroles.LiveNotDeclared {
			t.Errorf("вид расхождения не тот: %+v", d)
		}
	}
	names := census.String() + " " + found[0].String() + " " + found[1].String()
	for _, want := range []string{"vpc.network.view", "vpc.subnet.admin"} {
		if !strings.Contains(names, want) {
			t.Errorf("сверка не называет живую строку %q: %v", want, found)
		}
	}
}

// TestMODRD20RolesWithoutAModuleOwnerAreSilent — MOD-RD-20: шесть ролей без
// модуля-владельца сверку молчать не мешают.
//
// Признак — ЧЛЕНСТВО в закрытом наборе модулей, а не число сегментов: две
// `kacho-system.*` точку несут, и по признаку «односегментное» уехали бы в
// класс ждущих манифеста несуществующего модуля вечно.
func TestMODRD20RolesWithoutAModuleOwnerAreSilent(t *testing.T) {
	live := []domain.Role{
		liveSystemRole("admin"), liveSystemRole("edit"), liveSystemRole("view"),
		liveSystemRole("owner"),
		liveSystemRole("kacho-system.admin"), liveSystemRole("kacho-system.viewer"),
	}
	found, census := moduleroles.Reconcile("vpc", declaredRoles(), live)
	t.Logf("перепись сверки: %s", census)
	if len(found) != 0 {
		t.Fatalf("роли без модуля-владельца объявлены расхождением: %v\n"+
			"Владельца у них нет by construction, и ждать манифеста им нечего", found)
	}
	if census.WithoutOwner != 6 {
		t.Errorf("без модуля-владельца насчитано %d из шести — признак считает не членство "+
			"в наборе, а что-то другое: %s", census.WithoutOwner, census)
	}
	if census.OtherModule != 0 {
		t.Errorf("роли без владельца отнесены к чужому модулю: %s", census)
	}
}

// TestReconcileLeavesForeignModulesAlone — роль ЧУЖОГО модуля не расхождение:
// её сверяет манифест её собственного модуля.
func TestReconcileLeavesForeignModulesAlone(t *testing.T) {
	live := []domain.Role{
		liveSystemRole("vpc.network.admin"),
		liveSystemRole("compute.instance.admin"),
		liveSystemRole("storage.volumes.view"),
	}
	found, census := moduleroles.Reconcile("vpc", declaredRoles("vpc.network.admin"), live)
	if len(found) != 0 {
		t.Fatalf("роли чужих модулей объявлены расхождением: %v", found)
	}
	if census.OtherModule != 2 {
		t.Errorf("чужих модулей насчитано %d из двух: %s", census.OtherModule, census)
	}
}

// TestReconcileNamesADeclaredRoleThatIsNotLive — вторая сторона: объявлено и не
// заведено. Она НЕ находка до применения, но названа отдельным видом: иначе
// «расхождений нет» после сбоя применителя означало бы «всё на месте».
func TestReconcileNamesADeclaredRoleThatIsNotLive(t *testing.T) {
	found, census := moduleroles.Reconcile("vpc",
		declaredRoles("vpc.network.admin", "vpc.subnet.admin"),
		[]domain.Role{liveSystemRole("vpc.network.admin")})
	if len(found) != 1 || found[0].Kind != moduleroles.DeclaredNotLive {
		t.Fatalf("объявленная и не заведённая роль не названа: %v (%s)", found, census)
	}
	if !strings.Contains(found[0].String(), "vpc.subnet.admin") {
		t.Errorf("расхождение не называет роль: %s", found[0])
	}
}

// TestReconcileCensusMakesAnEmptyWalkVisible — «ноль расхождений» обязано быть
// отличимо от «ноль осмотренного».
func TestReconcileCensusMakesAnEmptyWalkVisible(t *testing.T) {
	found, census := moduleroles.Reconcile("vpc", nil, nil)
	if len(found) != 0 {
		t.Fatalf("на пустом входе найдены расхождения: %v", found)
	}
	if !census.Void() {
		t.Fatalf("перепись пустого обхода не объявляет себя беспредметной: %s", census)
	}
	if !strings.Contains(census.String(), "0") {
		t.Errorf("перепись не печатает чисел: %s", census)
	}
}
