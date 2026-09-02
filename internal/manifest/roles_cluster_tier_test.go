// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// roles_cluster_tier_test.go — раздел `roles` принимает КЛАСТЕРНЫЙ ярус
// (приёмка `services/iam/docs/engineering/acceptance/roles-come-as-data-not-migrations.md`
// §3.2, §3.2.1; сценарии MOD-RD-01 … MOD-RD-05).
//
// # Что здесь заменено, а не ослаблено
//
// Прежняя проба MOD-MR-14 утверждала отказ `ErrSystemRoleNotAuthorable` по
// кластерному ярусу. Её предмет СНЯТ решением §3.2: отказ ФОРМЫ заменён отказом
// ВЛАДЕНИЯ. Ослабить её (убрать утверждение) было бы нельзя — она обязана
// утверждать НОВОЕ свойство того же предмета, и утверждает: ярус принимается,
// а чужой модуль по-прежнему отвергается.
//
// # Почему это не «принято-и-проигнорировано»
//
// Все сорок восемь живых системных ролей — кластерные, и исполнимого входа,
// которым модуль объявил бы свою роль, не существовало НИ ОДНОГО: раздел
// объявлен, разобран, покрыт типами — и для единственного яруса, на котором
// живут роли продукта, отвергался.
package manifest_test

import (
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	"github.com/PRO-Robotech/kacho/services/iam/internal/manifest"
)

// clusterRoleDoc — манифест vpc с одной ролью заданного идентификатора и яруса.
func clusterRoleDoc(id, tierType, tierID string) []byte {
	return []byte("apiVersion: iam/v1\nmodule: vpc\nroles:\n" +
		"  - id: " + id + "\n" +
		"    description: Распоряжается сетями модуля.\n" +
		"    tier: {tierType: " + tierType + ", tierId: " + tierID + "}\n" +
		"    rules:\n      - {module: vpc, resources: [network], classes: [get]}\n")
}

// TestMODRD01ClusterTierRoleOfOwnModuleIsAccepted — MOD-RD-01.
func TestMODRD01ClusterTierRoleOfOwnModuleIsAccepted(t *testing.T) {
	m, err := manifest.Load(clusterRoleDoc("vpc.network.admin",
		domain.ScopeTypeClusterDotted, domain.ClusterSingletonID))
	if err != nil {
		t.Fatalf("кластерная роль своего модуля отвергнута: %v\n"+
			"Пока она отвергается, исполнимого входа, которым модуль объявил бы свою "+
			"роль, не существует ни одного: все живые системные роли — кластерные", err)
	}
	if len(m.Roles) != 1 || m.Roles[0].ID != "vpc.network.admin" {
		t.Fatalf("разобранная роль не та: %+v", m.Roles)
	}
	if m.Roles[0].Tier == nil || m.Roles[0].Tier.TierType != domain.ScopeTypeClusterDotted {
		t.Fatalf("ярус разобранной роли не кластерный: %+v", m.Roles[0].Tier)
	}
}

// TestMODRD02ClusterTierRoleOfAForeignModuleIsStillRefused — MOD-RD-02: снятие
// отказа по ярусу НЕ расширяет право объявления.
func TestMODRD02ClusterTierRoleOfAForeignModuleIsStillRefused(t *testing.T) {
	_, err := manifest.Load(clusterRoleDoc("storage.volumes.admin",
		domain.ScopeTypeClusterDotted, domain.ClusterSingletonID))
	if err == nil {
		t.Fatalf("кластерная роль ЧУЖОГО модуля принята — снятие отказа по ярусу " +
			"расширило право объявления, а не перенесло его")
	}
	if !errors.Is(err, manifest.ErrRoleForeignModule) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	for _, want := range []string{"roles[0].id", "storage", "vpc"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}
}

// TestMODRD03RoleIDOutOfTheSystemNameFormNamesFieldAndRule — MOD-RD-03: отказ
// называет ПОЛЕ и ПРАВИЛО, а не «имя неверно».
func TestMODRD03RoleIDOutOfTheSystemNameFormNamesFieldAndRule(t *testing.T) {
	_, err := manifest.Load(clusterRoleDoc("vpc.networkOperator",
		domain.ScopeTypeClusterDotted, domain.ClusterSingletonID))
	if err == nil {
		t.Fatalf("идентификатор с заглавной буквой принят — ограничение " +
			"`roles_system_name_check` отвергло бы его у писателя, то есть SQLSTATE 23514 " +
			"вместо отказа разбора с координатой")
	}
	if !errors.Is(err, manifest.ErrRoleIDOutOfForm) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	for _, want := range []string{
		"roles[0].id", "vpc.networkOperator", "roles_system_name_check", manifest.RoleIDForm,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}

	// Парный положительный: то же имя в змеином написании принимается.
	if _, err := manifest.Load(clusterRoleDoc("vpc.network_operator",
		domain.ScopeTypeClusterDotted, domain.ClusterSingletonID)); err != nil {
		t.Fatalf("парный положительный отвергнут — отказ ловит не форму, а что-то ещё: %v", err)
	}
}

// TestMODRD04RoleIDOfFourSegmentsIsRefusedByTheSameForm — MOD-RD-04.
func TestMODRD04RoleIDOfFourSegmentsIsRefusedByTheSameForm(t *testing.T) {
	_, err := manifest.Load(clusterRoleDoc("vpc.network.rules.admin",
		domain.ScopeTypeClusterDotted, domain.ClusterSingletonID))
	if err == nil {
		t.Fatalf("имя из четырёх сегментов принято — ограничение таблицы допускает не более трёх")
	}
	if !errors.Is(err, manifest.ErrRoleIDOutOfForm) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	if !strings.Contains(err.Error(), "vpc.network.rules.admin") {
		t.Errorf("отказ не называет полученное значение: %v", err)
	}

	// Парный положительный: три сегмента — законная верхняя граница.
	if _, err := manifest.Load(clusterRoleDoc("vpc.network.admin",
		domain.ScopeTypeClusterDotted, domain.ClusterSingletonID)); err != nil {
		t.Fatalf("парный положительный отвергнут: %v", err)
	}
}

// TestMODRD05AccountAndProjectTiersAreNotNarrowedByTheChange — MOD-RD-05:
// положительный контроль. Расширение, сузившее соседнюю полосу, — регрессия.
func TestMODRD05AccountAndProjectTiersAreNotNarrowedByTheChange(t *testing.T) {
	for _, c := range []struct{ tierType, tierID string }{
		{domain.ScopeTypeProjectDotted, "prj000000000000000"},
		{domain.ScopeTypeAccountDotted, "acc000000000000000"},
	} {
		if _, err := manifest.Load(clusterRoleDoc("vpc.viewer", c.tierType, c.tierID)); err != nil {
			t.Errorf("ярус %s отвергнут после снятия отказа по кластерному: %v", c.tierType, err)
		}
	}

	// Негодный ярус по-прежнему отвергается СВОИМ отказом, с тем же текстом.
	_, err := manifest.Load(clusterRoleDoc("vpc.viewer", "iam.organization", "org000000000000000"))
	if err == nil {
		t.Fatalf("ярус вне закрытого набора принят")
	}
	if !errors.Is(err, manifest.ErrRoleTierUnknown) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
}

// TestClusterTierAnchorIsReadAndRefusedWhenItIsNotTheSingleton — §3.2.1:
// «принято-и-проигнорировано» здесь запрещено. Кластер один, поэтому исходов у
// поля ровно два: применитель ЧИТАЕТ его и отвергает значение, отличное от
// синглтона. Молча подставить синглтон — не исход: автор получил бы успех на
// объявлении, которого платформа не исполняла.
func TestClusterTierAnchorIsReadAndRefusedWhenItIsNotTheSingleton(t *testing.T) {
	_, err := manifest.Load(clusterRoleDoc("vpc.network.admin",
		domain.ScopeTypeClusterDotted, "cluster_someone_elses"))
	if err == nil {
		t.Fatalf("якорь кластерного яруса принят и не прочитан — поле, принятое и " +
			"выброшенное, обещает возможность, которой нет")
	}
	if !errors.Is(err, manifest.ErrRoleTierAnchorUnknown) {
		t.Errorf("отказ не отнесён к своей причине: %v", err)
	}
	for _, want := range []string{
		"roles[0].tier.tierId", "cluster_someone_elses", domain.ClusterSingletonID,
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v", want, err)
		}
	}
}

// TestRoleIDFormIsTheIntersectionOfTwoLiveRules — форма объявлена ОДИН раз и
// равна ПЕРЕСЕЧЕНИЮ двух уже действующих правил, а не третьему правилу.
//
// Проверка на ЖИВОМ наборе, обе стороны: образец обязан принять трёхсегментные
// ярусные имена продукта и отвергнуть безмодульные — ровно тот класс, который
// §3.4 объявляет недостижимым для любого манифеста.
func TestRoleIDFormIsTheIntersectionOfTwoLiveRules(t *testing.T) {
	re := regexp.MustCompile(manifest.RoleIDForm)

	accept := []string{
		"vpc.network.admin", "iam.access_binding.view", "compute.instance.edit",
		"loadbalancer.operator", "kacho-system.admin", "module.storage_sa",
		"vpc.network_operator",
	}
	reject := []string{
		"admin", "edit", "view", "owner", // безмодульные — §3.4, третий класс
		"vpc.networkOperator",      // заглавная вне формы имени системной роли
		"vpc.network.rules.admin",  // четыре сегмента
		"vpc.", ".admin", "vpc..x", // вырожденные
		"vpc.Network.admin", "VPC.network.admin",
	}
	for _, s := range accept {
		if !re.MatchString(s) {
			t.Errorf("форма отвергает живое имя %q — модуль не смог бы объявить свою роль", s)
		}
	}
	for _, s := range reject {
		if re.MatchString(s) {
			t.Errorf("форма принимает %q — манифест объявил бы то, что писатель отвергнет "+
				"ограничением таблицы либо что ему не принадлежит", s)
		}
	}
	t.Logf("перепись формы: принято %d из %d, отвергнуто %d из %d",
		len(accept), len(accept), len(reject), len(reject))
}
