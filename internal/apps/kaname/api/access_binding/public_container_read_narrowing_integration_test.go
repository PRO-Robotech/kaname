// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// public_container_read_narrowing_integration_test.go — публичное чтение
// контейнера наследует сужение правила роли и снимается вместе со своим
// основанием (задача PRO-Robotech/kaname#856, стадия S5).
//
// Мир — П6 (`public_container_read_world_integration_test.go`). Роль — своя роль
// аккаунта из двух правил: над `registry.registries` (покрывает цель X) и над
// `registry.repositories` (ребёнок контейнера). Варьируется второе правило либо
// основание кортежа; законный близнец каждой строки — то же без сужения или без
// снятия.
//
// Утверждения двух уровней: прямой факт `public_reader` на X (его пишет только
// разворачивание выдачи классу — уровень записи) и вопрос `Check` на ребёнке на
// том глаголе, который сужение закрывает (уровень решения). Ветвь выдач решения
// сегодня не сужает выдачу по цели (SC-68, kaname#857), поэтому вопрос на
// ребёнке задаётся на том глаголе и том объекте, которых правило роли не даёт
// ни одной ветвью.

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

// pcrRegistriesRule — правило над контейнером: покрывает цель X.
func pcrRegistriesRule() domain.Rule {
	return domain.Rule{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get", "list"}}
}

// pcrRepositoriesRule — правило над ребёнком без сужения.
func pcrRepositoriesRule() domain.Rule {
	return domain.Rule{Module: "registry", Resources: []string{"repositories"}, Verbs: []string{"get", "list"}}
}

// publicReaderFacts — прямые факты `public_reader` на реестре id.
func (p *pcrWorld) publicReaderFacts(id string) int {
	p.t.Helper()
	var n int
	require.NoError(p.t, p.pool.QueryRow(p.ctx, `
		SELECT count(*) FROM kaname.relation_fact
		 WHERE object_type = $1 AND object_id = $2 AND relation = $3`,
		pcrRegType, id, domain.PublicReaderRelation).Scan(&n))
	return n
}

// pollPublicReaderFacts — опрос раз в 200 мс до 30 с (окно SC-13).
func (p *pcrWorld) pollPublicReaderFacts(id string, want int, why string) {
	p.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	last := -1
	for {
		if last = p.publicReaderFacts(id); last == want {
			return
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	p.t.Fatalf("%s: фактов public_reader на %s:%s за 30 с не стало %d (последнее %d)", why, pcrRegType, id, want, last)
}

// pollMaterialized — выдача развёрнута: у неё есть действующий член состава.
func (p *pcrWorld) pollMaterialized(bindingID, why string) {
	p.t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for {
		var n int
		require.NoError(p.t, p.pool.QueryRow(p.ctx, `
			SELECT count(*) FROM kaname.access_binding_target_members
			 WHERE binding_id = $1 AND verification_status = 'ACTIVE'`, bindingID).Scan(&n))
		if n > 0 {
			return
		}
		if time.Now().After(deadline) {
			p.t.Fatalf("%s: выдача %s за 30 с не развернулась", why, bindingID)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// grantClassRole — выдача анониму роли с правилами `rules` на X, развёрнутая.
func (p *pcrWorld) grantClassRole(name string, rules domain.Rules, why string) (domain.RoleID, string) {
	p.t.Helper()
	rid := p.seedRole(name, rules)
	id := p.createDone(asUser(p.ctx, p.usrA), p.grantRequest(classSubject("anonymous"), rid, pcrXTarget()), why)
	p.pollMaterialized(id, why)
	return rid, id
}

// roleUpdate — `RoleService.Update` с разворачиванием выдач, как в корне службы.
func (p *pcrWorld) roleUpdate() *roleapp.UpdateRoleUseCase {
	return roleapp.NewUpdateRoleUseCase(p.repo, p.ops, catalog.Fixed{F: p.facts}).
		WithTupleReconciler(accessbindingapp.NewRoleTupleReconciler()).
		WithMembershipFanout(accessbindingapp.NewRoleMembershipFanout(p.repo, p.rec))
}

// updateRules — правка правил роли, операция доходит до done без error.
func (p *pcrWorld) updateRules(rid domain.RoleID, rules domain.Rules, why string) {
	p.t.Helper()
	op, err := p.roleUpdate().Execute(asUser(p.ctx, p.usrA), roleapp.UpdateRoleInput{
		ID: rid, Rules: rules, UpdateMask: []string{"rules"},
	})
	require.NoErrorf(p.t, err, "%s: правка роли", why)
	require.Nilf(p.t, awaitOp(p.t, p.ctx, p.ops, op.ID).Error, "%s: операция правки роли", why)
}

// TestPublicContainerRead_NarrowedChildRuleOpensNoDescendants — правило над
// ребёнком, суженное метками либо одним глаголом чтения, `public_reader` не
// пишет, и сужение доходит до решения. Близнец — то же правило без сужения.
//
// Сужение ИМЕНАМИ здесь не строится: имя репозитория несёт `/`, и роль с таким
// правилом посев не принимает (`invalid argument: value violates a
// constraint`). Его держат пробы уровня разворачивания и домена
// (`TestPublicReaderMember_NarrowedChildRuleWritesNothing`,
// `TestReadsWholeTypeIsOneJudgementForRuleAndSelector`). Правило по меткам над
// репозиторием глаголом правки роли недостижимо («type registry.repositories is
// not selectable (no resource feed)»), посев его кладёт напрямую — так
// утверждается предикат разворачивания на состоянии, которое мог бы оставить
// иной путь записи.
func TestPublicContainerRead_NarrowedChildRuleOpensNoDescendants(t *testing.T) {
	twin := newPCRWorld(t)
	twin.deliverNewEdition("сужение: близнец")
	twin.grantClassRole("pcr_whole", domain.Rules{pcrRegistriesRule(), pcrRepositoriesRule()}, "близнец: [get, list] без сужения")
	twin.pollPublicReaderFacts(pcrX, 1, "близнец: несуженное правило над ребёнком пишет public_reader")
	twin.pollAsk(pcrAnon, "v_get", pcrRepoType, pcrXApp, true, "близнец: v_get на ребёнке")
	twin.pollAsk(pcrAnon, "v_list", pcrRepoType, pcrXApp, true, "близнец: v_list на ребёнке")

	for _, tc := range []struct {
		name     string
		child    func(domain.Rule) domain.Rule
		relation string // глагол на ребёнке, которого правило не даёт ни одной ветвью
	}{
		{"по меткам", func(r domain.Rule) domain.Rule { r.MatchLabels = map[string]string{"tier": "gold"}; return r }, "v_get"},
		{"только list", func(r domain.Rule) domain.Rule { r.Verbs = []string{"list"}; return r }, "v_get"},
		{"только get", func(r domain.Rule) domain.Rule { r.Verbs = []string{"get"}; return r }, "v_list"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPCRWorld(t)
			p.deliverNewEdition("сужение: " + tc.name)
			p.grantClassRole("pcr_narrow", domain.Rules{pcrRegistriesRule(), tc.child(pcrRepositoriesRule())}, "сужение: "+tc.name)
			p.pollAsk(pcrAnon, "v_get", pcrRegType, pcrX, true, "сужение "+tc.name+": выдача действует на X")
			require.Equalf(t, 0, p.publicReaderFacts(pcrX), "сужение %s: public_reader написан", tc.name)
			p.requireAsk(pcrAnon, tc.relation, pcrRepoType, pcrXApp, false, "сужение "+tc.name+": ребёнок без основания")
		})
	}
}

// TestPublicContainerRead_RoleUpdateWithdrawsPublicReader — правка роли снимает
// `public_reader`, когда правило над ребёнком снято либо сужено; v_* на самом
// реестре остаются. Близнец — правило над ребёнком переписано (слито с правилом
// над контейнером), но не снято: кортеж выживает.
func TestPublicContainerRead_RoleUpdateWithdrawsPublicReader(t *testing.T) {
	for _, tc := range []struct {
		name  string
		rules domain.Rules
		want  int
	}{
		{"близнец: правило над ребёнком переписано, не снято",
			domain.Rules{{Module: "registry", Resources: []string{"registries", "repositories"}, Verbs: []string{"get", "list"}}}, 1},
		{"правило над ребёнком снято", domain.Rules{pcrRegistriesRule()}, 0},
		{"правило над ребёнком сужено до одного глагола",
			domain.Rules{pcrRegistriesRule(), func() domain.Rule {
				r := pcrRepositoriesRule()
				r.Verbs = []string{"get"}
				return r
			}()}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPCRWorld(t)
			p.deliverNewEdition("правка роли: " + tc.name)
			rid, id := p.grantClassRole("pcr_upd", domain.Rules{pcrRegistriesRule(), pcrRepositoriesRule()}, "правка роли: Дано")
			p.pollPublicReaderFacts(pcrX, 1, "правка роли: Дано — public_reader написан")

			p.updateRules(rid, tc.rules, tc.name)
			// Полный проход ПОСЛЕ правки: близнец обязан выжить именно его, а не
			// отсутствие прохода.
			ctx, cancel := context.WithTimeout(p.ctx, 30*time.Second)
			defer cancel()
			require.NoError(t, p.rec.ReconcileBinding(ctx, domain.AccessBindingID(id)), "%s: полный проход", tc.name)
			p.pollPublicReaderFacts(pcrX, tc.want, tc.name)
			for _, rel := range []string{"v_get", "v_list"} {
				p.pollAsk(pcrAnon, rel, pcrRegType, pcrX, true, tc.name+": "+rel+" на реестре остаётся")
			}
		})
	}
}

// TestPublicContainerRead_DeclarationWithdrawnRemovesPublicReader — снятие ключа
// контейнера применителем каталога и обновление снимка: полный проход
// разворачивания снимает `public_reader`, v_* на реестре остаются. Близнец —
// тот же манифест с ключом применён повторно: кортеж на месте.
func TestPublicContainerRead_DeclarationWithdrawnRemovesPublicReader(t *testing.T) {
	for _, tc := range []struct {
		name    string
		keyless bool
		want    int
	}{
		{"близнец: ключ не тронут", false, 1},
		{"ключ снят", true, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPCRWorld(t)
			p.deliverNewEdition("снятие ключа: " + tc.name)
			id := p.createDone(asUser(p.ctx, p.usrA), p.pchRequest(), "снятие ключа: выдача ПЧ")
			p.pollMaterialized(id, "снятие ключа: выдача ПЧ")
			p.pollPublicReaderFacts(pcrX, 1, "снятие ключа: Дано — public_reader написан")

			doc, err := publicreadfixture.Read(publicreadfixture.NewEditionFile)
			require.NoError(t, err, "фикстура П6")
			if tc.keyless {
				doc, err = publicreadfixture.WithoutKey(doc)
				require.NoError(t, err, "фикстура П6: без ключа")
			}
			m, err := manifest.Load(doc)
			require.NoError(t, err, "фикстура П6: загрузка")
			p.applyDelivered(tc.name+": повторное применение каталога", m)
			require.Equalf(t, !tc.keyless, len(p.facts.PublicReadChildren(pcrRegTgt)) > 0,
				"%s: снимок каталога после применения", tc.name)

			ctx, cancel := context.WithTimeout(p.ctx, 30*time.Second)
			defer cancel()
			require.NoError(t, p.rec.ReconcileBinding(ctx, domain.AccessBindingID(id)), "%s: полный проход", tc.name)
			require.Equal(t, tc.want, p.publicReaderFacts(pcrX), fmt.Sprintf("%s: public_reader после прохода", tc.name))
			for _, rel := range []string{"v_get", "v_list"} {
				p.requireAsk(pcrAnon, rel, pcrRegType, pcrX, true, tc.name+": "+rel+" на реестре остаётся")
			}
		})
	}
}
