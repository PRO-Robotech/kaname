// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

// catalog_lag_test.go — разбор «тип не дошёл до снимка» против «тип снят» на уровне
// диффа (kaname#937). Сквозная проба на живой базе —
// repo/kaname/pg/reconcile_catalog_lag_integration_test.go; здесь — края, которые на
// базе собирать дорого: два правила на одном объекте и цена обычного прохода.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// lagType — точечный тип, которого литеральный каталог фикстуры не знает.
const lagType = "compute.widget"

func lagSelector(fp string) domain.RuleSelector {
	return domain.RuleSelector{Arm: domain.ArmAnchor, RuleFP: fp, ObjectTypes: []string{lagType}, Verbs: []string{"get"}}
}

// lagStore — объект w1 типа lagType в области; члены двух правил на нём ACTIVE, у
// координаты две строки реестра. Роль СЕЙЧАС несёт только правило fpKept: член fpGone
// выпадает по снятому правилу, а не по каталогу.
func lagStore(liveInCatalog bool) (*fakeStore, string, string) {
	fpKept, fpGone := "fp-kept", "fp-gone"
	return &fakeStore{
		scope:       domain.ScopeAnchor{Type: "project", ID: "prj-1"},
		subjectType: "user", subjectID: "usr-1", active: true,
		selectors: []domain.RuleSelector{lagSelector(fpKept)},
		mirror: map[string][]domain.MirrorObject{
			lagType: {{ObjectType: lagType, ObjectID: "w1", ParentProjectID: "prj-1"}},
		},
		current: []domain.TargetMember{
			{BindingID: "acb-1", RuleFP: fpKept, ObjectType: lagType, ObjectID: "w1", VerificationStatus: domain.VerificationActive},
			{BindingID: "acb-1", RuleFP: fpGone, ObjectType: lagType, ObjectID: "w1", VerificationStatus: domain.VerificationActive},
		},
		ledger: memberLedger(lagType,
			domain.MembershipTuple{User: "user:usr-1", Relation: "v_get", Object: "compute_widget:w1"},
			domain.MembershipTuple{User: "user:usr-1", Relation: "viewer", Object: "compute_widget:w1"},
		),
		liveCatalog: map[string]bool{lagType: liveInCatalog},
	}, fpKept, fpGone
}

func revokedOf(f *fakeStore) []domain.MembershipTuple {
	var out []domain.MembershipTuple
	for _, b := range f.tdeletes {
		out = append(out, b...)
	}
	return out
}

// Тип жив, снимок его не знает: член правила, которое объект по-прежнему выбирает,
// удержан с кортежами; член снятого правила той же координаты уходит строкой, но
// кортежей, на которые претендует удержанный, не забывает и не снимает.
func TestCatalogLag_HeldMemberKeepsSharedCoordinateTuples(t *testing.T) {
	f, _, _ := lagStore(true)
	_, known := catalogfixture.Facts().FGAObjectType(lagType)
	require.False(t, known, "ПРЕДПОСЫЛКА: снимок фикстуры не знает %s", lagType)
	require.NoError(t, New(fakeRunner{s: f}, nil, catalogfixture.Source()).ReconcileBinding(context.Background(), "acb-1"))

	assert.Equal(t, 1, f.liveCatalogReads, "тип, которого нет в снимке, спрошен у базы ровно раз")
	assert.Empty(t, f.upserts, "удержанный член не переписан")
	assert.Empty(t, allWrites(f), "удержанный член ничего не выпускает заново")
	assert.Empty(t, f.forgotten, "строки реестра удержанной координаты забыты")
	assert.Empty(t, revokedOf(f), "кортежи удержанной координаты сняты")
	assert.Equal(t, []string{memberKey(lagType, "w1")}, f.deletes, "уходит ровно член снятого правила")
}

// Близнец: строка каталога снята — оба члена уходят, кортежи сняты по реестру.
func TestCatalogLag_RetiredTypeRevokesBothMembers(t *testing.T) {
	f, _, _ := lagStore(false)
	require.NoError(t, New(fakeRunner{s: f}, nil, catalogfixture.Source()).ReconcileBinding(context.Background(), "acb-1"))

	assert.Equal(t, 1, f.liveCatalogReads)
	assert.Len(t, f.deletes, 2, "оба члена снятого типа уходят")
	assert.True(t, hasTuple(revokedOf(f), "v_get", "compute_widget:w1"), "кортеж снятого типа снят")
	assert.True(t, hasTuple(revokedOf(f), "viewer", "compute_widget:w1"), "ярусный кортеж снятого типа снят")
}

// Цена: проход, у которого каждый тип известен снимку, базу о каталоге не спрашивает.
func TestCatalogLag_KnownTypesCostNoCatalogRead(t *testing.T) {
	f := &fakeStore{
		scope:       domain.ScopeAnchor{Type: "project", ID: "prj-1"},
		subjectType: "user", subjectID: "usr-1", active: true,
		selectors: []domain.RuleSelector{{Arm: domain.ArmAnchor, RuleFP: "fp-n", ObjectTypes: []string{"vpc.network"}, Verbs: []string{"get"}}},
		mirror: map[string][]domain.MirrorObject{
			"vpc.network": {{ObjectType: "vpc.network", ObjectID: "n1", ParentProjectID: "prj-1"}},
		},
	}
	require.NoError(t, New(fakeRunner{s: f}, nil, catalogfixture.Source()).ReconcileBinding(context.Background(), "acb-1"))
	assert.Zero(t, f.liveCatalogReads, "обычный проход спросил каталог у базы")
	require.Len(t, f.upserts, 1)
}
