// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

// applied_type_materializes_test.go — РЕКОНСАЙЛЕР видит тип, заведённый
// применением манифеста в РАБОТАЮЩЕМ процессе (kacho#1967, kacho#1816).
//
// # Зеркало пробы пути запроса, и зеркалить его пришлось потому, что порт другой
//
// `catalog.TestIAMCT2_14_AppliedTypeReachesTheProjection` утверждает то же
// направление ЗАВЕДЕНИЯ у проекции «роль → тип × глагол». О реконсайлере она не
// утверждает ничего: он раскрывал точечное имя СВОИМ переходником
// (`fgaObjectType`), и тот спрашивал словарь, ПОРОЖДЁННЫЙ СБОРКОЙ. Зелень
// соседней пробы при этом сохранялась целиком — два порта, один вопрос, разные
// источники.
//
// # Что утверждается — НАБЛЮДАЕМОЕ, а не форма вызова
//
// Проба не смотрит, у кого реконсайлер спрашивает имя типа: она подаёт живые
// строки со ЗАВЕДЁННЫМ ресурсом, прогоняет проход и требует материализации —
// строку члена и кортежи на объекте этого типа. Утверждение о форме вызова
// («зовёт не литерал») пережило бы свой предмет при первой же перестановке кода
// и не сказало бы ничего о том, получает ли арендатор права.
//
// # Почему рядом ЖИВОЙ СОСЕД
//
// «Кортежей нет» на одном типе неотличимо от прохода, не материализующего
// НИЧЕГО. Поэтому в том же проходе идёт `compute.instance`: он обязан
// материализоваться при любом исходе, и его молчание означает сломанную
// фикстуру, а не предмет пробы.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// Ресурс, заведённый ПОСЛЕ сборки: ни его модуля, ни его точечного имени, ни
// имени его типа модели в дереве нет ни одним литералом. Проверяет это
// отдельная проба-контроль ниже, а не этот комментарий.
const (
	appliedModule     = "billing"
	appliedResource   = "invoice"
	appliedDotted     = appliedModule + "." + appliedResource
	appliedObjectType = "billing_invoice"
)

// rowsWithAppliedResource — живые строки каталога ПЛЮС ресурс, заведённый
// применением манифеста в работающем процессе.
//
// Строки посева берутся у `seed.LiteralRows()` — того же перечня, которым
// каталог посеян и с которым его сверяет страж старта; второй производитель
// того же перечня разошёлся бы с первым молча.
func rowsWithAppliedResource() catalog.Rows {
	rows := seed.LiteralRows()
	rows.Modules = append(rows.Modules, appliedModule)
	rows.Resources = append(rows.Resources, catalog.ResourceRow{
		Module: appliedModule, Resource: appliedResource, ObjectType: appliedObjectType,
	})
	for _, verb := range []string{"get", "list", "update", "delete"} {
		rows.Verbs = append(rows.Verbs, catalog.VerbRow{
			Module: appliedModule, Resource: appliedResource, Verb: verb, PerObject: true,
		})
	}
	return rows
}

// appliedCatalog — источник каталожного факта со заведённым ресурсом.
func appliedCatalog(t *testing.T) catalog.Source {
	t.Helper()
	f, err := catalog.NewFacts(rowsWithAppliedResource())
	require.NoError(t, err, "снимок со строкой заведённого ресурса")
	return catalog.Fixed{F: f}
}

// TestReconcile_AppliedTypeMaterializes — тип, заведённый применением манифеста
// в работающем процессе, материализуется проходом реконсайлера.
func TestReconcile_AppliedTypeMaterializes(t *testing.T) {
	appliedFP := domain.Rule{
		Module: appliedModule, Resources: []string{appliedResource}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"env": "prod"},
	}.Fingerprint()
	liveFP := domain.Rule{
		Module: "compute", Resources: []string{"instance"}, Verbs: []string{"get"},
		MatchLabels: map[string]string{"env": "prod"},
	}.Fingerprint()

	f := &fakeStore{
		scope:       domain.ScopeAnchor{Type: "project", ID: "prj-1"},
		subjectType: "user", subjectID: "usr-1", active: true,
		selectors: []domain.RuleSelector{
			{
				Arm: domain.ArmLabels, RuleFP: appliedFP,
				ObjectTypes: []string{appliedDotted},
				MatchLabels: map[string]string{"env": "prod"},
				Verbs:       []string{"get"},
			},
			{
				Arm: domain.ArmLabels, RuleFP: liveFP,
				ObjectTypes: []string{"compute.instance"},
				MatchLabels: map[string]string{"env": "prod"},
				Verbs:       []string{"get"},
			},
		},
		mirror: map[string][]domain.MirrorObject{
			appliedDotted: {{
				ObjectType: appliedDotted, ObjectID: "inv-1",
				ParentProjectID: "prj-1", Labels: map[string]string{"env": "prod"},
			}},
			"compute.instance": {{
				ObjectType: "compute.instance", ObjectID: "i-1",
				ParentProjectID: "prj-1", Labels: map[string]string{"env": "prod"},
			}},
		},
	}

	rec := New(fakeRunner{s: f}, nil, appliedCatalog(t))
	require.NoError(t, rec.ReconcileBinding(context.Background(), "acb-1"))

	w := allWrites(f)

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: живой сосед материализовался. Без него молчание по
	// заведённому типу неотличимо от прохода, не давшего ничего вовсе.
	require.Truef(t, hasTuple(w, "v_get", "compute_instance:i-1"),
		"живой сосед compute.instance не материализовался — фикстура сломана целиком, "+
			"вердикт о заведённом типе беспредметен (кортежей всего %d)", len(w))

	// ПРЕДМЕТ: заведённый применением тип даёт члена и кортежи.
	var applied *domain.TargetMember
	for i := range f.upserts {
		if f.upserts[i].ObjectType == appliedDotted {
			applied = &f.upserts[i]
		}
	}
	require.NotNilf(t, applied,
		"члена по типу %q проход НЕ записал: строки каталога поданы, членство модуля живо, "+
			"правило отобрало объект — и арендатор не получил бы НИЧЕГО. Имя типа модели прав "+
			"реконсайлер спрашивает у словаря, ПОРОЖДЁННОГО СБОРКОЙ, а типа %q сборка не знала "+
			"(записано членов: %d)", appliedDotted, appliedObjectType, len(f.upserts))
	assert.Equal(t, domain.VerificationActive, applied.VerificationStatus,
		"член заведённого типа записан не действующим")

	assert.Truef(t, hasTuple(w, "v_get", appliedObjectType+":inv-1"),
		"кортежа v_get на объекте %s:inv-1 нет — тип раскрылся, а отношение не эмитировано (кортежи: %v)",
		appliedObjectType, w)
	assert.Truef(t, hasTuple(w, "viewer", appliedObjectType+":inv-1"),
		"ярусного кортежа на объекте %s:inv-1 нет (кортежи: %v)", appliedObjectType, w)
}

// TestReconcile_ControlBuildDoesNotKnowTheAppliedType — ПРЕДПОСЫЛКА пробы выше.
//
// Она осмысленна ровно пока сборка этого имени НЕ знает: впиши кто-нибудь
// `billing.invoice` в манифест — и проба зеленела бы вхолостую, а отличить это
// от исправного порта было бы нечем.
//
// Спрашивается перечень ПОСЕВА (`authzmap.CatalogSeedResources`), а не
// переходник имени: переходник — предмет правки, и контроль, построенный на нём,
// перестал бы отвечать вместе с ним.
func TestReconcile_ControlBuildDoesNotKnowTheAppliedType(t *testing.T) {
	seeded := authzmap.CatalogSeedResources()
	require.NotEmpty(t, seeded, "перечень посева пуст — контроль предпосылки беспредметен")
	for _, r := range seeded {
		require.NotEqualf(t, appliedDotted, r.Dotted,
			"сборка знает %q — предпосылка отпала, и проба заведения зеленела бы вхолостую. "+
				"Возьмите имя, которого нет ни в одном манифесте", appliedDotted)
	}
	t.Logf("осмотрено строк посева: %d; ни одна не называет %q", len(seeded), appliedDotted)
}
