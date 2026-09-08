// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// pgmaperr_catalog_ref_lane_test.go — ветви ссылок каталога прав отдают клиенту
// ТОТ ЖЕ текст после перевода на форму с признаком полосы.
//
// ПРЕДМЕТ. Ветви `role_rule_ref_res_fk`, `role_rule_ref_verb_fk` и
// `role_verb_type_fk` пришли из линии каталога с одноместной сигнатурой
// (`fkText → string`), а линия identity сделала сигнатуру двухместной
// (`→ (string, error)`): вместе с текстом едет ПОЛОСА нарушения — ссылаемого нет
// либо ресурс ещё используется. При сведении полос обеих линий каждой из трёх
// ветвей назначена полоса ССЫЛКИ.
//
// ЧЕМ ЭТО МОГЛО СЛОМАТЬСЯ МОЛЧА. Полосы вложены в `ErrFailedPrecondition`
// (`iamerr.ErrReferenceMissing = fmt.Errorf("%w: …", ErrFailedPrecondition)`),
// поэтому снятие sentinel-префикса обязано снять ДВА уровня, а не один. Снимет
// один — и арендатор получит `referenced resource missing: resources: …`, то есть
// внутреннее имя полосы в тексте контракта. Ни код, ни `Contains`-утверждения
// соседних проб этого не покажут: код тот же, подстрока на месте.
//
// Проба утверждает РАВЕНСТВО текста и код, а не вхождение.
//
// ПОДСКАЗКА СТРОИТСЯ ПОМОЩНИКОМ ПИСАТЕЛЯ (`ruleRefHint`), а не выписывается
// строкой: разделитель половин — `\x1f`, и выписанная копия разошлась бы с
// писателем МОЛЧА — обе половины уехали бы в «ресурс», ветвь свернула бы на
// обобщённый текст, а проба осталась бы зелёной, утверждая не тот путь.

import (
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

func TestCatalogRefusalTextSurvivesTheLaneWrapper(t *testing.T) {
	cases := []struct {
		name       string
		constraint string
		hint       string
		want       string
	}{
		{
			name:       "ресурс правила: сегмент назван",
			constraint: "role_rule_ref_res_fk",
			hint:       ruleRefHint(domain.RoleRuleRef{Resource: "vpc.cidrGroup"}),
			want:       "resources: vpc.cidrGroup is not a live platform resource",
		},
		{
			name:       "ресурс правила: сегмент не разобран",
			constraint: "role_rule_ref_res_fk",
			hint:       "",
			want:       "resources: rule names a resource that is not live in the platform catalog",
		},
		{
			name:       "глагол правила: оба сегмента названы",
			constraint: "role_rule_ref_verb_fk",
			hint:       ruleRefHint(domain.RoleRuleRef{Resource: "storage.volume", Verb: "create"}),
			want:       "verbs: create is not a live verb of resource storage.volume",
		},
		{
			name:       "глагол правила: сегменты не разобраны",
			constraint: "role_rule_ref_verb_fk",
			hint:       "",
			want:       "verbs: rule names a verb that is not live for its resource",
		},
		{
			name:       "проекция глаголов роли",
			constraint: "role_verb_type_fk",
			hint:       "rol00000000000000001",
			want:       "resources: rule names a resource that is not live in the platform catalog",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := wrapPgErr(&pgconn.PgError{Code: "23503", ConstraintName: tc.constraint}, "", tc.hint)
			require.Error(t, err)
			require.Equal(t, tc.want, iamerr.StripSentinel(err),
				"текст, который увидит арендатор, изменился при переводе ветви на форму с полосой")
			require.ErrorIs(t, err, iamerr.ErrFailedPrecondition,
				"код отказа обязан остаться FAILED_PRECONDITION — полосы вложены в него, а не заменяют его")
			require.ErrorIs(t, err, iamerr.ErrReferenceMissing,
				"полоса у ссылки каталога — сторона ССЫЛКИ: правило назвало сегмент, которого нет")
		})
	}

	// Положительный контроль: полоса ОТЛИЧИМА. Без него утверждение выше зеленело
	// бы на реализации, где обе полосы — одно и то же значение.
	t.Run("положительный контроль: вторая полоса отличима", func(t *testing.T) {
		err := wrapPgErr(&pgconn.PgError{Code: "23503", ConstraintName: "projects_account_fk"},
			"Account.Delete", "acc00000000000000001")
		require.ErrorIs(t, err, iamerr.ErrReferenceInUse)
		require.NotErrorIs(t, err, iamerr.ErrReferenceMissing,
			"полосы неразличимы — тогда признак ничего не сообщает")
	})
}
