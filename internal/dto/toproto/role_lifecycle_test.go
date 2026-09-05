// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package toproto

// role_lifecycle_test.go — жизненное состояние роли на проводе (#1913).
//
// Приёмка `services/iam/docs/engineering/acceptance/role-withdrawal-has-a-producer.md`
// §2.6; сценарии IAM-RW-1-17, IAM-RW-1-19, IAM-RW-1-20.
//
// # Что здесь несущее
//
// «Не вычислено» обязано быть отличимо от «вычислено, и роль объявлена». На
// проводе это различие выражается ЗНАЧЕНИЕМ состояния, и сообщение приезжает
// ВСЕГДА — ровно как у `health` рядом.
//
// ЗДЕСЬ СТОЯЛО ОБРАТНОЕ, и довод был ложен: «сообщение, присутствующее всегда,
// оба состояния сливает». Перемерено во всех трёх кодировках — `UNSPECIFIED` и
// `DECLARED` различимы в каждой; отсутствие же сообщения лишало нулевое
// состояние ПРОИЗВОДИТЕЛЯ, то есть перечисление документировало значение,
// которого клиент не увидел бы никогда.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

// TestRoleLifecycleUnknownIsUnspecifiedNotDeclared — IAM-RW-1-20.
//
// Ответ операции состояния не вычисляет, и «нулевое значение означает „этим
// ответом не вычислено"» закрепляется ОТДЕЛЬНЫМ утверждением, а не
// подразумевается. Пара обязательна: без положительного близнеца отрицание
// зеленело бы на отображении, не производящем состояния никогда.
func TestRoleLifecycleUnknownIsUnspecifiedNotDeclared(t *testing.T) {
	unknown := roleLifecycleToPb(domain.RoleLifecycle{})
	require.NotNil(t, unknown,
		"сообщение обязано приезжать ВСЕГДА: у нулевого состояния иначе нет "+
			"производителя, и перечисление документировало бы значение, которого "+
			"клиент не увидит никогда")
	assert.Equal(t, iamv1.RoleLifecycleState_ROLE_LIFECYCLE_STATE_UNSPECIFIED, unknown.GetState(),
		"невычисленное состояние обязано приезжать UNSPECIFIED, а не DECLARED: "+
			"читать молчание как «роль объявлена» значит утверждать о праве по молчанию")

	// Положительный близнец: вычисленное состояние ОТЛИЧАЕТСЯ от нулевого.
	declared := roleLifecycleToPb(domain.RoleLifecycle{State: domain.RoleLifecycleDeclared})
	require.NotNil(t, declared)
	assert.Equal(t, iamv1.RoleLifecycleState_ROLE_LIFECYCLE_STATE_DECLARED, declared.GetState())
	assert.NotEqual(t, unknown.GetState(), declared.GetState(),
		"«не вычислено» и «объявлена» обязаны различаться значением: слив их, ответ "+
			"операции утверждал бы о праве")
	assert.Nil(t, declared.GetRetiredAt(), "у объявленной роли момента снятия быть не может")
	assert.Empty(t, declared.GetRetiredReason())
	assert.Empty(t, declared.GetRetiredBy())
}

// TestRoleLifecycleWithdrawnCarriesMomentReasonAndAuthor — IAM-RW-1-17.
//
// Снятая роль называет состояние СЛОВОМ и несёт все три обстоятельства: без
// причины «отобрали» неотличимо от «сломалось», без автора вопрос «кто у меня
// отобрал» остаётся без ответа.
func TestRoleLifecycleWithdrawnCarriesMomentReasonAndAuthor(t *testing.T) {
	at := time.Date(2026, 9, 4, 10, 20, 30, 123456000, time.UTC)
	got := roleLifecycleToPb(domain.RoleLifecycle{
		State:         domain.RoleLifecycleWithdrawn,
		RetiredAt:     at,
		RetiredReason: "манифест модуля vpc перестал объявлять эту роль",
		RetiredBy:     "iam-module-roles-boot",
	})
	require.NotNil(t, got)
	assert.Equal(t, iamv1.RoleLifecycleState_ROLE_LIFECYCLE_STATE_WITHDRAWN, got.GetState())
	assert.Equal(t, "манифест модуля vpc перестал объявлять эту роль", got.GetRetiredReason())
	assert.Equal(t, "iam-module-roles-boot", got.GetRetiredBy())
	require.NotNil(t, got.GetRetiredAt())
	// Усечение до секунд — общая дисциплина отметок времени: микросекунды базы на
	// провод не текут.
	assert.Equal(t, at.Truncate(time.Second).UTC(), got.GetRetiredAt().AsTime().UTC(),
		"момент снятия обязан быть усечён до секунд, как все отметки времени контракта")
}

// TestRoleLifecycleDistinguishesWithdrawnFromEmptyHealth — IAM-RW-1-19.
//
// Обе роли дают `ROLE_HEALTH_EMPTY`, и различает их ТОЛЬКО это поле. Утверждение
// стоит здесь, а не в пробе целости, потому что предмет у него — различимость
// двух состояний, а не величина каждого.
func TestRoleLifecycleDistinguishesWithdrawnFromEmptyHealth(t *testing.T) {
	withdrawn := domain.Role{
		Integrity: domain.RoleIntegrity{Health: domain.RoleHealthEmpty, Declared: 2, Unresolved: 2},
		Lifecycle: domain.RoleLifecycle{State: domain.RoleLifecycleWithdrawn},
	}
	unresolved := domain.Role{
		Integrity: domain.RoleIntegrity{Health: domain.RoleHealthEmpty, Declared: 2, Unresolved: 2},
		Lifecycle: domain.RoleLifecycle{State: domain.RoleLifecycleDeclared},
	}

	require.Equal(t, roleHealthToPb(withdrawn.Integrity.Health),
		roleHealthToPb(unresolved.Integrity.Health),
		"положительный контроль: целость у обеих ОДНА, иначе различать было бы нечего")

	assert.NotEqual(t,
		roleLifecycleToPb(withdrawn.Lifecycle).GetState(),
		roleLifecycleToPb(unresolved.Lifecycle).GetState(),
		"снятая роль и объявленная с неразрешёнными сегментами обязаны различаться "+
			"состоянием: следующий шаг у арендатора у них разный")
}
