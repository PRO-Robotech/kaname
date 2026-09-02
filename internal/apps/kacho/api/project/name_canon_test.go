// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package project

// name_canon_test.go — канон имени на пути создания Project (#1279, канон #715).
//
// Пустая строка — законный ВХОД создания и означает «назови сам»: до записи она
// заменяется именем, производным от идентификатора. Прежде iam отвергал её
// синхронно, то есть исполнял общий контракт иначе, чем остальные домены.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/operations"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// createProjectNamed прогоняет создание с заданным именем и возвращает ресурс,
// каким его увидит арендатор в ответе операции.
func createProjectNamed(t *testing.T, name string) *iamv1.Project {
	t.Helper()
	repo := newFakeProjRepo()
	opsRepo := newFakeOpsRepoProj()
	uc := NewCreateProjectUseCase(repo, opsRepo)

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr0000000000000abcd"})
	op, err := uc.Execute(ctx, domain.Project{
		AccountID: "acc0000000000000abcd",
		Name:      domain.ProjectName(name),
	})
	require.NoError(t, err, "создание с именем %q обязано пройти синхронную проверку", name)
	require.NotNil(t, op)

	wctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	require.NoError(t, operations.Wait(wctx))

	done, err := opsRepo.Get(context.Background(), op.ID)
	require.NoError(t, err)
	require.True(t, done.Done, "операция обязана завершиться")
	require.Nil(t, done.Error, "создание обязано пройти, отказ: %v", done.Error)
	require.NotNil(t, done.Response, "ответ операции обязан нести созданный ресурс")

	var got iamv1.Project
	require.NoError(t, done.Response.UnmarshalTo(&got))
	return &got
}

// TestCreateProject_EmptyName_WritesIdDerivedDefault — ось «пустое имя»: строка
// ресурса не может нести пустое имя, умолчание — сам идентификатор.
func TestCreateProject_EmptyName_WritesIdDerivedDefault(t *testing.T) {
	got := createProjectNamed(t, "")
	assert.NotEmpty(t, got.Name, "строка ресурса не может нести пустое имя")
	assert.Equal(t, got.Id, got.Name, "умолчание — сам идентификатор (pkg/validate.NameOrDefault)")
}

// TestCreateProject_TwoEmptyNames_DistinctNames — два безымянных создания в одном
// аккаунте проходят ОБА и получают РАЗНЫЕ имена. Умолчание, производное от
// чего-либо кроме идентификатора, столкнулось бы на `projects_account_name_unique`.
func TestCreateProject_TwoEmptyNames_DistinctNames(t *testing.T) {
	first := createProjectNamed(t, "")
	second := createProjectNamed(t, "")
	assert.NotEqual(t, first.Name, second.Name,
		"два безымянных создания обязаны получить разные имена")
}

// TestCreateProject_CanonNames_Accepted — положительный контроль по двум осям,
// на которых прежняя форма iam была УЖЕ канона. Без него отрицание выше
// зеленело бы и на валидаторе, отвергающем всё подряд.
func TestCreateProject_CanonNames_Accepted(t *testing.T) {
	for _, tc := range []struct{ label, value string }{
		{"цифра первым символом", "9lives"},
		{"один символ", "a"},
		{"обычное имя", "prj-ok"},
	} {
		t.Run(tc.label, func(t *testing.T) {
			got := createProjectNamed(t, tc.value)
			assert.Equal(t, tc.value, got.Name, "присланное имя обязано сохраниться как есть")
		})
	}
}
