// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// usecase_id_length_test.go — ПОЛОСА ОТКАЗА для задачи #1791 на полосе
// персонального токена. Полоса-близнец — `sa_keys/usecase_id_length_test.go`;
// разбор класса записан там один раз и здесь не пересказывается.
//
// Коротко: здесь стояла рукописная копия `shared.ValidateResourceID`,
// производившая побайтово тот же отказ `"invalid user id '<id>'"` и сверявшая
// только префикс. Обрезанный идентификатор проходил, а везде ещё отвергался;
// проба, сверяющая СООБЩЕНИЕ, различия показать не могла — тексты совпадали
// дословно.
package user_tokens

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// truncatedUserID — префикс верен, длина на один символ меньше требуемой.
// негодная форма id намеренно: проба УТВЕРЖДАЕТ отказ по длине, поэтому
// негодную форму обязана предъявить — привести её к форме значило бы снять
// само утверждение (ids_fixture_form_test.go).
const truncatedUserID = "usr0000000000000000"

// wellFormedUserID — тот же идентификатор полной длины: пара различается ровно
// одним символом.
const wellFormedUserID = truncatedUserID + "7"

func TestIssueUserToken_UserIDLengthIsJudged(t *testing.T) {
	require.Len(t, wellFormedUserID, domain.ShortIDLen,
		"положительный контроль обязан быть ПОЛНОЙ длины")
	require.Len(t, truncatedUserID, domain.ShortIDLen-1,
		"отрицание обязано отличаться от контроля РОВНО длиной")

	uc := NewIssueUserTokenUseCase(nil, nil, nil)

	t.Run("truncated is rejected by format", func(t *testing.T) {
		// created_by намеренно не назван: без починки исполнение проходит
		// проверку формата насквозь и отвергает запрос про ДРУГОЕ поле.
		_, err := uc.Execute(context.Background(), IssueInput{
			UserID: truncatedUserID,
		})

		require.Error(t, err)
		require.Equal(t, codes.InvalidArgument, grpcstatus.Code(err),
			"негодная форма идентификатора — INVALID_ARGUMENT")
		require.Equal(t, "invalid user id '"+truncatedUserID+"'",
			grpcstatus.Convert(err).Message(),
			"обрезанный идентификатор обязан отвергаться ФОРМОЙ, а не проезжать дальше")
	})

	t.Run("well-formed passes the format check", func(t *testing.T) {
		_, err := uc.Execute(context.Background(), IssueInput{
			UserID: wellFormedUserID,
		})

		require.Error(t, err, "use-case зовётся после подстановки — отказ ожидаем")
		require.Equal(t, "created_by_user_id required", grpcstatus.Convert(err).Message(),
			"полная длина проверкой формата не отвергается: отказ приходит про "+
				"СЛЕДУЮЩЕЕ поле. Без этого утверждения отрицание выше зеленело бы "+
				"на проверке, отвергающей всякий вход")
	})
}
