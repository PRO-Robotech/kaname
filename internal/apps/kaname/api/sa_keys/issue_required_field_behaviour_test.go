// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// issue_required_field_behaviour_test.go — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к правилу об
// ответственном на полосе ключа служебной учётки (задача #1255, приёмка PROTO-1,
// сценарий Д-03). Полоса-близнец — `user_tokens/issue_required_field_behaviour_test.go`;
// разбор, почему замена именно такая, записан там один раз и здесь не
// пересказывается.
//
// Коротко: обязательность прежде утверждалась ОПИСАТЕЛЕМ (расширение
// `(required)` снятого семейства `kacho.cloud.validation`), у которого не было
// исполнителя. Теперь она утверждается тем, что край **отвергает** запрос без
// поля, — единственным признаком, который не может разойтись с поведением.
package sa_keys

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"
)

// TestIssueSAKey_ServiceAccountIDIsRequiredByBehaviour — Д-03 на полосе ключа.
func TestIssueSAKey_ServiceAccountIDIsRequiredByBehaviour(t *testing.T) {
	// Пустые зависимости намеренно: отказ обязан наступить до первой из них.
	// Дойди исполнение до репозитория — проба упала бы паникой, и это отличает
	// «отвергнуто первым стейтментом» от «отвергнуто когда-нибудь».
	uc := NewIssueSAKeyUseCase(nil, nil, nil, nil)

	_, err := uc.Execute(context.Background(), IssueInput{
		// service_account_id не назван — это и есть предмет.
		CreatedByUserID: "usr00000000000000007",
	})

	require.Error(t, err,
		"service_account_id обязателен: без отказа положительный контроль вакуумен")
	require.Equal(t, codes.InvalidArgument, grpcstatus.Code(err),
		"отсутствие обязательного поля — INVALID_ARGUMENT")
	// Сверка ДОСЛОВНАЯ: тон отказа — часть контракта, а проверка на вхождение
	// подстроки не отличила бы отказ про это поле от отказа про соседнее.
	require.Equal(t, "service_account_id required", grpcstatus.Convert(err).Message(),
		"отказ обязан назвать ИМЕННО это поле")
}

// TestIssueSAKey_CreatedByOmitted_IsNotRefusedForBeingAbsent — вторая сторона
// пары: отказ обязан быть про ДРУГОЕ поле, иначе проба выше зеленела бы на крае,
// отвергающем всякий запрос целиком.
func TestIssueSAKey_CreatedByOmitted_IsNotRefusedForBeingAbsent(t *testing.T) {
	uc := NewIssueSAKeyUseCase(nil, nil, nil, nil)

	_, err := uc.Execute(context.Background(), IssueInput{
		ServiceAccountID: "sva00000000000000009",
	})

	require.Error(t, err, "use-case зовётся после подстановки — пустое значение сюда не приходит")
	require.Equal(t, codes.InvalidArgument, grpcstatus.Code(err))
	require.Equal(t, "created_by_user_id required", grpcstatus.Convert(err).Message(),
		"предмет отказа обязан быть РАЗНЫМ у двух проб этого файла — иначе они "+
			"утверждают одно и то же")
}
