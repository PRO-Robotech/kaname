// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// usecase_id_length_test.go — ПОЛОСА ОТКАЗА для задачи #1791: проверка формата
// идентификатора служебной учётки на пути выдачи ключа обязана судить ДЛИНУ, а
// не только префикс.
//
// # ПОЧЕМУ ЭТОГО НЕ ВИДЕЛА НИ ОДНА ПРЕЖНЯЯ ПРОБА
//
// Здесь стояла рукописная копия `shared.ValidateResourceID`, производившая
// ПОБАЙТОВО ТОТ ЖЕ отказ — `"invalid service account id '<id>'"` — и сверявшая
// только префикс. Тексты совпадали дословно, поэтому проба, сверяющая
// СООБЩЕНИЕ, зеленела на обеих реализациях и различия не показывала никогда.
// Расхождение находится только сравнением того, что проверка ДЕЛАЕТ: обрезанный
// идентификатор с верным префиксом здесь проходил, а везде ещё отвергался.
//
// # ПАРА РАЗЛИЧАЕТСЯ РОВНО ОСЬЮ ДЛИНЫ
//
// Оба входа пробы ниже — один и тот же идентификатор, отличающийся ОДНИМ
// последним символом. Отрицание без такого положительного контроля зеленело бы
// на проверке, отвергающей всякий вход; контроль без отрицания — на проверке,
// не отвергающей ничего.
//
// # ЗАВИСИМОСТИ НЕ НУЖНЫ, И ЭТО ЧАСТЬ УТВЕРЖДЕНИЯ
//
// Формат судится ДО репозитория, транзакции и журнала операций, поэтому
// use-case строится с пустыми зависимостями: дойди исполнение до любой из них,
// проба упала бы паникой — и это отличает «отвергнуто формой» от «отвергнуто
// когда-нибудь».
package sa_keys

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// truncatedSAID — префикс верен, длина на один символ меньше требуемой
// `domain.ShortIDLen`. Именно такой вход прежняя копия принимала.
// негодная форма id намеренно: проба УТВЕРЖДАЕТ отказ по длине, поэтому
// негодную форму обязана предъявить — привести её к форме значило бы снять
// само утверждение (ids_fixture_form_test.go).
const truncatedSAID = "sva0000000000000000"

// wellFormedSAID — тот же идентификатор полной длины: пара различается ровно
// одним символом, поэтому её вердикт говорит об оси ДЛИНЫ и ни о чём другом.
const wellFormedSAID = truncatedSAID + "9"

func TestIssueSAKey_ServiceAccountIDLengthIsJudged(t *testing.T) {
	// Посылка пробы объявлена, а не подразумевается: сломайся она — пара
	// перестала бы различаться длиной, и вердикт стал бы про другое.
	require.Len(t, wellFormedSAID, domain.ShortIDLen,
		"положительный контроль обязан быть ПОЛНОЙ длины")
	require.Len(t, truncatedSAID, domain.ShortIDLen-1,
		"отрицание обязано отличаться от контроля РОВНО длиной")

	uc := NewIssueSAKeyUseCase(nil, nil, nil, nil)

	t.Run("truncated is rejected by format", func(t *testing.T) {
		// created_by намеренно не назван: без починки исполнение проходит
		// проверку формата насквозь и отвергает запрос про ДРУГОЕ поле — это и
		// есть наблюдаемое красное, а не паника на пустой зависимости.
		_, err := uc.Execute(context.Background(), IssueInput{
			ServiceAccountID: truncatedSAID,
		})

		require.Error(t, err)
		require.Equal(t, codes.InvalidArgument, grpcstatus.Code(err),
			"негодная форма идентификатора — INVALID_ARGUMENT")
		// Сверка ДОСЛОВНАЯ: тон отказа — часть контракта
		// (api-conventions.md §Error-format), и проверка на вхождение подстроки
		// не отличила бы отказ про формат от отказа про соседнее поле.
		require.Equal(t, "invalid service account id '"+truncatedSAID+"'",
			grpcstatus.Convert(err).Message(),
			"обрезанный идентификатор обязан отвергаться ФОРМОЙ, а не проезжать дальше")
	})

	t.Run("well-formed passes the format check", func(t *testing.T) {
		_, err := uc.Execute(context.Background(), IssueInput{
			ServiceAccountID: wellFormedSAID,
		})

		require.Error(t, err, "use-case зовётся после подстановки — отказ ожидаем")
		require.Equal(t, "created_by_user_id required", grpcstatus.Convert(err).Message(),
			"полная длина проверкой формата не отвергается: отказ приходит про "+
				"СЛЕДУЮЩЕЕ поле. Без этого утверждения отрицание выше зеленело бы "+
				"на проверке, отвергающей всякий вход")
	})
}
