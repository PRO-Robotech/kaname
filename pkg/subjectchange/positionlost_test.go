// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: Apache-2.0

// positionlost_test.go — СЛОВАРЬ ОТКАЗА «позиция утрачена» замкнут сам на себя.
//
// # Что здесь держится
//
// Отказ собирает ВЛАДЕЛЕЦ журнала (iam), а разбирает ЧИТАТЕЛЬ (край). Это две
// стороны одного шва, и класс, которым он ломается, назван в корпусе: два
// механизма об одном предмете, каждый исправен, а вопрос одного — не тот, на
// который отвечает другой. Здесь шов сделан НЕВЫРАЗИМЫМ: производитель и
// распознаватель — одна пара функций одного файла, поэтому разойтись им нечем.
//
// Проба утверждает это круговым проходом: собрать отказ → провести его сквозь
// `google.rpc.Status` (именно так он и едет по проводу) → разобрать обратно.
// Утверждение только о конструкторе зеленело бы на распознавателе, не читающем
// ничего.
//
// # Отрицания стоят В ПАРЕ с положительным
//
// «Чужой отказ не признаётся своим» — утверждение, зелёное у распознавателя,
// который не признаёт НИЧЕГО. Поэтому рядом с каждым отрицанием стоит проход,
// обязанный совпасть.
package subjectchange_test

import (
	"errors"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/pkg/subjectchange"
)

// TestPositionLostRefusalSurvivesTheWireAndIsRecognisedBack — круговой проход.
func TestPositionLostRefusalSurvivesTheWireAndIsRecognisedBack(t *testing.T) {
	err := subjectchange.PositionLost(599)

	// Код — часть полосы, а не украшение: по нему вызывающий, не читающий
	// деталей вовсе, всё равно отличает «исправь позицию» от «повтори позже».
	if got := status.Code(err); got != codes.OutOfRange {
		t.Fatalf("код отказа %v, ожидался %v", got, codes.OutOfRange)
	}

	// Машинный признак доезжает деталью, а не прозой сообщения.
	var seenReason, seenDomain string
	for _, d := range status.Convert(err).Details() {
		info, ok := d.(*errdetails.ErrorInfo)
		if !ok {
			continue
		}
		seenReason, seenDomain = info.GetReason(), info.GetDomain()
	}
	if seenReason != subjectchange.ReasonPositionLost {
		t.Fatalf("признак полосы %q, ожидался %q", seenReason, subjectchange.ReasonPositionLost)
	}
	if seenDomain == "" {
		t.Fatal("поверхность отказа не названа: домен пуст")
	}

	// Разбор обратно — та же величина, а не «что-то ненулевое».
	lost, ok := subjectchange.AsPositionLost(err)
	if !ok {
		t.Fatal("собственный отказ не опознан распознавателем — шов разошёлся")
	}
	if lost.EarliestResumable != 599 {
		t.Fatalf("возобновимая позиция %d, ожидалось 599", lost.EarliestResumable)
	}
}

// TestPositionLostIsNotConfusedWithAnyOtherRefusal — отрицания, каждое в паре с
// положительным проходом выше.
func TestPositionLostIsNotConfusedWithAnyOtherRefusal(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{name: "отказа нет вовсе", err: nil},
		{name: "обычная ошибка", err: errors.New("connection refused")},
		{
			name: "недоступность владельца — повторить, а не гасить кэш",
			err:  status.Error(codes.Unavailable, "subject change position not settled"),
		},
		{
			// Тот же КОД, но чужая полоса: распознаватель обязан ключеваться на
			// признак, а не на код, иначе он признал бы своим всякий OutOfRange.
			name: "чужая полоса под тем же кодом",
			err:  otherLaneOutOfRange(t),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := subjectchange.AsPositionLost(tc.err); ok {
				t.Fatalf("чужой отказ признан своим: %v", tc.err)
			}
		})
	}
}

// TestPositionLostWithoutAPositionIsNotAPositionLost — отказ, не назвавший
// возобновимой позиции, полосой НЕ является.
//
// Читателю от такого отказа нет пользы: погасить кэш он ещё может, а сесть ему
// некуда — принять ноль значило бы проиграть журнал с начала, остаться на месте
// значило бы получать тот же отказ вечно. Поэтому такой ответ уходит в общую
// полосу, где он громкий (жалоба) и безопасный (fail-closed по сроку), а не
// притворяется полосой контракта.
func TestPositionLostWithoutAPositionIsNotAPositionLost(t *testing.T) {
	st := status.New(codes.OutOfRange, "subject change position is no longer resumable")
	withDetails, err := st.WithDetails(&errdetails.ErrorInfo{
		Reason: subjectchange.ReasonPositionLost,
		Domain: "iam.kacho.cloud",
		// Метаданных нет: позиция не названа.
	})
	if err != nil {
		t.Fatalf("собрать отказ без позиции: %v", err)
	}
	if _, ok := subjectchange.AsPositionLost(withDetails.Err()); ok {
		t.Fatal("отказ без возобновимой позиции признан полосой — читателю некуда садиться")
	}
}

// otherLaneOutOfRange — отказ того же кода из ЧУЖОЙ полосы.
func otherLaneOutOfRange(t *testing.T) error {
	t.Helper()
	st := status.New(codes.OutOfRange, "page token is out of range")
	withDetails, err := st.WithDetails(&errdetails.ErrorInfo{
		Reason: "SUBSCRIPTION_POSITION_LOST",
		Domain: "subscription.kacho.cloud",
	})
	if err != nil {
		t.Fatalf("собрать чужой отказ: %v", err)
	}
	return withDetails.Err()
}
