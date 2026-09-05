// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// usecase_quota_lane_test.go — ГДЕ вызывающий узнаёт об исчерпании потолка
// (задача #1191, приёмка сценарий CRED-CAP-24).
//
// ЗДЕСЬ БЫЛО НЕВЕРНОЕ ОЖИДАНИЕ, и его исправила сама проба. Первая редакция
// требовала у секрета СИНХРОННОГО статуса `RESOURCE_EXHAUSTED` — на том
// основании, что вся его работа делается на пути запроса. Прогон показал другое:
// глагол возвращает `Operation` в ЛЮБОМ случае (мутации отвечают операцией, это
// контракт домена), и отказ приезжает её телом. У секрета операция завершена уже
// в ответе самого `Issue`, у ключевой пары — после работника.
//
// Разница поэтому не в ФОРМЕ ответа, а в МОМЕНТЕ: секрет отвечает исходом сразу,
// ключевая пара — по завершении. Утверждаются обе стороны: одна зеленела бы и на
// реализации, где отказ теряется, — «ошибки нет» и «ошибка приехала не сюда» по
// одной стороне неразличимы.

package user_tokens

import (
	"context"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	grpcstatus "google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

const quotaRefusalText = "iam.user usr00000000000000001 has reached its limit of 10 iam.user.credential"

func TestQuotaRefusalOnASecretIssueArrivesWithTheOperationItself(t *testing.T) {
	repo := &stubUserClientRepo{
		insertErr: iamerr.Wrapf(iamerr.ErrQuotaExceeded, "%s", quotaRefusalText),
	}
	uc := NewIssueUserTokenUseCase(repo, &stubTx{}, &stubOpsRepo{})

	op, err := uc.Execute(context.Background(), IssueInput{
		UserID:          "usr00000000000000001",
		CreatedByUserID: "usr00000000000000001",
		TTLSeconds:      int64((30 * 24 * time.Hour).Seconds()),
		CredentialKind:  domain.CredentialKindSecret,
	})
	if err != nil {
		// Синхронный статус тоже был бы исполнением контракта, но сегодня глагол
		// отвечает операцией; проба принимает то, что делает продукт, и требует
		// от него ПРАВИЛЬНОГО кода, а не своей формы.
		st, _ := grpcstatus.FromError(err)
		if st.Code() != codes.ResourceExhausted {
			t.Fatalf("отказ учёта пришёл как %v (%q), а не как исчерпание", st.Code(), st.Message())
		}
		return
	}
	if op == nil {
		t.Fatal("ни ошибки, ни операции: вызывающему не за чем возвращаться")
	}
	if !op.Done {
		t.Fatal("операция секрета НЕ завершена в ответе самого Issue — вся его работа делается " +
			"на пути запроса, и незавершённый ответ означал бы, что отказ где-то ещё")
	}
	if op.Error == nil {
		t.Fatal("операция завершена БЕЗ ошибки при исчерпанном потолке: предел не наступил")
	}
	if got := codes.Code(op.Error.GetCode()); got != codes.ResourceExhausted {
		t.Errorf("операция несёт код %v, а не исчерпание — клиент прочитает предел как поломку", got)
	}
	if !contains(op.Error.GetMessage(), "has reached its limit of 10") {
		t.Errorf("текст единственного производителя отказа не доехал дословно: %q", op.Error.GetMessage())
	}
	var reason string
	for _, d := range op.Error.GetDetails() {
		if d.MessageIs(&errdetails.ErrorInfo{}) {
			var info errdetails.ErrorInfo
			if d.UnmarshalTo(&info) == nil {
				reason = info.GetReason()
			}
		}
	}
	if reason != "QUOTA_EXCEEDED" {
		t.Errorf("признак полосы не доехал до операции (%q): клиенту придётся разбирать прозу", reason)
	}
}

// Вторая сторона: у ключевой пары выдача асинхронна, и отказ приезжает ТЕЛОМ
// завершённой операции. Утверждается, что он не теряется и несёт тот же код.
func TestQuotaRefusalOnAKeypairIssueArrivesInTheOperation(t *testing.T) {
	repo := &stubUserClientRepo{
		insertErr: iamerr.Wrapf(iamerr.ErrQuotaExceeded, "%s", quotaRefusalText),
	}
	ops := &stubOpsRepo{}
	uc := NewIssueUserTokenUseCase(repo, &stubTx{}, ops)

	op, err := uc.Execute(context.Background(), IssueInput{
		UserID:          "usr00000000000000001",
		CreatedByUserID: "usr00000000000000001",
		CredentialKind:  domain.CredentialKindKeypair,
	})
	if err != nil {
		t.Fatalf("глагол отказал синхронно, хотя его работа асинхронна: %v", err)
	}
	if op == nil {
		t.Fatal("операции нет вовсе — вызывающему не за чем возвращаться")
	}
	// Исход работника виден в ХРАНИЛИЩЕ операций, а не в возвращённом конверте:
	// конверт отдан клиенту раньше, чем работник начал. Проба, ждущая изменения
	// конверта, ждала бы того, чего не бывает, и падала бы по времени — то есть
	// сообщала бы о потере отказа там, где он доехал.
	waitForOp(t, ops)
	ops.mu.Lock()
	failed := ops.lastErr
	ops.mu.Unlock()
	if failed == nil {
		t.Fatal("операция завершена БЕЗ ошибки при исчерпанном потолке: предел не наступил")
	}
	if got := codes.Code(failed.GetCode()); got != codes.ResourceExhausted {
		t.Errorf("операция несёт код %v, а не исчерпание — клиент не отличит предел от поломки", got)
	}
	if !contains(failed.GetMessage(), "has reached its limit of 10") {
		t.Errorf("текст отказа не доехал дословно: %q", failed.GetMessage())
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
