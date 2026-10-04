// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// recipient_directory_supergate_exempt_test.go — приёмка NTF-3 (kacho#2918),
// NTF3-151 «точная пара по типу»: место Д-3 `verdictForRelation` переписи §1.11
// NTF-1, вход `InternalIAMService/Check`.
//
// Меняется ровно один факт — объект вопроса (тип с его отношением и id), вход и
// субъект те же:
//
//	{user:usr-ca, token_issuer, iam_user:usr-A}                   → true  (надзор вне перечня жив)
//	{user:usr-ca, reader, notification_recipient_directory:root}  → false (Р28: надзор на типе не применяется)
//
// Близнец по субъекту — `service:notify` с посеянным кортежем `reader`:
// отличает «перечень снял надзор» от «дверь отказывает всем».
//
// Обработчик настоящий, дверь под ним — настоящая `service.AuthorizeService`;
// дублёр стоит только на месте хранилища отношений (relationFacts соседнего
// файла) и отвечает ровно посеянными фактами.

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/service"
)

const recipientDirectoryRoot = "notification_recipient_directory:root"

func TestNTF3151_InternalCheck_RecipientDirectoryIsNotReadBySuperGate(t *testing.T) {
	facts := newRelationFacts()
	facts.facts[notifySvc+"|reader|"+recipientDirectoryRoot] = true
	h := newCheckHandler(service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations:           facts,
		ClusterAdminChecker: facts,
	}))

	// Близнецы ДО предмета: сломанная дверь не выдаёт себя за снятый надзор.
	if twinType := internalCheck(t, h, exemptAdmin, "token_issuer", "iam_user:"+exemptTwinUser); !twinType.GetAllowed() {
		t.Fatalf("близнец по типу (форма NTF1-F12) iam_user:<U2>/token_issuer: отказ %q — надзор вне перечня "+
			"обязан остаться в силе; вопрос пробы сломан", twinType.GetReason())
	}
	if twinSubject := internalCheck(t, h, notifySvc, "reader", recipientDirectoryRoot); !twinSubject.GetAllowed() {
		t.Fatalf("близнец по субъекту service:notify с кортежем reader: отказ %q — дверь обязана отвечать моделью",
			twinSubject.GetReason())
	}
	before := facts.asks()

	resp := internalCheck(t, h, exemptAdmin, "reader", recipientDirectoryRoot)
	if resp.GetAllowed() {
		t.Fatalf("Check{%s reader %s} = true: администратор облака читает справочник адресов мимо модели — "+
			"надзор решил исход на типе, который Р28 вносит в перечень без надзора", exemptAdmin, recipientDirectoryRoot)
	}
	if resp.GetReason() == "" {
		t.Fatal("отказ без причины")
	}
	if n := facts.asks() - before; n != 0 {
		t.Fatalf("надзор спрошен %d раз на типе справочника — на типе перечня он не спрашивается", n)
	}
}
