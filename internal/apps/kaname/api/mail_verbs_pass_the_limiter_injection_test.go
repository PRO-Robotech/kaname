// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mail_verbs_pass_the_limiter_injection_test.go — доказательство, что гейт
// ограничителя (mail_verbs_pass_the_limiter_test.go) СПОСОБЕН упасть и падает
// ровно на своём предмете (`testing.md` §«Гейт на класс», п. 2).
//
// Дефект вносится в СИНТЕТИЧЕСКОЕ дерево в t.TempDir(), а не в рабочее: у
// каждой оси — дефект и законный близнец.
package api_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeTree кладёт файлы синтетического дерева.
func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for rel, body := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// Обработчик службы контракта UserService с двумя глаголами: один зовёт
// use-case, ставящий письмо, другой — use-case без письма.
const syntheticHandler = `package user

type Handler struct {
	iamv1.UnimplementedUserServiceServer
	invite *InviteUseCase
	get    *GetUseCase
}

func (h *Handler) Invite(ctx context.Context, req *iamv1.InviteUserRequest) (*operationpb.Operation, error) {
	return h.invite.Execute(ctx)
}

func (h *Handler) Get(ctx context.Context, req *iamv1.GetUserRequest) (*iamv1.User, error) {
	return h.get.Execute(ctx)
}
`

const syntheticUseCaseWithLimit = `package user

type InviteUseCase struct{ repo Repo; mailLimit outboxtypes.InviteMailRateLimit }
type GetUseCase struct{}

func (uc *InviteUseCase) Execute(ctx context.Context) (*operationpb.Operation, error) {
	// EmitInviteMail упоминается и здесь, в комментарии — гейт его не считает.
	w, _ := uc.repo.Writer(ctx)
	_, err := w.EmitInviteMail(ctx, outboxtypes.InviteMailIntent{To: "a@b", Limit: uc.mailLimit})
	return nil, err
}

func (uc *GetUseCase) Execute(ctx context.Context) (*iamv1.User, error) { return nil, nil }
`

const syntheticUseCaseNoLimit = `package user

type InviteUseCase struct{ repo Repo }
type GetUseCase struct{}

func (uc *InviteUseCase) Execute(ctx context.Context) (*operationpb.Operation, error) {
	w, _ := uc.repo.Writer(ctx)
	_, err := w.EmitInviteMail(ctx, outboxtypes.InviteMailIntent{To: "a@b"})
	return nil, err
}

func (uc *GetUseCase) Execute(ctx context.Context) (*iamv1.User, error) { return nil, nil }
`

const syntheticWriterLegal = `package pg

func (w *writeTx) EmitInviteMail(ctx context.Context, intent outboxtypes.InviteMailIntent) (bool, error) {
	admitted, err := chargeInviteMailWindowTx(ctx, w.tx, intent.To, intent.Limit)
	if err != nil || !admitted {
		return false, err
	}
	return true, invite_mail_outbox.EmitTx(ctx, w.tx, intent.UserID, intent.AccountID, intent.To, intent.LoginURL)
}
`

const syntheticWriterChargeAfter = `package pg

func (w *writeTx) EmitInviteMail(ctx context.Context, intent outboxtypes.InviteMailIntent) (bool, error) {
	if err := invite_mail_outbox.EmitTx(ctx, w.tx, intent.UserID, intent.AccountID, intent.To, intent.LoginURL); err != nil {
		return false, err
	}
	return chargeInviteMailWindowTx(ctx, w.tx, intent.To, intent.Limit)
}
`

const syntheticSecondWriter = `package other

func sneakyMail(ctx context.Context, tx pgx.Tx) error {
	return invite_mail_outbox.EmitTx(ctx, tx, "u", "a", "x@y", "")
}
`

func TestMailVerbGate_DerivesTheVerbsFromTheContract(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"api/user/handler.go": syntheticHandler,
		"api/user/invite.go":  syntheticUseCaseWithLimit,
	})
	verbs, examined := deriveMailVerbs(t, filepath.Join(root, "api"))
	if examined != 2 {
		t.Fatalf("осмотрено %d методов-глаголов, ожидалось 2 (Invite и Get)", examined)
	}
	if len(verbs) != 1 || !strings.HasSuffix(verbs[0].fqn, "UserService/Invite") {
		t.Fatalf("выведен перечень %+v, ожидался ровно Invite", verbs)
	}
	if verbs[0].intentsNoLimit != 0 || verbs[0].intentsTotalLit != 1 {
		t.Fatalf("законный use-case дал находку: %+v", verbs[0])
	}
}

func TestMailVerbGate_RedOnAnIntentWithoutTheLimit(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"api/user/handler.go": syntheticHandler,
		"api/user/invite.go":  syntheticUseCaseNoLimit,
	})
	verbs, _ := deriveMailVerbs(t, filepath.Join(root, "api"))
	if len(verbs) != 1 || verbs[0].intentsNoLimit != 1 {
		t.Fatalf("намерение без Limit не найдено: %+v", verbs)
	}
}

func TestMailVerbGate_QueueWriterOrderAndSingularity(t *testing.T) {
	legal := t.TempDir()
	writeTree(t, legal, map[string]string{"repo/pg/tx.go": syntheticWriterLegal})
	findings, callers := queueWriterFindings(t, legal)
	if callers != 1 || len(findings) != 0 {
		t.Fatalf("законный писатель дал находки: %v (мест %d)", findings, callers)
	}

	after := t.TempDir()
	writeTree(t, after, map[string]string{"repo/pg/tx.go": syntheticWriterChargeAfter})
	findings, _ = queueWriterFindings(t, after)
	if len(findings) != 1 || !strings.Contains(findings[0], "не списав окно") {
		t.Fatalf("списание после постановки не найдено: %v", findings)
	}

	second := t.TempDir()
	writeTree(t, second, map[string]string{
		"repo/pg/tx.go":      syntheticWriterLegal,
		"apps/other/mail.go": syntheticSecondWriter,
	})
	findings, callers = queueWriterFindings(t, second)
	if callers != 2 || len(findings) != 1 || !strings.Contains(findings[0], "второй путь к письму") {
		t.Fatalf("второй писатель очереди не найден: %v (мест %d)", findings, callers)
	}
}
