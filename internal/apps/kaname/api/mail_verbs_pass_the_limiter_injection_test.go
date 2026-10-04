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

// invitePorts — порт письма приглашения, чей писатель списывает окно.
var invitePorts = map[string]mailPort{"EmitInviteMail": {charged: true}}

func TestMailVerbGate_DerivesTheVerbsFromTheContract(t *testing.T) {
	root := t.TempDir()
	writeTree(t, root, map[string]string{
		"api/user/handler.go": syntheticHandler,
		"api/user/invite.go":  syntheticUseCaseWithLimit,
	})
	verbs, examined := deriveMailVerbs(t, filepath.Join(root, "api"), invitePorts)
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
	verbs, _ := deriveMailVerbs(t, filepath.Join(root, "api"), invitePorts)
	if len(verbs) != 1 || verbs[0].intentsNoLimit != 1 {
		t.Fatalf("намерение без Limit не найдено: %+v", verbs)
	}
}

func TestMailVerbGate_QueueWriterOrderAndSingularity(t *testing.T) {
	legal := t.TempDir()
	writeTree(t, legal, map[string]string{"repo/pg/tx.go": syntheticWriterLegal})
	findings, callers, ports := queueWriterFindings(t, legal)
	if callers != 1 || len(findings) != 0 || !ports["EmitInviteMail"].charged {
		t.Fatalf("законный писатель дал находки: %v (мест %d, порты %v)", findings, callers, ports)
	}

	after := t.TempDir()
	writeTree(t, after, map[string]string{"repo/pg/tx.go": syntheticWriterChargeAfter})
	findings, _, _ = queueWriterFindings(t, after)
	if len(findings) != 1 || !strings.Contains(findings[0], "не списав окно") {
		t.Fatalf("списание после постановки не найдено: %v", findings)
	}

	second := t.TempDir()
	writeTree(t, second, map[string]string{
		"repo/pg/tx.go":      syntheticWriterLegal,
		"apps/other/mail.go": syntheticSecondWriter,
	})
	findings, callers, _ = queueWriterFindings(t, second)
	if callers != 2 || len(findings) != 1 || !strings.Contains(findings[0], "второй путь к письму") {
		t.Fatalf("второй писатель очереди не найден: %v (мест %d)", findings, callers)
	}
}

// ─── Форма «маршрут полосы входа» (Ф5-28) ────────────────────────────────────

// Слушатель полосы: три маршрута, два зовут глаголы, отправляющие письмо, один
// — вход, письма не шлющий.
const syntheticLaneHandler = `package loginlanehttp

const (
	PathLogin    = "/iam/v1/auth/login"
	PathRegister = "/iam/v1/auth/register"
	PathRecovery = "/iam/v1/auth/recovery"
)

type Lane interface {
	Login(ctx context.Context, in LoginInput) error
	Register(ctx context.Context, in RegisterInput) error
	RequestRecovery(ctx context.Context, in RecoveryInput) error
}

type Handler struct {
	lane Lane
	mux  *http.ServeMux
}

func (h *Handler) routes() {
	h.mux.HandleFunc(PathLogin, h.method(http.MethodPost, h.login))
	h.mux.HandleFunc(PathRegister, h.method(http.MethodPost, h.register))
	h.mux.HandleFunc(PathRecovery, h.method(http.MethodPost, h.requestRecovery))
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request)    { _ = h.lane.Login(r.Context(), LoginInput{}) }
func (h *Handler) register(w http.ResponseWriter, r *http.Request) { _ = h.lane.Register(r.Context(), RegisterInput{}) }
func (h *Handler) requestRecovery(w http.ResponseWriter, r *http.Request) {
	// h.lane.RequestRecovery упомянут и в комментарии — гейт его не считает.
	_ = h.lane.RequestRecovery(r.Context(), RecoveryInput{})
}
`

// Адаптер порта в композиционном корне.
const syntheticLaneRoot = `package main

type laneVerbs struct {
	login    *humansession.LoginUseCase
	register *registration.RegisterUseCase
	request  *humansession.RequestRecoveryUseCase
}

func (v laneVerbs) Login(ctx context.Context, in loginlanehttp.LoginInput) error { return v.login.Execute(ctx, in) }
func (v laneVerbs) Register(ctx context.Context, in loginlanehttp.RegisterInput) error {
	return v.register.Execute(ctx, in)
}
func (v laneVerbs) RequestRecovery(ctx context.Context, in loginlanehttp.RecoveryInput) error {
	return v.request.Execute(ctx, in)
}
`

// Запрос кода: письмо ставится вспомогательным методом того же типа.
const syntheticRecoveryUseCase = `package humansession

type RequestRecoveryUseCase struct{ store Store; mailLimit outboxtypes.InviteMailRateLimit }
type LoginUseCase struct{}

func (uc *RequestRecoveryUseCase) Execute(ctx context.Context, in RecoveryInput) error {
	return uc.write(ctx)
}

func (uc *RequestRecoveryUseCase) write(ctx context.Context) error {
	w, _ := uc.store.Writer(ctx)
	return w.EmitRecoveryMail(ctx, RecoveryMailIntent{To: "a@b", Limit: uc.mailLimit})
}

func (uc *LoginUseCase) Execute(ctx context.Context, in LoginInput) error { return nil }
`

// Письмо подтверждения: функция пакета, зовомая регистрацией из ДРУГОГО
// пакета; предел решён вставкой строки кода раньше вызова порта.
const syntheticVerificationLetter = `package humansession

func EnqueueVerificationLetter(ctx context.Context, w Writer, pace Pace) error {
	refusal, err := w.InsertVerificationCodePaced(ctx, pace)
	if err != nil || refusal {
		return err
	}
	return w.EmitVerificationMail(ctx, VerificationMailIntent{To: "a@b"})
}
`

const syntheticVerificationLetterPacedAfter = `package humansession

func EnqueueVerificationLetter(ctx context.Context, w Writer, pace Pace) error {
	if err := w.EmitVerificationMail(ctx, VerificationMailIntent{To: "a@b"}); err != nil {
		return err
	}
	_, err := w.InsertVerificationCodePaced(ctx, pace)
	return err
}
`

const syntheticRegisterUseCase = `package registration

type RegisterUseCase struct{ store Store; pace humansession.Pace }

func (uc *RegisterUseCase) Execute(ctx context.Context, in Input) error {
	w, _ := uc.store.Writer(ctx)
	return humansession.EnqueueVerificationLetter(ctx, w, uc.pace)
}
`

// lanePorts — порты письма синтетического дерева: восстановление списывает
// окно у писателя, подтверждение — предел у вызывающего.
func lanePorts(recoveryCharged bool) map[string]mailPort {
	return map[string]mailPort{
		"EmitRecoveryMail":     {charged: recoveryCharged},
		"EmitVerificationMail": {charged: false},
	}
}

// syntheticLane — дерево формы «маршрут полосы»; правки — поверх законного.
func syntheticLane(t *testing.T, override map[string]string) (handler, root, api string) {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		"handler/handler.go":               syntheticLaneHandler,
		"cmd/loginlane.go":                 syntheticLaneRoot,
		"api/humansession/recovery.go":     syntheticRecoveryUseCase,
		"api/humansession/verification.go": syntheticVerificationLetter,
		"api/registration/register.go":     syntheticRegisterUseCase,
	}
	for k, v := range override {
		files[k] = v
	}
	writeTree(t, dir, files)
	return filepath.Join(dir, "handler"), filepath.Join(dir, "cmd"), filepath.Join(dir, "api")
}

func laneFindings(verbs []mailVerb) []string {
	var out []string
	for _, v := range verbs {
		out = append(out, verbFindings(v)...)
	}
	return out
}

// Законный близнец: обе формы ограничения узнаны, маршрут входа письма не
// шлёт, находок нет.
func TestMailVerbGate_LaneRoutesAreDerivedAndTheLawfulTwinIsSilent(t *testing.T) {
	h, r, a := syntheticLane(t, nil)
	verbs, routes, err := deriveLaneMailVerbs(t, h, r, a, lanePorts(true))
	if err != nil {
		t.Fatal(err)
	}
	if routes != 3 {
		t.Fatalf("осмотрено маршрутов %d, ожидалось 3", routes)
	}
	var got []string
	for _, v := range verbs {
		got = append(got, v.fqn)
	}
	want := "POST /iam/v1/auth/recovery POST /iam/v1/auth/register"
	if strings.Join(got, " ") != want {
		t.Fatalf("выведен перечень %v, ожидался %q", got, want)
	}
	if f := laneFindings(verbs); len(f) != 0 {
		t.Fatalf("законное дерево дало находки: %v", f)
	}
}

// Дефект: писатель порта восстановления окна не списывает (снятое списание) —
// находка с координатой вызова порта и именем маршрута.
func TestMailVerbGate_RedOnARecoveryPortWithoutTheWindow(t *testing.T) {
	h, r, a := syntheticLane(t, nil)
	verbs, _, err := deriveLaneMailVerbs(t, h, r, a, lanePorts(false))
	if err != nil {
		t.Fatal(err)
	}
	f := laneFindings(verbs)
	if len(f) != 1 || !strings.Contains(f[0], "POST /iam/v1/auth/recovery") ||
		!strings.Contains(f[0], "recovery.go:") || !strings.Contains(f[0], "без списания") {
		t.Fatalf("снятое списание окна адресата не найдено с координатой: %v", f)
	}
}

// Дефект: предел писем решён ПОСЛЕ вызова порта — форма (б) не засчитана.
func TestMailVerbGate_RedOnALetterPacedAfterTheQueue(t *testing.T) {
	h, r, a := syntheticLane(t, map[string]string{"api/humansession/verification.go": syntheticVerificationLetterPacedAfter})
	verbs, _, err := deriveLaneMailVerbs(t, h, r, a, lanePorts(true))
	if err != nil {
		t.Fatal(err)
	}
	f := laneFindings(verbs)
	if len(f) != 1 || !strings.Contains(f[0], "POST /iam/v1/auth/register") || !strings.Contains(f[0], "verification.go:") {
		t.Fatalf("предел после постановки не найден: %v", f)
	}
}

// Дефект: намерение письма восстановления без поля Limit.
func TestMailVerbGate_RedOnARecoveryIntentWithoutTheLimit(t *testing.T) {
	h, r, a := syntheticLane(t, map[string]string{"api/humansession/recovery.go": strings.Replace(
		syntheticRecoveryUseCase, `RecoveryMailIntent{To: "a@b", Limit: uc.mailLimit}`, `RecoveryMailIntent{To: "a@b"}`, 1)})
	verbs, _, err := deriveLaneMailVerbs(t, h, r, a, lanePorts(true))
	if err != nil {
		t.Fatal(err)
	}
	f := laneFindings(verbs)
	if len(f) != 1 || !strings.Contains(f[0], "без поля Limit") {
		t.Fatalf("намерение без Limit не найдено: %v", f)
	}
}

// Пустой обход формы — отказ, а не успех: слушатель без маршрутов.
func TestMailVerbGate_AnEmptyLaneWalkIsARefusal(t *testing.T) {
	h, r, a := syntheticLane(t, map[string]string{"handler/handler.go": "package loginlanehttp\n"})
	if _, routes, err := deriveLaneMailVerbs(t, h, r, a, lanePorts(true)); err == nil {
		t.Fatalf("пустой обход полосы (маршрутов %d) не отказал", routes)
	}
}

// Писатель порта восстановления без списания — порт выводится «предел у
// вызывающего», и глагол, не решивший предела, краснеет (выше); здесь —
// что вывод порта различает форму.
func TestMailVerbGate_PortFormIsDerivedFromTheWriter(t *testing.T) {
	dir := t.TempDir()
	writeTree(t, dir, map[string]string{"repo/pg/recovery.go": `package pg

func (w *humanSessionWriter) EmitRecoveryMail(ctx context.Context, in RecoveryMailIntent) error {
	admitted, err := chargeInviteMailWindowTx(ctx, w.tx, mailWindowRecovery, in.To, in.Limit)
	if err != nil || !admitted {
		return err
	}
	return invite_mail_outbox.EmitRecoveryTx(ctx, w.tx, "u", "a", in.To, "c", 0)
}

func (w *humanSessionWriter) EmitVerificationMail(ctx context.Context, in VerificationMailIntent) error {
	return invite_mail_outbox.EmitVerificationTx(ctx, w.tx, "u", "a", in.To, "c", 0)
}
`})
	findings, callers, ports := queueWriterFindings(t, dir)
	if len(findings) != 0 || callers != 2 || !ports["EmitRecoveryMail"].charged || ports["EmitVerificationMail"].charged {
		t.Fatalf("форма портов не выведена: находки %v, мест %d, порты %v", findings, callers, ports)
	}
}
