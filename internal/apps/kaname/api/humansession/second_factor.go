// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// second_factor.go — ВТОРОЙ ФАКТОР на полосе входа: порты, формы, отказы,
// наблюдаемость и вид ответа церемонии (фаза Ф12, задача
// PRO-Robotech/kacho#1281; приёмка
// `docs/engineering/acceptance/second-factor-totp-and-recovery-codes.md`,
// Р1…Р11). Глаголы — по файлам: `sf_enroll.go` (заведение и подтверждение),
// `sf_status.go`, `sf_remove.go`, `sf_backup_codes.go`, `step_up.go`
// (церемония повышения — три ветви), `sf_present.go` (сверка кода, общая для
// входа и глаголов внутри сессии); поле `secondFactor` входа — `login.go`.
//
// # Матрица «глагол × состояние строки totp» (Р4) — читается отсюда
//
// Строка `totp` у человека одна; состояний три: нет · `pending` · `active`;
// набор есть ровно при `active`. Токенов о состоянии три, каждый — один факт:
//
//	SECOND_FACTOR_NOT_ENROLLED     step-up, remove, backup-codes, ResetSecondFactor
//	                               — при «нет» и при `pending`; ВХОД с полем
//	                               токена не несёт: там факт наружу не выходит
//	                               (тот же 401, Ф12-13 «е», kaname#257)
//	SECOND_FACTOR_ALREADY_ENROLLED enroll и confirm при `active`
//	ENROLLMENT_NOT_PENDING         confirm без ожидающего заведения: не начато,
//	                               истекло, снято уборкой — ОДИН токен
//
// Порядок проверок у глаголов семейства — несущий: форма → сессия → признак
// формы (транспорт) → частота → СВЕЖЕСТЬ, где требуется → СОСТОЯНИЕ строки →
// СРОК `pending` → СВЕРКА кода. Отказ по состоянию и по сроку код не сверяет и
// попыткой не считается (Р7).

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/loginmethod"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
)

// TOTPVerifier — проверяющий кода по времени (порт по существующему типу).
type TOTPVerifier interface {
	Wrap(s totpverify.Secret) (domain.LoginVerifier, error)
	Verify(stored domain.LoginVerifier, last totpverify.LastAccepted, code string, at time.Time) totpverify.Result
}

// SetVerifier — проверяющий набора запасных кодов (порт по проверяющему
// пароля: та же ёмкость — Р6).
type SetVerifier interface {
	SetCandidate(stored domain.LoginVerifier, presented string) passwordverify.SetCandidate
	MatchSet(stored domain.LoginVerifier, c passwordverify.SetCandidate) passwordverify.SetMatch
	SetSize(stored domain.LoginVerifier) (int, bool)
}

// SetHasher — чеканка набора тем же хешером, что пароль (Р6).
type SetHasher interface {
	HashSet(codes []string) (domain.LoginVerifier, error)
}

// SecondFactorDeps — зависимости глаголов второго фактора; все обязательны,
// кроме наблюдателя и журнала.
type SecondFactorDeps struct {
	Store     Store
	Methods   loginmethod.Store
	TOTP      TOTPVerifier
	Sets      SetVerifier
	SetHasher SetHasher
	// Verifier — проверяющий пароля: ветвь `password` церемонии (Ф11-09).
	Verifier Verifier
	Limits   Limits
	// Freshness — окно свежести правки своих данных (Р8): ручка без умолчания.
	Freshness time.Duration
	// Domain — доменное имя посадки: издатель и метка в `otpauth`-адресе (Р5).
	Domain   string
	Observer Observer
	Now      func() time.Time
	Logger   *slog.Logger
}

func (d SecondFactorDeps) validate(verb string) (SecondFactorDeps, error) {
	switch {
	case d.Store == nil:
		return d, fmt.Errorf("%s: session store required", verb)
	case d.Methods == nil:
		return d, fmt.Errorf("%s: login method store required", verb)
	case d.TOTP == nil:
		return d, fmt.Errorf("%s: totp verifier required", verb)
	case d.Sets == nil:
		return d, fmt.Errorf("%s: backup code set verifier required", verb)
	case d.SetHasher == nil:
		return d, fmt.Errorf("%s: backup code set hasher required", verb)
	case d.Verifier == nil:
		return d, fmt.Errorf("%s: password verifier required", verb)
	case d.Freshness <= 0:
		return d, fmt.Errorf("%s: self-service freshness window must be positive", verb)
	case d.Domain == "":
		return d, fmt.Errorf("%s: posture domain required", verb)
	}
	if err := d.Limits.Validate(); err != nil {
		return d, err
	}
	if d.Observer == nil {
		d.Observer = NopObserver{}
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	return d, nil
}

func (d SecondFactorDeps) gate() attemptGate {
	return attemptGate{store: d.Store, limits: d.Limits, now: d.Now, observer: d.Observer}
}

// SecondFactorPresentation — предъявление кода: способ называет КЛИЕНТ (Р4),
// а не выводится по длине кода.
type SecondFactorPresentation struct {
	Method assurance.Method
	Code   string
}

// ParseSecondFactorMethod — способ второго фактора из строки формы: `totp`
// либо `lookup_secret` (словарь Ф11 Р8); иное — отказ формы с именем поля.
func ParseSecondFactorMethod(field, s string) (assurance.Method, error) {
	switch s {
	case assurance.MethodTOTP.String():
		return assurance.MethodTOTP, nil
	case assurance.MethodLookupSecret.String():
		return assurance.MethodLookupSecret, nil
	case "":
		return assurance.Method{}, FieldRequired(field)
	}
	return assurance.Method{}, &FieldError{Field: field, Rule: "must be one of totp|lookup_secret"}
}

// ParseStepUpMethod — способ церемонии из строки формы: `password`, `totp`,
// `lookup_secret` (ветвь пароля — Ф11-09, ветви кода — Ф12); иное — отказ
// формы с именем поля. Словарь один: имена берутся у `assurance`.
func ParseStepUpMethod(field, s string) (assurance.Method, error) {
	switch s {
	case assurance.MethodPassword.String():
		return assurance.MethodPassword, nil
	case assurance.MethodTOTP.String():
		return assurance.MethodTOTP, nil
	case assurance.MethodLookupSecret.String():
		return assurance.MethodLookupSecret, nil
	case "":
		return assurance.Method{}, FieldRequired(field)
	}
	return assurance.Method{}, &FieldError{Field: field, Rule: "must be one of password|totp|lookup_secret"}
}

// JudgeStepUpForm — форма церемонии по способу: у `password` — пароль, у кода
// — форма кода (Н12). Судится и транспортом, и глаголом одним разбором.
func JudgeStepUpForm(in StepUpInput) error {
	switch in.Method {
	case assurance.MethodPassword:
		if in.Password == "" {
			return FieldRequired("password")
		}
		return nil
	case assurance.MethodTOTP, assurance.MethodLookupSecret:
		return JudgeCodeForm("code", SecondFactorPresentation{Method: in.Method, Code: in.Code})
	}
	return &FieldError{Field: "method", Rule: "must be one of password|totp|lookup_secret"}
}

// JudgeCodeForm — форма кода по способу (Н12): шесть цифр у `totp`, десять
// знаков Crockford у `lookup_secret`. Судится ДО пароля и до состояния;
// малоформенный код — отказ формы с именем поля, не попытка.
func JudgeCodeForm(field string, p SecondFactorPresentation) error {
	if p.Code == "" {
		return FieldRequired(field)
	}
	switch p.Method {
	case assurance.MethodTOTP:
		if !totpverify.IsWellFormedCode(p.Code) {
			return &FieldError{Field: field, Rule: fmt.Sprintf("must be %d digits", totpverify.Digits)}
		}
	case assurance.MethodLookupSecret:
		if !passwordverify.IsWellFormedBackupCode(p.Code) {
			return &FieldError{Field: field, Rule: fmt.Sprintf("must be %d characters of the backup-code alphabet", passwordverify.BackupCodeLength)}
		}
	default:
		return &FieldError{Field: field, Rule: "method must be one of totp|lookup_secret"}
	}
	return nil
}

// --- отказы: тексты и токены — контракт (Р4, §7 инв. 14) ---

const (
	TextSecondFactorNotEnrolled     = "second factor is not enrolled"
	TextSecondFactorAlreadyEnrolled = "second factor is already enrolled"
	TextEnrollmentNotPending        = "no pending enrollment: begin with enroll"
	TextSessionNotFresh             = "re-authentication required: present a credential again"
	TextSecondFactorUnavailable     = "second factor temporarily unavailable"
)

const (
	ReasonSecondFactorNotEnrolled     = "SECOND_FACTOR_NOT_ENROLLED"
	ReasonSecondFactorAlreadyEnrolled = "SECOND_FACTOR_ALREADY_ENROLLED"
	ReasonEnrollmentNotPending        = "ENROLLMENT_NOT_PENDING"
	ReasonSessionNotFresh             = "SESSION_NOT_FRESH"
)

// Сентинелы состояния (FAILED_PRECONDITION / ALREADY_EXISTS / PERMISSION_DENIED
// у транспорта) и недоступности материала (UNAVAILABLE, Р2).
var (
	ErrSecondFactorNotEnrolled     = errors.New(TextSecondFactorNotEnrolled)
	ErrSecondFactorAlreadyEnrolled = errors.New(TextSecondFactorAlreadyEnrolled)
	ErrEnrollmentNotPending        = errors.New(TextEnrollmentNotPending)
	ErrSessionNotFresh             = errors.New(TextSessionNotFresh)
	ErrSecondFactorUnavailable     = errors.New(TextSecondFactorUnavailable)
)

// --- события аудита (Р11) ---

const (
	AuditSecondFactorEnrolled   = "iam.user.second_factor_enrolled"
	AuditSecondFactorRemoved    = "iam.user.second_factor_removed"
	AuditBackupCodesRegenerated = "iam.user.backup_codes_regenerated"
	// AuditSessionStepUp — журнал повышения (Ф11-14): предъявление внутри
	// сессии — способ, уровень до и после. Производитель журнала — Ф11; здесь
	// заведён первым вместе с церемонией (§9 п.2 приёмки Ф12), и имена способов
	// в нём — словарь Ф11 Р8.
	AuditSessionStepUp = "iam.session.step_up"
)

// --- наблюдаемость (Ф12-43): три закрытых перечня ---

// PresentationOutcome — исход предъявления кода по способу.
type PresentationOutcome string

const (
	PresentationMatched            PresentationOutcome = "matched"
	PresentationMismatched         PresentationOutcome = "mismatched"
	PresentationReplayed           PresentationOutcome = "replayed"
	PresentationMaterialUnreadable PresentationOutcome = "material-unreadable"
	PresentationCapacityExhausted  PresentationOutcome = "capacity-exhausted" // только lookup_secret (Р6)
)

// PresentationOutcomes — закрытый перечень.
func PresentationOutcomes() []PresentationOutcome {
	return []PresentationOutcome{PresentationMatched, PresentationMismatched, PresentationReplayed,
		PresentationMaterialUnreadable, PresentationCapacityExhausted}
}

// SecondFactorMethods — способы, по которым считаются предъявления.
func SecondFactorMethods() []assurance.Method {
	return []assurance.Method{assurance.MethodTOTP, assurance.MethodLookupSecret}
}

// PresentationCell — пара способ × исход, которую полоса ПРОИЗВОДИТ.
type PresentationCell struct {
	Method  assurance.Method
	Outcome PresentationOutcome
}

// PresentationCells — закрытый перечень производимых пар: клетка, которая не
// может вырасти ни при каком входе, не заводится (форма Ф-е). Повтор — только
// у кода по времени (Р5); исчерпание ёмкости — только у запасного (Р6: HMAC
// ёмкости не занимает).
func PresentationCells() []PresentationCell {
	return []PresentationCell{
		{assurance.MethodTOTP, PresentationMatched},
		{assurance.MethodTOTP, PresentationMismatched},
		{assurance.MethodTOTP, PresentationReplayed},
		{assurance.MethodTOTP, PresentationMaterialUnreadable},
		{assurance.MethodLookupSecret, PresentationMatched},
		{assurance.MethodLookupSecret, PresentationMismatched},
		{assurance.MethodLookupSecret, PresentationMaterialUnreadable},
		{assurance.MethodLookupSecret, PresentationCapacityExhausted},
	}
}

// SecondFactorRefusal — отказ по состоянию, свежести либо недоступности:
// попыткой не считается, видим только клеткой.
type SecondFactorRefusal string

const (
	RefusalNotEnrolled          SecondFactorRefusal = "not-enrolled"
	RefusalAlreadyEnrolled      SecondFactorRefusal = "already-enrolled"
	RefusalEnrollmentNotPending SecondFactorRefusal = "enrollment-not-pending"
	RefusalSessionNotFresh      SecondFactorRefusal = "session-not-fresh"
	RefusalUnavailable          SecondFactorRefusal = "unavailable"
)

// SecondFactorRefusals — закрытый перечень.
func SecondFactorRefusals() []SecondFactorRefusal {
	return []SecondFactorRefusal{RefusalNotEnrolled, RefusalAlreadyEnrolled, RefusalEnrollmentNotPending,
		RefusalSessionNotFresh, RefusalUnavailable}
}

// SecondFactorEvent — событие второго фактора.
type SecondFactorEvent string

const (
	SecondFactorEnrollmentStarted   SecondFactorEvent = "enrollment-started"
	SecondFactorEnrollmentConfirmed SecondFactorEvent = "enrollment-confirmed"
	SecondFactorRemoved             SecondFactorEvent = "removed"
	SecondFactorBackupCodesMinted   SecondFactorEvent = "backup-codes-regenerated"
	SecondFactorBackupCodeConsumed  SecondFactorEvent = "backup-code-consumed"
)

// SecondFactorEvents — закрытый перечень.
func SecondFactorEvents() []SecondFactorEvent {
	return []SecondFactorEvent{SecondFactorEnrollmentStarted, SecondFactorEnrollmentConfirmed, SecondFactorRemoved,
		SecondFactorBackupCodesMinted, SecondFactorBackupCodeConsumed}
}

// --- ответ церемонии (Р4) ---

// AssuranceView — объект `assurance` ответа: два поля, два факта.
type AssuranceView struct {
	// Level — уровень сессии ПОСЛЕ предъявления.
	Level string
	// Level2Reachable — есть ли среди ЗАВЕДЁННЫХ у личности способов строка
	// «2» правила.
	Level2Reachable bool
	// MissingForLevel2 — способы словаря, чьё предъявление в этой сессии
	// её выполнит; пуст, когда «2» достигнут либо недостижим.
	MissingForLevel2 []string
}

// assuranceViewOf — вид из множества предъявленного и заведённых способов
// личности; уровень — только правилом (§7 инв. 8).
func assuranceViewOf(presented []string, enrolled []assurance.Method) AssuranceView {
	level, _ := assurance.LevelOf(presentationsOf(presented))
	view := AssuranceView{Level: level.String(), MissingForLevel2: []string{}}
	for _, l := range assurance.PresentableLevels(enrolled) {
		if l == assurance.Level2 {
			view.Level2Reachable = true
		}
	}
	if level == assurance.Level2 || level == assurance.Level3 || !view.Level2Reachable {
		return view
	}
	have := map[string]bool{}
	for _, m := range presented {
		have[m] = true
	}
	for _, m := range enrolled {
		if have[m.String()] {
			continue
		}
		with := append(append([]string(nil), presented...), m.String())
		if l, ok := assurance.LevelOf(presentationsOf(with)); ok && l == assurance.Level2 {
			view.MissingForLevel2 = append(view.MissingForLevel2, m.String())
		}
	}
	sort.Strings(view.MissingForLevel2)
	return view
}

// enrolledMethods — способы, ЗАВЕДЁННЫЕ у личности: пароль — строка `password`,
// второй фактор — строка `totp` в состоянии `active` (и с ней — набор).
func enrolledMethods(ctx context.Context, methods loginmethod.Store, userID domain.UserID) ([]assurance.Method, error) {
	var out []assurance.Method
	if _, err := methods.Get(ctx, userID, domain.LoginMethodPassword); err == nil {
		out = append(out, assurance.MethodPassword)
	} else if !isNotFound(err) {
		return nil, err
	}
	totp, err := methods.Get(ctx, userID, domain.LoginMethodTOTP)
	switch {
	case err == nil && totp.Enrolled():
		out = append(out, assurance.MethodTOTP, assurance.MethodLookupSecret)
	case err == nil, isNotFound(err):
	default:
		return nil, err
	}
	return out, nil
}

// factorState — строка `totp` человека: нет · pending · active (матрица Р4).
func factorState(ctx context.Context, methods loginmethod.Store, userID domain.UserID) (domain.LoginMethod, bool, error) {
	row, err := methods.Get(ctx, userID, domain.LoginMethodTOTP)
	if err == nil {
		return row, true, nil
	}
	if isNotFound(err) {
		return domain.LoginMethod{}, false, nil
	}
	return domain.LoginMethod{}, false, err
}

// withMethod — множество предъявленного с добавленным способом, без повтора.
func withMethod(presented []string, m assurance.Method) []string {
	for _, p := range presented {
		if p == m.String() {
			return append([]string(nil), presented...)
		}
	}
	return append(append([]string(nil), presented...), m.String())
}

// levelOf — уровень множества правилом; множество, не дающее уровня, у живой
// сессии не бывает (база не пропускает), поэтому отказ — наш дефект.
func levelOf(presented []string) (string, error) {
	level, ok := assurance.LevelOf(presentationsOf(presented))
	if !ok {
		return "", fmt.Errorf("session methods %v yield no assurance level", presented)
	}
	return level.String(), nil
}
