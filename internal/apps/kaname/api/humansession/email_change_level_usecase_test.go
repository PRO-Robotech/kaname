// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// email_change_level_usecase_test.go — пробы уровня U редакции 3 приёмки
// `docs/engineering/acceptance/email-change-is-confirmed-from-the-new-address.md`
// (задача PRO-Robotech/kaname#770, решение Р2 «уровень — по заведённому»):
// сценарии EC-32 и EC-33 на портах-дублёрах. Исходное условие «ключ доступа
// заведён» и «чтение заведённого отказало» харнесс слушателя не создаёт —
// поэтому здесь, а не на проводе.
//
// # Ступени пробы
//
//  1. МИР — дублёры отвечают объявленным заведённым и объявленным отказом
//     чтения; проверяется ДО предмета вызовом самих дублёров. Отказ —
//     «НЕ-ВЫПОЛНИЛОСЬ(фикстура)».
//  2. ПРЕДМЕТ — исход глагола; отказ несёт номер сценария и клетку.
//
// # Каналы чтения заведённого
//
// Приёмка заказывает чтение заведённого (строки способов входа и наличие ключа,
// `enrolledForCompletion`), но не его носитель. Дублёр отвечает одним и тем же
// на всех трёх законных носителях, чтобы проба не диктовала реализации форму
// провязки: поле зависимостей глаголов (любое незаполненное поле-интерфейс,
// которое дублёр способов удовлетворяет, — `wireEnrolledReader`), хранилище
// глаголов и транзакция глаголов (`LoginMethod`, `AccessKeyEnrolled` порта
// `Writer`). Отказ чтения включается на всех носителях сразу.

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// errEnrolledUnreadable — отказ чтения заведённого дублёром (EC-33).
var errEnrolledUnreadable = errors.New("injected: enrolled methods are unreadable")

// ec2Methods — дублёр способов входа личности: пароль заведён всегда, код по
// времени и ключ — по клетке; fail — чтение отвечает ошибкой хранилища на всех
// носителях. Отвечает и как `loginmethod.Store` (запись не разрешена: вызов
// записи — ошибка пробы, а не тихий успех).
type ec2Methods struct {
	totp  bool
	key   bool
	fail  bool
	reads int
}

func (m *ec2Methods) Get(_ context.Context, userID domain.UserID, kind domain.LoginMethodKind) (domain.LoginMethod, error) {
	m.reads++
	if m.fail {
		return domain.LoginMethod{}, errEnrolledUnreadable
	}
	switch {
	case kind == domain.LoginMethodPassword:
		return domain.LoginMethod{UserID: userID, Kind: kind, State: domain.LoginMethodStateActive, CreatedAt: ecNow.Add(-time.Hour)}, nil
	case kind == domain.LoginMethodTOTP && m.totp:
		return domain.LoginMethod{UserID: userID, Kind: kind, State: domain.LoginMethodStateActive,
			AcceptedStep: 1, StepAccepted: true, CreatedAt: ecNow.Add(-time.Hour)}, nil
	case kind == domain.LoginMethodLookupSecret && m.totp:
		return domain.LoginMethod{UserID: userID, Kind: kind, State: domain.LoginMethodStateActive, CreatedAt: ecNow.Add(-time.Hour)}, nil
	}
	return domain.LoginMethod{}, iamerr.ErrNotFound
}

// LoginMethod — то же чтение носителем транзакции (порт `Writer`).
func (m *ec2Methods) LoginMethod(ctx context.Context, userID domain.UserID, kind domain.LoginMethodKind) (domain.LoginMethod, error) {
	return m.Get(ctx, userID, kind)
}

func (m *ec2Methods) AccessKeyEnrolled(context.Context, domain.UserID) (bool, error) {
	m.reads++
	if m.fail {
		return false, errEnrolledUnreadable
	}
	return m.key, nil
}

func (m *ec2Methods) Create(context.Context, domain.LoginMethod) (domain.LoginMethod, error) {
	return domain.LoginMethod{}, errors.New("probe: the email change verbs must not create a login method")
}

func (m *ec2Methods) MarkEmailVerified(context.Context, domain.UserID, domain.Email, time.Time) error {
	return errors.New("probe: the email change verbs must not mark through the login method store")
}

func (m *ec2Methods) EmailVerification(context.Context, domain.UserID) (time.Time, bool, error) {
	return ecNow.Add(-time.Hour), true, nil
}

// wireEnrolledReader — провязка дублёра способов в КАЖДОЕ незаполненное
// экспортируемое поле-интерфейс зависимостей, которое он удовлетворяет. Пустой
// интерфейс не считается: ему удовлетворяет всё. Полей ноль — тоже исход: тогда
// носитель чтения — хранилище либо транзакция глаголов.
func wireEnrolledReader(deps *humansession.EmailChangeDeps, reader any) {
	v := reflect.ValueOf(deps).Elem()
	rt := reflect.TypeOf(reader)
	for i := 0; i < v.NumField(); i++ {
		f, ft := v.Field(i), v.Type().Field(i)
		if !ft.IsExported() || ft.Type.Kind() != reflect.Interface || ft.Type.NumMethod() == 0 || !f.IsNil() {
			continue
		}
		if rt.Implements(ft.Type) {
			f.Set(reflect.ValueOf(reader))
		}
	}
}

// ec2Cell — посев клетки: человек в подтверждённом положении, свежая сессия
// уровня level, заведённое — по дублёру.
func ec2Cell(t *testing.T, level string, m *ec2Methods) (*ecStore, humansession.EmailChangeDeps, domain.SessionBearer) {
	t.Helper()
	s, b := newECStore(t)
	s.resolved.Session.AssuranceLevel = level
	*s.methods = *m
	m = s.methods
	d := ecDeps(s)

	// МИР: дублёры отвечают объявленным — до предмета.
	ctx := context.Background()
	_, pwErr := m.Get(ctx, "usr-1", domain.LoginMethodPassword)
	_, totpErr := m.Get(ctx, "usr-1", domain.LoginMethodTOTP)
	key, keyErr := m.AccessKeyEnrolled(ctx, "usr-1")
	if m.fail {
		require.ErrorIs(t, pwErr, errEnrolledUnreadable, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): чтение способов отвечает отказом")
		require.ErrorIs(t, keyErr, errEnrolledUnreadable, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): чтение ключа отвечает отказом")
	} else {
		require.NoError(t, pwErr, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): пароль заведён")
		require.NoError(t, keyErr, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): чтение ключа исправно")
		require.Equal(t, m.key, key, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): ключ — по клетке")
		if m.totp {
			require.NoError(t, totpErr, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): код по времени заведён")
		} else {
			require.ErrorIs(t, totpErr, iamerr.ErrNotFound, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): кода по времени нет")
		}
	}
	m.reads = 0
	require.True(t, s.resolved.EmailVerified, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): подтверждённое положение")
	require.Equal(t, level, s.resolved.Session.AssuranceLevel, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): уровень сессии клетки")
	return s, d, b
}

// requireStepUpRefusal — указание повысить уровень формой Ф11 Р11: текст одного
// объявления и вызов «требуется 2, предъявлена 1».
func requireStepUpRefusal(t *testing.T, err error, what string) {
	t.Helper()
	require.Errorf(t, err, "%s ЧЕСТНЫЙ-КРАСНЫЙ: ждалось указание повысить уровень — глагол выполнен (условия уровня нет)", what)
	require.Equalf(t, iamerr.TextStepUpRequired, err.Error(), "%s: текст указания (Ф11 Р11, одно объявление)", what)
	var ch interface{ Challenge() string }
	require.Truef(t, errors.As(err, &ch), "%s: отказ несёт вызов повышения (`WWW-Authenticate`): %T", what, err)
	require.Equalf(t, iamerr.StepUpChallenge("2", "1"), ch.Challenge(), "%s: ступени вызова — требуется «2», предъявлена «1»", what)
}

// requireNothingWritten — отказ ничего не записал: ни строки кода, ни
// вытеснения, ни темпа, ни окна адресата, ни письма, ни предъявления кода.
func requireNothingWritten(t *testing.T, w *ecWriter, what string) {
	t.Helper()
	for _, c := range []string{"Supersede", "InsertPaced", "ChargeWindow", "EmitChangeMail", "Present", "ChangeEmail", "Mark"} {
		require.NotContainsf(t, w.calls, c, "%s: отказ ничего не пишет — вызван %s: %v", what, c, w.calls)
	}
	require.Falsef(t, w.committed, "%s: транзакция не зафиксирована", what)
}

var ec2AcceptedCalls = []string{"AddressTaken", "Supersede", "InsertPaced", "ChargeWindow", "EmitChangeMail", "Commit"}

// TestEC32_KeyHolderNeedsLevelTwoAndAPersonWithoutOneDoesNot — EC-32: четыре
// клетки; соседние отличаются одним фактом. (а) — отрицание, (б) и (в) —
// близнецы (а), (г) — отрицание предъявления.
func TestEC32_KeyHolderNeedsLevelTwoAndAPersonWithoutOneDoesNot(t *testing.T) {
	t.Run("(а) ключ заведён, сессия «1» — запрос: указание повысить", func(t *testing.T) {
		st, d, b := ec2Cell(t, "1", &ec2Methods{key: true})
		uc, err := humansession.NewRequestEmailChangeUseCase(d)
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): глагол собран")
		_, err = uc.Execute(context.Background(), humansession.RequestEmailChangeInput{Bearer: b, NewEmail: "new@example.test"})
		requireStepUpRefusal(t, err, "EC-32 (а)")
		requireNothingWritten(t, st.w, "EC-32 (а)")
	})
	t.Run("(б) ключ заведён, сессия «2» — запрос принят", func(t *testing.T) {
		st, d, b := ec2Cell(t, "2", &ec2Methods{key: true})
		uc, err := humansession.NewRequestEmailChangeUseCase(d)
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): глагол собран")
		_, err = uc.Execute(context.Background(), humansession.RequestEmailChangeInput{Bearer: b, NewEmail: "new@example.test"})
		require.NoError(t, err, "EC-32 (б): сессия «2» — исход EC-01")
		require.Equal(t, ec2AcceptedCalls, st.w.calls, "EC-32 (б): исход EC-01")
	})
	t.Run("(в) ни ключа, ни кода, сессия «1» — запрос принят", func(t *testing.T) {
		st, d, b := ec2Cell(t, "1", &ec2Methods{})
		uc, err := humansession.NewRequestEmailChangeUseCase(d)
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): глагол собран")
		_, err = uc.Execute(context.Background(), humansession.RequestEmailChangeInput{Bearer: b, NewEmail: "new@example.test"})
		require.NoError(t, err, "EC-32 (в): условия уровня у человека без способа «2» нет")
		require.Equal(t, ec2AcceptedCalls, st.w.calls, "EC-32 (в): исход EC-01")
	})
	t.Run("(г) ключ заведён, сессия «1» — предъявление: указание повысить", func(t *testing.T) {
		st, d, b := ec2Cell(t, "1", &ec2Methods{key: true})
		st.w.presented, st.w.newEmail = humansession.CodeMatched, "new@example.test"
		uc, err := humansession.NewConfirmEmailChangeUseCase(d)
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): глагол собран")
		_, err = uc.Execute(context.Background(), humansession.ConfirmEmailChangeInput{Bearer: b, Code: "ABCDE-FGHJK"})
		requireStepUpRefusal(t, err, "EC-32 (г)")
		requireNothingWritten(t, st.w, "EC-32 (г): код не применён, попытка не засчитана, адрес прежний")
	})
}

// TestEC33_UnreadableEnrolledIsAStoreRefusalNotNothingEnrolled — EC-33: (а),
// (б) — отрицания; (в) — близнец, отличается одним фактом: чтение исправно.
func TestEC33_UnreadableEnrolledIsAStoreRefusalNotNothingEnrolled(t *testing.T) {
	t.Run("(а) чтение отказало — запрос: отказ хранилища", func(t *testing.T) {
		st, d, b := ec2Cell(t, "1", &ec2Methods{fail: true})
		uc, err := humansession.NewRequestEmailChangeUseCase(d)
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): глагол собран")
		_, err = uc.Execute(context.Background(), humansession.RequestEmailChangeInput{Bearer: b, NewEmail: "new@example.test"})
		require.ErrorIsf(t, err, humansession.ErrStoreUnavailable,
			"EC-33 (а) ЧЕСТНЫЙ-КРАСНЫЙ: нечитаемое заведённое прочитано как «ничего не заведено»: %v", err)
		requireNothingWritten(t, st.w, "EC-33 (а)")
	})
	t.Run("(б) чтение отказало — предъявление: отказ хранилища", func(t *testing.T) {
		st, d, b := ec2Cell(t, "1", &ec2Methods{fail: true})
		st.w.presented, st.w.newEmail = humansession.CodeMatched, "new@example.test"
		uc, err := humansession.NewConfirmEmailChangeUseCase(d)
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): глагол собран")
		_, err = uc.Execute(context.Background(), humansession.ConfirmEmailChangeInput{Bearer: b, Code: "ABCDE-FGHJK"})
		require.ErrorIsf(t, err, humansession.ErrStoreUnavailable,
			"EC-33 (б) ЧЕСТНЫЙ-КРАСНЫЙ: нечитаемое заведённое прочитано как «ничего не заведено»: %v", err)
		requireNothingWritten(t, st.w, "EC-33 (б): код не применён, попытка не засчитана, адрес прежний")
	})
	t.Run("(в) чтение исправно, ничего не заведено — запрос принят", func(t *testing.T) {
		st, d, b := ec2Cell(t, "1", &ec2Methods{})
		uc, err := humansession.NewRequestEmailChangeUseCase(d)
		require.NoError(t, err, "НЕ-ВЫПОЛНИЛОСЬ(фикстура): глагол собран")
		_, err = uc.Execute(context.Background(), humansession.RequestEmailChangeInput{Bearer: b, NewEmail: "new@example.test"})
		require.NoError(t, err, "EC-33 (в): исход EC-01")
		require.Equal(t, ec2AcceptedCalls, st.w.calls, "EC-33 (в): исход EC-01")
	})
}
