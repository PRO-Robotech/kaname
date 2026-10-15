// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession_test

// level_two_enrollment_usecase_test.go — условие Р4 у заведения второго
// фактора (задача kaname#747; приёмка
// `docs/engineering/acceptance/level-two-is-enrolled-at-level-two.md`,
// отпечаток 711609ce…, Р4, §7 инварианты 4 и 6, §8 третья строка; сценарии
// KN747-05…07, -17, -18).
//
// # Клетки (§8)
//
// Глагол проходит, если сессия «2» ЛИБО перечень ключей личности ПРОЧИТАН и
// пуст. Клетки «ключ есть / нет» × «сессия 1 / 2» и пятая — сессия «1» при
// нечитаемом перечне — у обоих глаголов (`enroll`, `confirm`).
//
// # Как строится «Дано»
//
// Уровень «2» без ключа и без кода в дублёре недостижим глаголом продукта
// (вход ключом живёт у другой полосы), поэтому сессия «2» ставится записью
// дублёра — той, что ставит оператор предъявления (`PresentInSession`):
// уровень и множество. Предмет пробы — условие глагола заведения, а не путь к
// «2»; путь к «2» входом ключом держит сквозная проба уровня обработчика
// (`internal/handler/loginlanehttp/level_two_enrollment_integration_test.go`).
//
// # Почему отказ по уровню — не именем
//
// Производителя указания повысить уровень на полосе формы сегодня нет
// (§5, строка KN747-06, -07): ссылка на незаведённое имя сорвала бы сборку, а
// сорванная сборка — «не выполнилось», не красный (`change-graph.md` §5).
// Клетка отказа утверждает НАБЛЮДАЕМОЕ: ошибка есть, это не отказ хранилища и
// не отказ свежести, ожидающее заведение не начато и не тронуто. Форму на
// проводе (`401`, `code` 16, вызов) судит проба обработчика.

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// kn747LevelTwo — «Дано: сессия уровня «2»» записью дублёра (шапка файла).
func (h *sfHarness) kn747LevelTwo(t *testing.T, login humansession.LoginOutput) {
	t.Helper()
	h.store.mu.Lock()
	defer h.store.mu.Unlock()
	digest := login.Bearer.Digest()
	for _, r := range h.store.rows {
		if r.digest == digest && r.ended == nil {
			r.s.AssuranceLevel = "2"
			return
		}
	}
	t.Fatalf("НЕ ВЫПОЛНИЛОСЬ(фикстура): запись сессии по носителю не найдена")
}

// kn747Person — личность с паролем, с ключом либо без, и свежая сессия
// названного уровня; уровень проверен ЧТЕНИЕМ до предмета.
func (h *sfHarness) kn747Person(t *testing.T, id string, withKey bool, level string) (domain.User, humansession.LoginOutput) {
	t.Helper()
	email := id + "@example.invalid"
	u := h.person(t, id, email, "correct horse battery", true)
	h.store.keys[u.ID] = withKey
	login := h.freshSession(t, email, "correct horse battery")
	require.Equal(t, "1", login.View.Session.AssuranceLevel, "Дано: вход паролем — «1»")
	if level == "2" {
		h.kn747LevelTwo(t, login)
	}
	res, reason, err := h.store.Resolve(context.Background(), login.Bearer.Digest(), h.clock)
	require.NoError(t, err)
	require.Equal(t, humansession.SessionFound, reason, "Дано: сессия жива")
	require.Equal(t, level, res.Session.AssuranceLevel, "Дано: уровень сессии")
	enrolled, err := fakeMethods{h.store}.AccessKeyEnrolled(context.Background(), u.ID)
	require.NoError(t, err, "Дано: перечень ключей читается")
	require.Equal(t, withKey, enrolled, "Дано: ключ у личности")
	return u, login
}

// kn747RequireLevelRefusal — клетка отказа по уровню (шапка файла).
func kn747RequireLevelRefusal(t *testing.T, err error, what string) {
	t.Helper()
	require.Errorf(t, err, "%s: глагол выполнен — у личности с ключом сессия ниже «2» завела способ (Р4)", what)
	require.Falsef(t, errors.Is(err, humansession.ErrStoreUnavailable), "%s: отказ хранилища вместо отказа по уровню: %v", what, err)
	require.Falsef(t, errors.Is(err, humansession.ErrSessionNotFresh), "%s: отказ свежести вместо отказа по уровню: %v", what, err)
}

// TestKN747_EnrollCells — `enroll`: четыре клетки и пятая (§8).
func TestKN747_EnrollCells(t *testing.T) {
	cells := []struct {
		id, uid string
		withKey bool
		level   string
		allowed bool
	}{
		{"KN747-05", "usr-e05", false, "1", true}, // без ключа — свежая «1» (Ф12 Р8)
		{"KN747-06", "usr-e06", true, "1", false}, // с ключом — «1» мало
		{"KN747-06/twin-2", "usr-e62", true, "2", true},
		{"no-key/2", "usr-e02", false, "2", true},
	}
	for _, c := range cells {
		t.Run(c.id, func(t *testing.T) {
			h := newSFHarness(t)
			u, login := h.kn747Person(t, c.uid, c.withKey, c.level)
			_, err := h.enroll.Execute(context.Background(), humansession.EnrollInput{Bearer: login.Bearer})
			_, pending := h.sfRow(u.ID, domain.LoginMethodTOTP)
			if c.allowed {
				require.NoError(t, err, "%s: заведение начато", c.id)
				require.True(t, pending, "%s: строка ожидающего заведения есть", c.id)
				return
			}
			kn747RequireLevelRefusal(t, err, c.id)
			require.False(t, pending, "%s: заведение не начато", c.id)
		})
	}
}

// TestKN747_17_EnrollWithUnreadableKeyListIsAStoreRefusal — KN747-17: пятая
// клетка `enroll`; близнец — KN747-06 (тот же человек, чтение исправно).
func TestKN747_17_EnrollWithUnreadableKeyListIsAStoreRefusal(t *testing.T) {
	h := newSFHarness(t)
	u, login := h.kn747Person(t, "usr-k17", true, "1")

	// Фикстура проверяется ДО предмета: переключатель роняет ровно чтение
	// перечня ключей и ничего больше.
	h.store.keyListUnreadable = true
	_, err := fakeMethods{h.store}.AccessKeyEnrolled(context.Background(), u.ID)
	require.Error(t, err, "Дано: чтение перечня ключей отвечает ошибкой")
	_, err = fakeMethods{h.store}.Get(context.Background(), u.ID, domain.LoginMethodPassword)
	require.NoError(t, err, "Дано: прочие чтения исправны")

	_, err = h.enroll.Execute(context.Background(), humansession.EnrollInput{Bearer: login.Bearer})
	require.ErrorIs(t, err, humansession.ErrStoreUnavailable,
		"KN747-17: нечитаемый перечень ключей — отказ хранилища, а не «ключа нет» (Р4, §7 п. 6)")
	_, pending := h.sfRow(u.ID, domain.LoginMethodTOTP)
	require.False(t, pending, "KN747-17: заведение не начато")
}

// TestKN747_ConfirmCells — `confirm`: KN747-07 (из «1» у личности с ключом),
// KN747-08 (из «2») и KN747-18 (из «1» при нечитаемом перечне). «Дано» у всех
// трёх: заведение начато сессией «2».
func TestKN747_ConfirmCells(t *testing.T) {
	cells := []struct {
		id         string
		level      string
		unreadable bool
	}{
		{"KN747-07", "1", false},
		{"KN747-08", "2", false},
		{"KN747-18", "1", true},
	}
	for _, c := range cells {
		t.Run(c.id, func(t *testing.T) {
			h := newSFHarness(t)
			id := "usr-c" + c.id[len(c.id)-2:]
			u, two := h.kn747Person(t, id, true, "2")
			en, err := h.enroll.Execute(context.Background(), humansession.EnrollInput{Bearer: two.Bearer})
			require.NoError(t, err, "Дано: заведение начато в сессии «2»")
			before, ok := h.sfRow(u.ID, domain.LoginMethodTOTP)
			require.True(t, ok, "Дано: строка ожидающего заведения есть")
			require.Equal(t, domain.LoginMethodStatePending, before.State)

			bearer := two.Bearer
			if c.level == "1" {
				one := h.freshSession(t, id+"@example.invalid", "correct horse battery")
				require.Equal(t, "1", one.View.Session.AssuranceLevel, "Дано: вторая живая сессия — «1»")
				bearer = one.Bearer
			}
			if c.unreadable {
				h.store.keyListUnreadable = true
				_, err := fakeMethods{h.store}.AccessKeyEnrolled(context.Background(), u.ID)
				require.Error(t, err, "Дано: чтение перечня ключей отвечает ошибкой")
			}

			_, err = h.confirm.Execute(context.Background(), humansession.ConfirmInput{
				Bearer: bearer, Code: probeTOTP(t, en.Secret, h.step()), Source: "203.0.113.7",
			})
			after, _ := h.sfRow(u.ID, domain.LoginMethodTOTP)
			switch {
			case c.unreadable:
				require.ErrorIs(t, err, humansession.ErrStoreUnavailable,
					"%s: нечитаемый перечень ключей — отказ хранилища, а не «ключа нет» (Р4, §7 п. 6)", c.id)
			case c.level == "1":
				kn747RequireLevelRefusal(t, err, c.id)
			default:
				require.NoError(t, err, "%s: подтверждение из «2» проходит", c.id)
				require.Equal(t, domain.LoginMethodStateActive, after.State, "%s: фактор заведён", c.id)
				return
			}
			require.Equal(t, domain.LoginMethodStatePending, after.State, "%s: фактор не заведён", c.id)
			require.True(t, after.CreatedAt.Equal(before.CreatedAt), "%s: ожидающее заведение не тронуто (§7 п. 4)", c.id)
		})
	}
}

// staleKeyList — чтение перечня ключей ВНЕ транзакции записи, сделанное до
// того, как заведение ключа зафиксировано: «ключа нет» при ключе, уже лежащем
// в хранилище. Прочие чтения — те же, что у дублёра способов.
type staleKeyList struct{ fakeMethods }

func (staleKeyList) AccessKeyEnrolled(context.Context, domain.UserID) (bool, error) {
	return false, nil
}

// staleKeyVerbs — глаголы заведения над тем же дублёром, но с устаревшим
// чтением перечня ключей вне транзакции: решить по заведённому они вправе
// только чтением транзакции записи (kaname#770, находка ревью безопасности).
func (h *sfHarness) staleKeyVerbs(t *testing.T) (*humansession.EnrollSecondFactorUseCase, *humansession.ConfirmSecondFactorUseCase) {
	t.Helper()
	deps := humansession.SecondFactorDeps{
		Store: h.store, Methods: staleKeyList{fakeMethods{h.store}}, TOTP: h.totp, Sets: h.verifier, SetHasher: h.hasher,
		Verifier: h.verifier, Limits: sfLimits(), Freshness: sfWindow, Domain: sfDomain, Keys: sfKeys(),
		Observer: h.obs, Now: func() time.Time { return h.clock }, Logger: slog.New(slog.DiscardHandler),
	}
	enroll, err := humansession.NewEnrollSecondFactorUseCase(deps)
	require.NoError(t, err)
	confirm, err := humansession.NewConfirmSecondFactorUseCase(deps)
	require.NoError(t, err)
	return enroll, confirm
}

// TestKN747_EnrollDecidesOnTheKeyListReadInsideItsWriter — `enroll`: ключ
// лежит в хранилище, чтение вне транзакции его не видит. Близнец отличается
// одним фактом — ключа в хранилище нет.
func TestKN747_EnrollDecidesOnTheKeyListReadInsideItsWriter(t *testing.T) {
	for _, withKey := range []bool{true, false} {
		t.Run(map[bool]string{true: "ключ в хранилище", false: "близнец: ключа нет"}[withKey], func(t *testing.T) {
			h := newSFHarness(t)
			u, login := h.kn747Person(t, "usr-st1", withKey, "1")
			enroll, _ := h.staleKeyVerbs(t)
			stale, err := staleKeyList{fakeMethods{h.store}}.AccessKeyEnrolled(context.Background(), u.ID)
			require.NoError(t, err)
			require.False(t, stale, "Дано: чтение вне транзакции ключа не видит")

			_, err = enroll.Execute(context.Background(), humansession.EnrollInput{Bearer: login.Bearer})
			_, pending := h.sfRow(u.ID, domain.LoginMethodTOTP)
			if !withKey {
				require.NoError(t, err, "близнец: заведение начато")
				require.True(t, pending, "близнец: строка ожидающего заведения есть")
				return
			}
			kn747RequireLevelRefusal(t, err, "ЧЕСТНЫЙ-КРАСНЫЙ: решено чтением вне транзакции записи")
			require.False(t, pending, "заведение не начато")
		})
	}
}

// TestKN747_ConfirmDecidesOnTheKeyListReadInsideItsWriter — `confirm`:
// заведение начато без ключа, ключ зафиксирован между началом и
// подтверждением, чтение вне транзакции его не видит.
func TestKN747_ConfirmDecidesOnTheKeyListReadInsideItsWriter(t *testing.T) {
	for _, keyArrives := range []bool{true, false} {
		t.Run(map[bool]string{true: "ключ заведён до подтверждения", false: "близнец: ключа нет"}[keyArrives], func(t *testing.T) {
			h := newSFHarness(t)
			u, login := h.kn747Person(t, "usr-st2", false, "1")
			enroll, confirm := h.staleKeyVerbs(t)
			en, err := enroll.Execute(context.Background(), humansession.EnrollInput{Bearer: login.Bearer})
			require.NoError(t, err, "Дано: заведение начато сессией «1» без ключа")
			before, ok := h.sfRow(u.ID, domain.LoginMethodTOTP)
			require.True(t, ok, "Дано: строка ожидающего заведения есть")
			if keyArrives {
				h.store.mu.Lock()
				h.store.keys[u.ID] = true
				h.store.mu.Unlock()
			}

			_, err = confirm.Execute(context.Background(), humansession.ConfirmInput{
				Bearer: login.Bearer, Code: probeTOTP(t, en.Secret, h.step()), Source: "203.0.113.7",
			})
			after, _ := h.sfRow(u.ID, domain.LoginMethodTOTP)
			if !keyArrives {
				require.NoError(t, err, "близнец: подтверждение проходит")
				require.Equal(t, domain.LoginMethodStateActive, after.State, "близнец: фактор заведён")
				return
			}
			kn747RequireLevelRefusal(t, err, "ЧЕСТНЫЙ-КРАСНЫЙ: решено чтением вне транзакции записи")
			require.Equal(t, domain.LoginMethodStatePending, after.State, "фактор не заведён")
			require.True(t, after.CreatedAt.Equal(before.CreatedAt), "ожидающее заведение не тронуто")
		})
	}
}
