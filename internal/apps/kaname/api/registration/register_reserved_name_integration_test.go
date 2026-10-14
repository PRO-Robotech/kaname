// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// register_reserved_name_integration_test.go — ИМЯ ЛИЧНОГО АККАУНТА НЕ ПРИЧИНА
// ОТКАЗА РЕГИСТРАЦИИ (приёмка Ф4 редакции 4, sha256
// 7c81fa29d71d70f283cc15dc9cf450f2cb39fe7fa7dec4878e2c6f510e2c6293; Р9,
// сценарии Ф4-25 мир (ii), Ф4-28; §5.5, §9, §10а п. 1/1а).
//
// # Что доказывается
//
// Личный аккаунт заводится той же транзакцией, что человек (Р8), и имя ему
// выбирает система — `personal-cloud-<хвост идентификатора>` (`mirror_tx.go:198`).
// Приёмка Р9 требует: отказ записи ЛИЧНОГО аккаунта — невыполнение (503
// UNAVAILABLE), а НЕ единый отказ занятости адреса (400 FAILED_PRECONDITION), и
// совпадение выбранного имени с уже занятым регистрацию свободного адреса не
// заканчивает.
//
// # Шов — запись аккаунта поверх НАСТОЯЩЕГО адаптера (§10а п. 1)
//
// Внесённое различие — РОВНО ОДНО против положительного контроля Ф4-05, и вносится
// оно на записи ЛИЧНОГО АККАУНТА внутри `user.RegisterMirrorTx`, а не на записи
// зеркала целиком (Ф4-02 её уже покрыл, но он не различает, может ли АККАУНТ уехать
// мимо транзакции). Шов обёртывает `AccountsW()` той же транзакции; всё прочее —
// настоящий адаптер на настоящей базе:
//   - мир (i)  — запись аккаунта возвращает ПОСТОРОННИЙ отказ (не про каталог);
//   - мир (ii) — перед каждой записью ОТДЕЛЬНОЙ транзакцией фиксируется аккаунт с
//     тем именем, которое регистрация выбрала для этой попытки.
//
// # Чем краснеет ДО кода (§9)
//
// Мир (i) зелёный уже сегодня: посторонний отказ уходит в ветвь «хранилище
// отказало» (`register.go:269-270`) — невыполнение. Он — законный близнец: тот же
// шов, одно иное «Дано» (РОД отказа записи), и он ОБЯЗАН молчать.
// Мир (ii) и Ф4-28 — ЧЕСТНЫЙ КРАСНЫЙ: глагол классифицирует ЛЮБОЙ ErrAlreadyExists
// как занятость по сентинелу, а не по месту (`register.go:258-260`), поэтому
// совпадение имени личного аккаунта отвечает единым отказом (400), а не
// невыполнением (503); занятое имя завершает регистрацию свободного адреса.
// Производитель — §10а п. 1а, правки 1 и 2; красный признаётся честным только при
// зелёном Ф4-05 тем же прогоном (§9).
//
// Run: `go test ./internal/apps/kaname/api/registration/ -run Integration -count=1 -v`
// (Docker). Skipped under -short. Харнесс — из register_integration_test.go.
package registration_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	repoaccount "github.com/PRO-Robotech/kaname/internal/repo/kaname/account"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// seamStore — Store, чей писатель пропускает запись ЛИЧНОГО аккаунта через шов.
// Композиция зеркала — та же, что в композиционном корне, но kaname.Writer,
// который читает `user.RegisterMirrorTx`, обёрнут `wrap`.
type seamStore struct {
	inner *kanamepg.RegistrationStore
	wrap  func(kanamerepo.Writer) kanamerepo.Writer
}

func (s seamStore) Writer(ctx context.Context) (registration.Writer, error) {
	w, err := s.inner.Writer(ctx)
	if err != nil {
		return nil, err
	}
	return seamWriter{RegistrationWriter: w, wrap: s.wrap}, nil
}

type seamWriter struct {
	*kanamepg.RegistrationWriter
	wrap func(kanamerepo.Writer) kanamerepo.Writer
}

func (w seamWriter) Mirror(ctx context.Context, in registration.MirrorInput) (registration.MirrorResult, error) {
	return user.RegisterMirrorTx(ctx, w.wrap(w.MirrorWriter()), in)
}

// accountSeamWriter — kaname.Writer, у которого перехвачена ТОЛЬКО запись
// аккаунта; всё прочее — настоящий писатель транзакции.
type accountSeamWriter struct {
	kanamerepo.Writer
	insert func(ctx context.Context, a domain.Account, real func() (domain.Account, error)) (domain.Account, error)
}

func (w accountSeamWriter) AccountsW() repoaccount.WriterIface {
	return accountSeamAccounts{WriterIface: w.Writer.AccountsW(), insert: w.insert}
}

type accountSeamAccounts struct {
	repoaccount.WriterIface
	insert func(ctx context.Context, a domain.Account, real func() (domain.Account, error)) (domain.Account, error)
}

func (a accountSeamAccounts) Insert(ctx context.Context, acc domain.Account) (domain.Account, error) {
	return a.insert(ctx, acc, func() (domain.Account, error) { return a.WriterIface.Insert(ctx, acc) })
}

// foreignFaultWrap — мир (i): запись аккаунта возвращает посторонний отказ
// (`errInjected` из register_integration_test.go), не связанный с каталогом.
func foreignFaultWrap(inner kanamerepo.Writer) kanamerepo.Writer {
	return accountSeamWriter{Writer: inner, insert: func(_ context.Context, _ domain.Account, _ func() (domain.Account, error)) (domain.Account, error) {
		return domain.Account{}, errInjected
	}}
}

// nameSeedCapture — исход посева конфликтного имени. Отделяет сломанную фикстуру
// (посев не состоялся) от честного красного: без этого разделения отказ посева
// уехал бы в ту же ветвь «хранилище отказало» и МАСКИРОВАЛ бы отсутствие
// производителя ложным зелёным (§9, gate-authoring §11).
type nameSeedCapture struct {
	names []domain.AccountName
	errs  []error
}

// seedCollisionWrap — миры (ii)/Ф4-28: перед записью аккаунта ОТДЕЛЬНОЙ
// транзакцией (`pool.Exec` — автокоммит на своём соединении) фиксируется аккаунт
// с тем именем, которое регистрация выбрала для этой попытки; владелец — уже
// заведённый holder (FK `accounts_owner_fk` при коммите). Дальше — настоящий
// адаптер, и запись натыкается на `accounts_name_unique` → 23505 → ErrAlreadyExists.
//
// every=true (мир ii) — сеет ПЕРЕД КАЖДОЙ попыткой; every=false (Ф4-28) — только
// перед ПЕРВОЙ. Сегодня попытка одна (§5.5), поэтому обе формы красные; различие
// проявится после правки 2 (регистрация переберёт свободное имя).
func seedCollisionWrap(h *harness, owner domain.UserID, every bool, seedCap *nameSeedCapture) func(kanamerepo.Writer) kanamerepo.Writer {
	seeded := 0
	return func(inner kanamerepo.Writer) kanamerepo.Writer {
		return accountSeamWriter{Writer: inner, insert: func(ctx context.Context, acc domain.Account, real func() (domain.Account, error)) (domain.Account, error) {
			if every || seeded == 0 {
				seeded++
				_, err := h.pool.Exec(ctx,
					`INSERT INTO accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`,
					ids.NewID(domain.PrefixAccount), string(acc.Name), string(owner))
				seedCap.names = append(seedCap.names, acc.Name)
				seedCap.errs = append(seedCap.errs, err)
				if err != nil {
					// Посев не состоялся — это НЕ honest red, а сломанная фикстура.
					// Отдаём именно этот отказ, но проба его увидит отдельным
					// утверждением (require.NoError по seedCap.errs) и назовёт починку.
					return domain.Account{}, err
				}
			}
			return real()
		}}
	}
}

// TestRegisterIntegration_F4_25_AccountWriteRefusalIsNotOccupancy — Ф4-25 в двух
// мирах: отказ записи личного аккаунта по ЛЮБОЙ причине — невыполнение (503
// UNAVAILABLE), не единый отказ занятости (400 FAILED_PRECONDITION); адрес
// свободен, и отказ занятости солгал бы о нём (Р3).
func TestRegisterIntegration_F4_25_AccountWriteRefusalIsNotOccupancy(t *testing.T) {
	h := newHarness(t)

	// Мир (i) — ЗАКОННЫЙ БЛИЗНЕЦ (зелёный сегодня, §9): посторонний отказ записи
	// аккаунта уходит невыполнением; тот же шов, одно иное «Дано» — РОД отказа.
	t.Run("мир (i) посторонний отказ записи аккаунта — невыполнение, не единый отказ", func(t *testing.T) {
		email := freshEmail("f4-25-i")
		store := seamStore{inner: kanamepg.NewRegistrationStore(h.pool), wrap: foreignFaultWrap}
		_, err := h.register(t, h.useCase(t, store), email)
		require.Error(t, err, "внесённый отказ записи аккаунта обязан дойти до вызывающего")
		require.ErrorIs(t, err, humansession.ErrStoreUnavailable, "отказ дошёл как невыполнение (503 UNAVAILABLE)")
		require.NotErrorIs(t, err, registration.ErrRefused, "не единый отказ регистрации (400)")
		require.Equal(t, rows{}, h.rowsFor(t, email), "не осталось НИЧЕГО из четырёх")

		// Повтор тем же адресом без внесённого различия — Ф4-05 (адрес не занят).
		out, err := h.register(t, h.useCase(t, h.store), email)
		require.NoError(t, err, "повтор тем же адресом обязан пройти и дать все четыре")
		h.assertAllThree(t, email, out)
	})

	// Мир (ii) — ЧЕСТНЫЙ КРАСНЫЙ (§9): совпадение имени личного аккаунта отвечает
	// сегодня единым отказом (`register.go:258-260`), а обязано — невыполнением.
	t.Run("мир (ii) совпадение имени личного аккаунта — невыполнение, не занятость", func(t *testing.T) {
		holder := seedActiveUserWithAccount(t, h, freshEmail("f4-25-holder"))
		var seedCap nameSeedCapture
		email := freshEmail("f4-25-ii")
		store := seamStore{inner: kanamepg.NewRegistrationStore(h.pool), wrap: seedCollisionWrap(h, holder.ID, true, &seedCap)}
		_, err := h.register(t, h.useCase(t, store), email)

		// Сначала — что посев конфликтного имени СОСТОЯЛСЯ: иначе «невыполнение»
		// было бы отказом фикстуры, а не отсутствием производителя (§9).
		require.NotEmpty(t, seedCap.names, "шов записи аккаунта обязан исполниться")
		for i, e := range seedCap.errs {
			require.NoError(t, e, "посев конфликтного имени %q обязан состояться", seedCap.names[i])
		}
		require.True(t, strings.HasPrefix(string(seedCap.names[0]), "personal-cloud-"),
			"имя личного аккаунта — из зарезервированного пространства (Р9): %q", seedCap.names[0])

		require.Error(t, err, "запись аккаунта отвергнута — отказ обязан дойти до вызывающего")
		require.ErrorIs(t, err, humansession.ErrStoreUnavailable,
			"совпадение имени — невыполнение (503 UNAVAILABLE), адрес свободен и занятостью не объясняется (Р3)")
		require.NotErrorIs(t, err, registration.ErrRefused, "не единый отказ занятости (400)")
		require.Zero(t, h.obs.count(registration.OutcomeRefusedOccupied), "клетка счётчика — не «занято»")
		require.Equal(t, rows{}, h.rowsFor(t, email), "не осталось НИЧЕГО из четырёх")

		// Повтор тем же адресом без внесённого различия — Ф4-05.
		out, err := h.register(t, h.useCase(t, h.store), email)
		require.NoError(t, err, "повтор тем же адресом без различия обязан дать все четыре (Ф4-05)")
		h.assertAllThree(t, email, out)
	})
}

// TestRegisterIntegration_F4_28_OccupiedNameDoesNotRefuseRegistration — Ф4-28:
// имя, занятое к моменту записи, не отказывает регистрации свободного адреса;
// личный аккаунт получает свободное имя с префиксом той же транзакцией.
func TestRegisterIntegration_F4_28_OccupiedNameDoesNotRefuseRegistration(t *testing.T) {
	h := newHarness(t)

	// Положительный контроль Ф4-05 — свободный адрес без шва проходит; без него
	// отрицание зеленело бы на регистрации, отвергающей всё (§9, gate-authoring §4).
	t.Run("положительный контроль Ф4-05 — свободный адрес проходит", func(t *testing.T) {
		email := freshEmail("f4-28-ctl")
		out, err := h.register(t, h.useCase(t, h.store), email)
		require.NoError(t, err)
		h.assertAllThree(t, email, out)
	})

	// ЧЕСТНЫЙ КРАСНЫЙ (§9): занятое имя завершает регистрацию единым отказом,
	// потому что производителя «переживи занятое имя» нет (§5.5).
	t.Run("занятое имя не отказывает регистрации свободного адреса", func(t *testing.T) {
		holder := seedActiveUserWithAccount(t, h, freshEmail("f4-28-holder"))
		var seedCap nameSeedCapture
		email := freshEmail("f4-28")
		store := seamStore{inner: kanamepg.NewRegistrationStore(h.pool), wrap: seedCollisionWrap(h, holder.ID, false, &seedCap)}
		out, err := h.register(t, h.useCase(t, store), email)

		// Посев занятого имени обязан состояться — иначе «Дано» сценария не создано.
		require.NotEmpty(t, seedCap.names, "шов записи аккаунта обязан исполниться")
		require.NoError(t, seedCap.errs[0], "посев занятого имени %q обязан состояться", seedCap.names[0])
		occupiedName := string(seedCap.names[0])

		require.NoError(t, err, "занятое имя личного аккаунта НЕ отказывает регистрации свободного адреса (Р9)")
		h.assertAllThree(t, email, out)

		// Имя личного аккаунта отличается от занятого и несёт префикс (Р9).
		var gotName string
		require.NoError(t, h.pool.QueryRow(h.ctx,
			`SELECT a.name FROM accounts a JOIN users u ON u.id = a.owner_user_id WHERE lower(u.email) = lower($1)`,
			email).Scan(&gotName))
		require.NotEqual(t, occupiedName, gotName, "личный аккаунт получил СВОБОДНОЕ имя, не занятое")
		require.True(t, strings.HasPrefix(gotName, "personal-cloud-"),
			"имя личного аккаунта осталось из зарезервированного пространства: %q", gotName)

		// Занявший имя аккаунт не изменился: ни имени, ни владельца.
		var seedOwner string
		require.NoError(t, h.pool.QueryRow(h.ctx,
			`SELECT owner_user_id FROM accounts WHERE name = $1`, occupiedName).Scan(&seedOwner))
		require.Equal(t, string(holder.ID), seedOwner, "занявший имя аккаунт не сменил владельца")

		// Вызывающий не получил ни отказа, ни невыполнения: клетка — «выдано».
		require.Zero(t, h.obs.count(registration.OutcomeRefusedOccupied), "клетка счётчика — не «занято»")
	})
}
