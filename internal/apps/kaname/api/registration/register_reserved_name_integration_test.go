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
//   - мир (ii) — до открытия писателя ОТДЕЛЬНОЙ транзакцией фиксируется аккаунт
//     с занятым именем; шов направляет каждую попытку на это имя.
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
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
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
	insert func(ctx context.Context, a domain.Account, real func(domain.Account) (domain.Account, error)) (domain.Account, error)
}

func (w accountSeamWriter) AccountsW() repoaccount.WriterIface {
	return accountSeamAccounts{WriterIface: w.Writer.AccountsW(), insert: w.insert}
}

type accountSeamAccounts struct {
	repoaccount.WriterIface
	insert func(ctx context.Context, a domain.Account, real func(domain.Account) (domain.Account, error)) (domain.Account, error)
}

func (a accountSeamAccounts) Insert(ctx context.Context, acc domain.Account) (domain.Account, error) {
	return a.insert(ctx, acc, func(candidate domain.Account) (domain.Account, error) { return a.WriterIface.Insert(ctx, candidate) })
}

// foreignFaultWrap — мир (i): запись аккаунта возвращает посторонний отказ
// (`errInjected` из register_integration_test.go), не связанный с каталогом.
func foreignFaultWrap(inner kanamerepo.Writer) kanamerepo.Writer {
	return accountSeamWriter{Writer: inner, insert: func(_ context.Context, _ domain.Account, _ func(domain.Account) (domain.Account, error)) (domain.Account, error) {
		return domain.Account{}, errInjected
	}}
}

// nameSeedCapture — исход посева конфликтного имени. Отделяет сломанную фикстуру
// (посев не состоялся) от честного красного: без этого разделения отказ посева
// уехал бы в ту же ветвь «хранилище отказало» и МАСКИРОВАЛ бы отсутствие
// производителя ложным зелёным (§9, gate-authoring §11).
type nameSeedCapture struct {
	names      []domain.AccountName
	errs       []error
	candidates []domain.AccountName
	collisions []error
}

// seedCollisionWrap — миры (ii)/Ф4-28: ДО открытия писателя отдельным
// автокоммитом фиксируется занятое имя. На записи шов меняет только имя
// кандидата: ID, владелец и настоящий адаптер остаются прежними. Ограничение
// accounts_name_unique само даёт ErrAlreadyExists через ON CONFLICT адаптера.
//
// Вложенный внешний посев после INSERT users невозможен: текущая TX уже
// держит compatibility fence, а синхронный посев ждёт его до её завершения.
// every=true сталкивает каждую попытку; every=false — только первую,
// после которой глагол обязан сам выбрать и записать свободное имя.
func seedCollisionWrap(h *harness, owner domain.UserID, every bool, seedCap *nameSeedCapture) func(kanamerepo.Writer) kanamerepo.Writer {
	id := ids.NewID(domain.PrefixAccount)
	occupied := domain.AccountName(domain.PersonalAccountNamePrefix + strings.ToLower(id[len(id)-6:]))
	_, seedErr := h.pool.Exec(h.ctx,
		`INSERT INTO accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`, id, string(occupied), string(owner))
	seedCap.names = append(seedCap.names, occupied)
	seedCap.errs = append(seedCap.errs, seedErr)
	return func(inner kanamerepo.Writer) kanamerepo.Writer {
		return accountSeamWriter{Writer: inner, insert: func(_ context.Context, acc domain.Account, real func(domain.Account) (domain.Account, error)) (domain.Account, error) {
			seedCap.candidates = append(seedCap.candidates, acc.Name)
			if seedErr != nil {
				return domain.Account{}, seedErr
			}
			if every || len(seedCap.candidates) == 1 {
				acc.Name = occupied
				out, err := real(acc)
				seedCap.collisions = append(seedCap.collisions, err)
				return out, err
			}
			return real(acc)
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
		require.NotEmpty(t, seedCap.candidates, "шов записи аккаунта обязан исполниться")
		for i, e := range seedCap.errs {
			require.NoError(t, e, "посев конфликтного имени %q обязан состояться", seedCap.names[i])
		}
		require.Len(t, seedCap.collisions, len(seedCap.candidates), "каждая попытка встретила реальное занятое имя")
		for i, collision := range seedCap.collisions {
			require.ErrorIs(t, collision, iamerr.ErrAlreadyExists, "отказ дал настоящий адаптер accounts")
			require.True(t, strings.HasPrefix(string(seedCap.candidates[i]), domain.PersonalAccountNamePrefix), "глагол выбирал имя из зарезервированного пространства")
			require.NotContains(t, seedCap.candidates[:i], seedCap.candidates[i], "после коллизии глагол выбирает новое имя")
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
		require.NotEmpty(t, seedCap.candidates, "шов записи аккаунта обязан исполниться")
		require.NoError(t, seedCap.errs[0], "посев занятого имени %q обязан состояться", seedCap.names[0])
		require.Len(t, seedCap.collisions, 1, "занятым сделано только первое имя")
		require.ErrorIs(t, seedCap.collisions[0], iamerr.ErrAlreadyExists, "первое имя отверг настоящий адаптер accounts")
		require.Greater(t, len(seedCap.candidates), 1, "после столкновения глагол сам повторил запись")
		for i, candidate := range seedCap.candidates {
			require.True(t, strings.HasPrefix(string(candidate), domain.PersonalAccountNamePrefix), "глагол выбирал имя из зарезервированного пространства")
			require.NotContains(t, seedCap.candidates[:i], candidate, "после коллизии глагол выбирает новое имя")
		}
		occupiedName := string(seedCap.names[0])

		require.NoError(t, err, "занятое имя личного аккаунта НЕ отказывает регистрации свободного адреса (Р9)")
		h.assertAllThree(t, email, out)

		// Имя личного аккаунта отличается от занятого и несёт префикс (Р9).
		var gotName string
		require.NoError(t, h.pool.QueryRow(h.ctx,
			`SELECT a.name FROM accounts a JOIN users u ON u.id = a.owner_user_id WHERE lower(u.email) = lower($1)`,
			email).Scan(&gotName))
		require.NotEqual(t, occupiedName, gotName, "личный аккаунт получил СВОБОДНОЕ имя, не занятое")
		require.Equal(t, string(seedCap.candidates[len(seedCap.candidates)-1]), gotName, "записан следующий настоящий кандидат глагола")
		require.NotEqual(t, string(seedCap.candidates[0]), gotName, "повтор первоначального кандидата не скрыт швом")
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
