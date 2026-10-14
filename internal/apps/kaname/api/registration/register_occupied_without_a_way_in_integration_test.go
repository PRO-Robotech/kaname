// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// register_occupied_without_a_way_in_integration_test.go — регистрация на
// занятый адрес отвечает ОДНИМ отказом, кем бы ни был занят адрес (задача
// PRO-Robotech/kaname#608, предикат п. 3; санкция — Ф4
// `registration-and-its-three-consequences.md` Р3, сценарии Ф4-11, Ф4-13; AWI
// §0.2 и §4.2: единый отказ не меняется, законный выход — восстановление).
//
// # Что доказывается
//
// Адрес занят тремя видами личности:
//
//	(а) ACTIVE со строкой пароля;
//	(б) ACTIVE без строки пароля с отметкой открытого пути — форма «после
//	    переноса» (AWI-11), та самая личность, ради которой заведён выход
//	    восстановлением;
//	(в) BLOCKED.
//
// Исход регистрации на каждый — ПОБАЙТНО один и тот же: тот же сентинел, тот же
// текст, пустой результат, та же клетка счётчика, и ни одной новой строки.
// Различие (а)/(б) — строка пароля (отметка неотделима от формы (б): без неё
// такую строку база не фиксирует). Если бы регистрация отвечала на (б) иначе,
// посторонний узнавал бы по адресу, что у личности нет пароля, — и знал бы,
// по какому адресу просить код восстановления.
//
// Положительный контроль — свободный адрес рядом: регистрация проходит. Без
// него три одинаковых отказа не отличали бы «единый отказ» от «регистрация не
// работает вовсе».
//
// Полоса утверждает СОХРАНЕНИЕ Р3: неотличимость держится конструкцией (обе
// ветви отвергает уникальность адреса до первой записи, лишнего чтения строки
// пароля нет), проба её закрепляет.
//
// # Чем краснеет
//
// Красного до кода нет — свойство уже держится. Способность упасть доказана
// инъекцией: чтение зеркала, отвечающее на адрес личности БЕЗ строки пароля
// другим отказом, чем на адрес личности с паролем, краснит ветвь (б).
//
// Run: `go test ./internal/apps/kaname/api/registration/ -run OccupiedByAnyKind -count=1` (Docker).
package registration_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// occupant — вид личности, занимающей адрес.
type occupant struct {
	name     string
	state    string
	password bool
	mark     bool
}

// seedOccupant — личность данного вида с личным аккаунтом одной транзакцией.
func seedOccupant(t *testing.T, h *harness, o occupant, email string) {
	t.Helper()
	uid := domain.UserID(ids.NewID(domain.PrefixUser))
	acc := domain.AccountID(ids.NewID(domain.PrefixAccount))
	tx, err := h.pool.Begin(h.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(h.ctx) }()
	_, err = tx.Exec(h.ctx, `INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ($1, $2, $3)`,
		string(acc), "occ-"+string(acc[len(acc)-6:]), string(uid))
	require.NoError(t, err)
	_, err = tx.Exec(h.ctx, `INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status, recovery_path_opened_at)
		VALUES ($1, $2, $3, $4, 'Occupant', $5, CASE WHEN $6 THEN now() END)`,
		string(uid), string(acc), "ext-occ-"+string(uid), email, o.state, o.mark)
	require.NoError(t, err)
	if o.password {
		_, err = tx.Exec(h.ctx, `INSERT INTO kaname.user_login_methods (user_id, kind, verifier)
			VALUES ($1, 'password', 'fixture-password-row-without-a-known-password')`, string(uid))
		require.NoError(t, err)
	}
	require.NoError(t, tx.Commit(h.ctx), "посев занимающей личности %s", o.name)
}

// TestRegisterIntegration_F4_11_OccupiedByAnyKindIsOneRefusal — тройка занятых
// адресов отвечает побайтно одним отказом; свободный адрес — выдача.
func TestRegisterIntegration_F4_11_OccupiedByAnyKindIsOneRefusal(t *testing.T) {
	h := newHarness(t)
	uc := h.useCase(t, h.store)

	occupants := []occupant{
		{name: "(а) ACTIVE с паролем", state: "ACTIVE", password: true},
		{name: "(б) ACTIVE без пароля, путь открыт", state: "ACTIVE", mark: true},
		{name: "(в) BLOCKED", state: "BLOCKED", password: true},
	}

	type outcome struct {
		text string
		out  registration.Output
		rows rows
	}
	got := make([]outcome, 0, len(occupants))
	for _, o := range occupants {
		email := freshEmail("occ")
		seedOccupant(t, h, o, email)
		before := h.rowsFor(t, email)

		out, err := h.register(t, uc, email)
		require.ErrorIs(t, err, registration.ErrRefused, "%s: занятый адрес — единый отказ", o.name)
		require.Equal(t, before, h.rowsFor(t, email), "%s: ни одной новой строки", o.name)
		got = append(got, outcome{text: err.Error(), out: out, rows: before})
	}

	for i := 1; i < len(got); i++ {
		require.Equal(t, got[0].text, got[i].text,
			"%s и %s: текст отказа побайтно один (Р3)", occupants[0].name, occupants[i].name)
		require.Equal(t, got[0].out, got[i].out,
			"%s и %s: результат отказа один", occupants[0].name, occupants[i].name)
	}
	require.Equal(t, registration.TextRegistrationRefused, got[0].text, "текст отказа — контракт, без причины")
	require.Equal(t, registration.Output{}, got[0].out, "отказ не несёт ни личности, ни сессии")
	require.Equal(t, len(occupants), h.obs.count(registration.OutcomeRefusedOccupied),
		"все три — одна клетка счётчика")

	// Положительный контроль: свободный адрес проходит.
	free := freshEmail("occ-free")
	out, err := h.register(t, uc, free)
	require.NoError(t, err, "свободный адрес обязан регистрироваться")
	h.assertAllThree(t, free, out)
}
