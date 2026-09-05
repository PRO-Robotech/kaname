// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// pgmaperr_quota_test.go — отказ учёта числа ресурсов на мосту SQLSTATE→sentinel.
//
// ПРЕДМЕТ. `iam` — шестой владелец учёта и единственный, у кого совпали владение
// ВЕЛИЧИНАМИ и владение типом «аккаунт». Отказ у всех шести производит один
// шаблон (`pkg/quota/refusal.sql.tmpl`) и поднимает его тремя своими
// SQLSTATE'ами. Мост, который их не знает, отправляет отказ арендатора в
// последнюю ветвь — «неопознанный SQLSTATE» — и наружу уходит `INTERNAL
// "internal error"`: вызывающий видит поломку платформы там, где платформа
// сработала ровно как задумано, и не узнаёт ни носителя, ни предела, ни вида.
//
// Проба утверждает ТРИ исхода раздельно, потому что они означают разное:
// «место кончилось» (поднять предел), «предел не назван» (завести предел) и
// «строка не несёт носителя» (дефект нашей схемы, арендатору о нём знать нечего).

import (
	stderrors "errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

// mkQuotaPgErr — отказ в том виде, в каком его поднимает единственный
// производитель: текст называет носителя, предел и вид.
func mkQuotaPgErr(code, message string) *pgconn.PgError {
	return &pgconn.PgError{Code: code, Message: message}
}

// TestWrapPgErrClassifiesTheQuotaRefusal — три SQLSTATE'а учёта опознаются, и
// каждый своим исходом.
func TestWrapPgErrClassifiesTheQuotaRefusal(t *testing.T) {
	const exceeded = "identity ext-42 has reached its limit of 5 iam.account"
	const notProvisioned = "iam.account has no limit on identity ext-42"

	t.Run("KQ001 — место кончилось", func(t *testing.T) {
		err := wrapPgErr(mkQuotaPgErr("KQ001", exceeded), "", "")
		if !stderrors.Is(err, iamerr.ErrQuotaExceeded) {
			t.Fatalf("отказ учёта не опознан как ErrQuotaExceeded: %v", err)
		}
		if got := iamerr.StripSentinel(err); got != exceeded {
			t.Errorf("текст производителя обязан доехать ДОСЛОВНО — он и есть контракт;\n"+
				"получено %q, ожидалось %q", got, exceeded)
		}
	})

	t.Run("KQ002 — предел не назван", func(t *testing.T) {
		err := wrapPgErr(mkQuotaPgErr("KQ002", notProvisioned), "", "")
		if !stderrors.Is(err, iamerr.ErrQuotaNotProvisioned) {
			t.Fatalf("отсутствие предела не опознано как ErrQuotaNotProvisioned: %v", err)
		}
		if stderrors.Is(err, iamerr.ErrQuotaExceeded) {
			t.Error("«предел не назван» сведён с «место кончилось»: читающий пойдёт " +
				"искать, что понизить, там, где ничего не назначено")
		}
		if got := iamerr.StripSentinel(err); got != notProvisioned {
			t.Errorf("текст производителя обязан доехать дословно; получено %q", got)
		}
	})

	t.Run("KQ003 — строка не несёт носителя: наружу ничего о схеме", func(t *testing.T) {
		const schemaLeak = "quota: row of accounts carries no owner_external_id"
		err := wrapPgErr(mkQuotaPgErr("KQ003", schemaLeak), "", "")
		if !stderrors.Is(err, iamerr.ErrInternal) {
			t.Fatalf("дефект схемы обязан быть ErrInternal, получено: %v", err)
		}
		if strings.Contains(iamerr.StripSentinel(err), "accounts") {
			t.Errorf("текст о НАШЕЙ схеме утёк наружу: %q", iamerr.StripSentinel(err))
		}
	})

	// Положительный контроль: добавление трёх ветвей не сдвинуло ни одной
	// существующей. Без него зелёное выше означало бы лишь «новые ветви есть».
	t.Run("положительный контроль — прежние отображения на месте", func(t *testing.T) {
		dup := wrapPgErr(mkPgErr("23505", "accounts_name_unique"), "", "acc-1")
		if !stderrors.Is(dup, iamerr.ErrAlreadyExists) {
			t.Errorf("23505 перестал быть ErrAlreadyExists: %v", dup)
		}
		fk := wrapPgErr(mkPgErr("23503", "accounts_owner_fk"), "", "usr-1")
		if !stderrors.Is(fk, iamerr.ErrFailedPrecondition) {
			t.Errorf("23503 перестал быть ErrFailedPrecondition: %v", fk)
		}
		unknown := wrapPgErr(mkQuotaPgErr("XX999", "boom"), "", "")
		if !stderrors.Is(unknown, iamerr.ErrInternal) {
			t.Errorf("неопознанный SQLSTATE перестал быть ErrInternal: %v", unknown)
		}
	})
}
