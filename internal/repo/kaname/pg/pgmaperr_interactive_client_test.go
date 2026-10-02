// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// pgmaperr_interactive_client_test.go — полоса отказов проверок таблицы
// интерактивных клиентов (kaname#317).
//
// Предмет — вопрос «чьё это значение». Идентификатор и состояние строки
// чеканит служба; способ аутентификации приходит от производителя клиента
// (поле output-only и неизменяемо); материал секрета и момент его установки
// производит служба. Вызывающий ни одно из них не присылает, поэтому
// срабатывание ограничения — дефект службы или производителя, и отказ
// `INVALID_ARGUMENT` обвинял бы вызывающего в том, чего он не делал и не
// может исправить. Отказ здесь — фиксированный `INTERNAL`, а оператору —
// запись в журнале с координатами ограничения.
//
// Проба синтетическая: поля отказа заполняет она сама. Что кладёт сервер
// (имя таблицы, по которому переводчик отличает свою строку), утверждает
// integration-проба той же полосы на настоящих отказах.

import (
	"bytes"
	stderrors "errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// icMaterialInDetail — материал так, как его положил бы сервер в `Detail`.
const icMaterialInDetail = "$argon2id$v=19$m=65536,t=3,p=4$DETAILinteractiveclient$material"

func icCheckPgErr(constraint, table string) *pgconn.PgError {
	return &pgconn.PgError{
		Code:           "23514",
		ConstraintName: constraint,
		TableName:      table,
		Message:        `new row for relation "` + table + `" violates check constraint "` + constraint + `"`,
		Detail:         "Failing row contains (ic-00000000000000001, " + icMaterialInDetail + ").",
	}
}

// icProducedValueChecks — ограничения, судящие значения, которых вызывающий
// не присылает. Выписаны здесь как СПЕЦИФИКАЦИЯ полосы: перечень в коде —
// реализация, и его полноту против живой схемы судит integration-проба.
var icProducedValueChecks = []string{
	"interactive_clients_id_form_ck",
	"interactive_clients_status_ck",
	"interactive_clients_auth_method_ck",
	"interactive_clients_secret_verifier_method_ck",
	"interactive_clients_secret_verifier_form_ck",
	"interactive_clients_secret_verifier_stamp_ck",
}

func icCaptureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// TestWrapPgErr_InteractiveClientProducedValueBackstopIsOurDefect — отказ по
// значению, которого вызывающий не присылал, — фиксированный INTERNAL с записью
// в журнале.
func TestWrapPgErr_InteractiveClientProducedValueBackstopIsOurDefect(t *testing.T) {
	logBuf := icCaptureLog(t)
	for _, constraint := range icProducedValueChecks {
		t.Run(constraint, func(t *testing.T) {
			logBuf.Reset()
			err := wrapPgErr(icCheckPgErr(constraint, "interactive_clients"), "InteractiveClient", "ic-probe")
			require.False(t, stderrors.Is(err, iamerr.ErrInvalidArg),
				"значение производит служба или поставщик — вызывающий обвинён в чужом дефекте: %v", err)
			require.True(t, stderrors.Is(err, iamerr.ErrInternal), "want ErrInternal, got %v", err)
			require.Equal(t, iamerr.ErrInternal.Error(), err.Error(),
				"текст отказа фиксированный: ни имени ограничения, ни строки")

			logged := logBuf.String()
			require.Contains(t, logged, "interactive client backstop fired",
				"оператор обязан узнать о сработавшем рубеже")
			require.Contains(t, logged, "constraint="+constraint, "запись называет ограничение")
			require.Contains(t, logged, "id=ic-probe", "запись называет строку")
			require.NotContains(t, logged, icMaterialInDetail, "материал не доезжает до журнала")
			require.NotContains(t, logged, "Failing row", "строка целиком не доезжает до журнала")
		})
	}
}

// TestWrapPgErr_InteractiveClientCallerValueStaysInputLane — положительные
// близнецы, отличающиеся одним фактом: иначе утверждение выше зеленело бы на
// переводчике, объявляющем дефектом службы всякую проверку.
func TestWrapPgErr_InteractiveClientCallerValueStaysInputLane(t *testing.T) {
	logBuf := icCaptureLog(t)

	// Значение ПРИСЛАЛ вызывающий — перечень адресов возврата. Полоса ввода.
	for _, constraint := range []string{
		"interactive_clients_redirect_uris_count_ck", "interactive_clients_post_logout_uris_count_ck",
	} {
		err := wrapPgErr(icCheckPgErr(constraint, "interactive_clients"), "InteractiveClient", "ic-probe")
		require.True(t, stderrors.Is(err, iamerr.ErrInvalidArg),
			"%s: значение вызывающего остаётся полосой ввода, получено %v", constraint, err)
	}

	// То же имя ограничения, но ДРУГАЯ таблица: переводчик судит свою строку, а
	// не похожее имя.
	err := wrapPgErr(icCheckPgErr("interactive_clients_auth_method_ck", "users"), "User", "usr-probe")
	require.False(t, stderrors.Is(err, iamerr.ErrInternal),
		"ограничение чужой таблицы не отводится в полосу клиента, получено %v", err)

	require.False(t, strings.Contains(logBuf.String(), "interactive client backstop fired"),
		"близнецы не пишут записи о рубеже клиента: %s", logBuf.String())
}
