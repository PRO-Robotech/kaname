// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// access_token_record_lane_test.go — полоса отказов писателя записи выпуска
// токена доступа ДО базы (kaname#319, находка ревью GSR-319-2).
//
// Предмет — вопрос «чьё это значение». Идентификатор выпуска, семейство и оба
// момента производит сама служба: подписант чеканит `jti`, `iat` и `exp`,
// церемония называет семейство. Вызывающий точки выдачи не присылает ни
// одного из них. Значит негодное значение здесь — дефект службы, и отказ
// ввода обвинял бы клиента в том, чего он не делал и не может исправить.
// Отказ — фиксированный INTERNAL, оператору — запись в журнале, называющая
// поле.
//
// Проба без базы: проверки стоят до оператора, и хранилище им не нужно.
// Отказы самой базы судит integration-проба той же полосы.
package pg_test

import (
	"bytes"
	"context"
	stderrors "errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// issuanceBackstopLine — запись журнала о сработавшем рубеже писателя выпуска.
const issuanceBackstopLine = "access token issuance record refused a value the service produced"

func captureDefaultLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })
	return &buf
}

// TestRecordAccessToken_ProducedValueRefusalIsOurDefect — каждая проверка до
// базы отказывает фиксированным INTERNAL с записью, называющей поле.
func TestRecordAccessToken_ProducedValueRefusalIsOurDefect(t *testing.T) {
	const (
		jti    = "tok000000000000rec01"
		family = "tfm-000000000000rec01"
	)
	issued := time.Date(2026, 9, 24, 10, 0, 0, 0, time.UTC)
	expires := issued.Add(15 * time.Minute)

	// Хранилища у писателя нет намеренно: до оператора проверка обязана
	// отказать сама, иначе проба упала бы на пустом пуле, а не на отказе.
	repo := kanamepg.NewOAuthCeremonyRepo(nil)
	logBuf := captureDefaultLog(t)

	cases := []struct {
		name, field     string
		jti, family     string
		issued, expires time.Time
	}{
		{"идентификатор выпуска пуст", "jti", "", family, issued, expires},
		{"семейство не названо", "family_id", jti, "", issued, expires},
		{"момент выпуска не задан", "issued_at", jti, family, time.Time{}, expires},
		{"срок не задан", "expires_at", jti, family, issued, time.Time{}},
		{"срок не позже выпуска", "expires_at", jti, family, issued, issued},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			logBuf.Reset()
			err := repo.RecordAccessToken(context.Background(), c.jti, c.family, c.issued, c.expires)
			require.Error(t, err, "негодная запись выпуска принята")
			require.False(t, stderrors.Is(err, iamerr.ErrInvalidArg),
				"значение производит служба — клиент обвинён в чужом дефекте: %v", err)
			require.True(t, stderrors.Is(err, iamerr.ErrInternal), "want ErrInternal, got %v", err)
			require.Equal(t, iamerr.ErrInternal.Error(), err.Error(),
				"текст отказа фиксированный: ни поля, ни значения")

			logged := logBuf.String()
			require.Contains(t, logged, issuanceBackstopLine, "оператор обязан узнать о сработавшем рубеже")
			require.Contains(t, logged, "field="+c.field, "запись называет поле")
			if c.jti != "" {
				require.NotContains(t, logged, c.jti, "идентификатор выпуска в журнал не идёт")
			}
		})
	}
}
