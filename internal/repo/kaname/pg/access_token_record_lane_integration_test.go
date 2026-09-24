// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// access_token_record_lane_integration_test.go — полоса отказов писателя записи
// выпуска на ЖИВОЙ схеме и НАСТОЯЩИХ отказах сервера (kaname#319, находка ревью
// GSR-319-2).
//
// Каждую колонку записи выпуска производит служба, поэтому исходов у писателя
// ровно два:
//
//   - семейства нет либо оно отозвано — исход ЗАВЕДЕНИЯ, доменный
//     `ErrAccessTokenFamilyNotLive`: выдача обязана не состояться, и это не
//     поломка;
//   - любой другой отказ целостности — дефект службы: фиксированный INTERNAL и
//     запись в журнале с координатами ограничения. Отказ ввода обвинял бы
//     клиента в значении, которого он не присылал.
//
// Перепись ограничений таблицы на живой схеме держит полноту: ограничение,
// заведённое позже без решения о полосе, эту пробу краснит.
package pg_test

import (
	stderrors "errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// issuanceConstraintLanes — решение по КАЖДОМУ ограничению таблицы выпусков.
//
//   - writer — отказ достижим через писателя и приходит от базы;
//   - precheck — писатель отказывает раньше базы той же полосой (проба без
//     базы, `access_token_record_lane_test.go`); ограничение остаётся рубежом
//     для писателя в обход;
//   - family — доменный исход заведения.
var issuanceConstraintLanes = map[string]string{
	"access_tokens_pkey":                  "writer",
	"access_tokens_jti_form_ck":           "writer",
	"access_tokens_family_form_ck":        "writer",
	"access_tokens_expiry_after_issue_ck": "precheck",
	"access_tokens_family_fk":             "family",
}

// TestIntegration_AccessTokenRecordConstraintsAreAllAdjudicated — перепись
// ограничений таблицы выпусков: каждое решено, и решение не называет
// несуществующего.
func TestIntegration_AccessTokenRecordConstraintsAreAllAdjudicated(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool := catalogPool(t)

	rows, err := pool.Query(ctx, `
		SELECT conname FROM pg_constraint
		 WHERE conrelid = 'kaname.access_tokens'::regclass
		 ORDER BY conname`)
	require.NoError(t, err)
	live := map[string]bool{}
	for rows.Next() {
		var name string
		require.NoError(t, rows.Scan(&name))
		live[name] = true
	}
	rows.Close()
	require.NoError(t, rows.Err())
	require.NotEmpty(t, live, "проверка НЕ ИСПОЛНЯЛАСЬ: у таблицы выпусков не найдено ни одного ограничения")

	for name := range live {
		_, decided := issuanceConstraintLanes[name]
		require.True(t, decided,
			"ограничение %s таблицы выпусков не решено: его отказ ушёл бы в полосу ввода и обвинил "+
				"бы клиента в значении, которого тот не присылал. Решение — здесь и у писателя", name)
	}
	for name := range issuanceConstraintLanes {
		require.True(t, live[name], "решение называет ограничение %s, которого в схеме нет", name)
	}
	t.Logf("перепись: ограничений таблицы выпусков %d, решено %d", len(live), len(issuanceConstraintLanes))
}

// TestIntegration_AccessTokenRecordRefusalLanes — настоящие отказы сервера по
// каждому ограничению полосы дефекта и близнец доменного исхода.
func TestIntegration_AccessTokenRecordRefusalLanes(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx, pool := catalogPool(t)
	repo := kanamepg.NewOAuthCeremonyRepo(pool)
	scene := ceremonyScene(t, ctx, pool, "atrec")
	require.NoError(t, repo.IssueAuthorizationCode(ctx, kanamepg.NewAuthorizationCode{
		Context:             scene,
		CodeDigest:          ceremonyDigest(0x6100),
		RedirectURI:         "https://app.example.test/cb",
		CodeChallenge:       ceremonyChallenge,
		CodeChallengeMethod: domain.PKCEMethodS256,
		TTL:                 time.Minute,
	}), "семейство сцены")

	issued := time.Now().UTC().Truncate(time.Second)
	expires := issued.Add(15 * time.Minute)
	jti := func(tag string) string { return "tok" + ceremonyPad(tag) }
	logBuf := captureDefaultLog(t)

	// Положительный контроль сцены: законная запись принимается и журнал молчит
	// — иначе каждый отказ ниже мог бы прийти от чего угодно.
	require.NoError(t, repo.RecordAccessToken(ctx, jti("rc1"), scene.FamilyID, issued, expires),
		"законная запись выпуска обязана лечь")
	require.NotContains(t, logBuf.String(), issuanceBackstopLine, "законная запись не пишет записи о рубеже")

	defects := []struct {
		constraint  string
		jti, family string
	}{
		{"access_tokens_jti_form_ck", "tok-NOT-OUR-FORM", scene.FamilyID},
		{"access_tokens_family_form_ck", jti("rc2"), "tfm-NOT-OUR-FORM"},
		// Повтор идентификатора: подписант чеканит его сам, совпадение — наш дефект.
		{"access_tokens_pkey", jti("rc1"), scene.FamilyID},
	}
	for _, c := range defects {
		t.Run(c.constraint, func(t *testing.T) {
			logBuf.Reset()
			err := repo.RecordAccessToken(ctx, c.jti, c.family, issued, expires)
			require.Error(t, err, "запись обязана быть отвергнута")
			require.False(t, stderrors.Is(err, domain.ErrAccessTokenFamilyNotLive),
				"отказ формы выдан за исход семейства: %v", err)
			require.False(t, stderrors.Is(err, iamerr.ErrInvalidArg),
				"значение производит служба — клиент обвинён в чужом дефекте: %v", err)
			require.False(t, stderrors.Is(err, iamerr.ErrAlreadyExists),
				"совпадение идентификатора выпуска клиенту не принадлежит: %v", err)
			require.True(t, stderrors.Is(err, iamerr.ErrInternal), "want ErrInternal, got %v", err)
			require.Equal(t, iamerr.ErrInternal.Error(), err.Error(), "текст отказа фиксированный")

			logged := logBuf.String()
			require.Contains(t, logged, issuanceBackstopLine, "оператор обязан узнать о сработавшем рубеже")
			require.Contains(t, logged, "constraint="+c.constraint, "сработать обязано ИМЕННО это ограничение")
			require.Contains(t, logged, "table=access_tokens", "сервер называет таблицу")
			require.NotContains(t, logged, "Failing row", "строка целиком до журнала не доезжает")
		})
	}

	// БЛИЗНЕЦ доменного исхода: семейства нет — не дефект службы, а исход
	// заведения. Отличается от случая формы одним фактом: семейство названо
	// законной формой, но не существует.
	t.Run("семейства нет", func(t *testing.T) {
		logBuf.Reset()
		err := repo.RecordAccessToken(ctx, jti("rc3"), "tfm-"+ceremonyPad("atrecnf"), issued, expires)
		require.True(t, stderrors.Is(err, domain.ErrAccessTokenFamilyNotLive), "want ErrAccessTokenFamilyNotLive, got %v", err)
		require.False(t, stderrors.Is(err, iamerr.ErrInternal), "исход семейства выдан за дефект службы: %v", err)
		require.NotContains(t, logBuf.String(), issuanceBackstopLine, "исход семейства записи о рубеже не пишет")
	})
}
