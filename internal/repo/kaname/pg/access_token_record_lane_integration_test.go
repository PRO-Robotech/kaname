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
// Полосу решает перепись `checkValueLanes` (таблица в ней целиком полоса
// службы), писатель её спрашивает. Здесь — перепись ограничений таблицы на
// живой схеме: у каждого названо, чем проба достигает его отказа, и
// ограничение, заведённое позже без этого, пробу краснит — его исход не
// подтверждён настоящим отказом сервера.
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

// issuanceConstraintReach — чем проба достигает отказа КАЖДОГО ограничения
// таблицы выпусков (полосу решает перепись `checkValueLanes`, не этот перечень):
//
//   - writer — отказ достижим через писателя и приходит от базы;
//   - precheck — писатель отказывает раньше базы той же полосой (проба без
//     базы, `access_token_record_lane_test.go`); ограничение остаётся рубежом
//     для писателя в обход;
//   - family — доменный исход заведения.
var issuanceConstraintReach = map[string]string{
	"access_tokens_pkey":                  "writer",
	"access_tokens_jti_form_ck":           "writer",
	"access_tokens_family_form_ck":        "writer",
	"access_tokens_expiry_after_issue_ck": "precheck",
	"access_tokens_family_live_fk":        "family",
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
		_, decided := issuanceConstraintReach[name]
		require.True(t, decided,
			"у ограничения %s таблицы выпусков не названо, чем проба достигает его отказа: исход "+
				"писателя по нему настоящим отказом сервера не подтверждён. Путь — здесь и в пробе полос", name)
	}
	for name := range issuanceConstraintReach {
		require.True(t, live[name], "решение называет ограничение %s, которого в схеме нет", name)
	}
	t.Logf("перепись: ограничений таблицы выпусков %d, решено %d", len(live), len(issuanceConstraintReach))
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
	// законной формой, но не существует. Идентификатор выпуска — тот же, что у
	// случая формы: тот отвергнут и не записан, повтора ключа здесь нет.
	t.Run("семейства нет", func(t *testing.T) {
		logBuf.Reset()
		err := repo.RecordAccessToken(ctx, jti("rc2"), "tfm-"+ceremonyPad("atrecnf"), issued, expires)
		require.True(t, stderrors.Is(err, domain.ErrAccessTokenFamilyNotLive), "want ErrAccessTokenFamilyNotLive, got %v", err)
		require.False(t, stderrors.Is(err, iamerr.ErrInternal), "исход семейства выдан за дефект службы: %v", err)
		require.NotContains(t, logBuf.String(), issuanceBackstopLine, "исход семейства записи о рубеже не пишет")
	})
}
