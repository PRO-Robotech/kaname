// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// access_key_lane_harness_test.go — «ДАНО» полосы входа ключом (Ф13): привязка
// стенда, строка принятого ключа и живое испытание.
//
// # Почему «Дано» лежит здесь, а не внутри проб
//
// Пробы полосы (`f13_passwordless_login_red_integration_test.go`) утверждают
// ИСХОД; предпосылку строит стенд. Предпосылок у полосы две, и обе обязаны
// строиться ДЕЙСТВИЕМ продукта, а не приготовленным ответом:
//
//   - «личность с принятым ключом» — строка ключа кладётся ПИСАТЕЛЕМ ПРОДУКТА
//     (`access_keys.Writer.InsertKey`) с НАСТОЯЩИМ открытым ключом подставного
//     аутентификатора: сверка потом идёт над тем самым материалом, которым
//     аутентификатор подписывает, а ограничения схемы судят строку так же, как
//     на посадке;
//   - «испытание выдано» — НАСТОЯЩИМ глаголом `begin` под тем же контекстом
//     формы, под которым предъявляется утверждение. Испытание, положенное в
//     обход глагола, доказывало бы лишь то, что проверяющий сверяет байты, а
//     не то, что полоса выдаёт и гасит своё.
package loginlanehttp_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

// laneKeyBinding — привязка ключей стенда: та же доверяющая сторона и то же
// происхождение, которыми пробы собирают утверждение. Величины стенда и
// величины проб обязаны совпадать — иначе отказ происхождения читался бы как
// отказ подписи.
func laneKeyBinding() webauthnverify.Binding {
	return webauthnverify.Binding{
		RPID:       akProbeRPID,
		Origins:    []string{akProbeOrigin},
		Algorithms: []webauthnverify.Algorithm{webauthnverify.AlgES256},
	}
}

// givenAcceptedAccessKey — «Дано: личность с принятым ключом» (Ф7-01).
// Рукоятку называет проба: полоса сверяет её БЕЗУСЛОВНО, и «Дано» обязано её
// содержать, иначе сверять было бы не с чем.
func givenAcceptedAccessKey(t *testing.T, h *sessionLane, auth *webauthntest.Authenticator, handle []byte) domain.AccessKeyID {
	t.Helper()
	// Потолок вида объявляется ДО вставки: без него писатель отказывает
	// учётом, и это «условие не создано», а не отказ полосы. Различать их
	// обязательно — иначе несозданное условие читалось бы как сломанный
	// продукт.
	_, err := h.pool.Exec(h.ctx, `
		INSERT INTO own_ceilings (kind, limit_value) VALUES ('iam.user.accessKey', $1)
		ON CONFLICT (kind) DO UPDATE SET limit_value = EXCLUDED.limit_value`, 8)
	require.NoError(t, err, "Дано: потолок вида ключа объявлен")
	w, err := h.keys.Writer(h.ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(h.ctx) }()
	k, err := w.InsertKey(h.ctx, domain.AccessKey{
		ID:           domain.AccessKeyID(ids.NewHyphenID(ids.PrefixAccessKeyHyphen)),
		UserID:       h.user.ID,
		CredentialID: auth.CredentialID(),
		PublicKey:    auth.COSEPublicKey(t),
		Algorithm:    auth.Algorithm(),
		UserHandle:   handle,
		Name:         "probe-key",
		CreatedAt:    time.Now().UTC(),
	})
	require.NoError(t, err, "Дано: строка ключа кладётся писателем продукта")
	require.NoError(t, w.Commit(h.ctx))
	return k.ID
}

// akFormContext — контекст формы вида `access-key-login` и признак под ним.
func akFormContext(t *testing.T, h *sessionLane) (token string, form *http.Cookie) {
	t.Helper()
	return h.lane.csrf(t, h.c, string(domain.FormAccessKeyLogin), nil)
}

// akLiveChallenge — «Дано: испытание выдано» (Ф13-01): НАСТОЯЩИЙ глагол
// `begin` под контекстом, который и вернётся вызывающему.
func akLiveChallenge(t *testing.T, h *sessionLane) (challenge []byte, token string, form *http.Cookie) {
	t.Helper()
	token, form = akFormContext(t, h)
	r := h.lane.do(t, h.c, http.MethodPost, pathAccessKeyBegin,
		map[string]any{"csrfToken": token}, fwd(), form)
	require.Equalf(t, http.StatusOK, r.status, "Дано: `begin` выдаёт испытание: %s", r.body)
	var out struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	require.NoError(t, json.Unmarshal([]byte(r.body), &out))
	raw, err := base64.RawURLEncoding.DecodeString(out.PublicKey.Challenge)
	require.NoError(t, err, "Дано: испытание — base64url без дополнения")
	return raw, token, form
}
