// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// method_refusal_test.go — ФОРМА ОТКАЗА НА НЕВЕРНЫЙ МЕТОД у полосы входа
// (задача #261, решение R36 п. 3).
//
// Предмет: «путь есть, метод не тот» — один и тот же класс отказа у обеих
// HTTP-поверхностей службы (полоса входа и REST-фронт). Прежде полоса отвечала
// `code 3` (INVALID_ARGUMENT), фронт — `code 12` (UNIMPLEMENTED), и клиент,
// ключующийся на `code`, читал один отказ двумя разными способами в
// зависимости от адреса. Форма решения: `405`,
// `{"code":12,"message":"method not allowed","details":[]}`, заголовок `Allow`
// с допустимыми методами пути.
//
// Утверждается ТЕЛО дословно, а не только статус: предмет находки — число в
// теле, которое читает клиент.
package loginlanehttp_test

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

// wrongMethodBody — тело отказа на неверный метод, дословно (R36 п. 3).
const wrongMethodBody = `{"code":12,"message":"method not allowed","details":[]}`

func TestLane_261_WrongMethodAnswersTheOneFormOfBothSurfaces(t *testing.T) {
	l := newLane(t, &stubLane{}, "")
	c := l.client(t, gatewaySAN)

	cases := []struct {
		name, method, path, allow string
	}{
		// Путь под POST, предъявлен GET.
		{"post-path-get", http.MethodGet, "/iam/v1/auth/login", http.MethodPost},
		// Путь под GET, предъявлен POST: Allow называет ДРУГОЙ метод — заголовок
		// берётся у маршрута, а не выписан одной константой на полосу.
		{"get-path-post", http.MethodPost, "/iam/v1/auth/csrf", http.MethodGet},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := l.do(t, c, tc.method, tc.path, nil, nil)
			require.Equal(t, http.StatusMethodNotAllowed, r.status)
			require.JSONEq(t, wrongMethodBody, r.body,
				"неверный метод — code 12 (UNIMPLEMENTED), как у REST-фронта службы")
			require.Equal(t, tc.allow, r.header.Get("Allow"))
		})
	}
}

// ЗАКОННЫЙ БЛИЗНЕЦ: тот же путь верным методом до отказа метода не доходит.
// Без него утверждение выше зеленело бы на полосе, отвечающей 405 на всё.
func TestLane_261_RightMethodIsNotRefusedAsAWrongOne(t *testing.T) {
	l := newLane(t, &stubLane{}, "")
	c := l.client(t, gatewaySAN)

	r := l.do(t, c, http.MethodGet, "/iam/v1/auth/csrf?form=password", nil, nil)
	require.Equal(t, http.StatusOK, r.status)
	require.Empty(t, r.header.Get("Allow"), "успешный ответ перечня методов не несёт")
}
