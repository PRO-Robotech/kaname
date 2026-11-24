// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package restfront

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// Равенства перечней REST/gRPC недостаточно: ошибочная регистрация на обоих
// внутренних фронтах сохранила бы паритет. Закрепляем назначенный фронт явно.
func TestCatalogPublicationRESTRegistrationIsPublicOnly(t *testing.T) {
	for _, test := range []struct {
		function string
		want     bool
	}{
		{"registerPublicRESTServices", true},
		{"registerInternalRESTServices", false},
	} {
		services, found, err := registrationsIn(restFrontDir(t), test.function, "ServiceHandlerFromEndpoint")
		if err != nil || !found {
			t.Fatalf("разбор %s: found=%v, err=%v", test.function, found, err)
		}
		_, registered := services["CatalogPublicationService"]
		if registered != test.want {
			t.Errorf("%s: CatalogPublicationService registered=%v, want=%v", test.function, registered, test.want)
		}
		_, legacy := services["InternalModuleService"]
		if legacy == test.want {
			t.Errorf("%s: InternalModuleService должен остаться только на внутреннем фронте", test.function)
		}
	}
}

func TestCatalogPublicationRESTRoutesFollowPublicProfile(t *testing.T) {
	for _, profile := range []struct {
		name     string
		services PublicServices
		want     int
	}{
		{"staged", PublicServices{}, http.StatusNotFound},
		{"full_without_publication_handler", PublicServices{ChildRegistration: true}, http.StatusNotFound},
		{"full_with_publication_handler", PublicServices{ChildRegistration: true, CatalogPublication: true}, http.StatusBadRequest},
	} {
		t.Run(profile.name, func(t *testing.T) {
			front, err := NewPublic(t.Context(), "127.0.0.1:1", dialOpts(), Limits{}, profile.services)
			require.NoError(t, err)
			for _, method := range []string{"planPublication", "applyPublication"} {
				// Подключённый маршрут отвергает неверный JSON до обращения к gRPC.
				req := httptest.NewRequest(http.MethodPost, "/iam/v1/catalog/modules/erp:"+method, strings.NewReader("{"))
				req.Header.Set("Content-Type", "application/json")
				response := httptest.NewRecorder()
				front.ServeHTTP(response, req)
				require.Equal(t, profile.want, response.Code, method)
			}
		})
	}
}
