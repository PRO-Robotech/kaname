// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package restfront

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// NewPublic собирает публичный REST-фронт службы.
//
// grpcAddr — адрес СОБСТВЕННОГО публичного gRPC-слушателя. Через него и только
// через него идёт каждый запрос фронта: все звенья, решающие о вызывающем и о
// доступе к объекту, суть перехватчики слушателя, и внутрипроцессная
// регистрация обошла бы их все.
//
// limits — потолки тела и одновременности (limits.go). Аргумент, а не опция:
// фронт, опубликованный наружу, без них не собирается — забыть их негде.
func NewPublic(ctx context.Context, grpcAddr string, opts []grpc.DialOption, limits Limits) (http.Handler, error) {
	if grpcAddr == "" {
		return nil, fmt.Errorf("публичный REST-фронт: адрес собственного gRPC-слушателя пуст")
	}
	mux := newMux()
	if err := registerPublicRESTServices(ctx, mux, grpcAddr, opts); err != nil {
		return nil, err
	}
	// Подсказка аутентификации — только здесь, и почему только здесь, сказано в
	// challenge.go: внутренний фронт обслуживает модули, называющиеся
	// сертификатом, и совет «предъяви Bearer» указал бы им действие, которого у
	// них нет.
	//
	// Потолки — ВНУТРИ подсказки: их отказы — не 401, и подсказка их не
	// трогает, а слот одновременности берётся до чтения тела мультиплексором.
	return withAuthenticationChallenge(WithLimits(mux, limits)), nil
}

// Admission — допуск предъявителя внутреннего фронта по состоянию его
// рукопожатия. Ложь — отказ `PermissionDenied` до вызова слушателя.
type Admission func(*tls.ConnectionState) bool

// NewInternal собирает внутренний REST-фронт службы.
//
// Отдельный мультиплексор на отдельном слушателе, а не разбор пути на общем:
// принадлежность маршрута фронту обязана быть свойством того, куда вообще можно
// дозвониться, а не решением, принимаемым на каждом запросе.
//
// # Допуск предъявителя — ЗДЕСЬ, а не у слушателя (SEC-1017-1)
//
// Слушатель видит пиром сам фронт, а не того, кто пришёл к фронту: личность
// предъявителя HTTP знает только рукопожатие фронта. Обработчик, сужающий довод
// по личности вызывающего (внутренний Check плоскости данных, kaname#987), на
// хопе её не видит, — и решать, кого пускать, может только фронт. admit задаёт
// корень (`authzguard.InternalFrontAdmission`); пустой допуск — отказ сборки, а не
// «пускать всех»: молчание значило бы ровно прежнюю дыру.
//
// Отказ рендерится обработчиком ошибок мультиплексора — той же формой, что отказ
// слушателя: `403`, `{"code":7,"message":"permission denied","details":[]}`.
func NewInternal(ctx context.Context, grpcAddr string, opts []grpc.DialOption, admit Admission) (http.Handler, error) {
	if grpcAddr == "" {
		return nil, fmt.Errorf("внутренний REST-фронт: адрес собственного gRPC-слушателя пуст")
	}
	if admit == nil {
		return nil, fmt.Errorf("внутренний REST-фронт: допуск предъявителя не назван")
	}
	mux := newMux()
	if err := registerInternalRESTServices(ctx, mux, grpcAddr, opts); err != nil {
		return nil, err
	}
	return admitted(mux, admit), nil
}

// admitted — мультиплексор за допуском предъявителя.
func admitted(mux *runtime.ServeMux, admit Admission) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !admit(r.TLS) {
			_, outbound := runtime.MarshalerForRequest(mux, r)
			runtime.HTTPError(r.Context(), mux, outbound, w, r, status.Error(codes.PermissionDenied, "permission denied"))
			return
		}
		mux.ServeHTTP(w, r)
	})
}
