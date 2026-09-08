// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package restfront

import (
	"context"
	"fmt"
	"net/http"

	"google.golang.org/grpc"
)

// NewPublic собирает публичный REST-фронт службы.
//
// grpcAddr — адрес СОБСТВЕННОГО публичного gRPC-слушателя. Через него и только
// через него идёт каждый запрос фронта: все звенья, решающие о вызывающем и о
// доступе к объекту, суть перехватчики слушателя, и внутрипроцессная
// регистрация обошла бы их все.
func NewPublic(ctx context.Context, grpcAddr string, opts []grpc.DialOption) (http.Handler, error) {
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
	return withAuthenticationChallenge(mux), nil
}

// NewInternal собирает внутренний REST-фронт службы.
//
// Отдельный мультиплексор на отдельном слушателе, а не разбор пути на общем:
// принадлежность маршрута фронту обязана быть свойством того, куда вообще можно
// дозвониться, а не решением, принимаемым на каждом запросе.
func NewInternal(ctx context.Context, grpcAddr string, opts []grpc.DialOption) (http.Handler, error) {
	if grpcAddr == "" {
		return nil, fmt.Errorf("внутренний REST-фронт: адрес собственного gRPC-слушателя пуст")
	}
	mux := newMux()
	if err := registerInternalRESTServices(ctx, mux, grpcAddr, opts); err != nil {
		return nil, err
	}
	return mux, nil
}
