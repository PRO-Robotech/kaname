// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	moduleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/module"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestCatalogPublicationRegistrationIsPublicAndConditional(t *testing.T) {
	const publication = "kaname.cloud.iam.v1.CatalogPublicationService"
	const internalModule = "kaname.cloud.iam.v1.InternalModuleService"
	// Проверяется регистрация, без вызова сценариев и без порта базы.
	svcs := &services{
		catalogPublicationHandler: &moduleapp.PublicationHandler{},
		moduleHandler:             moduleapp.NewHandler(nil, nil, nil, nil),
	}
	public := grpc.NewServer()
	t.Cleanup(public.Stop)
	registerPublicServices(public, svcs, nil)
	require.Contains(t, public.GetServiceInfo(), publication)
	require.NotEmpty(t, public.GetServiceInfo()[publication].Methods)
	require.NotContains(t, public.GetServiceInfo(), internalModule)

	internal := grpc.NewServer()
	t.Cleanup(internal.Stop)
	registerInternalServices(internal, svcs, nil, config.Config{}, nil)
	require.Contains(t, internal.GetServiceInfo(), internalModule)
	require.NotContains(t, internal.GetServiceInfo(), publication)

	for _, absent := range []*services{nil, {}} {
		server := grpc.NewServer()
		t.Cleanup(server.Stop)
		registerPublicServices(server, absent, nil)
		require.NotContains(t, server.GetServiceInfo(), publication,
			"без собранного сценария публичная служба не регистрируется")
	}
}
