// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"testing"

	childregistrationapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/child_registration"
	internaliamapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func TestChildRegistrationSurfaceRequiresComposedPublicHandler(t *testing.T) {
	const service = "kaname.cloud.iam.v1.ChildRegistrationService"
	staged := grpc.NewServer()
	defer staged.Stop()
	registerPublicServices(staged, &services{}, nil)
	require.NotContains(t, staged.GetServiceInfo(), service)

	// Здесь проверяется регистрация слушателей, а не полномочие пользователя.
	svcs := &services{childRegistrationHandler: childregistrationapp.NewHandler(internaliamapp.NewUserChildRegistration(nil))}
	public := grpc.NewServer()
	defer public.Stop()
	registerPublicServices(public, svcs, nil)
	require.Contains(t, public.GetServiceInfo(), service)
	internal := grpc.NewServer()
	defer internal.Stop()
	registerInternalServices(internal, svcs, nil, config.Config{}, nil)
	require.NotContains(t, internal.GetServiceInfo(), service)
}
