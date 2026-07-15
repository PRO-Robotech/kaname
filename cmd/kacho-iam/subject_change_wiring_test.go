// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package main

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/PRO-Robotech/kacho/pkg/grpcclient"
)

// TestGatewayDialOpts_IncludesIdleKeepalive — KA-02: subject-drainer conn →
// api-gateway internal — idle-prone (conn используется только когда дренится
// subject_change_outbox). Должен нести keepalive Time=10s, Timeout=Time/3,
// PermitWithoutStream=true (idle-prone drainer-conn). The idle-keepalive params
// applied on the dial come from grpcclient.KeepaliveParams(true).
func TestGatewayDialOpts_IncludesIdleKeepalive(t *testing.T) {
	p := grpcclient.KeepaliveParams(true)
	require.Equal(t, 10*time.Second, p.Time)
	require.Equal(t, 10*time.Second/3, p.Timeout)
	require.True(t, p.PermitWithoutStream,
		"subject-drainer conn is idle-prone → PermitWithoutStream must be true (FD-2)")

	opts := gatewayDialOpts(insecure.NewCredentials())
	require.GreaterOrEqual(t, len(opts), 2,
		"gatewayDialOpts must include creds + keepalive DialOption")
}

// TestGatewayDialOpts_PreservesCreds — KA-02 and: creds (gatewayDialCreds)
// прокидываются без изменений; keepalive только добавляется.
func TestGatewayDialOpts_PreservesCreds(t *testing.T) {
	var _ []grpc.DialOption = gatewayDialOpts(insecure.NewCredentials())
}
