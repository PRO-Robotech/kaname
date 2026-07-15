// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package config_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
)

// TestLoad_SAKeyRedactGrace_Default — без override grace-окно затирания
// одноразового SA-key private_key_pem по умолчанию 120s: разумное окно для
// poll-based retrieval (клиент успевает опросить Operation.Get и сохранить ключ).
func TestLoad_SAKeyRedactGrace_Default(t *testing.T) {
	cfg, err := config.Load("")
	require.NoError(t, err)

	require.Equal(t, 120*time.Second, cfg.AuthN.SAKeyRedactGrace,
		"default sakey redact grace must be 120s (poll-retrieval window)")
}

// TestLoad_SAKeyRedactGrace_EnvOverride — KACHO_IAM_SAKEY_REDACT_GRACE
// переопределяет grace-окно (оператор может расширить/сузить окно под свой
// retrieval-флоу).
func TestLoad_SAKeyRedactGrace_EnvOverride(t *testing.T) {
	t.Setenv("KACHO_IAM_SAKEY_REDACT_GRACE", "45s")

	cfg, err := config.Load("")
	require.NoError(t, err)

	require.Equal(t, 45*time.Second, cfg.AuthN.SAKeyRedactGrace,
		"KACHO_IAM_SAKEY_REDACT_GRACE must override the default grace window")
}
