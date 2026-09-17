// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// loginlane_test.go — посадка полосы входа (Ф3-44, Ф3-45 в доме службы):
// под `own` полоса поднимается и наблюдатель провязки видит хранилища; под
// `external` полоса не поднимается; режим слушателя формы, отличный от
// `mutual`, под `own` — отказ старта с именем ручки; предел памяти не наложен —
// отказ с числами.
package main

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/retention"
	"github.com/PRO-Robotech/kaname/internal/assurance"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func loginLaneCfg(p config.IdentityProvider) config.Config {
	cfg := roadCfg(p, "9097")
	cfg.APIServer.LoginLaneEndpoint = "tcp://0.0.0.0:9098"
	cfg.AuthN.TrustDomainName = "kacho.cloud"
	cfg.AuthN.Login = config.LoginLaneConfig{
		SessionTTL: 24 * 3600e9, CookieDomain: config.CookieDomainNone,
		AddressAttempts: 5, AddressWindow: 15 * 60e9, SourceAttempts: 50, SourceWindow: 15 * 60e9,
		PasswordMinLength: 8, BreachCheck: config.BreachCheckDisabled,
		HasherFormat: "argon2id", HasherMemory: 65536, HasherIterations: 3, HasherParallelism: 4,
		VerifierCapacity: 4, MemoryReserveBytes: 256 << 20,
	}
	return cfg
}

func mutualLane() config.MTLSConfig {
	return config.MTLSConfig{
		LoginLaneServerMTLS: grpcsrv.TLSServer{Enable: true, CertFile: "/etc/kaname/tls/lane/tls.crt",
			KeyFile: "/etc/kaname/tls/lane/tls.key", ClientCAFiles: []string{"/etc/kaname/tls/ca.crt"}},
		LoginLaneClientAuthMode: config.InternalRESTMutualModeName(),
	}
}

// TestLoginLane_F3_44_ListenerModeIsMutualOrTheStartIsRefused — (в): режим,
// отличный от `mutual`, под `own` — отказ с именем ручки; пустой адрес под
// `own` — отказ; под `external` — ни то ни другое не требуется.
func TestLoginLane_F3_44_ListenerModeIsMutualOrTheStartIsRefused(t *testing.T) {
	own := loginLaneCfg(config.IdentityProviderOwn)
	require.NoError(t, requireLoginLaneTLS(true, own, mutualLane()), "положительный контроль: mutual и адрес — старт")

	plain := mutualLane()
	plain.LoginLaneClientAuthMode = "server-tls-only"
	err := requireLoginLaneTLS(true, own, plain)
	require.Error(t, err)
	require.Contains(t, err.Error(), "KANAME_LOGINLANE_SERVER_MTLS_CLIENTAUTHMODE")
	require.Contains(t, err.Error(), "mutual")

	off := mutualLane()
	off.LoginLaneServerMTLS.Enable = false
	err = requireLoginLaneTLS(true, own, off)
	require.Error(t, err)
	require.Contains(t, err.Error(), "KANAME_LOGINLANE_SERVER_MTLS_ENABLE")

	noAddr := own
	noAddr.APIServer.LoginLaneEndpoint = ""
	err = requireLoginLaneTLS(true, noAddr, mutualLane())
	require.Error(t, err, "под own полоса обязана подняться: пустой адрес — отказ")
	require.Contains(t, err.Error(), knobLoginLane)

	ext := loginLaneCfg(config.IdentityProviderExternal)
	ext.APIServer.LoginLaneEndpoint = ""
	require.NoError(t, requireLoginLaneTLS(true, ext, config.MTLSConfig{}), "под external полосы нет и требований к ней нет")
	require.NoError(t, requireLoginLaneTLS(false, own, config.MTLSConfig{}), "не production — стража нет (in-process фикстура)")
}

// TestLoginLane_F3_45_LaneIsRaisedOnlyUnderOwn — под `external` полоса не
// строится вовсе: ни слушателя, ни `Resolve`; наблюдатель провязки сообщает
// хранилища не провязанными.
func TestLoginLane_F3_45_LaneIsRaisedOnlyUnderOwn(t *testing.T) {
	require.False(t, loginLaneWanted(loginLaneCfg(config.IdentityProviderExternal)))
	require.True(t, loginLaneWanted(loginLaneCfg(config.IdentityProviderOwn)))
	var none *loginLane
	require.False(t, none.wired(), "полосы нет — хранилища не провязаны")
	require.Nil(t, none.signInMethods())
	w := laneWiringOf(none)
	require.False(t, w.HumanSessionsWired)
	require.False(t, w.HumanCredentialsWired)
}

// TestLoginLane_F3_42_MemoryLimitProbeReadsTheCgroup — порт стража: значение
// `max` — предел не наложен; число — предел; нечитаемый файл — не наложен.
func TestLoginLane_F3_42_MemoryLimitProbeReadsTheCgroup(t *testing.T) {
	dir := t.TempDir()
	limit, ok := readMemoryLimit([]string{dir + "/absent"})
	require.False(t, ok)
	require.Zero(t, limit)
	writeFile(t, dir+"/max", "max\n")
	_, ok = readMemoryLimit([]string{dir + "/max"})
	require.False(t, ok, "«max» — предел не наложен")
	writeFile(t, dir+"/limit", "1073741824\n")
	limit, ok = readMemoryLimit([]string{dir + "/absent", dir + "/limit"})
	require.True(t, ok)
	require.EqualValues(t, 1<<30, limit)
	writeFile(t, dir+"/v1", "9223372036854771712\n")
	_, ok = readMemoryLimit([]string{dir + "/v1"})
	require.False(t, ok, "величина cgroup v1 «без предела» — не наложен")
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	require.NoError(t, writeProbeFile(path, body))
}

var _ = strings.Contains

// TestLoginLane_F12_34_WiredLaneNamesThreeMethodsAndTwoLevels — Ф12-34 (Ф11-28):
// поднятая полоса называет `password`, `totp`, `lookup_secret` наблюдением, и
// правило даёт из них два предъявимых уровня; уборка полосы несёт четвёртый
// предмет — заведения — с порогом, равным окну свежести (Ф12-44, Р8).
func TestLoginLane_F12_34_WiredLaneNamesThreeMethodsAndTwoLevels(t *testing.T) {
	lane := &loginLane{
		sessions: kanamepg.NewHumanSessionRepo(nil), methods: kanamepg.NewLoginMethodRepo(nil),
		freshness: 15 * time.Minute, keys: kanamepg.NewAccessKeyRepo(nil), keyFreshness: kanamepg.NewHumanSessionFreshness(nil),
	}
	require.True(t, lane.wired())
	require.Equal(t, []assurance.Method{assurance.MethodPassword, assurance.MethodTOTP, assurance.MethodLookupSecret}, lane.signInMethods())
	require.Equal(t, []string{"1", "2"}, assurance.PresentableLevels(lane.signInMethods()).Strings())

	reapers := lane.retentionReapers()
	require.NotNil(t, reapers.Enrollments)
	require.Equal(t, 15*time.Minute, reapers.EnrollmentWindow)
	names := map[string]time.Duration{}
	for _, s := range retention.WithHumanSessions(nil, reapers) {
		names[s.Name] = s.Grace
	}
	require.Len(t, names, 5, "пятый — испытания ключей доступа (Ф7)")
	require.Equal(t, 15*time.Minute, names[retention.SubjectSecondFactorEnrollments])
	require.Contains(t, names, retention.SubjectAccessKeyChallenges)

	// Ф12-37: сброс распорядителем провязан ровно там, где полоса поднята.
	require.NotNil(t, lane.resetSecondFactorUseCase(nil, nil))
	var none *loginLane
	require.Nil(t, none.resetSecondFactorUseCase(nil, nil), "под external глагол не провязан")
}
