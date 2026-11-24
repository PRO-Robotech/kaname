// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	"github.com/stretchr/testify/require"
)

// Только JSON подготовленной посадки. Ни Docker, ни PrepareNativeStand, ни serve не вызываются.
func ridSessionEnvironmentStand(t *testing.T, moduleWriter bool) (*installruntime.NativeStand, map[string]string) {
	t.Helper()
	evidence := t.TempDir()
	require.NoError(t, os.Mkdir(filepath.Join(evidence, "run"), 0700))
	values := map[string]string{
		"KANAME_CONFIG_PATH": filepath.Join(evidence, "delivery", "registration-writers.json"),
		"KANAME_DB_HOST":     "127.0.0.1", "KANAME_DB_PORT": "original-port",
		"KANAME_DB_USER": "kaname", "KANAME_DB_NAME": "kaname",
		"KANAME_POLICY_SENTINEL": "unchanged-policy", "KANAME_TLS_SENTINEL": "unchanged-tls",
	}
	if moduleWriter {
		values["KANAME_MANIFESTS__DIR"] = filepath.Join(evidence, "delivery", "manifests")
		values["KANAME_MANIFESTS__REQUIRED"] = "true"
	}
	stand := &installruntime.NativeStand{Evidence: evidence, PGPort: "15432"}
	ridWriteSessionEnvironment(t, stand, values)
	return stand, values
}

func ridWriteSessionEnvironment(t *testing.T, stand *installruntime.NativeStand, values map[string]string) {
	t.Helper()
	raw, err := json.Marshal(values)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(stand.Evidence, "run", "native-environment.json"), raw, 0600))
}

func ridSessionEnvironmentValues(t *testing.T, environment []string) map[string]string {
	t.Helper()
	values := map[string]string{}
	for _, entry := range environment {
		name, value, ok := strings.Cut(entry, "=")
		require.True(t, ok)
		_, duplicate := values[name]
		require.False(t, duplicate)
		values[name] = value
	}
	return values
}

// nil Probe не позволяет Session.start дойти до файлов процесса или exec.
// Ошибка readiness доказывает прохождение неизменённого checkEnvironment и typed config.
func ridRequireSessionEnvironmentAcceptedWithoutExec(t *testing.T, environment []string) {
	t.Helper()
	session := &installruntime.Session{Environment: environment}
	process, err := session.StartBase(context.Background(), installruntime.EmptyRegistrationWriterPlan())
	require.Nil(t, process)
	require.EqualError(t, err, "real readiness probe and frozen binary fingerprint are required")
	require.Empty(t, session.History)
}

func TestRIDSessionEnvironmentPreparedConfigBoundary(t *testing.T) {
	// Inherited переменная не переписывается адаптером и не заменяет captured prepared input.
	t.Setenv("KANAME_CONFIG_PATH", "/external/inherited-config.json")
	for _, moduleWriter := range []bool{false, true} {
		t.Run(fmt.Sprint(moduleWriter), func(t *testing.T) {
			stand, _ := ridSessionEnvironmentStand(t, moduleWriter)
			overrides := map[string]string{"KANAME_BOOTSTRAP_ROOT_EMAIL": "operator@example.invalid", "KANAME_ACCESS_KEY_TTL": "30m"}
			path := filepath.Join(stand.Evidence, "run", "native-environment.json")
			before, err := os.ReadFile(path)
			require.NoError(t, err)
			ordinary, err := stand.Environment(overrides)
			require.NoError(t, err)
			expected := ridSessionEnvironmentValues(t, ordinary)
			require.Equal(t, filepath.Join(stand.Evidence, "delivery", "registration-writers.json"), expected["KANAME_CONFIG_PATH"])
			delete(expected, "KANAME_CONFIG_PATH")
			if moduleWriter {
				delete(expected, "KANAME_MANIFESTS__DIR")
				delete(expected, "KANAME_MANIFESTS__REQUIRED")
			}
			environment, err := nativeSessionEnvironment(stand, overrides, moduleWriter)
			require.NoError(t, err)
			require.Equal(t, expected, ridSessionEnvironmentValues(t, environment))
			ridRequireSessionEnvironmentAcceptedWithoutExec(t, environment)
			require.Equal(t, "/external/inherited-config.json", os.Getenv("KANAME_CONFIG_PATH"))
			after, err := os.ReadFile(path)
			require.NoError(t, err)
			require.Equal(t, before, after)
			ordinaryAfter, err := stand.Environment(overrides)
			require.NoError(t, err)
			require.Equal(t, ordinary, ordinaryAfter, "ordinary stand/migrator environment remains intact")
			require.Equal(t, map[string]string{"KANAME_BOOTSTRAP_ROOT_EMAIL": "operator@example.invalid", "KANAME_ACCESS_KEY_TTL": "30m"}, overrides)
		})
	}
}

func TestRIDSessionEnvironmentRejectsUnexpectedConfig(t *testing.T) {
	for _, moduleWriter := range []bool{false, true} {
		for _, mutation := range []string{"external", "relative", "lexical-alias", "missing", "case-alias", "override-external", "override-own", "override-empty", "override-case"} {
			t.Run(fmt.Sprintf("%t/%s", moduleWriter, mutation), func(t *testing.T) {
				stand, values := ridSessionEnvironmentStand(t, moduleWriter)
				overrides := map[string]string{}
				switch mutation {
				case "external":
					values["KANAME_CONFIG_PATH"] = "/external/config.json"
				case "relative":
					values["KANAME_CONFIG_PATH"] = "delivery/registration-writers.json"
				case "lexical-alias":
					values["KANAME_CONFIG_PATH"] = stand.Evidence + "/delivery/../delivery/registration-writers.json"
				case "missing":
					delete(values, "KANAME_CONFIG_PATH")
				case "case-alias":
					values["kaname_config_path"] = values["KANAME_CONFIG_PATH"]
				case "override-external":
					overrides["KANAME_CONFIG_PATH"] = "/external/config.json"
				case "override-own":
					overrides["KANAME_CONFIG_PATH"] = values["KANAME_CONFIG_PATH"]
				case "override-empty":
					overrides["KANAME_CONFIG_PATH"] = ""
				case "override-case":
					overrides["kaname_config_path"] = values["KANAME_CONFIG_PATH"]
				}
				ridWriteSessionEnvironment(t, stand, values)
				environment, err := nativeSessionEnvironment(stand, overrides, moduleWriter)
				require.Error(t, err)
				require.Nil(t, environment, "unexpected config never silently disappears")
			})
		}
	}
}

func TestRIDSessionEnvironmentRejectsUnpreparedEvidence(t *testing.T) {
	for _, evidence := range []string{"relative-evidence", "/tmp/native-session/../other-evidence"} {
		t.Run(evidence, func(t *testing.T) {
			environment, err := nativeSessionEnvironment(&installruntime.NativeStand{Evidence: evidence}, nil, false)
			require.Error(t, err)
			require.Nil(t, environment)
		})
	}
}

func TestRIDSessionEnvironmentPreservesReservedInputRejection(t *testing.T) {
	for _, moduleWriter := range []bool{false, true} {
		for _, key := range []string{"KANAME_MODULESEEDINSTALLER__CREDENTIAL_FILE", "KANAME_REGISTRATION_ACCOUNT_WRITERS__SOURCES"} {
			t.Run(fmt.Sprintf("%t/%s", moduleWriter, key), func(t *testing.T) {
				stand, _ := ridSessionEnvironmentStand(t, moduleWriter)
				environment, err := nativeSessionEnvironment(stand, map[string]string{key: "external-input"}, moduleWriter)
				require.NoError(t, err)
				require.Equal(t, "external-input", ridSessionEnvironmentValues(t, environment)[key])
				session := &installruntime.Session{Environment: environment}
				_, err = session.StartBase(context.Background(), installruntime.EmptyRegistrationWriterPlan())
				require.ErrorContains(t, err, "environment would shadow installation input: "+key)
			})
		}
	}
	// Прежний non-moduleWriter путь не удаляет manifest inputs.
	stand, _ := ridSessionEnvironmentStand(t, false)
	environment, err := nativeSessionEnvironment(stand, map[string]string{"KANAME_MANIFESTS__DIR": "/external/manifests"}, false)
	require.NoError(t, err)
	session := &installruntime.Session{Environment: environment}
	_, err = session.StartBase(context.Background(), installruntime.EmptyRegistrationWriterPlan())
	require.ErrorContains(t, err, "environment would shadow installation input: KANAME_MANIFESTS__DIR")
}

func TestRIDSessionEnvironmentConcurrentInheritance(t *testing.T) {
	for _, moduleWriter := range []bool{false, true} {
		t.Run(fmt.Sprint(moduleWriter), func(t *testing.T) {
			stand, _ := ridSessionEnvironmentStand(t, moduleWriter)
			environment, err := nativeSessionEnvironment(stand, nil, moduleWriter)
			require.NoError(t, err)
			before := append([]string(nil), environment...)
			world := &installationNativeWorld{stand: stand, session: &installruntime.Session{Environment: environment}}
			ports := installruntime.SecondNativePorts()
			concurrent := nativeConcurrentEnvironment(t, world, ports, "session-boundary-control")
			values := ridSessionEnvironmentValues(t, concurrent)
			require.NotContains(t, values, "KANAME_CONFIG_PATH")
			require.Equal(t, "unchanged-policy", values["KANAME_POLICY_SENTINEL"])
			require.Equal(t, "unchanged-tls", values["KANAME_TLS_SENTINEL"])
			for _, key := range []string{"KANAME_DB_HOST", "KANAME_DB_PORT", "KANAME_DB_USER", "KANAME_DB_NAME"} {
				require.NotContains(t, values, key)
			}
			expectedPorts, err := ports.EnvironmentOverrides()
			require.NoError(t, err)
			for key, value := range expectedPorts {
				require.Equal(t, value, values[key])
			}
			require.Equal(t, "postgres://kaname@127.0.0.1:15432/kaname?sslmode=require&application_name=session-boundary-control", values["KANAME_REPOSITORY__POSTGRES__URL"])
			require.Equal(t, "2", values["KANAME_REPOSITORY__POSTGRES__REPLICA_BUDGET"])
			require.Equal(t, before, world.session.Environment)
			ridRequireSessionEnvironmentAcceptedWithoutExec(t, concurrent)
		})
	}
}
