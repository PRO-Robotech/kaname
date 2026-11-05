// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const rid01KeyRedactionCase = "registry-installation-rid01-EXPIRED-KEY-REFUSAL"

type rid01KeyRedactionProfile struct {
	SAKeyGrace        time.Duration
	UserTokenGrace    time.Duration
	Settled           time.Duration
	Window            time.Duration
	EnvironmentSHA256 string
	ExtraConfigSHA256 string
}

func rid01RedactionHash(v any) string {
	raw, _ := json.Marshal(v)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Это намеренно поддерживает ТОЛЬКО известный профиль nativeSingleDelivery.
// Никогда не вызывает config.Load/AutomaticEnv, не читает и не меняет окружающий os.Environ.
// Производственный Session.StartDelivery владеет настоящим YAML из этого ExtraConfig,
// а Process.Start использует ровно Session.Environment и собственный путь конфигурации.
func rid01ResolveRedactionProfile(environment []string, extra map[string]any) (rid01KeyRedactionProfile, error) {
	fail := errors.New("fixture NOT_ACCEPTED: unsupported RID01 redaction profile")
	if len(extra) != 0 {
		return rid01KeyRedactionProfile{}, fail
	}
	for _, entry := range environment {
		name, _, ok := strings.Cut(entry, "=")
		if !ok {
			return rid01KeyRedactionProfile{}, fail
		}
		// Включает оба настоящих пространства имён загрузчика и прежние плоские псевдонимы. Неизвестные
		// имена скрытия тоже отклоняются, даже переопределение пустым/умолчальным значением.
		name = strings.ToUpper(name)
		if strings.HasPrefix(name, "KANAME_") && strings.Contains(name, "REDACT") {
			return rid01KeyRedactionProfile{}, fail
		}
	}
	v := viper.New()
	config.RegisterDefaults(v)
	sa, user := v.GetDuration("authn.sakey-redact-grace"), v.GetDuration("authn.usertoken-redact-grace")
	if sa <= 0 || user <= 0 {
		return rid01KeyRedactionProfile{}, fail
	}
	settled := sa
	if user > settled {
		settled = user
	}
	settled += secretSweepMargin
	if settled <= 0 || secretSweepWindow <= settled {
		return rid01KeyRedactionProfile{}, fail
	}
	return rid01KeyRedactionProfile{SAKeyGrace: sa, UserTokenGrace: user, Settled: settled, Window: secretSweepWindow, EnvironmentSHA256: rid01RedactionHash(environment), ExtraConfigSHA256: rid01RedactionHash(extra)}, nil
}

type rid01KeyRedactionProof struct {
	State                             string    `json:"state"`
	CaseID                            string    `json:"caseId"`
	OperationID                       string    `json:"operationId"`
	ResponseType                      string    `json:"responseType"`
	BeforeCount                       int       `json:"beforeOperationCount"`
	AfterCount                        int       `json:"afterOperationCount"`
	BeforeRowSHA256                   string    `json:"beforeRowSHA256"`
	AfterRowSHA256                    string    `json:"afterRowSHA256"`
	BeforeCellSHA256                  string    `json:"beforeResponseCellSHA256"`
	AfterCellSHA256                   string    `json:"afterResponseCellSHA256"`
	ClearedFields                     []string  `json:"documentedClearedFields"`
	ActualSecretsGone                 bool      `json:"actualSecretsGone"`
	AllOtherColumnsEqual              bool      `json:"allOtherColumnsEqual"`
	AllOtherOperationsEqual           bool      `json:"allOtherOperationsEqual"`
	FullTypedNonsecretAndUnknownEqual bool      `json:"fullTypedNonsecretAndUnknownEqual"`
	PreRestoreStartedAt               time.Time `json:"preRestorePrimaryStartedAt"`
	PreRestoreFinishedAt              time.Time `json:"preRestorePrimaryFinishedAt"`
	OperationModifiedAt               time.Time `json:"operationModifiedAt"`
	SAKeyGrace                        string    `json:"actualSAKeyRedactGrace"`
	UserTokenGrace                    string    `json:"actualUserTokenRedactGrace"`
	Settled                           string    `json:"settled"`
	Window                            string    `json:"window"`
	EnvironmentSHA256                 string    `json:"actualSessionEnvironmentSHA256"`
	ExtraConfigSHA256                 string    `json:"actualStartDeliveryExtraConfigSHA256"`
	WholeDoDAccepted                  bool      `json:"wholeDoDAccepted"`
}

func rid01ReadByteaCell(row rid09PrimaryRow, name string) ([]byte, error) {
	fail := errors.New("RID01 typed credential evidence decode failed")
	value, ok := row[name]
	if !ok || len(value) > 2<<20 {
		return nil, fail
	}
	var encoded string
	if json.Unmarshal(value, &encoded) != nil || !strings.HasPrefix(encoded, "\\x") {
		return nil, fail
	}
	raw, err := hex.DecodeString(strings.TrimPrefix(encoded, "\\x"))
	if err != nil {
		return nil, fail
	}
	return raw, nil
}
func rid01RawString(row rid09PrimaryRow, name string) (string, bool) {
	raw, ok := row[name]
	if !ok {
		return "", false
	}
	var value string
	if json.Unmarshal(raw, &value) != nil {
		return "", false
	}
	return value, true
}

// Единственная нормализация — клон BEFORE. AFTER остаётся нетронутым и должен
// равняться этому полному типизированному клону, включая вложенные поля и неизвестные байты
// proto. Ячейки/столбцы SQL вне response_data сохраняются побайтно, без отбора.
func rid01ProveKeyRedaction(caseID, keyID string, before, after, preRestore rid01NewmanSnapshot, profile rid01KeyRedactionProfile) (*rid01KeyRedactionProof, error) {
	fail := errors.New("RID01 typed key redaction NOT_ACCEPTED")
	if caseID != rid01KeyRedactionCase || keyID == "" || len(before.Operations) != len(after.Operations) || len(before.OperationRawRows) != len(before.Operations) || len(after.OperationRawRows) != len(after.Operations) {
		return nil, fail
	}
	// Заново выводим значения по умолчанию без чтения окружающего окружения процесса. Настоящий
	// профиль отдельно проверен/опечатан до восстановления StartDelivery.
	expected, err := rid01ResolveRedactionProfile(nil, nil)
	if err != nil || profile.SAKeyGrace != expected.SAKeyGrace || profile.UserTokenGrace != expected.UserTokenGrace || profile.Settled != expected.Settled || profile.Window != expected.Window || profile.EnvironmentSHA256 == "" || profile.ExtraConfigSHA256 == "" {
		return nil, fail
	}
	a, ok := before.OperationRawRows[keyID]
	if !ok {
		return nil, fail
	}
	b, ok := after.OperationRawRows[keyID]
	if !ok {
		return nil, fail
	}
	if len(a) != len(b) || len(a) == 0 {
		return nil, fail
	}
	for id, digest := range before.Operations {
		originalRow, oldPresent := before.OperationRawRows[id]
		if !oldPresent {
			return nil, fail
		}
		row, present := after.OperationRawRows[id]
		if !present {
			return nil, fail
		}
		if digest != rid01RedactionHash(originalRow) || after.Operations[id] != rid01RedactionHash(row) {
			return nil, fail
		}
		if id != keyID && (digest != after.Operations[id] || !reflect.DeepEqual(before.OperationRawRows[id], row)) {
			return nil, fail
		}
	}
	for key, raw := range a {
		other, present := b[key]
		if !present {
			return nil, fail
		}
		if key != "response_data" && !bytes.Equal(raw, other) {
			return nil, fail
		}
	}
	if bytes.Equal(a["response_data"], b["response_data"]) {
		return nil, fail
	}
	id, ok := rid01RawString(a, "id")
	if !ok || id != keyID {
		return nil, fail
	}
	responseType, ok := rid01RawString(a, "response_type")
	if !ok {
		return nil, fail
	}
	typed, err := anypb.New(&iamv1.IssueSAKeyResponse{})
	if err != nil || responseType != typed.TypeUrl {
		return nil, fail
	}
	var done bool
	if json.Unmarshal(a["done"], &done) != nil || !done {
		return nil, fail
	}
	var modified time.Time
	if json.Unmarshal(a["modified_at"], &modified) != nil || modified.IsZero() {
		return nil, fail
	}
	start, end := preRestore.Whole.PrimaryStartedAt, preRestore.Whole.PrimaryFinishedAt
	if start.IsZero() || end.Before(start) || !modified.Before(start.Add(-profile.Settled)) || !modified.After(end.Add(-profile.Window)) {
		return nil, fail
	}
	// Сохраняем исходную строгую контрольную точку нулевой разницы независимой обязательной
	// предпосылкой. Этот компаратор сам не может разрешить неудачное доказательство до восстановления.
	if !reflect.DeepEqual(before.Operations, preRestore.Operations) || !reflect.DeepEqual(before.OperationRawRows, preRestore.OperationRawRows) {
		return nil, fail
	}
	rawBefore, err := rid01ReadByteaCell(a, "response_data")
	if err != nil {
		return nil, fail
	}
	rawAfter, err := rid01ReadByteaCell(b, "response_data")
	if err != nil {
		return nil, fail
	}
	original, current := &iamv1.IssueSAKeyResponse{}, &iamv1.IssueSAKeyResponse{}
	if proto.Unmarshal(rawBefore, original) != nil || proto.Unmarshal(rawAfter, current) != nil {
		return nil, fail
	}
	if original.PrivateKeyPem == "" && original.ClientSecret == "" && original.Secret == "" {
		return nil, fail
	}
	if current.PrivateKeyPem != "" || current.ClientSecret != "" || current.Secret != "" {
		return nil, fail
	}
	cleared := proto.Clone(original).(*iamv1.IssueSAKeyResponse)
	cleared.PrivateKeyPem = ""
	cleared.ClientSecret = ""
	cleared.Secret = ""
	if !proto.Equal(cleared, current) {
		return nil, fail
	}
	// Детерминированная кодировка известных полей также сохраняет точные необработанные неизвестные
	// байты каждого вложенного сообщения. Нормализация неизвестных полей запрещена.
	expectedBytes, err := (proto.MarshalOptions{Deterministic: true}).Marshal(cleared)
	if err != nil {
		return nil, fail
	}
	currentBytes, err := (proto.MarshalOptions{Deterministic: true}).Marshal(current)
	if err != nil || !bytes.Equal(expectedBytes, currentBytes) {
		return nil, fail
	}
	return &rid01KeyRedactionProof{State: "EXACT_TYPED_KEY_REDACTION_PROVEN_PUBLIC_ACCEPTANCE_SEPARATE", CaseID: caseID, OperationID: keyID, ResponseType: typed.TypeUrl, BeforeCount: len(before.Operations), AfterCount: len(after.Operations), BeforeRowSHA256: before.Operations[keyID], AfterRowSHA256: after.Operations[keyID], BeforeCellSHA256: rid01RedactionHash(a["response_data"]), AfterCellSHA256: rid01RedactionHash(b["response_data"]), ClearedFields: []string{"private_key_pem", "client_secret", "secret"}, ActualSecretsGone: true, AllOtherColumnsEqual: true, AllOtherOperationsEqual: true, FullTypedNonsecretAndUnknownEqual: true, PreRestoreStartedAt: start, PreRestoreFinishedAt: end, OperationModifiedAt: modified, SAKeyGrace: profile.SAKeyGrace.String(), UserTokenGrace: profile.UserTokenGrace.String(), Settled: profile.Settled.String(), Window: profile.Window.String(), EnvironmentSHA256: profile.EnvironmentSHA256, ExtraConfigSHA256: profile.ExtraConfigSHA256}, nil
}
func rid01AcceptedKeyRedaction(t *testing.T, h *rid01PublicContext, before, after rid01NewmanSnapshot) *rid01KeyRedactionProof {
	t.Helper()
	require.NotNil(t, h.RefusalBeforeRestore, "strict pre-restore capture mandatory")
	require.NotNil(t, h.RestoreRedactionProfile, "actual restoring input profile mandatory")
	profile, err := rid01ResolveRedactionProfile(h.f.session.Environment, h.RestoreExtraConfig)
	require.True(t, err == nil, "fixture NOT_ACCEPTED: unsupported actual RID01 redaction profile")
	require.True(t, reflect.DeepEqual(profile, *h.RestoreRedactionProfile), "fixture NOT_ACCEPTED: restoring profile changed")
	keyID := h.f.creator.KeyOperation.ID
	_, oldPresent := before.OperationRawRows[keyID]
	_, newPresent := after.OperationRawRows[keyID]
	require.True(t, oldPresent && newPresent, "known standing-key Operation row mandatory")
	if before.Operations[keyID] == after.Operations[keyID] {
		return nil
	}
	proof, err := rid01ProveKeyRedaction(rid01KeyRedactionCase, keyID, before, after, *h.RefusalBeforeRestore, profile)
	require.True(t, err == nil, "RID01 exact typed key redaction NOT_ACCEPTED; safe diagnostic retained")
	return proof
}

// Привязываем публичный контекст к точному настоящему входу StartDelivery.
func rid01SealRestoreProfile(t *testing.T, f *installationNativeWorld, in installruntime.DeliveryInput, h *rid01PublicContext) {
	t.Helper()
	require.NotNil(t, h)
	require.Same(t, f, h.f)
	require.Equal(t, "key", h.Kind)
	require.NotNil(t, h.RefusalBeforeRestore)
	require.Nil(t, h.RestoreRedactionProfile)
	profile, err := rid01ResolveRedactionProfile(f.session.Environment, in.ExtraConfig)
	require.True(t, err == nil, "fixture NOT_ACCEPTED: unsupported actual RID01 restoring profile")
	h.RestoreRedactionProfile = &profile
	// Принимается только nil/пустой ExtraConfig, но его точная форма nil/пустого значения сохраняется,
	// чтобы дайджест был привязан к тому же настоящему входу файла, а не реконструкции.
	if in.ExtraConfig != nil {
		h.RestoreExtraConfig = map[string]any{}
	}
}
