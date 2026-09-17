// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys_test

// declarative_test.go — ДЕКЛАРАТИВНЫЕ пробы Ф7 (§8): читают ОБЪЯВЛЕНИЯ, а не
// поведение, и сверяют каждое с решённым значением. Поведенческие пробы
// (Ф7-40, Ф7-42) утверждают, что испытание равно объявлению; здесь — что само
// объявление равно решению (Р9, Р4, Р5, Р11). Второй держатель, названный
// §7 инв. 5: продукт, чьё объявление сменили вместе с испытанием, прошёл бы
// Ф7-40 и Ф7-42, оставаясь другим продуктом.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
	"gopkg.in/yaml.v3"

	authzv1 "github.com/PRO-Robotech/corelib/api/corelib/authz/v1"
	"github.com/PRO-Robotech/corelib/authz/catalogderive"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// TestAccessKey_Declared_ContractLiteralsEqualTheDecisions — пять литералов
// контракта объявлены значениями, которые решили Р9 и Р4; шестой (срок
// испытания) решён границей и проверяется ниже.
func TestAccessKey_Declared_ContractLiteralsEqualTheDecisions(t *testing.T) {
	require.Equal(t, "Kacho Cloud", access_keys.RPDisplayName, "видимое имя доверяющей стороны (Р9)")
	require.Equal(t, "preferred", access_keys.UserVerificationRegistration, "проверка пользователя при регистрации — «предпочтительна» (Р9)")
	require.Equal(t, "preferred", access_keys.UserVerificationAssertion, "проверка пользователя при предъявлении — «предпочтительна» (Р9)")
	require.Equal(t, "required", access_keys.ResidentKey, "обнаруживаемое удостоверение — «требуется» (Р9)")
	require.Equal(t, "none", access_keys.Attestation, "аттестация — «нет» (Р4)")
	require.Equal(t, 5*time.Minute, access_keys.ChallengeTTL, "срок испытания — перенос Ф1 §4.1 (Ф7-34)")
}

// TestAccessKey_Declared_ChallengeTTLIsBelowTheFreshnessWindow — срок
// испытания меньше окна свежести (Р5), сравнением ДВУХ объявленных величин:
// срок — литерал контракта, окно — величина профиля (боевой профиль чарта и
// образец документа оператора). Величина, поднятая до окна либо выше, —
// красное с обеими величинами в тексте.
func TestAccessKey_Declared_ChallengeTTLIsBelowTheFreshnessWindow(t *testing.T) {
	root := moduleRootOf(t)
	raw, err := os.ReadFile(filepath.Join(root, "deploy", "values.prod.yaml"))
	require.NoError(t, err)
	var tree map[string]any
	require.NoError(t, yaml.Unmarshal(raw, &tree))
	authn, _ := tree["authn"].(map[string]any)
	declared, _ := authn["selfServiceFreshness"].(string)
	require.NotEmpty(t, declared, "боевой профиль обязан объявлять окно свежести")
	window, err := time.ParseDuration(declared)
	require.NoError(t, err)
	require.Less(t, access_keys.ChallengeTTL, window,
		"срок испытания %s не меньше окна свежести профиля %s: Р5 обходился бы сбором испытания внутри окна", access_keys.ChallengeTTL, window)

	for _, s := range config.RequiredSettings {
		if s.Key != "authn.self-service-freshness" {
			continue
		}
		sample, err := time.ParseDuration(s.Sample)
		require.NoError(t, err)
		require.Less(t, access_keys.ChallengeTTL, sample, "образец документа оператора (%s)", s.Sample)
		return
	}
	t.Fatal("строки окна свежести в таблице обязательных величин нет")
}

type verbDecision struct {
	permission, relation, objectType, field, acr, exemptReason string
}

// decidedVerbs — Р11 дословно.
var decidedVerbs = map[string]verbDecision{
	"BeginRegistration":  {"iam.access_keys.begin_registration", "token_issuer", "iam_user", "user_id", "1", ""},
	"FinishRegistration": {"iam.access_keys.register", "token_issuer", "iam_user", "user_id", "1", ""},
	"List":               {"iam.access_keys.list", "token_reader", "iam_user", "user_id", "1", ""},
	"Revoke":             {"iam.access_keys.revoke", "token_issuer", "iam_user", "user_id", "1", ""},
	"BeginAssertion":     {"<exempt>", "", "", "", "", "SELF_SERVICE"},
	"FinishAssertion":    {"<exempt>", "", "", "", "", "SELF_SERVICE"},
}

// TestAccessKey_Declared_CatalogDescriptorsCarryTheDecidedLanes — первая из
// двух декларативных проб каталога (Р11): дескрипторы контракта этого дерева
// несут решённые право, отношение, область, пол и причину освобождения у
// каждого из шести глаголов — и глаголов ровно шесть.
func TestAccessKey_Declared_CatalogDescriptorsCarryTheDecidedLanes(t *testing.T) {
	seen := map[string]bool{}
	catalogderive.RangeAnnotated([]string{"kaname.cloud.iam.v1"}, func(full string, md protoreflect.MethodDescriptor, a catalogderive.Annotations) {
		if !strings.HasPrefix(full, "/kaname.cloud.iam.v1.AccessKeyService/") {
			return
		}
		verb := string(md.Name())
		want, ok := decidedVerbs[verb]
		require.True(t, ok, "глагол %s контрактом объявлен, а Р11 его не решала", verb)
		seen[verb] = true
		opts, _ := md.Options().(*descriptorpb.MethodOptions)
		require.NotNil(t, opts)
		acr, _ := proto.GetExtension(opts, authzv1.E_RequiredAcrMin).(string)
		reason, _ := proto.GetExtension(opts, authzv1.E_ExemptReason).(string)
		require.Equal(t, want.permission, a.Permission, "%s: право", verb)
		require.Equal(t, want.relation, a.RequiredRelation, "%s: отношение", verb)
		require.Equal(t, want.objectType, a.ScopeObjectType, "%s: область", verb)
		require.Equal(t, want.field, a.ScopeFromRequestField, "%s: поле области", verb)
		require.Equal(t, want.acr, acr, "%s: пол уровня доверия", verb)
		require.Equal(t, want.exemptReason, reason, "%s: причина освобождения", verb)
	})
	require.Len(t, seen, len(decidedVerbs), "глаголов ключа ровно шесть: %v", seen)
	_ = iamv1.File_kaname_cloud_iam_v1_access_key_service_proto // дескрипторы влинкованы этим импортом
}

// TestAccessKey_Declared_CatalogCopyCarriesTheDecidedLanes — вторая проба
// каталога (Р11): копия каталога прав, возвращённая с платформы, несёт те же
// шесть записей с теми же решениями.
func TestAccessKey_Declared_CatalogCopyCarriesTheDecidedLanes(t *testing.T) {
	root := moduleRootOf(t)
	raw, err := os.ReadFile(filepath.Join(root, "internal", "apps", "kaname", "seed", "embedded", "permission_catalog.json"))
	require.NoError(t, err)
	var rows []struct {
		FQN              string `json:"fqn"`
		Permission       string `json:"permission"`
		RequiredRelation string `json:"required_relation"`
		Scope            struct {
			ObjectType       string `json:"object_type"`
			FromRequestField string `json:"from_request_field"`
		} `json:"scope_extractor"`
		ACR          string `json:"required_acr_min"`
		ExemptReason string `json:"exempt_reason"`
	}
	require.NoError(t, json.Unmarshal(raw, &rows))
	seen := map[string]bool{}
	for _, r := range rows {
		const prefix = "kaname.cloud.iam.v1.AccessKeyService/"
		if !strings.HasPrefix(r.FQN, prefix) {
			continue
		}
		verb := strings.TrimPrefix(r.FQN, prefix)
		want, ok := decidedVerbs[verb]
		require.True(t, ok, "запись %s в копии, а Р11 глагол не решала", r.FQN)
		seen[verb] = true
		require.Equal(t, want.permission, r.Permission, "%s: право", verb)
		require.Equal(t, want.relation, r.RequiredRelation, "%s: отношение", verb)
		require.Equal(t, want.objectType, r.Scope.ObjectType, "%s: область", verb)
		require.Equal(t, want.field, r.Scope.FromRequestField, "%s: поле области", verb)
		require.Equal(t, want.acr, r.ACR, "%s: пол", verb)
		require.Equal(t, want.exemptReason, r.ExemptReason, "%s: причина освобождения", verb)
	}
	require.Len(t, seen, len(decidedVerbs), "в копии каталога записей ключа ровно шесть: %v", seen)
	t.Logf("перепись: записей каталога %d · записей ключа %d", len(rows), len(seen))
}

// moduleRootOf — корень модуля: каталог с go.mod вверх от пакета проб.
func moduleRootOf(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, dir, parent, "go.mod не найден вверх от %s", dir)
		dir = parent
	}
}
