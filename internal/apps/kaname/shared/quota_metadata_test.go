// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/quota/quotadetail"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// Величины отказа учёта доезжают до клиента МАШИННО (задача продукта #1605).
//
// Производитель отказа уже посчитал носителя, вид, предел и занятое и положил их
// в `DETAIL`. Клиент обязан читать их из `google.rpc.ErrorInfo.metadata`, а не
// разбором прозы: тон сообщения стабилен, но не парсибелен
// (`api-conventions.md` §By-lane code-split).

// refusalMetadataInfo достаёт `ErrorInfo` из статуса; отсутствие детали —
// находка, а не «ну и ладно».
func refusalMetadataInfo(t testing.TB, err error) *errdetails.ErrorInfo {
	t.Helper()
	st, ok := status.FromError(err)
	require.True(t, ok, "отказ обязан быть gRPC-статусом: %v", err)
	for _, d := range st.Details() {
		if info, isInfo := d.(*errdetails.ErrorInfo); isInfo {
			return info
		}
	}
	t.Fatalf("статус обязан нести google.rpc.ErrorInfo: %v", err)
	return nil
}

// Дословно то, что кладёт в DETAIL полоса KQ001 производителя.
const quotaDetailExceeded = `{"carrier_type": "project", "carrier_id": "prj-1", ` +
	`"kind": "iam.project", "limit": 4, "used": 4}`

func TestQuotaRefusalCarriesTheProducerAmounts(t *testing.T) {
	const producer = "project prj-1 has reached its limit of 4 iam.project"
	err := quotadetail.Attach(
		fmt.Errorf("%w: %s", iamerr.ErrQuotaExceeded, producer), quotaDetailExceeded)

	out := MapRepoErr(err)

	st, _ := status.FromError(out)
	assert.Equal(t, codes.ResourceExhausted, st.Code())
	assert.Equal(t, producer, st.Message(),
		"текст производителя — контракт, и он не меняется от появления величин")

	info := refusalMetadataInfo(t, out)
	assert.Equal(t, "QUOTA_EXCEEDED", info.GetReason())
	assert.Equal(t, "iam.kacho.cloud", info.GetDomain())
	assert.Equal(t, map[string]string{
		"carrier_type": "project",
		"carrier_id":   "prj-1",
		"kind":         "iam.project",
		"limit":        "4",
		"used":         "4",
	}, info.GetMetadata(), "величины производителя обязаны доезжать до клиента")
}

// Полоса «потолок не назван» несёт носителя и вид, но не предел: его не назвали.
func TestQuotaRefusalNotProvisionedCarriesTheCarrierWithoutAmounts(t *testing.T) {
	const detail = `{"carrier_type": "project", "carrier_id": "prj-1", "kind": "iam.serviceaccount"}`
	err := quotadetail.Attach(
		fmt.Errorf("%w: project prj-1 has no ceiling stated for iam.serviceaccount",
			iamerr.ErrQuotaNotProvisioned), detail)

	out := MapRepoErr(err)

	st, _ := status.FromError(out)
	assert.Equal(t, codes.FailedPrecondition, st.Code())

	info := refusalMetadataInfo(t, out)
	assert.Equal(t, "QUOTA_NOT_PROVISIONED", info.GetReason())
	assert.Equal(t, "prj-1", info.GetMetadata()["carrier_id"])
	assert.NotContains(t, info.GetMetadata(), "limit",
		"предела нет — ключа быть не должно; ноль здесь означал бы названную величину")
}

// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ к отрицанию выше: без величин отказ остаётся отказом —
// код, признак и текст на месте, метаданных просто нет.
func TestQuotaRefusalWithoutDetailStaysAValidRefusal(t *testing.T) {
	const producer = "project prj-1 has reached its limit of 4 iam.project"
	err := fmt.Errorf("%w: %s", iamerr.ErrQuotaExceeded, producer)

	out := MapRepoErr(err)

	st, _ := status.FromError(out)
	assert.Equal(t, codes.ResourceExhausted, st.Code())
	assert.Equal(t, producer, st.Message())

	info := refusalMetadataInfo(t, out)
	assert.Equal(t, "QUOTA_EXCEEDED", info.GetReason())
	assert.Empty(t, info.GetMetadata(), "величин не было — выдумывать их нечем")
}

// Обёртка величин не должна ломать распознавание sentinel'а ни на одном пути.
func TestQuotaDetailKeepsTheSentinelRecognisable(t *testing.T) {
	err := quotadetail.Attach(
		fmt.Errorf("%w: project prj-1 has reached its limit of 4 iam.project",
			iamerr.ErrQuotaExceeded), quotaDetailExceeded)

	assert.True(t, errors.Is(err, iamerr.ErrQuotaExceeded))
}
