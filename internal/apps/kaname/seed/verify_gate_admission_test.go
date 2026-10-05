// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed

// verify_gate_admission_test.go — отказ ДОПУСКА субъекта не есть потеря
// материализации (задача #610).
//
// # Предмет
//
// Страж спрашивает дверь решения, разрешается ли материализованное чтение. Дверь
// сначала судит допуск субъекта (#456, Р4а) и человеку с неподтверждённым
// адресом отвечает «нет», не вычисляя отношения. Страж засчитывал такой ответ
// находкой «materialized read tuple does not resolve», и на стенде, где не
// подтверждён ни один человек, каждый старт печатал 52 WARN о потере, которой
// нет: отношения совпадали все.
//
// Проба строит дублёр двери, отвечающий ТАК ЖЕ, как настоящая дверь: Check
// неподтверждённому субъекту — «нет» при любом отношении. Без вопроса о допуске
// страж различить причины не может, и это ровно то, что проба утверждает.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/admission"
)

// doorLikeChecker — дублёр двери решения: допуск судится ПЕРЕД отношением, как
// в `authzcascade.Client.CheckWithContext`. Неподтверждённому субъекту Check
// отвечает «нет», даже когда отношение материализовано.
type doorLikeChecker struct {
	unadmitted map[string]bool // субъект → адрес не подтверждён
	resolves   map[string]bool // объект → отношение материализовано и разрешается
	admitErr   error
	checks     int
	admits     int
}

func (c *doorLikeChecker) SubjectAdmitted(_ context.Context, subject string) (bool, error) {
	c.admits++
	if c.admitErr != nil {
		return false, c.admitErr
	}
	return !c.unadmitted[subject], nil
}

func (c *doorLikeChecker) Check(_ context.Context, subject, _ string, object string) (bool, error) {
	c.checks++
	if c.unadmitted[subject] {
		return false, nil
	}
	return c.resolves[object], nil
}

// warnLines — записи уровня WARN и выше.
func warnLines(recs []map[string]any) []map[string]any {
	var out []map[string]any
	for _, r := range recs {
		if lvl, _ := r["level"].(string); lvl == "WARN" || lvl == "ERROR" {
			out = append(out, r)
		}
	}
	return out
}

// TestVerifyGateAdmissionRefusalIsNotAccessLoss — субъект с неподтверждённым
// адресом и материализованными отношениями: 0 находок «не разрешается», 1 отказ
// допуска с причиной, ни одной записи WARN.
func TestVerifyGateAdmissionRefusalIsNotAccessLoss(t *testing.T) {
	store := relCheckStore{checks: []BindingRelationCheck{
		{BindingID: "acb_unv", Subject: "user:usr_unverified", Relation: "v_get", Object: "iam_user:usr_x"},
	}}
	chk := &doorLikeChecker{
		unadmitted: map[string]bool{"user:usr_unverified": true},
		resolves:   map[string]bool{"iam_user:usr_x": true},
	}

	logger, buf := captureLogger()
	gate := NewVerifyGate(panicEngine{}, store, logger).WithRelationChecker(chk)
	report, err := gate.VerifyRelationSatisfiesAction(context.Background())
	require.NoError(t, err)

	assert.True(t, report.NoAccessLoss,
		"отказ допуска — не потеря материализации: отношение материализовано и разрешилось бы")
	assert.Empty(t, report.Failures, "находок «не разрешается» быть не должно")
	require.Len(t, report.Refusals, 1, "отказ допуска называется отдельной причиной")
	assert.Equal(t, admission.DenyReason, report.Refusals[0].Reason)
	assert.Equal(t, "user:usr_unverified", report.Refusals[0].Subject)
	assert.Equal(t, 1, report.ByReason()[admission.DenyReason])
	assert.Equal(t, 0, report.ByReason()[ReasonRelationUnresolved])

	recs := logLines(t, buf)
	assert.Empty(t, warnLines(recs), "отказ допуска не пишется WARN: %s", buf.String())
	// Сводка называет счёт по КАЖДОЙ причине, включая ноль.
	var summary map[string]any
	for _, r := range recs {
		if _, ok := r[admission.DenyReason]; ok {
			summary = r
		}
	}
	require.NotNil(t, summary, "сводка не называет счёт отказов допуска: %s", buf.String())
	assert.EqualValues(t, 1, summary[admission.DenyReason])
	assert.EqualValues(t, 0, summary[ReasonRelationUnresolved])
	assert.Equal(t, 0, chk.checks, "неподтверждённому субъекту отношение не спрашивается: ответ двери известен")
}

// TestVerifyGateLostRelationOfAdmittedSubjectStillFound — законный близнец:
// потерянное отношение у ПОДТВЕРЖДЁННОГО субъекта по-прежнему находка, и сводка
// называет обе причины своим счётом.
func TestVerifyGateLostRelationOfAdmittedSubjectStillFound(t *testing.T) {
	store := relCheckStore{checks: []BindingRelationCheck{
		{BindingID: "acb_lost", Subject: "user:usr_verified", Relation: "v_get", Object: "iam_role:rol_lost"},
		{BindingID: "acb_unv", Subject: "user:usr_unverified", Relation: "v_get", Object: "iam_user:usr_x"},
		{BindingID: "acb_unv2", Subject: "user:usr_unverified", Relation: "v_list", Object: "iam_user:usr_y"},
	}}
	chk := &doorLikeChecker{
		unadmitted: map[string]bool{"user:usr_unverified": true},
		resolves:   map[string]bool{"iam_user:usr_x": true, "iam_user:usr_y": true},
	}

	logger, buf := captureLogger()
	gate := NewVerifyGate(panicEngine{}, store, logger).WithRelationChecker(chk)
	report, err := gate.VerifyRelationSatisfiesAction(context.Background())
	require.NoError(t, err)

	assert.False(t, report.NoAccessLoss, "потеря у подтверждённого субъекта — находка")
	require.Len(t, report.Failures, 1)
	assert.Equal(t, "user:usr_verified", report.Failures[0].Subject)
	assert.Len(t, report.Refusals, 2)
	assert.Equal(t, map[string]int{ReasonRelationUnresolved: 1, admission.DenyReason: 2}, report.ByReason())
	assert.Equal(t, 2, chk.admits, "допуск спрашивается один раз на субъекта, а не на каждую тройку")

	var warnSummary map[string]any
	for _, r := range warnLines(logLines(t, buf)) {
		if _, ok := r[ReasonRelationUnresolved]; ok {
			warnSummary = r
		}
	}
	require.NotNil(t, warnSummary, "сводка находок не называет счёт по причинам: %s", buf.String())
	assert.EqualValues(t, 1, warnSummary[ReasonRelationUnresolved])
	assert.EqualValues(t, 2, warnSummary[admission.DenyReason])
}

// TestVerifyGateAdmissionUnansweredIsAnError — третий исход: «спросить не
// смогли» не сливается ни с допуском, ни с отказом.
func TestVerifyGateAdmissionUnansweredIsAnError(t *testing.T) {
	store := relCheckStore{checks: []BindingRelationCheck{
		{BindingID: "acb_1", Subject: "user:usr_a", Relation: "v_get", Object: "iam_user:usr_x"},
	}}
	chk := &doorLikeChecker{admitErr: errors.New("отметки не прочитаны")}

	gate := NewVerifyGate(panicEngine{}, store, nil).WithRelationChecker(chk)
	_, err := gate.VerifyRelationSatisfiesAction(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "user:usr_a")
	assert.Equal(t, 0, chk.checks)
}
