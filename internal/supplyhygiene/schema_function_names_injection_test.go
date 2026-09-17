// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// schema_function_names_injection_test.go — доказательство того, что судья
// имён функций схемы СПОСОБЕН упасть и МОЛЧИТ на законных близнецах.
//
// Каждая инъекция меняет РОВНО ОДИН факт против контроля: иначе красное могло
// бы прийти от соседа, а судья остаться вакуумным, не показав этого ничем.
// Живой перечень имён здесь не читается намеренно — он у держателя в
// `internal/migrations`; сюда подаётся синтетика, и судья тот же самый.
package supplyhygiene

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// soundSchemaFunctions — законный близнец: собственные имена без приставки
// платформы и две функции, отрисованные шаблоном фундамента, названные
// ведомостью.
var soundSchemaFunctions = []string{
	"labels_valid", "quota_count", "quota_carrier_lifecycle", "rate_refuse",
	"admission_rate_count", "kacho_quota_refuse", "kacho_quota_admit",
	"limits_scope_ref_exists", "resource_journal_emit",
}

var soundSchemaStays = []SchemaFunctionStay{
	{Name: "kacho_quota_refuse", Why: "шаблон фундамента, один на шесть владельцев"},
	{Name: "kacho_quota_admit", Why: "шаблон фундамента, один на шесть владельцев"},
}

func TestSchemaFunctionNamesControl_SoundSchemaIsSilent(t *testing.T) {
	census, findings := JudgeSchemaFunctionNames(soundSchemaFunctions, soundSchemaStays)
	require.Empty(t, findings, "законная схема объявлена нарушением: судья ловит форму, а не существо")
	require.Equal(t, SchemaFunctionCensus{Functions: 9, Branded: 2, Stayed: 2}, census,
		"перепись контроля обязана назвать и прочитанное, и прощённое")
}

func TestSchemaFunctionNamesInjection_BrandedFunctionOutsideTheLedgerIsNamed(t *testing.T) {
	names := append(append([]string(nil), soundSchemaFunctions...), "kacho_probe_count")
	_, findings := JudgeSchemaFunctionNames(names, soundSchemaStays)
	require.Len(t, findings, 1, "ровно один внесённый дефект — ровно одна находка")
	require.Contains(t, findings[0], `"kacho_probe_count"`, "находка обязана назвать функцию по имени")
}

func TestSchemaFunctionNamesInjection_DiacriticFormIsNotBlindSpot(t *testing.T) {
	names := append(append([]string(nil), soundSchemaFunctions...), "kachō_probe_count")
	_, findings := JudgeSchemaFunctionNames(names, soundSchemaStays)
	require.Len(t, findings, 1, "диакритическая форма имени — не слепая зона: ASCII-предикат объявил бы её чистой")
	require.Contains(t, findings[0], `"kachō_probe_count"`)
}

func TestSchemaFunctionNamesInjection_LedgerEntryWithoutAFunctionExpires(t *testing.T) {
	stays := append(append([]SchemaFunctionStay(nil), soundSchemaStays...),
		SchemaFunctionStay{Name: "kacho_no_such_function", Why: "довод есть, предмета нет"})
	_, findings := JudgeSchemaFunctionNames(soundSchemaFunctions, stays)
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], "послабление без предмета")
	require.Contains(t, findings[0], `"kacho_no_such_function"`)
}

func TestSchemaFunctionNamesInjection_LedgerEntryWithoutBrandExpires(t *testing.T) {
	stays := append(append([]SchemaFunctionStay(nil), soundSchemaStays...),
		SchemaFunctionStay{Name: "labels_valid", Why: "запись о функции, которой прощать нечего"})
	_, findings := JudgeSchemaFunctionNames(soundSchemaFunctions, stays)
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], "прощать нечего")
}

func TestSchemaFunctionNamesInjection_LedgerEntryWithoutAReasonIsNamed(t *testing.T) {
	stays := []SchemaFunctionStay{
		{Name: "kacho_quota_refuse", Why: "шаблон фундамента"},
		{Name: "kacho_quota_admit"},
	}
	_, findings := JudgeSchemaFunctionNames(soundSchemaFunctions, stays)
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], "без довода")
}

func TestSchemaFunctionNamesInjection_EmptyCensusIsARefusal(t *testing.T) {
	census, findings := JudgeSchemaFunctionNames(nil, soundSchemaStays)
	require.Len(t, findings, 1, "пустой обход — отказ, а не чистая схема")
	require.Contains(t, findings[0], "обход пуст")
	require.Zero(t, census.Functions)
}
