// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics_test

// build_info_test.go — витрина отвечает на первый вопрос дежурного: «какая
// версия у меня работает».
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТО НЕ КОСМЕТИКА
//
// Проверка готовности службы умеет отказать словами «образ не может обслужить
// эту схему». Отказ называет РАСХОЖДЕНИЕ и не даёт ни одной из двух
// сравниваемых величин: версии образа на витрине не было ни одной серией.
// Служба поставляется ОТДЕЛЬНО от платформы, где такие вопросы закрывает чужой
// инвентарь, — значит спросить больше некого.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ДВЕ МЕТКИ, А НЕ ОДНА, И ПОЧЕМУ ИМЕННО ЭТИ ИМЕНА
//
// `revision` и `version` — те же имена, под которыми величины уже стоят клеймом
// образа (`org.opencontainers.image.revision` / `.version`) и лежат файлом внутри
// него. Совпадение имён здесь несущее: оператор сверяет строку с витрины со
// строкой на образе БЕЗ пересчёта, а расхождение читается как расхождение, а не
// как разные способы назвать одно.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ «НЕ ПРОСТАВЛЕНО» — ОТДЕЛЬНОЕ ЗНАЧЕНИЕ, А НЕ ПУСТАЯ СТРОКА
//
// Пустая метка на витрине читается как «версии нет», а правдоподобное `dev`
// читается как имя ветки. Оба неотличимы от «сборка величину не проставила» —
// то есть от «не измеряли». Поэтому непроставленное называет себя словом, и
// тревога на него написуема.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
)

// TestBuildInfo_CarriesTheStampedRevisionAndVersion — величины со штампа сборки
// доезжают до витрины ОБЕИМИ метками, и ряд постоянный (значение 1).
func TestBuildInfo_CarriesTheStampedRevisionAndVersion(t *testing.T) {
	t.Parallel()
	reg := metrics.NewRegistry()
	reg.RegisterBuildInfo("release/kaname-tail", "e5ae2dedbb1234567890abcdef1234567890abcd")

	got := dumpMetrics(t, reg)
	const want = `kaname_build_info{revision="e5ae2dedbb1234567890abcdef1234567890abcd",version="release/kaname-tail"} 1`
	if !strings.Contains(got, want) {
		t.Fatalf("серии версии сборки нет на витрине.\nждали подстроку: %s\nполучено:\n%s", want, got)
	}
}

// TestBuildInfo_UnstampedSaysSoInsteadOfLookingLikeAVersion — законный близнец
// предыдущей пробы: сборка без штампа объявляет это СЛОВОМ.
//
// Без этой половины ряд зеленел бы на реализации, подставляющей правдоподобное
// умолчание, — и «версия dev» было бы неотличимо от «версию не проставили».
func TestBuildInfo_UnstampedSaysSoInsteadOfLookingLikeAVersion(t *testing.T) {
	t.Parallel()
	reg := metrics.NewRegistry()
	reg.RegisterBuildInfo("", "")

	got := dumpMetrics(t, reg)
	want := `kaname_build_info{revision="` + metrics.BuildInfoUnstamped +
		`",version="` + metrics.BuildInfoUnstamped + `"} 1`
	if !strings.Contains(got, want) {
		t.Fatalf("непроставленный штамп не называет себя.\nждали подстроку: %s\nполучено:\n%s", want, got)
	}
	if metrics.BuildInfoUnstamped == "" || metrics.BuildInfoUnstamped == "dev" {
		t.Fatalf("значение «не проставлено» равно %q — оно обязано быть отличимо "+
			"и от пустой метки, и от правдоподобного имени ветки",
			metrics.BuildInfoUnstamped)
	}
}
