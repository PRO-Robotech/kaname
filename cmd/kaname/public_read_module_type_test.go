// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// public_read_module_type_test.go — провязка перечня термов ключа в корне старта
// (задача PRO-Robotech/kaname#866; приёмка
// docs/engineering/acceptance/public-read-container-of-a-module-type-is-admitted.md,
// отпечаток a129f53c4c46525b390d5f71bda31866e43e0776c6c556326806ce313836babf,
// PM-01, PM-07, PM-10).
//
// Поля находок утверждает пакет `internal/modelcompose`; здесь утверждается то,
// чего там утверждать нельзя: что `installComposedModel` передаёт допуску перечень
// ТОЙ ЖЕ композиции. Без перечня PM-01 отвергался бы, с перечнем, набранным
// не из композиции, — пропускал бы лишнее.
//
// Успешный пуск ставит модель процесса, а установка в процессе одна (шапка
// model_compose_test.go), поэтому PM-01 исполняется в своём процессе; отказы до
// установки не доходят и идут в общем.

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

// pmStartManifests — доставка одного манифеста `probemod` путём старта.
func pmStartManifests(t *testing.T, doc []byte) []*manifest.Manifest {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "probemod")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("фикстура: каталог доставки: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.yaml"), doc, 0o600); err != nil {
		t.Fatalf("фикстура: манифест доставки: %v", err)
	}
	rep, err := manifest.LoadDelivered(root)
	if err != nil {
		t.Fatalf("условие не создано: доставка П1 отвергнута загрузкой: %v", err)
	}
	return rep.Manifests
}

// pmStartFixture — П1 с заменой ровно одного вхождения (пустая замена — П1 как есть).
func pmStartFixture(t *testing.T, old, repl string) []byte {
	t.Helper()
	doc, err := publicreadfixture.Read(publicreadfixture.ProbemodFile)
	if err != nil {
		t.Fatalf("фикстура П1: %v", err)
	}
	if old == "" {
		return doc
	}
	if n := strings.Count(string(doc), old); n != 1 {
		t.Fatalf("фикстура: %q встречается %d раз, нужна одна замена", old, n)
	}
	return []byte(strings.Replace(string(doc), old, repl, 1))
}

// TestPM_StartChainAdmitsAModuleContainerWithTheKey — PM-01 путём старта: модель
// поставлена, и её тип-контейнер несёт `public_reader`.
func TestPM_StartChainAdmitsAModuleContainerWithTheKey(t *testing.T) {
	if os.Getenv(modelComposeChildEnv) != "1" {
		runInOwnProcess(t, "TestPM_StartChainAdmitsAModuleContainerWithTheKey")
		return
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	if _, err := installComposedModel(logger, pmStartManifests(t, pmStartFixture(t, "", ""))); err != nil {
		t.Fatalf("PM-01: модуль с типом вне канона и ключом обязан стартовать, отказ: %v", err)
	}
	plans, err := authzmodel.Shared()
	if err != nil {
		t.Fatalf("модель процесса не отдалась после установки: %v", err)
	}
	if _, err := plans.Plan("probemod_box", "public_reader"); err != nil {
		t.Fatalf("поставленная модель обязана объявлять probemod_box.public_reader: %v", err)
	}
	if _, err := plans.Plan("probemod_item", "v_get"); err != nil {
		t.Fatalf("поставленная модель обязана объявлять probemod_item.v_get: %v", err)
	}
}

// TestPM_StartChainRefusesWhatTheKeyDoesNotCover — PM-07 и PM-10 путём старта:
// отказ пуска допуском, строка отказа называет правило и объявление-семя.
func TestPM_StartChainRefusesWhatTheKeyDoesNotCover(t *testing.T) {
	const items = "    verbs: [get, list, update, delete]"
	cases := []struct{ name, repl, seed string }{
		{"PM-07", "    verbs: [get, list, {name: update, from: [super_admin, v_get]}, delete]", "probemod_item.v_update"},
		{"PM-10", "    verbs: [{name: get, subjects: [system_class, user, service_account, 'group#member']}, list, update, delete]", "probemod_item.v_get"},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := installComposedModel(logger, pmStartManifests(t, pmStartFixture(t, items, c.repl)))
			if err == nil {
				t.Fatalf("%s: пуск обязан быть отвергнут", c.name)
			}
			msg := err.Error()
			if !strings.Contains(msg, "допуск собранной модели прав отверг её") {
				t.Fatalf("%s: отказ обязан прийти от допуска: %v", c.name, err)
			}
			if !strings.Contains(msg, "Д3:") || !strings.Contains(msg, c.seed) {
				t.Fatalf("%s: строка отказа пуска обязана содержать «Д3:» и %s: %v", c.name, c.seed, err)
			}
			// Семя находки — начало её текста: «<семя>: подстановочная запись…»
			// либо «подстановка достижима: <семя> → …».
			if strings.Contains(msg, "Д3: probemod_box.") || strings.Contains(msg, "достижима: probemod_box.") {
				t.Fatalf("%s: термы контейнера законны, находок о probemod_box быть не должно: %v", c.name, err)
			}
		})
	}
}
