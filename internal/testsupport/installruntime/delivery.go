// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package installruntime

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// RIDDeliveryFixture содержит полные независимые тестовые модули. Он не
// требует установленной службы-потребителя. Оба объявления включают штатные
// входы каталога, ролей, SA, группы, выдачи и присоединения, поэтому предварительный снимок может
// обнаружить записи и вне таблицы делегирования.
type RIDDeliveryFixture struct {
	First  []byte
	Second []byte
}

func NewRIDDeliveryFixture() RIDDeliveryFixture {
	return RIDDeliveryFixture{First: ridModule("ridfirst"), Second: ridModule("ridsecond")}
}

func ridModule(module string) []byte {
	return []byte(fmt.Sprintf(`apiVersion: iam/v1
module: %[1]s
resources:
  - name: objects
    objectType: %[1]s_object
    parents: [project]
    producer: derived
    verbs:
      - {name: get, from: [super_admin]}
      - {name: list, from: [super_admin]}
roles:
  - id: %[1]s.reader
    description: Independent module reader fixture
    tier: {tierType: iam.cluster, tierId: cluster_root}
    rules:
      - module: %[1]s
        resources: [objects]
        classes: [get, list]
seed:
  serviceAccounts:
    - {account: system, name: svc-%[1]s, description: Independent installation issuer}
  groups:
    - {account: system, name: %[1]s-readers, description: Independent installation readers}
  accessBindings:
    - subjects: [{type: group, name: %[1]s-readers}]
      roleId: %[1]s.reader
      scopeType: iam.cluster
      scopeId: cluster_root
      target: allInScope
  joins:
    - serviceAccount: {account: system, name: svc-%[1]s}
      group: {account: system, name: module-relation-writers}
      why: Fixture uses the existing module registration mechanism
  grantDelegations:
    - delegate: {account: system, name: svc-%[1]s}
      roleIds: [%[1]s.reader]
      targetTypes: [%[1]s.objects]
      subjectTypes: [SUBJECT_TYPE_SERVICE_ACCOUNT]
`, module))
}

// Write создаёт новую полную поставку; порядок закодирован именами файлов в соответствии
// с производственным чтением каталога. Возвращённые хеши обозначают точные входы.
func (d RIDDeliveryFixture) Write(dir string, reversed bool) ([]string, error) {
	if err := os.Mkdir(dir, 0700); err != nil {
		return nil, err
	}
	inputs := [][]byte{d.First}
	// S1 может поставить один полный модуль. Вызывающие M1/M2 по-прежнему передают оба.
	if len(d.Second) > 0 {
		inputs = append(inputs, d.Second)
	}
	if reversed && len(inputs) == 2 {
		inputs[0], inputs[1] = inputs[1], inputs[0]
	}
	var hashes []string
	for i, input := range inputs {
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("%02d.yaml", i)), input, 0600); err != nil {
			return nil, err
		}
		h := sha256.Sum256(input)
		hashes = append(hashes, hex.EncodeToString(h[:]))
	}
	return hashes, nil
}

// BoundaryDelivery всегда объявляет ВСЕ 17 допустимых собственных ролей и типов. Изменение
// осей делегирования поэтому изолирует границу 16/17 от внешних связей.
func BoundaryDelivery(roles, types int) ([]byte, error) {
	if roles < 0 || roles > 17 || types < 0 || types > 17 {
		return nil, fmt.Errorf("boundary fixture accepts axis counts 0..17")
	}
	var b strings.Builder
	b.WriteString("apiVersion: iam/v1\nmodule: ridbounds\nresources:\n")
	var names, ids, targets []string
	for i := 0; i < 17; i++ {
		name := fmt.Sprintf("objects%02d", i)
		names = append(names, name)
		ids = append(ids, fmt.Sprintf("ridbounds.reader%02d", i))
		targets = append(targets, "ridbounds."+name)
		fmt.Fprintf(&b, "  - name: %s\n    objectType: ridbounds_object%02d\n    parents: [project]\n    producer: derived\n    verbs:\n      - {name: get, from: [super_admin]}\n      - {name: list, from: [super_admin]}\n", name, i)
	}
	b.WriteString("roles:\n")
	for _, id := range ids {
		fmt.Fprintf(&b, "  - id: %s\n    description: Independent boundary reader fixture\n    tier: {tierType: iam.cluster, tierId: cluster_root}\n    rules:\n", id)
		// Независимая доменная граница — 16 ресурсов на правило роли. Сохраняем
		// покрытие всех 17 типов каталога двумя допустимыми правилами, чтобы только мощность
		// оси GD различалась у принятого и отклонённого близнецов.
		for _, resources := range [][]string{names[:16], names[16:]} {
			fmt.Fprintf(&b, "      - module: ridbounds\n        resources: [%s]\n        classes: [get, list]\n", strings.Join(resources, ", "))
		}
	}
	fmt.Fprintf(&b, `seed:
  serviceAccounts:
    - {account: system, name: svc-ridbounds, description: Boundary installation issuer}
  grantDelegations:
    - delegate: {account: system, name: svc-ridbounds}
      roleIds: [%s]
      targetTypes: [%s]
      subjectTypes: [SUBJECT_TYPE_USER, SUBJECT_TYPE_SERVICE_ACCOUNT, SUBJECT_TYPE_GROUP, SUBJECT_TYPE_SYSTEM_CLASS]
`, strings.Join(ids[:roles], ", "), strings.Join(targets[:types], ", "))
	return []byte(b.String()), nil
}

// ChangeAxis меняет одно поле объявления, сохраняя весь другой разобранный вход.
// Неизвестные/пустые/повторные формы используют ту же полную поставку, что и их близнец.
func ChangeAxis(input []byte, field string, value any) ([]byte, error) {
	var doc map[string]any
	if err := yaml.Unmarshal(input, &doc); err != nil {
		return nil, err
	}
	seed, ok := doc["seed"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("fixture seed missing")
	}
	entries, ok := seed["grantDelegations"].([]any)
	if !ok || len(entries) != 1 {
		return nil, fmt.Errorf("fixture requires one declaration")
	}
	entry, ok := entries[0].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("fixture declaration missing")
	}
	entry[field] = value
	return yaml.Marshal(doc)
}
