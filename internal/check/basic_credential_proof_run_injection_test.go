// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// basic_credential_proof_run_injection_test.go — инъекция в обе стороны. Без
// второй стороны гейт мерил бы наличие СЛОВА: сырой файл содержит имя
// скрипта и в прозе, и в шапке шага, который его объясняет.
package check_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

func TestBasicCredentialProofDetectorSeesBothForms(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name     string
		yaml     string
		wantCall bool
	}{
		{
			name: "вызов в исполняемой части — молчит",
			yaml: "jobs:\n  g:\n    steps:\n      - name: проба формы\n" +
				"        run: python3 " + credentialFormRunProof + "\n",
			wantCall: true,
		},
		{
			name: "имя только в комментарии YAML — находка",
			yaml: "jobs:\n  g:\n    steps:\n" +
				"      # тут зовётся " + credentialFormRunProof + "\n" +
				"      - name: проба формы\n        run: echo ok\n",
			wantCall: false,
		},
		{
			name: "вызов закомментирован в оболочке, объяснение осталось — находка",
			yaml: "jobs:\n  g:\n    steps:\n      - name: проба формы\n" +
				"        run: |\n" +
				"          # python3 " + credentialFormRunProof + "\n" +
				"          echo ok\n",
			wantCall: false,
		},
		{
			name: "зовётся СОСЕДНИЙ скрипт того же каталога — находка",
			yaml: "jobs:\n  g:\n    steps:\n      - name: чужая проба\n" +
				"        run: python3 tests/newman/scripts/selftest_authz_allow_lanes.py\n",
			wantCall: false,
		},
		{
			name:     "шага `run:` нет вовсе — находка",
			yaml:     "jobs:\n  g:\n    steps:\n      - uses: actions/checkout@v7\n",
			wantCall: false,
		},
		{
			name: "вызов среди нескольких строк тела — молчит",
			yaml: "jobs:\n  g:\n    steps:\n      - name: пробы\n        run: |\n" +
				"          python3 tests/newman/scripts/selftest_authz_allow_lanes.py\n" +
				"          python3 " + credentialFormRunProof + "\n",
			wantCall: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bodies, _, err := check.ExecutableRunBodies(c.yaml)
			if err != nil {
				t.Fatalf("синтетика не разобралась: %v", err)
			}
			got := check.InvocationsOf(credentialFormRunProof, bodies) > 0
			if got != c.wantCall {
				t.Errorf("вызов распознан как %v, ожидалось %v", got, c.wantCall)
			}
		})
	}
}
