// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// secret_bearing_ledger_injection_test.go — ДОКАЗАТЕЛЬСТВО, ЧТО ГЕЙТ BAT-1-73
// СПОСОБЕН УПАСТЬ, И ЧТО ОН МОЛЧИТ НА ЗАКОННОМ БЛИЗНЕЦЕ.
//
// Гейт, не проверенный инъекцией, ловит форму, а не существо: он одинаково
// зелен на исправном дереве и на дереве, где сняли пометку. Здесь предикат
// гейта вынесен в чистую функцию и прогоняется на СИНТЕТИЧЕСКОМ входе — обе
// стороны по каждой оси.

package main

import "testing"

// ledgerFindings — тот же предикат, что исполняет гейт: помеченное поле
// сообщения, НАЗВАННОГО ответом операции, обязано стоять в перечне.
func ledgerFindings(
	marked map[string][]string,
	responses map[string]struct{},
	ledger map[string]map[string]struct{},
) (findings []string, checked int) {
	for msg, fields := range marked {
		if _, isResponse := responses[msg]; !isResponse {
			continue
		}
		for _, f := range fields {
			checked++
			if _, ok := ledger[msg][f]; !ok {
				findings = append(findings, msg+"."+f)
			}
		}
	}
	return findings, checked
}

func TestBAT1_73_InjectionProvesTheGateCanFailAndCanStaySilent(t *testing.T) {
	const respMsg = "kacho.cloud.iam.v1.IssueUserTokenResponse"
	const syncMsg = "kacho.cloud.iam.v1.MintBootstrapTokenResponse"

	responses := map[string]struct{}{respMsg: {}}

	t.Run("дефект возвращён — гейт КРАСНЕЕТ и называет координату", func(t *testing.T) {
		findings, checked := ledgerFindings(
			map[string][]string{respMsg: {"secret"}},
			responses,
			map[string]map[string]struct{}{respMsg: {"private_key_pem": {}}}, // «secret» не внесён
		)
		if checked == 0 {
			t.Fatal("предикат отработал на пустом множестве — краснеть было не на чем")
		}
		if len(findings) != 1 || findings[0] != respMsg+".secret" {
			t.Fatalf("находки = %v, ожидалась ровно одна с координатой %s.secret", findings, respMsg)
		}
	})

	t.Run("законный близнец — гейт МОЛЧИТ (поле внесено)", func(t *testing.T) {
		findings, checked := ledgerFindings(
			map[string][]string{respMsg: {"secret"}},
			responses,
			map[string]map[string]struct{}{respMsg: {"private_key_pem": {}, "secret": {}}},
		)
		if checked != 1 {
			t.Fatalf("осмотрено %d полей, ожидалось 1", checked)
		}
		if len(findings) != 0 {
			t.Fatalf("гейт покраснел на исправном дереве: %v", findings)
		}
	})

	t.Run("СУЖЕНИЕ: синхронный ответ в перечне стоять не обязан", func(t *testing.T) {
		// Второй законный близнец, и он несущий: без сужения гейт требовал бы
		// вносить в перечень то, чего подметальщик увидеть не может, — и был бы
		// снят первым же ложным срабатом. В дереве такой случай реален:
		// ответ чеканки бутстрап-токена несёт предъявительский секрет и ответом
		// операции НЕ является.
		findings, checked := ledgerFindings(
			map[string][]string{syncMsg: {"access_token"}},
			responses, // syncMsg сюда не входит
			map[string]map[string]struct{}{},
		)
		if checked != 0 {
			t.Fatalf("синхронный ответ попал под проверку (%d полей) — сужение не работает", checked)
		}
		if len(findings) != 0 {
			t.Fatalf("гейт покраснел на синхронном ответе: %v", findings)
		}
	})

	t.Run("СНЯТАЯ ПОМЕТКА обнуляет ось — и это ловит перепись, а не находки", func(t *testing.T) {
		// Пометку сняли: находок ноль, но и ОСМОТРЕНО ноль. Именно поэтому гейт
		// печатает перепись и падает на пустом пересечении: «ноль находок» из
		// пустого множества неотличимо от «ноль находок» из проверенного.
		findings, checked := ledgerFindings(
			map[string][]string{}, // пометок нет вовсе
			responses,
			map[string]map[string]struct{}{respMsg: {"private_key_pem": {}}},
		)
		if len(findings) != 0 {
			t.Fatalf("находки на пустом входе: %v", findings)
		}
		if checked != 0 {
			t.Fatalf("осмотрено %d при снятой пометке", checked)
		}
		// Сам гейт на таком дереве обязан ПАДАТЬ по переписи — это проверено
		// его собственной ветвью `checked == 0`.
	})
}
