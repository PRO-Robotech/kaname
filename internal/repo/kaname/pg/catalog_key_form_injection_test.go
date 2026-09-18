// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// catalog_key_form_injection_test.go — ДОКАЗАТЕЛЬСТВО способности гейта формы
// ключей упасть, инъекцией настоящим сервером и с законным близнецом.
//
// Синтетический DDL исполняет сервер на пустой базе, схема читается тем же
// `readLiveSchema`, что у гейта, и судится тем же `auditLiveKeyForm`. Снятие
// ключа — явное или неявное — поэтому решает сервер, а не распознаватель пробы.
//
// Осей по ведомости ТРИ, и все обязательны: прощённый ключ молчит · непрощённый
// той же формы краснеет · запись, которой нечего исключать, краснеет сама — и
// последняя проверяется в обеих формах снятия: неявной (`DROP COLUMN`, класс
// kaname#278) и сменой формы ключа.

import (
	"strings"
	"testing"
)

// keyFormSchema — цикл двух ключей формы `RESTRICT … DEFERRABLE` (как у
// `accounts_owner_fk`/`users_account_fk`) и ключ проекции, объявленный
// немедленным.
var keyFormSchema = []string{
	`CREATE TABLE owners (id text PRIMARY KEY, member_id text)`,
	`CREATE TABLE members (id text PRIMARY KEY, owner_id text, ref_id text)`,
	`ALTER TABLE members ADD CONSTRAINT members_owner_fk FOREIGN KEY (owner_id)
	   REFERENCES owners(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED`,
	`ALTER TABLE owners ADD CONSTRAINT owners_member_fk FOREIGN KEY (member_id)
	   REFERENCES members(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED`,
	`ALTER TABLE members ADD CONSTRAINT members_ref_fk FOREIGN KEY (ref_id)
	   REFERENCES owners(id) ON DELETE NO ACTION DEFERRABLE INITIALLY IMMEDIATE`,
}

var (
	keyFormImmediate = []keyRef{{"public.members", "members_ref_fk"}}
	keyFormExempt    = []keyRef{{"public.members", "members_owner_fk"}, {"public.owners", "owners_member_fk"}}
)

func keyFormAfter(extra ...string) []string {
	return append(append([]string{}, keyFormSchema...), extra...)
}

// requireFindings — находок ровно столько, и каждая названа своим ключом.
func requireFindings(t *testing.T, findings []string, want ...string) {
	t.Helper()
	if len(findings) != len(want) {
		t.Fatalf("находок ждали %d (%v), получено %d:\n  %s", len(want), want, len(findings),
			strings.Join(findings, "\n  "))
	}
	for i, sub := range want {
		if !strings.Contains(findings[i], sub) {
			t.Fatalf("находка %d обязана содержать %q:\n  %s", i, sub, strings.Join(findings, "\n  "))
		}
	}
}

func TestIAMCT113_Injection_LiveSchema(t *testing.T) {
	t.Run("контроль: прощённый цикл и немедленный ключ — молчание", func(t *testing.T) {
		s := liveSchemaAfter(t, keyFormSchema...)
		census, findings := auditLiveKeyForm(s, keyFormImmediate, keyFormExempt)
		t.Logf("перепись: %s · %s", s.census(), census)
		if got := len(s.foreignKeys()); got != 3 {
			t.Fatalf("внешних ключей обязано быть прочитано 3, прочитано %d", got)
		}
		requireFindings(t, findings)
	})

	t.Run("инъекция: исключение, чей ключ НЕЯВНО унёс DROP COLUMN, — «снимите запись» (kaname#278)", func(t *testing.T) {
		s := liveSchemaAfter(t, keyFormAfter(`ALTER TABLE owners DROP COLUMN member_id`)...)
		_, findings := auditLiveKeyForm(s, keyFormImmediate, keyFormExempt)
		requireFindings(t, findings, "owners_member_fk на public.owners, а в действующей схеме такого ключа нет")
		if !strings.Contains(findings[0], "снимите запись") {
			t.Errorf("находка обязана назвать исход: %q", findings[0])
		}
	})

	t.Run("законный близнец: то же снятие ЯВНО и вместе с записью — молчание", func(t *testing.T) {
		s := liveSchemaAfter(t, keyFormAfter(
			`ALTER TABLE owners DROP CONSTRAINT owners_member_fk`,
			`ALTER TABLE owners DROP COLUMN member_id`)...)
		_, findings := auditLiveKeyForm(s, keyFormImmediate, []keyRef{{"public.members", "members_owner_fk"}})
		requireFindings(t, findings)
	})

	// МАСКА-2 (check-verifier ⛔): по-именное прощение открывало бы слепую зону
	// одноимённому ключу на ЛЮБОЙ другой таблице. Здесь `owners_member_fk` живёт
	// и на своей прощённой таблице (молчит), и на чужой (обязан быть находкой).
	// На по-именной ведомости оба прощались бы — 0 находок; на по-парной чужой
	// краснеет, свой прощён.
	t.Run("инъекция МАСКА-2: тот же ключ на ЧУЖОЙ таблице не прощается по имени", func(t *testing.T) {
		s := liveSchemaAfter(t, keyFormAfter(
			`CREATE TABLE zz_probe_holders (id text PRIMARY KEY, owner_id text)`,
			`ALTER TABLE zz_probe_holders ADD CONSTRAINT owners_member_fk FOREIGN KEY (owner_id)
			   REFERENCES owners(id) ON DELETE RESTRICT DEFERRABLE INITIALLY DEFERRED`)...)
		_, findings := auditLiveKeyForm(s, keyFormImmediate, keyFormExempt)
		requireFindings(t, findings,
			"ключ owners_member_fk на public.zz_probe_holders несёт RESTRICT рядом с DEFERRABLE")
	})

	t.Run("инъекция: исключение, чей ключ сменил форму, — «снимите запись»", func(t *testing.T) {
		s := liveSchemaAfter(t, keyFormAfter(
			`ALTER TABLE owners DROP CONSTRAINT owners_member_fk`,
			`ALTER TABLE owners ADD CONSTRAINT owners_member_fk FOREIGN KEY (member_id)
			   REFERENCES members(id) ON DELETE NO ACTION DEFERRABLE INITIALLY DEFERRED`)...)
		_, findings := auditLiveKeyForm(s, keyFormImmediate, keyFormExempt)
		requireFindings(t, findings, "owners_member_fk на public.owners, а ключ этой формы больше не несёт")
	})

	t.Run("инъекция: та же форма у НЕпрощённого ключа — находка", func(t *testing.T) {
		s := liveSchemaAfter(t, keyFormSchema...)
		_, findings := auditLiveKeyForm(s, keyFormImmediate, []keyRef{{"public.members", "members_owner_fk"}})
		requireFindings(t, findings, "ключ owners_member_fk на public.owners несёт RESTRICT рядом с DEFERRABLE")
	})

	t.Run("инъекция: RESTRICT при ИЗМЕНЕНИИ рядом с DEFERRABLE — вторая форма той же находки", func(t *testing.T) {
		s := liveSchemaAfter(t, keyFormAfter(
			`ALTER TABLE members ADD COLUMN peer_id text`,
			`ALTER TABLE members ADD CONSTRAINT members_peer_fk FOREIGN KEY (peer_id)
			   REFERENCES owners(id) ON UPDATE RESTRICT DEFERRABLE`)...)
		_, findings := auditLiveKeyForm(s, keyFormImmediate, keyFormExempt)
		requireFindings(t, findings, "ключ members_peer_fk на public.members несёт RESTRICT рядом с DEFERRABLE")
	})

	t.Run("законный близнец формы: RESTRICT без DEFERRABLE — молчание", func(t *testing.T) {
		s := liveSchemaAfter(t, keyFormAfter(
			`ALTER TABLE members ADD COLUMN peer_id text`,
			`ALTER TABLE members ADD CONSTRAINT members_peer_fk FOREIGN KEY (peer_id)
			   REFERENCES owners(id) ON DELETE RESTRICT NOT DEFERRABLE`)...)
		_, findings := auditLiveKeyForm(s, keyFormImmediate, keyFormExempt)
		requireFindings(t, findings)
	})

	t.Run("инъекция: немедленный ключ объявлен INITIALLY DEFERRED", func(t *testing.T) {
		s := liveSchemaAfter(t, keyFormAfter(
			`ALTER TABLE members ALTER CONSTRAINT members_ref_fk DEFERRABLE INITIALLY DEFERRED`)...)
		_, findings := auditLiveKeyForm(s, keyFormImmediate, keyFormExempt)
		requireFindings(t, findings, "ключ members_ref_fk на public.members объявлен INITIALLY DEFERRED")
	})

	t.Run("инъекция: немедленный ключ неявно унесён DROP COLUMN", func(t *testing.T) {
		s := liveSchemaAfter(t, keyFormAfter(`ALTER TABLE members DROP COLUMN ref_id`)...)
		_, findings := auditLiveKeyForm(s, keyFormImmediate, keyFormExempt)
		requireFindings(t, findings, "ключ members_ref_fk на public.members в действующей схеме не существует")
	})
}
