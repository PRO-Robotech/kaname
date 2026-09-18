// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// constraint_liveness_injection_test.go — доказательство, что гейт живости
// ограничений СПОСОБЕН упасть и способен смолчать.
//
// Вход подаётся СИНТЕТИЧЕСКИЙ, а не находкой из дерева: проба, опирающаяся на
// живой дефект, исчезает вместе с ним — то есть ровно тогда, когда дерево
// починено, и удостоверять ей становится нечего.
//
// Синтетический DDL исполняет НАСТОЯЩИЙ сервер на пустой базе, а схема читается
// тем же `readLiveSchema`, что у гейта. Поэтому снятие — явное или неявное —
// решает сервер: проба не может «согласиться» с распознавателем, повторив его
// ошибку своим текстом.
//
// Оси проверяются ПО ОДНОЙ (каждая инъекция роняет ровно своё): неявное снятие
// `DROP COLUMN` (класс kaname#278) · снос таблицы · снятие по имени · переименование
// индекса · триггер, унесённый `CASCADE`, при оставшейся функции · неуникальный
// индекс · имя, которого не заводили · имя в комментарии функции · не-триггерная
// функция (предпосылка) · законные близнецы (живое имя и явно снятое вместе с
// ветвью — молчание). Отдельно — обе формы записи ветви в разборе Go.

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// widgetsSchema — схема, где каждое имя производится своей формой: ключ,
// уникальный индекс, CHECK, первичный ключ, имя, поднимаемое триггерной
// функцией, и неуникальный индекс, который отказа не производит.
var widgetsSchema = []string{
	`CREATE TABLE owners (id text PRIMARY KEY)`,
	`CREATE TABLE widgets (id text PRIMARY KEY, owner_id text, name text, tag text)`,
	`ALTER TABLE widgets ADD CONSTRAINT widgets_owner_fk FOREIGN KEY (owner_id) REFERENCES owners(id)`,
	`CREATE UNIQUE INDEX widgets_owner_name_uniq ON widgets (owner_id, name)`,
	`CREATE INDEX widgets_tag_idx ON widgets (tag)`,
	`ALTER TABLE widgets ADD CONSTRAINT widgets_name_check CHECK (name <> '')`,
	`CREATE FUNCTION widgets_guard() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  -- здесь стояло CONSTRAINT = 'widgets_ghost_raise'; имя в объяснении не поднимается никем
  IF NEW.tag = 'bad' THEN
    RAISE EXCEPTION 'bad -- tag' USING ERRCODE = '23503', CONSTRAINT = 'widgets_guard_raise';
  END IF;
  RETURN NEW;
END $$`,
	`CREATE TRIGGER widgets_guard_trg BEFORE INSERT OR UPDATE OF tag ON widgets
	   FOR EACH ROW EXECUTE FUNCTION widgets_guard()`,
}

// liveNames — имена, которые схема выше производит.
var liveNames = []string{
	"widgets_owner_fk", "widgets_owner_name_uniq", "widgets_name_check",
	"widgets_pkey", "widgets_guard_raise",
}

func widgetsAfter(extra ...string) []string {
	return append(append([]string{}, widgetsSchema...), extra...)
}

func mappedFrom(names ...string) map[string]token.Position {
	out := map[string]token.Position{}
	for _, n := range names {
		out[n] = token.Position{Filename: "synthetic.go", Line: 1}
	}
	return out
}

// deadNames — имена находок без диагностики, для сравнения множеств.
func deadNames(dead []string) []string {
	var out []string
	for _, d := range dead {
		out = append(out, strings.SplitN(d, " ", 2)[0])
	}
	return out
}

func requireDead(t *testing.T, dead []string, want ...string) {
	t.Helper()
	got := strings.Join(deadNames(dead), ",")
	if got != strings.Join(want, ",") {
		t.Fatalf("гейт обязан назвать ровно %v, назвал %v:\n  %s", want, deadNames(dead), strings.Join(dead, "\n  "))
	}
}

func TestConstraintLivenessGateInjection(t *testing.T) {
	t.Run("контроль: каждое живое имя — молчание", func(t *testing.T) {
		s := liveSchemaAfter(t, widgetsSchema...)
		t.Logf("перепись синтетической схемы: %s", s.census())
		requireDead(t, deadMappedConstraints(s, mappedFrom(liveNames...)))
	})

	t.Run("инъекция: DROP COLUMN НЕЯВНО уносит ключ и уникальный индекс — класс kaname#278", func(t *testing.T) {
		s := liveSchemaAfter(t, widgetsAfter(`ALTER TABLE widgets DROP COLUMN owner_id`)...)
		dead := deadMappedConstraints(s, mappedFrom(liveNames...))
		requireDead(t, dead, "widgets_owner_fk", "widgets_owner_name_uniq")
		if !strings.Contains(dead[0], "унесено неявно") {
			t.Errorf("находка обязана назвать, КАК предмет мог уйти, а не только что его нет: %q", dead[0])
		}
	})

	t.Run("законный близнец: то же снятие ЯВНО и вместе с ветвями — молчание", func(t *testing.T) {
		s := liveSchemaAfter(t, widgetsAfter(
			`ALTER TABLE widgets DROP CONSTRAINT widgets_owner_fk`,
			`DROP INDEX widgets_owner_name_uniq`,
			`ALTER TABLE widgets DROP COLUMN owner_id`)...)
		requireDead(t, deadMappedConstraints(s,
			mappedFrom("widgets_name_check", "widgets_pkey", "widgets_guard_raise")))
	})

	t.Run("инъекция: снос таблицы уносит все её имена, функция остаётся сиротой", func(t *testing.T) {
		s := liveSchemaAfter(t, widgetsAfter(`DROP TABLE widgets`)...)
		dead := deadMappedConstraints(s, mappedFrom(liveNames...))
		requireDead(t, dead, "widgets_guard_raise", "widgets_name_check", "widgets_owner_fk",
			"widgets_owner_name_uniq", "widgets_pkey")
		if !strings.Contains(dead[0], "ни один живой триггер") {
			t.Errorf("имя сироты обязано называть функцию и снятый триггер: %q", dead[0])
		}
	})

	t.Run("инъекция: DROP COLUMN … CASCADE уносит триггер — поднимаемое имя умирает при живой функции", func(t *testing.T) {
		s := liveSchemaAfter(t, widgetsAfter(`ALTER TABLE widgets DROP COLUMN tag CASCADE`)...)
		requireDead(t, deadMappedConstraints(s, mappedFrom(liveNames...)), "widgets_guard_raise")
	})

	t.Run("инъекция: выключенный триггер имени не поднимает", func(t *testing.T) {
		s := liveSchemaAfter(t, widgetsAfter(`ALTER TABLE widgets DISABLE TRIGGER widgets_guard_trg`)...)
		requireDead(t, deadMappedConstraints(s, mappedFrom(liveNames...)), "widgets_guard_raise")
	})

	t.Run("инъекция: снятие ПО ИМЕНИ — ограничение и индекс", func(t *testing.T) {
		s := liveSchemaAfter(t, widgetsAfter(
			`ALTER TABLE widgets DROP CONSTRAINT widgets_name_check`,
			`DROP INDEX widgets_owner_name_uniq`)...)
		requireDead(t, deadMappedConstraints(s, mappedFrom(liveNames...)),
			"widgets_name_check", "widgets_owner_name_uniq")
	})

	t.Run("инъекция: переименование индекса — прежнее имя мертво, новое живо", func(t *testing.T) {
		s := liveSchemaAfter(t, widgetsAfter(`ALTER INDEX widgets_owner_name_uniq RENAME TO widgets_owner_name_key`)...)
		requireDead(t, deadMappedConstraints(s,
			mappedFrom("widgets_owner_name_uniq", "widgets_owner_name_key")), "widgets_owner_name_uniq")
	})

	t.Run("инъекция: неуникальный индекс отказа не производит", func(t *testing.T) {
		s := liveSchemaAfter(t, widgetsSchema...)
		dead := deadMappedConstraints(s, mappedFrom("widgets_tag_idx"))
		requireDead(t, dead, "widgets_tag_idx")
		if !strings.Contains(dead[0], "НЕуникальный индекс") {
			t.Errorf("находка обязана сказать, что объект есть, но отказа не даёт: %q", dead[0])
		}
	})

	t.Run("инъекция: имя, которого не заводили вовсе", func(t *testing.T) {
		s := liveSchemaAfter(t, widgetsSchema...)
		requireDead(t, deadMappedConstraints(s, mappedFrom("widgets_never_existed_fk")), "widgets_never_existed_fk")
	})

	t.Run("контроль: имя в комментарии функции фактом схемы не является", func(t *testing.T) {
		s := liveSchemaAfter(t, widgetsSchema...)
		requireDead(t, deadMappedConstraints(s, mappedFrom("widgets_ghost_raise")), "widgets_ghost_raise")
	})

	t.Run("предпосылка: имя НЕ триггерной функции — находка, а не молчание", func(t *testing.T) {
		s := liveSchemaAfter(t, widgetsAfter(`CREATE FUNCTION widgets_helper() RETURNS void LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'x' USING CONSTRAINT = 'widgets_helper_raise';
END $$`)...)
		dead := deadMappedConstraints(s, mappedFrom("widgets_helper_raise"))
		requireDead(t, dead, "widgets_helper_raise")
		if !strings.Contains(dead[0], "ПРЕДПОСЫЛКА") {
			t.Errorf("не-триггерная функция обязана называться нарушенной предпосылкой: %q", dead[0])
		}
	})

	t.Run("предпосылка: слот CONSTRAINT = без литерала распознаватель называет", func(t *testing.T) {
		s := liveSchemaAfter(t, widgetsAfter(`CREATE FUNCTION widgets_dynamic() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE v text := 'widgets_dynamic_raise';
BEGIN
  RAISE EXCEPTION 'x' USING CONSTRAINT = v;
END $$`)...)
		if strings.Join(s.unrecognizedRaise, ",") != "public.widgets_dynamic" {
			t.Fatalf("форма без литерала обязана попасть в нераспознанные, получено %v", s.unrecognizedRaise)
		}
	})
}

// TestConstraintLivenessRecognizerForms — разбор Go знает ОБЕ законные формы
// ветви и называет чтение в третьей, а не молчит о нём.
func TestConstraintLivenessRecognizerForms(t *testing.T) {
	const src = `package x

func a(e *E) string {
	// "in_comment" — имя в объяснении ветвью не является
	switch e.ConstraintName {
	case "by_switch_one", "by_switch_two":
		return "s"
	}
	if e.ConstraintName == "by_equality" || "by_reversed" == e.ConstraintName {
		return "c"
	}
	if e.ConstraintName != "by_inequality" {
		return "n"
	}
	if e.TableName == "not_a_constraint" {
		return "t"
	}
	log(e.ConstraintName)
	return ""
}
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	got := mappedConstraintNamesIn(fset, f)

	var names []string
	for n := range got.names {
		names = append(names, n)
	}
	want := map[string]bool{"by_switch_one": true, "by_switch_two": true, "by_equality": true,
		"by_reversed": true, "by_inequality": true}
	if len(names) != len(want) {
		t.Fatalf("имена ветвей: ждали %d, прочитано %v", len(want), names)
	}
	for _, n := range names {
		if !want[n] {
			t.Fatalf("прочитано не имя ветви: %q (все: %v)", n, names)
		}
	}
	if got.reads != 5 || got.bySwitch != 1 || got.byComparison != 3 {
		t.Fatalf("перепись разбора: чтений %d, switch %d, сравнений %d — ждали 5, 1, 3",
			got.reads, got.bySwitch, got.byComparison)
	}
	if len(got.unclassified) != 1 || !strings.HasPrefix(got.unclassified[0], "synthetic.go:18:") {
		t.Fatalf("чтение вне обеих форм обязано быть названо позицией, получено %v", got.unclassified)
	}
}
