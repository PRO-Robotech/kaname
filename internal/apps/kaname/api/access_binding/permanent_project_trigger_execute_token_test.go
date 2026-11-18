// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPermanentProjectCommand_TriggerExecuteTokensRespectSQLQuoting(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		count      int
		malformed  bool
	}{
		{name: "privilege_literal", body: `IF has_function_privilege(current_user, p.oid, 'EXECUTE') THEN RETURN NEW; END IF;`},
		{name: "single_quote_escape", body: `PERFORM 'it''s EXECUTE';`},
		{name: "escape_string", body: `PERFORM E'it\'s EXECUTE';`},
		{name: "quoted_identifier", body: `PERFORM "EXECUTE", "escaped""EXECUTE";`},
		{name: "dollar_quote", body: `PERFORM $$EXECUTE 'hidden'$$;`},
		{name: "tagged_dollar_quote", body: `PERFORM $tag_7$EXECUTE $$hidden$$$tag_7$;`},
		{name: "line_comment", body: "-- EXECUTE 'hidden'\nPERFORM 1;"},
		{name: "nested_block_comment", body: `/* outer /* EXECUTE */ still EXECUTE */ PERFORM 1;`},
		{name: "comment_markers_inside_string", body: `PERFORM '-- /* EXECUTE */'; EXECUTE 'DELETE FROM x';`, count: 1},
		{name: "following_single_quote", body: `PERFORM 'EXECUTE'; EXECUTE 'DELETE FROM x';`, count: 1},
		{name: "following_escape_string", body: `PERFORM E'it\'s EXECUTE'; EXECUTE 'DELETE FROM x';`, count: 1},
		{name: "following_identifier", body: `PERFORM "EXECUTE"; EXECUTE 'DELETE FROM x';`, count: 1},
		{name: "following_dollar_quote", body: `PERFORM $q$EXECUTE 'hidden'$q$; EXECUTE 'DELETE FROM x';`, count: 1},
		{name: "following_comments", body: "/* EXECUTE /* hidden */ */ -- EXECUTE\nexecute 'DELETE FROM x';", count: 1},
		{name: "word_boundary", body: `PERFORM execute_suffix, prefix$EXECUTE, $1; EXECUTE 'SELECT 1';`, count: 1},
		{name: "unterminated_single_quote", body: `PERFORM 'EXECUTE`, malformed: true},
		{name: "unterminated_escape_string", body: `PERFORM E'tail\`, malformed: true},
		{name: "unterminated_identifier", body: `PERFORM "EXECUTE`, malformed: true},
		{name: "unterminated_dollar_quote", body: `PERFORM $q$EXECUTE`, malformed: true},
		{name: "wrong_dollar_tag", body: `PERFORM $q$EXECUTE$Q$`, malformed: true},
		{name: "unterminated_nested_comment", body: `/* outer /* inner */ EXECUTE`, malformed: true},
		{name: "stray_comment_end", body: `PERFORM 1; */ EXECUTE 'SELECT 1';`, malformed: true},
		{name: "nul", body: "PERFORM 1;\x00", malformed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, offsets, err := ppTriggerExecuteTokens(tc.body)
			if tc.malformed {
				require.Error(t, err)
				unreviewed, gateErr := ppTriggerHasUnreviewedExecute(tc.body)
				require.Error(t, gateErr)
				require.True(t, unreviewed, "повреждённое тело нельзя принять за отсутствие dynamic SQL")
				return
			}
			require.NoError(t, err)
			require.Len(t, offsets, tc.count)
			for _, at := range offsets {
				require.True(t, strings.EqualFold("EXECUTE", tc.body[at:at+7]))
			}
		})
	}
}

func TestPermanentProjectCommand_TriggerExecuteGateKeepsOnlyApprovedReads(t *testing.T) {
	const rowRead = `EXECUTE format('SELECT to_jsonb(t) FROM kaname.%I t WHERE t.id = $1', TG_TABLE_NAME) INTO v_row USING NEW.id;`
	const countRead = `EXECUTE format('SELECT count(*) FROM %I.%I WHERE %I = $1 AND id <> $2', TG_TABLE_SCHEMA, TG_TABLE_NAME, v_carrier_col) INTO v_existing USING v_carrier, NEW.id;`
	const tempPresenceRead = `EXECUTE format('SELECT EXISTS(SELECT 1 FROM pg_temp.%I)',name) INTO populated;`
	for _, tc := range []struct {
		name, body string
		unreviewed bool
	}{
		{name: "privilege_literal", body: `PERFORM has_function_privilege(current_user, p.oid, 'EXECUTE');`},
		{name: "reviewed_row_read", body: rowRead},
		{name: "reviewed_count_read", body: countRead},
		{name: "both_reviewed_reads", body: rowRead + countRead},
		{name: "comment_between_tokens", body: `EXECUTE /* reviewed read */ format('SELECT to_jsonb(t) FROM kaname.%I t WHERE t.id = $1', TG_TABLE_NAME) INTO v_row USING NEW.id;`},
		{name: "unknown_read", body: `EXECUTE 'SELECT 1';`, unreviewed: true},
		{name: "unknown_write", body: `EXECUTE 'DELETE FROM kaname.resource_mirror';`, unreviewed: true},
		{name: "approved_then_unknown", body: rowRead + `EXECUTE 'SELECT 1';`, unreviewed: true},
		{name: "quoted_approval_cannot_hide_real_execute", body: `PERFORM $q$` + rowRead + `$q$; EXECUTE 'SELECT 1';`, unreviewed: true},
		{name: "comments_cannot_fuse_keyword", body: `EXECUTE/* gap */suffix 'SELECT 1';`, unreviewed: true},
		{name: "reviewed_temp_presence_read", body: tempPresenceRead},
		{name: "temp_presence_other_namespace", body: `EXECUTE format('SELECT EXISTS(SELECT 1 FROM kaname.%I)',name) INTO populated;`, unreviewed: true},
		{name: "temp_presence_write_in_format", body: `EXECUTE format('SELECT EXISTS(SELECT 1 FROM pg_temp.%I); DELETE FROM kaname.resource_mirror',name) INTO populated;`, unreviewed: true},
		{name: "temp_presence_concatenated_format_input", body: `EXECUTE format('SELECT EXISTS(SELECT 1 FROM pg_temp.%I)' || extra_sql,name) INTO populated;`, unreviewed: true},
		{name: "temp_presence_concatenated_result", body: `EXECUTE format('SELECT EXISTS(SELECT 1 FROM pg_temp.%I)',name) || extra_sql INTO populated;`, unreviewed: true},
		{name: "temp_presence_other_format_argument", body: `EXECUTE format('SELECT EXISTS(SELECT 1 FROM pg_temp.%I)',other_name) INTO populated;`, unreviewed: true},
		{name: "temp_presence_extra_format_argument", body: `EXECUTE format('SELECT EXISTS(SELECT 1 FROM pg_temp.%I)',name,extra) INTO populated;`, unreviewed: true},
		{name: "temp_presence_quoted_approval_cannot_hide_execute", body: `PERFORM $q$` + tempPresenceRead + `$q$; EXECUTE 'SELECT 1';`, unreviewed: true},
		{name: "temp_presence_then_unknown", body: tempPresenceRead + `EXECUTE 'DELETE FROM kaname.resource_mirror';`, unreviewed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unreviewed, err := ppTriggerHasUnreviewedExecute(tc.body)
			require.NoError(t, err)
			require.Equal(t, tc.unreviewed, unreviewed)
		})
	}
}
