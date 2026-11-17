// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

func SpecialMemberBudgetCapturedForTest(t *testing.T, ctx context.Context, tx pgx.Tx, repo *Repository, bundle *granteffect.Bundle, binding domain.AccessBindingID) {
	t.Helper()
	owner, err := NewGroupMembershipParticipant(ctx, repo, bundle)
	require.NoError(t, err)
	participant, err := owner.NewBindingStageParticipant(ctx, slog.Default())
	require.NoError(t, err)
	stage, err := participant.stage(ctx, binding, false)
	require.NoError(t, err)
	defer stage.close()
	require.NotNil(t, stage.sequence)
	require.NotEmpty(t, stage.sequence.coordinates)
	var sources []resourceProposalSource
	for key, states := range stage.sequence.parents.source.entries {
		row := resourceProposalSource{Kind: key.kind, Type: key.typ, ID: key.id, Projection: key.projection, States: []string{}}
		for _, state := range states {
			row.States = append(row.States, state.state)
		}
		sources = append(sources, row)
	}
	encoded, err := json.Marshal(sources)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, specialMemberBudgetOracleSQL)
	require.NoError(t, err)
	hasDesired := false
	for _, coordinate := range stage.sequence.coordinates {
		if len(coordinate.Desired) > 0 {
			hasDesired = true
		}
		desired, e := json.Marshal(coordinate.Desired)
		require.NoError(t, e)
		for _, exact := range []bool{true, false} {
			value := desired
			if !exact {
				value = []byte(`[]`)
			}
			_, e = tx.Exec(ctx, `WITH i AS (SELECT kaname._authority_resource_capture_index_v2($1::jsonb,100000) idx),
 p AS (SELECT idx,kaname._authority_resource_projection_v2(idx,$4,$5) graph FROM i),
 g AS (SELECT idx,graph||jsonb_build_object('ancestors',kaname._authority_resource_ancestor_graph_v2(idx,$2::jsonb,graph)->'ancestors') graph FROM p)
 SELECT pg_temp.coordinate_budget_case(idx,$2::jsonb,$3,graph,$6::jsonb,$7) FROM g`, encoded, bundle.CanonicalCatalog(), string(binding), coordinate.Type, coordinate.ID, value, exact)
			require.NoError(t, e)
		}
	}
	require.True(t, hasDesired, "captured positive fixture must contain desired members")
}

const specialMemberBudgetOracleSQL = `CREATE FUNCTION pg_temp.special_member_r295_reference(
 p_index jsonb,p_catalog jsonb,p_binding_id text,p_desired jsonb,p_graph jsonb,p_verified_members jsonb
) RETURNS boolean LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER
SET search_path=pg_catalog,pg_temp AS $$
DECLARE
 captured jsonb; binding jsonb; role_row jsonb; selector jsonb; row_value jsonb;
 selectors jsonb; stored_fps jsonb:='[]'::jsonb; layout jsonb; proof jsonb; materialized_types jsonb;
 authored jsonb; owner_rule jsonb; child jsonb; owner_selector jsonb; child_selector jsonb;
 subjects jsonb; subject jsonb; classes text[]:=ARRAY[]::text[];
 verbs jsonb; recipient_verbs jsonb;
 ancestors jsonb; ancestor jsonb; projection jsonb; root_catalog jsonb; resource jsonb;
 mapped jsonb; relation jsonb; tuple_value jsonb; member jsonb;
 expected jsonb:='{}'::jsonb; actual jsonb:='{}'::jsonb;
 seen_ancestors jsonb:='{}'::jsonb; seen_selectors jsonb:='{}'::jsonb;
 role_id text; dotted text; identifier text; fp text; status text; derivation text; scope_type text; scope_id text;
 recipient text; typ text; sid text; model_type text; owner_type text; owner_fp text; child_fp text;
 validation_type text; expected_fp text; fps text[]:=ARRAY[]::text[]; vocabulary jsonb;
 selector_count integer:=0; n integer:=0; total integer:=0;
 exists_member boolean:=false; expected_status text:='ACTIVE'; nested boolean;
 per_object boolean; selected boolean; applies boolean;
 root_present boolean; has_nonclass boolean:=false;
BEGIN
 IF p_index IS NULL OR p_catalog IS NULL OR p_binding_id IS NULL OR p_desired IS NULL
 OR p_graph IS NULL OR p_verified_members IS NULL THEN
  RAISE EXCEPTION 'special member input missing' USING ERRCODE='42501';
 END IF;
 IF octet_length(p_index::text)>67108864 OR octet_length(p_catalog::text)>8388608
 OR octet_length(p_graph::text)>1048576 OR octet_length(p_desired::text)>8388608
 OR octet_length(p_verified_members::text)>8388608 THEN
  RAISE EXCEPTION 'special member input byte budget exceeded' USING ERRCODE='54000';
 END IF;
 IF jsonb_typeof(p_index) IS DISTINCT FROM 'object' OR jsonb_typeof(p_desired) IS DISTINCT FROM 'object'
 OR jsonb_typeof(p_graph) IS DISTINCT FROM 'object' OR coalesce(p_binding_id,'')=''
 OR jsonb_typeof(p_graph->'present') IS DISTINCT FROM 'boolean' THEN
  RAISE EXCEPTION 'invalid special member input' USING ERRCODE='42501';
 END IF;
 dotted:=p_desired->>'ObjectType';identifier:=p_desired->>'ObjectID';fp:=p_desired->>'RuleFP';status:=p_desired->>'Status';
 derivation:=p_desired->>'Derivation';
 IF coalesce(dotted,'')='' OR coalesce(identifier,'')='' OR coalesce(fp,'')=''
 OR octet_length(dotted)>1024 OR octet_length(identifier)>1024 OR octet_length(fp)>524288
 OR status IS NULL OR status NOT IN ('ACTIVE','REJECTED','ABSENT')
 OR derivation IS NULL OR derivation NOT IN ('nested','container','scope_self','public_reader')
 OR p_graph->>'object_type' IS DISTINCT FROM dotted OR p_graph->>'object_id' IS DISTINCT FROM identifier THEN
  RAISE EXCEPTION 'special member coordinate invalid' USING ERRCODE='42501';
 END IF;
 IF (derivation='scope_self') IS DISTINCT FROM (fp='scope_self')
 OR (derivation='public_reader') IS DISTINCT FROM (left(fp,14)='public_reader:') THEN
  RAISE EXCEPTION 'special derivation coordinate mismatch' USING ERRCODE='42501';
 END IF;
 p_verified_members:=coalesce(nullif(p_verified_members,'null'::jsonb),'[]'::jsonb);
 ancestors:=coalesce(nullif(p_graph->'ancestors','null'::jsonb),'[]'::jsonb);
 IF NOT (p_graph ?& ARRAY['ancestors','projection','current_accounts','current_project']) OR jsonb_typeof(ancestors) IS DISTINCT FROM 'array'
 OR jsonb_typeof(p_verified_members) IS DISTINCT FROM 'array'
 OR jsonb_typeof(p_graph->'current_accounts') IS DISTINCT FROM 'array'
 OR jsonb_typeof(p_graph->'current_project') NOT IN ('string','null') THEN
  RAISE EXCEPTION 'special member graph shape invalid' USING ERRCODE='42501';
 END IF;
 IF jsonb_array_length(ancestors)>4 OR jsonb_array_length(p_verified_members)>4096 THEN
  RAISE EXCEPTION 'special member graph budget exceeded' USING ERRCODE='54000';
 END IF;
 root_present:=(p_graph->>'present')::boolean;projection:=p_graph->'projection';
 FOR ancestor IN SELECT value FROM jsonb_array_elements(jsonb_build_array(p_graph)||ancestors) LOOP
  IF NOT (ancestor ?& ARRAY['object_type','object_id','projection','current_accounts','current_project'])
  OR coalesce(ancestor->>'object_type','')='' OR coalesce(ancestor->>'object_id','')=''
  OR jsonb_typeof(ancestor->'current_accounts') IS DISTINCT FROM 'array'
  OR jsonb_typeof(ancestor->'current_project') NOT IN ('string','null')
  OR EXISTS(SELECT 1 FROM jsonb_array_elements(ancestor->'current_accounts') a WHERE jsonb_typeof(a)<>'string' OR a#>>'{}'='') THEN
   RAISE EXCEPTION 'special member graph node incomplete' USING ERRCODE='42501';
  END IF;
  IF jsonb_array_length(ancestor->'current_accounts')>4096 THEN
   RAISE EXCEPTION 'special current accounts overbound' USING ERRCODE='54000';
  END IF;
  IF seen_ancestors ? jsonb_build_array(ancestor->>'object_type',ancestor->>'object_id')::text THEN
   RAISE EXCEPTION 'special member ancestor repeated' USING ERRCODE='42501';
  END IF;
  seen_ancestors:=seen_ancestors||jsonb_build_object(jsonb_build_array(ancestor->>'object_type',ancestor->>'object_id')::text,true);
  IF n<>0 OR root_present THEN
   IF jsonb_typeof(ancestor->'projection') IS DISTINCT FROM 'object' THEN
    RAISE EXCEPTION 'special member projection missing' USING ERRCODE='42501';
   END IF;
   IF ancestor->>'object_type' IN ('iam.account','iam.project','iam.role','iam.group','iam.serviceAccount','iam.accessBinding','iam.user') THEN
    IF ancestor->'projection'->>'id' IS DISTINCT FROM ancestor->>'object_id' THEN
     RAISE EXCEPTION 'special member IAM identity mismatch' USING ERRCODE='42501';
    END IF;
   ELSIF ancestor->'projection'->>'object_type' IS DISTINCT FROM ancestor->>'object_type'
    OR ancestor->'projection'->>'object_id' IS DISTINCT FROM ancestor->>'object_id' THEN
    RAISE EXCEPTION 'special member mirror identity mismatch' USING ERRCODE='42501';
   END IF;
  END IF;
  n:=n+1;
 END LOOP;
 IF dotted IN ('iam.account','iam.project','iam.role','iam.group','iam.serviceAccount','iam.accessBinding','iam.user')
 AND jsonb_array_length(ancestors)<>0 THEN
  RAISE EXCEPTION 'IAM direct object cannot have materializer ancestors' USING ERRCODE='42501';
 END IF;
 captured:=kaname._authority_resource_require_capture_v2(p_index,8,'binding',p_binding_id);
 IF jsonb_array_length(captured->'states')<>1 THEN RAISE EXCEPTION 'special binding witness missing' USING ERRCODE='42501'; END IF;
 binding:=captured->'states'->0->2;role_id:=binding->>'role_id';scope_type:=binding->>'resource_type';scope_id:=binding->>'resource_id';
 IF binding->>'id' IS DISTINCT FROM p_binding_id OR coalesce(role_id,'')='' OR coalesce(scope_id,'')=''
 OR scope_type IS NULL OR scope_type NOT IN ('account','project','cluster')
 OR coalesce(binding->>'scope','') NOT IN ('1','2','3')
 OR jsonb_typeof(binding->'target') IS DISTINCT FROM 'object' THEN
  RAISE EXCEPTION 'special binding canonical shape invalid' USING ERRCODE='42501';
 END IF;
 -- Этот вызов валидирует target целиком даже для ветви, которой он не подходит.
 IF jsonb_typeof(binding->'target'->'resources')='array' THEN
  IF jsonb_array_length(binding->'target'->'resources')>100000 THEN
   RAISE EXCEPTION 'special target budget exceeded' USING ERRCODE='54000';
  END IF;
 END IF;
 PERFORM kaname._authority_resource_target_contains_v2(binding->'target',dotted,identifier);
 per_object:=jsonb_array_length(coalesce(nullif(binding->'target'->'resources','null'::jsonb),'[]'::jsonb))>0;
 captured:=kaname._authority_resource_require_capture_v2(p_index,12,'role',role_id);
 IF jsonb_array_length(captured->'states')<>1 THEN RAISE EXCEPTION 'special role witness missing' USING ERRCODE='42501'; END IF;
 role_row:=captured->'states'->0->2;
 IF role_row->>'id' IS DISTINCT FROM role_id OR role_row->>'live' IS DISTINCT FROM 'true' THEN
  RAISE EXCEPTION 'special member role is not live' USING ERRCODE='42501';
 END IF;
 -- Каталог проверяется на реально присутствующем Live типе. Root mapping
 -- нужен не всем ветвям: container действие адресует родителя напрямую.
 -- Ни retired строка, ни подставной Live root сюда не добавляются.
 SELECT (r->>'Module')||'.'||(r->>'Resource') INTO validation_type
 FROM jsonb_array_elements(p_catalog#>'{Live,Resources}') r LIMIT 1;
 IF validation_type IS NULL THEN RAISE EXCEPTION 'special catalog has no live validation type' USING ERRCODE='42501';END IF;
 PERFORM kaname._authority_resource_tuple_relations_v2(p_catalog,role_row,validation_type,'[]','object');
 SELECT r INTO root_catalog FROM jsonb_array_elements(p_catalog#>'{Live,Resources}') r
 WHERE (r->>'Module')||'.'||(r->>'Resource')=dotted;
 model_type:=root_catalog->>'ObjectType';
 captured:=kaname._authority_resource_require_capture_v2(p_index,13,'role',role_id);selectors:=captured->'states';
 IF jsonb_array_length(selectors)>4096 THEN RAISE EXCEPTION 'special selector budget exceeded' USING ERRCODE='54000'; END IF;
 FOR row_value IN SELECT value->2 FROM jsonb_array_elements(selectors) LOOP
  IF row_value->>'role_id' IS DISTINCT FROM role_id OR coalesce(row_value->>'rule_fp','') !~ '^[0-9a-f]{64}$'
  OR seen_selectors ? (row_value->>'rule_fp') THEN
   RAISE EXCEPTION 'special selector linkage invalid' USING ERRCODE='42501';
  END IF;
  seen_selectors:=seen_selectors||jsonb_build_object(row_value->>'rule_fp',true);
  stored_fps:=stored_fps||jsonb_build_array(row_value->>'rule_fp');
  IF row_value->>'rule_fp'=fp THEN selector:=row_value;selector_count:=selector_count+1; END IF;
 END LOOP;
 layout:=kaname._authority_resource_rule_layout_v2(role_row,stored_fps);
 captured:=kaname._authority_resource_require_capture_v2(p_index,9,'binding',p_binding_id);
 SELECT coalesce(jsonb_agg(value->2),'[]'::jsonb) INTO subjects FROM jsonb_array_elements(captured->'states');
 IF jsonb_array_length(subjects)=0 THEN subjects:=jsonb_build_array(jsonb_build_object(
  'binding_id',p_binding_id,'subject_type',binding->>'subject_type','subject_id',binding->>'subject_id','ordinal',0)); END IF;
 IF jsonb_array_length(subjects)>32 THEN RAISE EXCEPTION 'special recipient budget exceeded' USING ERRCODE='54000'; END IF;
 FOR subject IN SELECT value FROM jsonb_array_elements(subjects) LOOP
  typ:=subject->>'subject_type';sid:=subject->>'subject_id';recipient:=typ||':'||sid||CASE WHEN typ='group' THEN '#member' ELSE '' END;
  -- Валидация полного canonical списка не исчезает при исключении классов.
  PERFORM kaname._authority_resource_recipient_verbs_v2(binding,subjects,'["get"]',recipient,false,'',false);
  IF typ='system_class' THEN classes:=array_append(classes,recipient); ELSE has_nonclass:=true; END IF;
 END LOOP;
 FOR member IN SELECT value FROM jsonb_array_elements(p_verified_members) LOOP
  IF jsonb_typeof(member) IS DISTINCT FROM 'object' OR member->>'Status' IS DISTINCT FROM 'ACTIVE'
  OR coalesce(member->>'ObjectType','')='' OR coalesce(member->>'ObjectID','')=''
  OR (coalesce(member->>'RuleFP','') !~ '^[0-9a-f]{64}$' AND member->>'RuleFP' IS DISTINCT FROM 'scope_self') THEN
   RAISE EXCEPTION 'public reader base set is not verified nonpublic members' USING ERRCODE='42501';
  END IF;
 END LOOP;
 expected_fp:=fp;
 <<branch_proof>>
 BEGIN
  IF fp='scope_self' THEN
   IF NOT root_present OR model_type IS NULL OR per_object OR scope_type NOT IN ('account','project')
   OR dotted<>'iam.'||scope_type OR identifier<>scope_id THEN EXIT branch_proof; END IF;
   verbs:='[]'::jsonb;
   FOR authored IN SELECT value FROM jsonb_array_elements(layout) LOOP
    IF (authored->>'module'='*' AND authored->'resources' ? '*')
    OR (authored->>'module'='iam' AND authored->'resources' ? scope_type) THEN verbs:=verbs||(authored->'verbs'); END IF;
   END LOOP;
   IF verbs ? '*' THEN
    -- ScopeSelfVerbs разворачивает type vocabulary, сохраняя сам знак '*'.
    SELECT coalesce(jsonb_agg(v->'Verb'),'[]'::jsonb) INTO vocabulary
    FROM jsonb_array_elements(p_catalog#>'{Live,Verbs}') v
    WHERE (v->>'Module')||'.'||(v->>'Resource')=dotted AND (v->>'PerObject')::boolean;
    IF jsonb_array_length(vocabulary)=0 THEN
     WITH per_type AS MATERIALIZED (
      SELECT r->>'ObjectType' typ,v->>'Verb' verb FROM jsonb_array_elements(p_catalog#>'{Live,Resources}') r
      JOIN jsonb_array_elements(p_catalog#>'{Live,Verbs}') v ON r->>'Module'=v->>'Module' AND r->>'Resource'=v->>'Resource'
      WHERE (v->>'PerObject')::boolean
     ), common AS (SELECT pt.verb FROM per_type pt GROUP BY pt.verb
      HAVING count(DISTINCT pt.typ)=(SELECT count(DISTINCT all_types.typ) FROM per_type all_types))
     SELECT coalesce(jsonb_agg(c.verb),'[]'::jsonb) INTO vocabulary FROM common c;
    END IF;
    verbs:=vocabulary||'["*"]'::jsonb;
   END IF;
   IF jsonb_array_length(verbs)>4096 THEN RAISE EXCEPTION 'scope self verbs overbound' USING ERRCODE='54000'; END IF;
   IF jsonb_array_length(verbs)=0 THEN EXIT branch_proof; END IF;
   FOR subject IN SELECT value FROM jsonb_array_elements(subjects) LOOP
    typ:=subject->>'subject_type';sid:=subject->>'subject_id';recipient:=typ||':'||sid||CASE WHEN typ='group' THEN '#member' ELSE '' END;
    IF typ='system_class' AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(verbs) v WHERE lower(btrim(v)) IN ('get','list')) THEN CONTINUE; END IF;
    recipient_verbs:=kaname._authority_resource_recipient_verbs_v2(binding,subjects,verbs,recipient,false,'',false);
    mapped:=kaname._authority_resource_tuple_relations_v2(p_catalog,role_row,dotted,recipient_verbs,'scope_self');
    FOR relation IN SELECT value FROM jsonb_array_elements(mapped->'relations') LOOP
     total:=total+1;IF total>100000 THEN RAISE EXCEPTION 'special tuple work overbound' USING ERRCODE='54000'; END IF;
     tuple_value:=jsonb_build_object('User',recipient,'Relation',relation#>>'{}','Object',model_type||':'||identifier);
     expected:=expected||jsonb_build_object(tuple_value::text,true);
    END LOOP;
   END LOOP;
  ELSIF left(fp,14)='public_reader:' THEN
   IF status='ABSENT' AND fp<>'public_reader:' THEN RAISE EXCEPTION 'public absence marker invalid' USING ERRCODE='42501'; END IF;
   IF NOT root_present OR model_type IS NULL OR cardinality(classes)=0 THEN EXIT branch_proof; END IF;
   IF jsonb_typeof(root_catalog->'PublicReadToChildren') IS DISTINCT FROM 'boolean' THEN
    RAISE EXCEPTION 'public reader catalog flag missing' USING ERRCODE='42501';
   END IF;
   IF NOT (root_catalog->>'PublicReadToChildren')::boolean THEN EXIT branch_proof; END IF;
   FOR owner_rule IN SELECT value FROM jsonb_array_elements(layout) LOOP
    IF jsonb_array_length(owner_rule->'resources')<>1 OR owner_rule->>'module'='*'
    OR owner_rule->'resources'->>0='*' OR (owner_rule->>'module')||'.'||(owner_rule->'resources'->>0)<>dotted THEN CONTINUE; END IF;
    owner_fp:=kaname._authority_resource_rule_fingerprint_v2(owner_rule,false);
    IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(owner_rule->'verbs') v WHERE lower(btrim(v)) IN ('get','list'))
    OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p_verified_members) m
     WHERE m->>'RuleFP'=owner_fp AND m->>'ObjectType'=dotted AND m->>'ObjectID'=identifier) THEN CONTINUE; END IF;
    FOR child IN SELECT value FROM jsonb_array_elements(coalesce(nullif(owner_rule->'children','null'::jsonb),'[]'::jsonb)) LOOP
     IF jsonb_array_length(coalesce(nullif(child->'resource_names','null'::jsonb),'[]'::jsonb))>0
     OR coalesce(nullif(child->'match_labels','null'::jsonb),'{}'::jsonb)<>'{}'::jsonb
     OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(child->'verbs') v WHERE lower(btrim(v))='get')
     OR NOT EXISTS(SELECT 1 FROM jsonb_array_elements_text(child->'verbs') v WHERE lower(btrim(v))='list') THEN CONTINUE; END IF;
     -- PublicReaderEffect сначала ClassReadVerbs, поэтому extra write verb
     -- не подменяет проверку actual producer более строгими admission воротами.
     applies:=false;
     FOR resource IN SELECT value FROM jsonb_array_elements(p_catalog#>'{Live,Resources}') LOOP
      IF resource->>'Module'<>owner_rule->>'module' OR NOT (child->'resources' ? (resource->>'Resource')) THEN CONTINUE; END IF;
      IF NOT resource ? 'ParentTypes' OR jsonb_typeof(resource->'ParentTypes') NOT IN ('array','null') THEN
       RAISE EXCEPTION 'public reader parent types invalid' USING ERRCODE='42501';
      END IF;
      applies:=applies OR coalesce(resource->'ParentTypes' ? model_type,false);
     END LOOP;
     IF NOT applies THEN CONTINUE; END IF;
     child_fp:=kaname._authority_resource_rule_fingerprint_v2(child,true);
     fps:=array_append(fps,encode(sha256(convert_to('nested','UTF8')||decode('00','hex')||convert_to(owner_fp,'UTF8')||decode('00','hex')||convert_to(child_fp,'UTF8')),'hex'));
     IF cardinality(fps)>4096 THEN RAISE EXCEPTION 'public reader witness budget exceeded' USING ERRCODE='54000'; END IF;
    END LOOP;
   END LOOP;
   IF cardinality(fps)=0 THEN EXIT branch_proof; END IF;
   SELECT 'public_reader:'||string_agg(x,',' ORDER BY x COLLATE "C") INTO expected_fp FROM unnest(fps) x;
   SELECT expected_fp||'@'||string_agg(x,',' ORDER BY x COLLATE "C") INTO expected_fp FROM unnest(classes) x;
   FOREACH recipient IN ARRAY classes LOOP
    total:=total+1;IF total>100000 THEN RAISE EXCEPTION 'special tuple work overbound' USING ERRCODE='54000'; END IF;
    tuple_value:=jsonb_build_object('User',recipient,'Relation','public_reader','Object',model_type||':'||identifier);
    expected:=expected||jsonb_build_object(tuple_value::text,true);
   END LOOP;
  ELSE
   IF selector_count<>1 THEN RAISE EXCEPTION 'special selector witness missing' USING ERRCODE='42501'; END IF;
   proof:=kaname._authority_resource_rule_witness_v2(role_row,fp,stored_fps);
   authored:=proof->'rule';nested:=(proof->>'nested')::boolean;
   IF nested IS DISTINCT FROM (derivation='nested') THEN
    RAISE EXCEPTION 'special derivation does not match authored rule' USING ERRCODE='42501';
   END IF;
   IF NOT root_present THEN EXIT branch_proof; END IF;
   IF nested THEN
    IF NOT has_nonclass THEN EXIT branch_proof; END IF;
    owner_rule:=proof->'owner';
    IF jsonb_array_length(owner_rule->'resources')<>1 OR coalesce(owner_rule->>'module','') IN ('','*')
    OR owner_rule->'resources'->>0='*' THEN RAISE EXCEPTION 'nested owner has no canonical type' USING ERRCODE='42501'; END IF;
    owner_type:=(owner_rule->>'module')||'.'||(owner_rule->'resources'->>0);
    child_selector:=jsonb_build_object('object_types',
     (SELECT coalesce(jsonb_agg((authored->>'module')||'.'||x),'[]'::jsonb) FROM jsonb_array_elements_text(authored->'resources') x),
     'arm',CASE WHEN jsonb_array_length(coalesce(nullif(authored->'resource_names','null'::jsonb),'[]'::jsonb))>0 THEN 'names'
      WHEN coalesce(nullif(authored->'match_labels','null'::jsonb),'{}'::jsonb)<>'{}'::jsonb THEN 'labels' ELSE 'anchor' END,
     'resource_names',coalesce(nullif(authored->'resource_names','null'::jsonb),'[]'::jsonb),
     'match_labels',coalesce(nullif(authored->'match_labels','null'::jsonb),'{}'::jsonb));
    IF NOT kaname._authority_resource_selector_matches_v2(child_selector,dotted,identifier,coalesce(nullif(projection->'labels','null'::jsonb),'{}'::jsonb)) THEN EXIT branch_proof; END IF;
    owner_selector:=jsonb_build_object('object_types',jsonb_build_array(owner_type),
     'arm',CASE WHEN jsonb_array_length(coalesce(nullif(owner_rule->'resource_names','null'::jsonb),'[]'::jsonb))>0 THEN 'names'
      WHEN coalesce(nullif(owner_rule->'match_labels','null'::jsonb),'{}'::jsonb)<>'{}'::jsonb THEN 'labels' ELSE 'anchor' END,
     'resource_names',coalesce(nullif(owner_rule->'resource_names','null'::jsonb),'[]'::jsonb),
     'match_labels',coalesce(nullif(owner_rule->'match_labels','null'::jsonb),'{}'::jsonb));
    selected:=false;
    FOR ancestor IN SELECT value FROM jsonb_array_elements(ancestors) LOOP
     IF kaname._authority_resource_selector_matches_v2(owner_selector,ancestor->>'object_type',ancestor->>'object_id',
       coalesce(nullif(ancestor->'projection'->'labels','null'::jsonb),'{}'::jsonb))
     AND kaname._authority_resource_target_contains_v2(binding->'target',ancestor->>'object_type',ancestor->>'object_id')
     AND kaname._authority_resource_contained_v2(scope_type,scope_id,ancestor->'current_accounts',ancestor->>'current_project') THEN selected:=true; END IF;
    END LOOP;
    IF NOT selected THEN EXIT branch_proof; END IF;
    verbs:=authored->'verbs';
    IF jsonb_array_length(verbs)=0 THEN EXIT branch_proof; END IF;
    IF NOT kaname._authority_resource_contained_v2(scope_type,scope_id,p_graph->'current_accounts',p_graph->>'current_project') THEN
     exists_member:=true;expected_status:='REJECTED';EXIT branch_proof;
    END IF;
    IF model_type IS NULL THEN EXIT branch_proof;END IF;
    FOR subject IN SELECT value FROM jsonb_array_elements(subjects) LOOP
     typ:=subject->>'subject_type';IF typ='system_class' THEN CONTINUE; END IF;
     sid:=subject->>'subject_id';recipient:=typ||':'||sid||CASE WHEN typ='group' THEN '#member' ELSE '' END;
     recipient_verbs:=kaname._authority_resource_recipient_verbs_v2(binding,subjects,verbs,recipient,true,'',false);
     mapped:=kaname._authority_resource_tuple_relations_v2(p_catalog,role_row,dotted,recipient_verbs,'object');
     FOR relation IN SELECT value FROM jsonb_array_elements(mapped->'relations') LOOP
      total:=total+1;IF total>100000 THEN RAISE EXCEPTION 'special tuple work overbound' USING ERRCODE='54000'; END IF;
      tuple_value:=jsonb_build_object('User',recipient,'Relation',relation#>>'{}','Object',model_type||':'||identifier);
      expected:=expected||jsonb_build_object(tuple_value::text,true);
     END LOOP;
    END LOOP;
   ELSE
    -- Обычный FP здесь обозначает только container contribution. Его ordinary
    -- вклад проверяется отдельно и затем объединяется C по точной координате.
    IF per_object OR dotted<>'iam.'||scope_type OR identifier<>scope_id THEN EXIT branch_proof; END IF;
    -- Типы выводит общий exact static-registry port C, а не все live строки
    -- каталога и не сохранённая selector-проекция. Concrete names сохраняются.
    materialized_types:=kaname._authority_resource_materialized_types_v2(authored,(binding->>'scope')::integer);
    IF jsonb_typeof(materialized_types) IS DISTINCT FROM 'array' THEN
     RAISE EXCEPTION 'materialized type proof incomplete' USING ERRCODE='42501';
    END IF;
    IF jsonb_array_length(materialized_types)>4096 THEN
     RAISE EXCEPTION 'materialized type proof overbound' USING ERRCODE='54000';
    END IF;
    FOR row_value IN SELECT value FROM jsonb_array_elements(p_catalog#>'{Live,Verbs}') LOOP
     typ:=(row_value->>'Module')||'.'||(row_value->>'Resource');
     IF row_value->>'ContainerParent'<>scope_type OR row_value->>'ContainerRelation'=''
     OR NOT (materialized_types ? typ) OR NOT (authored->'verbs' ? (row_value->>'Verb')) THEN CONTINUE; END IF;
     IF NOT ((authored->>'module'='*' AND authored->'resources' ? '*' AND binding->>'scope' IN ('2','3'))
      OR (authored->>'module'=row_value->>'Module' AND ((authored->'resources' ? (row_value->>'Resource'))
       OR (authored->'resources' ? '*' AND binding->>'scope' IN ('2','3'))))) THEN CONTINUE; END IF;
     IF NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p_catalog#>'{Live,Resources}') r
      WHERE r->>'Module'=row_value->>'Module' AND r->>'Resource'=row_value->>'Resource') THEN CONTINUE; END IF;
     FOR subject IN SELECT value FROM jsonb_array_elements(subjects) LOOP
      IF subject->>'subject_type'<>'service_account' THEN CONTINUE; END IF;
      total:=total+1;IF total>100000 THEN RAISE EXCEPTION 'special tuple work overbound' USING ERRCODE='54000'; END IF;
      tuple_value:=jsonb_build_object('User','service_account:'||(subject->>'subject_id'),
       'Relation',row_value->>'ContainerRelation','Object',scope_type||':'||scope_id);
      expected:=expected||jsonb_build_object(tuple_value::text,true);
     END LOOP;
    END LOOP;
   END IF;
  END IF;
  exists_member:=expected<>'{}'::jsonb;
 END branch_proof;
 IF (SELECT count(*) FROM jsonb_object_keys(expected))>100000 THEN
  RAISE EXCEPTION 'special expected tuples overbound' USING ERRCODE='54000';
 END IF;
 IF status='ABSENT' THEN
  IF exists_member OR (p_desired->'Tuples' IS DISTINCT FROM '[]'::jsonb AND p_desired->'Tuples' IS DISTINCT FROM 'null'::jsonb) THEN
   RAISE EXCEPTION 'unproven special member absence' USING ERRCODE='42501';
  END IF;
  RETURN true;
 END IF;
 IF NOT exists_member OR fp IS DISTINCT FROM expected_fp OR status IS DISTINCT FROM expected_status THEN
  RAISE EXCEPTION 'special member status or fingerprint mismatch' USING ERRCODE='42501';
 END IF;
 IF expected_status='REJECTED' THEN
  IF p_desired->'Tuples' IS DISTINCT FROM '[]'::jsonb AND p_desired->'Tuples' IS DISTINCT FROM 'null'::jsonb THEN
   RAISE EXCEPTION 'rejected special member carries tuples' USING ERRCODE='42501';
  END IF;
  RETURN true;
 END IF;
 IF jsonb_typeof(p_desired->'Tuples') IS DISTINCT FROM 'array' THEN
  RAISE EXCEPTION 'special tuple list missing' USING ERRCODE='42501';
 END IF;
 IF jsonb_array_length(p_desired->'Tuples')>100000 THEN RAISE EXCEPTION 'special actual tuples overbound' USING ERRCODE='54000'; END IF;
 FOR tuple_value IN SELECT value FROM jsonb_array_elements(p_desired->'Tuples') LOOP
  IF NOT expected ? tuple_value::text THEN RAISE EXCEPTION 'unproven special member tuple' USING ERRCODE='42501'; END IF;
  actual:=actual||jsonb_build_object(tuple_value::text,true);
 END LOOP;
 IF actual IS DISTINCT FROM expected THEN RAISE EXCEPTION 'special member tuple union incomplete' USING ERRCODE='42501'; END IF;
 RETURN true;
EXCEPTION WHEN invalid_parameter_value THEN
 -- Ошибка формы в общем predicate остаётся ошибкой, никогда не ABSENT.
 RAISE EXCEPTION 'invalid special member canonical source shape' USING ERRCODE='42501';
END $$;
CREATE FUNCTION pg_temp.coordinate_r295_reference(
 p_index jsonb,p_catalog jsonb,p_binding_id text,p_graph jsonb,p_desired jsonb)
RETURNS jsonb LANGUAGE plpgsql IMMUTABLE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $$
DECLARE captured jsonb;binding jsonb;role_row jsonb;layout jsonb;rule jsonb;child jsonb;row_value jsonb;
 stored_fps jsonb:='[]'::jsonb;obligations jsonb:='{}'::jsonb;seen jsonb:='{}'::jsonb;
 verified jsonb:='[]'::jsonb;active_base jsonb:='[]'::jsonb;public_member jsonb;desired jsonb;negative jsonb;
 role_id text;dotted text;identifier text;fp text;child_fp text;key text;derivation text;entry record;branch text;
 count_value integer;work integer:=0;special_empty boolean:=false;
BEGIN
 IF jsonb_typeof(p_graph) IS DISTINCT FROM 'object' OR jsonb_typeof(p_graph->'present') IS DISTINCT FROM 'boolean'
 OR jsonb_typeof(p_desired) IS DISTINCT FROM 'array' OR coalesce(p_binding_id,'')=''
 OR coalesce(p_graph->>'object_type','')='' OR coalesce(p_graph->>'object_id','')='' THEN
  RAISE EXCEPTION 'invalid coordinate certificate input' USING ERRCODE='42501';
 END IF;
 IF jsonb_array_length(p_desired)>4096 OR octet_length(p_desired::text)>8388608 THEN
  RAISE EXCEPTION 'coordinate contribution budget exceeded' USING ERRCODE='54000';
 END IF;
 dotted:=p_graph->>'object_type';identifier:=p_graph->>'object_id';
 captured:=kaname._authority_resource_require_capture_v2(p_index,8,'binding',p_binding_id);
 IF jsonb_array_length(captured->'states')<>1 THEN RAISE EXCEPTION 'coordinate binding missing' USING ERRCODE='42501';END IF;
 binding:=captured->'states'->0->2;role_id:=coalesce(binding->>'role_id','');
 IF binding->>'id' IS DISTINCT FROM p_binding_id THEN RAISE EXCEPTION 'coordinate binding linkage invalid' USING ERRCODE='42501';END IF;
 -- Эти состояния установлены canonical capture. Они не являются caller allow
 -- или исключением из ошибок leaf; actual Go здесь не вызывает desired compiler.
 IF NOT (p_graph->>'present')::boolean OR binding->>'status'<>'ACTIVE' OR role_id='' THEN
  IF jsonb_array_length(p_desired)<>0 THEN RAISE EXCEPTION 'inactive coordinate has desired effects' USING ERRCODE='42501';END IF;
  RETURN jsonb_build_object('desired','[]'::jsonb,'work',0);
 END IF;
 captured:=kaname._authority_resource_require_capture_v2(p_index,12,'role',role_id);
 IF jsonb_array_length(captured->'states')<>1 THEN RAISE EXCEPTION 'coordinate role missing' USING ERRCODE='42501';END IF;
 role_row:=captured->'states'->0->2;
 IF role_row->>'id' IS DISTINCT FROM role_id THEN RAISE EXCEPTION 'coordinate role linkage invalid' USING ERRCODE='42501';END IF;
 IF role_row->>'live' IS DISTINCT FROM 'true' THEN
  IF jsonb_array_length(p_desired)<>0 THEN RAISE EXCEPTION 'retired role has desired effects' USING ERRCODE='42501';END IF;
  RETURN jsonb_build_object('desired','[]'::jsonb,'work',0);
 END IF;
 captured:=kaname._authority_resource_require_capture_v2(p_index,13,'role',role_id);
 FOR row_value IN SELECT value->2 FROM jsonb_array_elements(captured->'states') LOOP
  IF row_value->>'role_id' IS DISTINCT FROM role_id OR stored_fps ? (row_value->>'rule_fp') THEN
   RAISE EXCEPTION 'coordinate selector linkage or uniqueness invalid' USING ERRCODE='42501';END IF;
  stored_fps:=stored_fps||jsonb_build_array(row_value->>'rule_fp');
 END LOOP;
 -- У retired не-IAM root current ancestor collector возвращает пустой
 -- список (нет live model mapping), scope/container coordinate невозможна,
 -- PublicReaderEffect также требует live FGA mapping. Это точное отрицательное
 -- доказательство специальных ветвей; ordinary foreign REJECTED всё ещё
 -- проверяется отдельно. IAM anchors сюда принципиально не входят.
 special_empty:=dotted NOT IN ('iam.account','iam.project','iam.role','iam.group','iam.serviceAccount','iam.accessBinding','iam.user')
  AND NOT EXISTS(SELECT 1 FROM jsonb_array_elements(p_catalog#>'{Live,Resources}') r WHERE (r->>'Module')||'.'||(r->>'Resource')=dotted);
 IF special_empty AND p_graph->'ancestors' IS DISTINCT FROM '[]'::jsonb THEN
  RAISE EXCEPTION 'retired root has unsupported ancestor proof' USING ERRCODE='42501';END IF;
 layout:=kaname._authority_resource_rule_layout_v2(role_row,stored_fps);
 FOR rule IN SELECT value FROM jsonb_array_elements(layout) LOOP
  fp:=kaname._authority_resource_rule_fingerprint_v2(rule,false);
  FOREACH branch IN ARRAY ARRAY['ordinary','container'] LOOP
   key:=jsonb_build_array(branch,fp)::text;
   obligations:=obligations||jsonb_build_object(key,coalesce((obligations->>key)::integer,0)+1);
  END LOOP;
  FOR child IN SELECT value FROM jsonb_array_elements(coalesce(nullif(rule->'children','null'::jsonb),'[]'::jsonb)) LOOP
   child_fp:=kaname._authority_resource_rule_fingerprint_v2(child,true);
   child_fp:=encode(sha256(convert_to('nested','UTF8')||decode('00','hex')||convert_to(fp,'UTF8')||decode('00','hex')||convert_to(child_fp,'UTF8')),'hex');
   key:=jsonb_build_array('nested',child_fp)::text;
   obligations:=obligations||jsonb_build_object(key,coalesce((obligations->>key)::integer,0)+1);
  END LOOP;
 END LOOP;
 obligations:=obligations||jsonb_build_object('["scope_self", "scope_self"]',1,'["public_reader", "public_reader:"]',1);
 IF (SELECT count(*) FROM jsonb_object_keys(obligations))>4096 THEN
  RAISE EXCEPTION 'coordinate branch census overbound' USING ERRCODE='54000';END IF;
 -- Порядок caller не управляет public premise: сначала доказываются все
 -- остальные ветви, затем public_reader получает только доказанные ACTIVE.
 FOR desired IN SELECT value FROM jsonb_array_elements(p_desired) LOOP
  IF jsonb_typeof(desired) IS DISTINCT FROM 'object' OR (SELECT count(*) FROM jsonb_object_keys(desired))<>6
  OR NOT (desired ?& ARRAY['Derivation','RuleFP','ObjectType','ObjectID','Status','Tuples'])
  OR desired->>'ObjectType' IS DISTINCT FROM dotted OR desired->>'ObjectID' IS DISTINCT FROM identifier
  OR coalesce(desired->>'Status','') NOT IN ('ACTIVE','REJECTED')
  OR coalesce(desired->>'Derivation','') NOT IN ('ordinary','container','nested','scope_self','public_reader') THEN
   RAISE EXCEPTION 'unclassified or foreign coordinate contribution' USING ERRCODE='42501';
  END IF;
  derivation:=desired->>'Derivation';fp:=desired->>'RuleFP';
  IF special_empty AND derivation<>'ordinary' THEN
   RAISE EXCEPTION 'retired non-IAM root has special contribution' USING ERRCODE='42501';END IF;
  key:=jsonb_build_array(derivation,CASE WHEN derivation='public_reader' THEN 'public_reader:' ELSE fp END)::text;
  IF NOT obligations ? key THEN RAISE EXCEPTION 'contribution has no canonical branch' USING ERRCODE='42501';END IF;
  count_value:=coalesce((seen->>key)::integer,0)+1;
  IF count_value>(obligations->>key)::integer THEN RAISE EXCEPTION 'duplicated contribution beyond canonical multiplicity' USING ERRCODE='42501';END IF;
  seen:=seen||jsonb_build_object(key,count_value);work:=work+1;
  IF derivation='public_reader' THEN public_member:=desired;CONTINUE;END IF;
  IF derivation='ordinary' THEN
   PERFORM kaname._authority_resource_ordinary_member_v2(p_index,p_catalog,p_binding_id,desired,p_graph);
  ELSE
   PERFORM pg_temp.special_member_r295_reference(p_index,p_catalog,p_binding_id,desired,p_graph,'[]');
  END IF;
  verified:=verified||jsonb_build_array(desired);
  IF desired->>'Status'='ACTIVE' THEN active_base:=active_base||jsonb_build_array(desired);END IF;
 END LOOP;
 FOR entry IN SELECT * FROM jsonb_each(obligations) LOOP
  count_value:=coalesce((seen->>entry.key)::integer,0);
  IF count_value<>0 AND count_value<>(entry.value#>>'{}')::integer THEN
   RAISE EXCEPTION 'partial canonical contribution multiplicity' USING ERRCODE='42501';END IF;
  IF count_value<>0 THEN CONTINUE;END IF;
  derivation:=(entry.key::jsonb)->>0;fp:=(entry.key::jsonb)->>1;
  IF special_empty AND derivation<>'ordinary' THEN CONTINUE;END IF;
  negative:=jsonb_build_object('Derivation',derivation,'RuleFP',fp,'ObjectType',dotted,'ObjectID',identifier,'Status','ABSENT','Tuples','[]'::jsonb);
  work:=work+1;
  IF derivation='ordinary' THEN
   PERFORM kaname._authority_resource_ordinary_member_v2(p_index,p_catalog,p_binding_id,negative,p_graph);
  ELSE
   PERFORM pg_temp.special_member_r295_reference(p_index,p_catalog,p_binding_id,negative,p_graph,
    CASE WHEN derivation='public_reader' THEN active_base ELSE '[]'::jsonb END);
  END IF;
 END LOOP;
 IF public_member IS NOT NULL THEN
  PERFORM pg_temp.special_member_r295_reference(p_index,p_catalog,p_binding_id,public_member,p_graph,active_base);
  verified:=verified||jsonb_build_array(public_member);
 END IF;
 IF work>8192 THEN RAISE EXCEPTION 'coordinate proof work exceeded' USING ERRCODE='54000';END IF;
 RETURN jsonb_build_object('desired',verified,'work',work);
END $$;
REVOKE ALL ON FUNCTION pg_temp.special_member_r295_reference(jsonb,jsonb,text,jsonb,jsonb,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION pg_temp.coordinate_r295_reference(jsonb,jsonb,text,jsonb,jsonb) FROM PUBLIC;

CREATE FUNCTION pg_temp.special_budget_case(args jsonb,expected_state text DEFAULT NULL) RETURNS void LANGUAGE plpgsql AS $$
DECLARE a boolean;b boolean;sa text:='00000';sb text:='00000';ma text;mb text;
BEGIN
 BEGIN a:=pg_temp.special_member_r295_reference(nullif(args->0,'null'),nullif(args->1,'null'),args->>2,nullif(args->3,'null'),nullif(args->4,'null'),nullif(args->5,'null'));
 EXCEPTION WHEN OTHERS THEN GET STACKED DIAGNOSTICS sa=RETURNED_SQLSTATE,ma=MESSAGE_TEXT;END;
 BEGIN b:=kaname._authority_resource_special_member_v2(nullif(args->0,'null'),nullif(args->1,'null'),args->>2,nullif(args->3,'null'),nullif(args->4,'null'),nullif(args->5,'null'));
 EXCEPTION WHEN OTHERS THEN GET STACKED DIAGNOSTICS sb=RETURNED_SQLSTATE,mb=MESSAGE_TEXT;END;
 IF (a,sa,ma) IS DISTINCT FROM (b,sb,mb) OR (expected_state IS NOT NULL AND sa<>expected_state) THEN
 RAISE EXCEPTION 'special wrapper differential mismatch reference % % candidate % %',sa,ma,sb,mb;END IF;
END $$;
CREATE FUNCTION pg_temp.coordinate_budget_case(idx jsonb,cat jsonb,bid text,graph jsonb,desired jsonb,must_succeed boolean) RETURNS void LANGUAGE plpgsql AS $$
DECLARE a jsonb;b jsonb;sa text:='00000';sb text:='00000';ma text;mb text;
BEGIN
 BEGIN a:=pg_temp.coordinate_r295_reference(idx,cat,bid,graph,desired);
 EXCEPTION WHEN OTHERS THEN GET STACKED DIAGNOSTICS sa=RETURNED_SQLSTATE,ma=MESSAGE_TEXT;END;
 BEGIN b:=kaname._authority_resource_coordinate_certificate_v2(idx,cat,bid,graph,desired);
 EXCEPTION WHEN OTHERS THEN GET STACKED DIAGNOSTICS sb=RETURNED_SQLSTATE,mb=MESSAGE_TEXT;END;
 IF (a,sa,ma) IS DISTINCT FROM (b,sb,mb) OR (must_succeed AND sa<>'00000') THEN
 RAISE EXCEPTION 'coordinate differential mismatch reference % % candidate % %',sa,ma,sb,mb;END IF;
END $$;
DO $$ DECLARE args jsonb:='[{}, {}, "binding", {}, {}, []]';i integer;v jsonb; BEGIN
 FOR i IN 0..5 LOOP PERFORM pg_temp.special_budget_case(jsonb_set(args,ARRAY[i::text],'null'),'42501');END LOOP;
 PERFORM pg_temp.special_budget_case(args,'42501');
 FOR i IN SELECT unnest(ARRAY[1,3,4,5]) LOOP
  v:=jsonb_set(args,ARRAY[i::text],to_jsonb(repeat('x',CASE WHEN i=4 THEN 1048577 ELSE 8388609 END)));
  PERFORM pg_temp.special_budget_case(v,'54000');
  -- Full null guard precedes ALL byte limits, even another oversized argument.
  PERFORM pg_temp.special_budget_case(jsonb_set(v,'{0}','null'),'42501');
 END LOOP;
 IF EXISTS(SELECT 1 FROM pg_catalog.pg_proc p CROSS JOIN LATERAL aclexplode(coalesce(p.proacl,acldefault('f',p.proowner))) a
 WHERE p.oid='kaname._authority_resource_special_member_core_v2(jsonb,jsonb,text,jsonb,jsonb,jsonb)'::regprocedure AND a.grantee<>p.proowner) THEN
 RAISE EXCEPTION 'special core has nonowner ACL';END IF;
 IF NOT kaname._authority_crud_storage_v3() THEN RAISE EXCEPTION 'special core ABI closure rejected';END IF;
END $$;
`
