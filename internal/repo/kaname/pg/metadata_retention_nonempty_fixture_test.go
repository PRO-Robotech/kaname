// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"encoding/json"
	"log/slog"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Компиляция выполняется в подписанной транзакции, которую проба откатывает.
type metadataRetentionNonemptyProbe func(t *testing.T, w metadataWorld, root domain.Account) (json.RawMessage, error)

type metadataRetentionNonemptyResult struct {
	Desired     map[string][]reconcile.DesiredMember `json:"desired"`
	Certificate struct {
		Bindings map[string]struct {
			Desired []reconcile.DesiredMember `json:"desired"`
		} `json:"bindings"`
	} `json:"certificate"`
	Classified struct {
		Retained map[string]struct {
			Fact   json.RawMessage `json:"fact"`
			Holder struct {
				Kind    string `json:"kind"`
				Binding string `json:"binding"`
			} `json:"holder"`
		} `json:"retained"`
		Absent  map[string]json.RawMessage `json:"absent"`
		Pending []struct {
			ObjectType string `json:"object_type"`
			ObjectID   string `json:"object_id"`
			Relation   string `json:"relation"`
			Subject    string `json:"subject"`
		} `json:"facts"`
	} `json:"classified"`
}

// Оба сценария используют один подписанный путь и закрытое состояние владельца.
func testMetadataOwnerRetentionNonempty(t *testing.T, probe metadataRetentionNonemptyProbe) {
	t.Helper()
	require.NotNil(t, probe)
	for _, keep := range []bool{true, false} {
		name := "second_holder_retains_new_fact"
		if !keep {
			name = "both_new_selectors_miss_old_physical_fact_stays_pending"
		}
		t.Run(name, func(t *testing.T) {
			var recipient string
			var losing, surviving domain.AccessBindingID
			w := metadataFixtureMode(t, false, "prepared", func(r protocolRig) {
				recipient, losing, surviving = seedMetadataRetentionTwoHolders(t, r)
			})
			bindings := []string{string(losing), string(surviving)}
			var memberBindings, ledgerBindings []string
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT coalesce(array_agg(DISTINCT binding_id ORDER BY binding_id),'{}'::text[])
 FROM kaname.access_binding_target_members WHERE binding_id=ANY($1::text[])
 AND object_type='iam.account' AND object_id=$2 AND verification_status='ACTIVE'`, bindings, w.r.a).Scan(&memberBindings))
			require.ElementsMatch(t, bindings, memberBindings)
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT coalesce(array_agg(DISTINCT binding_id ORDER BY binding_id),'{}'::text[])
 FROM kaname.access_binding_emitted_tuples WHERE binding_id=ANY($1::text[])
 AND member_object_type='iam.account' AND member_object_id=$2
 AND fga_user=$3 AND relation='viewer' AND object='account:'||$2`, bindings, w.r.a, "user:"+recipient).Scan(&ledgerBindings))
			require.ElementsMatch(t, bindings, ledgerBindings, "both physical holders emit the exact same tuple")
			var oldFact json.RawMessage
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT to_jsonb(f) FROM kaname.relation_fact f
 WHERE object_type='account' AND object_id=$1 AND relation='viewer' AND subject=$2`, w.r.a, "user:"+recipient).Scan(&oldFact))
			before := metadataRetentionNonemptyPhysical(t, w, bindings, recipient)
			root := w.account
			root.AccessLabels = domain.Labels{"team": "after", "keep": "yes"}
			if !keep {
				root.AccessLabels["keep"] = "no"
			}
			raw, err := probe(t, w, root)
			require.NoError(t, err)
			var result metadataRetentionNonemptyResult
			require.NoError(t, json.Unmarshal(raw, &result))
			require.NotNil(t, result.Desired)
			require.NotNil(t, result.Certificate.Bindings)
			require.NotNil(t, result.Classified.Retained)
			require.NotNil(t, result.Classified.Absent)
			require.NotNil(t, result.Classified.Pending)
			for _, id := range bindings {
				key := metadataRetentionFindCoordinate(t, result.Desired, id, "iam.account", w.r.a)
				members := result.Desired[key]
				require.NotNil(t, members, "missing/null proposal is never an empty certificate")
				binding, found := result.Certificate.Bindings[id]
				require.True(t, found)
				require.NotNil(t, binding.Desired)
				if id == string(losing) || !keep {
					require.Empty(t, members, "NEW protected selector no longer matches")
				} else {
					require.NotEmpty(t, members)
					foundTuple := false
					for _, member := range binding.Desired {
						if member.Status != domain.VerificationActive || member.ObjectType != "iam.account" || member.ObjectID != w.r.a {
							continue
						}
						for _, tuple := range member.Tuples {
							foundTuple = foundTuple || (tuple.User == "user:"+recipient && tuple.Relation == "viewer" && tuple.Object == "account:"+w.r.a)
						}
					}
					require.True(t, foundTuple, "owner independently certified the exact retained tuple")
				}
			}
			target := []string{"account", w.r.a, "viewer", "user:" + recipient}
			retained, absent, pending := 0, 0, 0
			for key, value := range result.Classified.Retained {
				if metadataRetentionKeyEquals(key, target) {
					retained++
					require.Equal(t, "verified_binding", value.Holder.Kind)
					require.Equal(t, string(surviving), value.Holder.Binding)
					require.JSONEq(t, string(oldFact), string(value.Fact), "retained receipt includes exact original fact row")
				}
			}
			for key := range result.Classified.Absent {
				if metadataRetentionKeyEquals(key, target) {
					absent++
				}
			}
			for _, fact := range result.Classified.Pending {
				if fact.ObjectType == target[0] && fact.ObjectID == target[1] && fact.Relation == target[2] && fact.Subject == target[3] {
					pending++
				}
			}
			require.Zero(t, absent, "the physical fact exists in both cases")
			if keep {
				require.Equal(t, []int{1, 0}, []int{retained, pending})
			} else {
				require.Equal(t, []int{0, 1}, []int{retained, pending}, "OLD ACTIVE rows alone cannot discharge NEW selection")
			}
			require.JSONEq(t, before, metadataRetentionNonemptyPhysical(t, w, bindings, recipient), "probe does not execute final writes")
		})
	}
}

func metadataRetentionFindCoordinate(t *testing.T, desired map[string][]reconcile.DesiredMember, binding, typ, id string) string {
	t.Helper()
	var keys []string
	for key := range desired {
		if metadataRetentionKeyEquals(key, []string{binding, typ, id}) {
			keys = append(keys, key)
		}
	}
	require.Len(t, keys, 1, "owner coordinate census must include the actual member identity")
	return keys[0]
}

func metadataRetentionKeyEquals(key string, expected []string) bool {
	var actual []string
	if json.Unmarshal([]byte(key), &actual) != nil || len(actual) != len(expected) {
		return false
	}
	for i := range expected {
		if actual[i] != expected[i] {
			return false
		}
	}
	return true
}

func metadataRetentionNonemptyPhysical(t *testing.T, w metadataWorld, bindings []string, recipient string) string {
	t.Helper()
	var snapshot string
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT jsonb_build_object(
 'root',(SELECT jsonb_build_array(xmin::text,ctid::text,to_jsonb(a)) FROM kaname.accounts a WHERE id=$1),
 'members',(SELECT coalesce(jsonb_agg(jsonb_build_array(m.xmin::text,m.ctid::text,to_jsonb(m)) ORDER BY m.binding_id,m.role_id,m.rule_fp,m.object_type,m.object_id),'[]') FROM kaname.access_binding_target_members m WHERE binding_id=ANY($2::text[])),
 'ledger',(SELECT coalesce(jsonb_agg(jsonb_build_array(l.xmin::text,l.ctid::text,to_jsonb(l)) ORDER BY l.binding_id,l.member_object_type,l.member_object_id,l.fga_user,l.relation,l.object),'[]') FROM kaname.access_binding_emitted_tuples l WHERE binding_id=ANY($2::text[])),
 'fact',(SELECT jsonb_build_array(f.xmin::text,f.ctid::text,to_jsonb(f)) FROM kaname.relation_fact f WHERE object_type='account' AND object_id=$1 AND relation='viewer' AND subject=$3))::text`, w.r.a, bindings, "user:"+recipient).Scan(&snapshot))
	return snapshot
}

func TestMetadataOwnerRetentionCertificateFromHeldSources(t *testing.T) {
	testMetadataOwnerRetentionNonempty(t, func(t *testing.T, w metadataWorld, root domain.Account) (json.RawMessage, error) {
		installMetadataOwnerHeldChainProbe(t, w.r)
		installMetadataRetentionCertificateProbe(t, w.r)
		return kanamepg.ProbeMetadataRetainedOwnerCertificate(w.r.ctx, w.factory, root,
			domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(w.actor)})
	})
}

func installMetadataRetentionCertificateProbe(t *testing.T, r protocolRig) {
	t.Helper()
	for _, signature := range []string{
		"kaname._authority_access_label_member_partition_v1(text,text,text[],jsonb,jsonb,jsonb,integer,integer)",
		"kaname._authority_access_label_old_facts_v2(text,text,text[],jsonb,jsonb,jsonb,integer,integer)",
		"kaname._authority_metadata_access_label_retention_prepare_v1(jsonb,boolean,integer,integer,integer)",
		"kaname._authority_metadata_access_label_retention_compile_v1(jsonb,integer)",
		"kaname._authority_metadata_access_label_retained_select_v1(jsonb,timestamptz,integer)",
	} {
		var installed, permitted bool
		require.NoError(t, r.runtime.QueryRow(r.ctx, `SELECT to_regprocedure($1) IS NOT NULL,
  CASE WHEN to_regprocedure($1) IS NOT NULL THEN has_function_privilege(current_user,$1,'EXECUTE') ELSE false END`, signature).Scan(&installed, &permitted))
		require.True(t, installed, signature)
		require.False(t, permitted, signature)
	}
	_, err := r.admin.Exec(r.ctx, `CREATE FUNCTION kaname.test_metadata_retention_inputs(
 p_patch jsonb,p_rename boolean,p_rows integer,p_reads integer,p_work integer
) RETURNS jsonb LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $inputs$
 SELECT kaname._authority_metadata_access_label_retention_prepare_v1(p_patch,p_rename,p_rows,p_reads,p_work)
$inputs$;
CREATE FUNCTION kaname.test_metadata_retention_compile(p_desired jsonb,p_work integer)
RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path=pg_catalog,pg_temp AS $compile$
DECLARE cert jsonb;proof jsonb;classified jsonb;
BEGIN
 cert:=kaname._authority_metadata_access_label_retention_compile_v1(p_desired,p_work);
 proof:=kaname.authority_protocol_attestation();
 classified:=kaname._authority_metadata_access_label_retained_select_v1(jsonb_build_object(
  'candidate_facts',cert#>'{receipt,facts}','prior_facts','[]'::jsonb,'retention',cert->'retention'),
  (proof->>'decision_at')::timestamptz,p_work-(cert->>'work')::integer);
 RETURN jsonb_build_object('desired',p_desired,'certificate',cert#>'{retention,certificate}','classified',classified);
END;
$compile$;
REVOKE ALL ON FUNCTION kaname.test_metadata_retention_inputs(jsonb,boolean,integer,integer,integer),
 kaname.test_metadata_retention_compile(jsonb,integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION kaname.test_metadata_retention_inputs(jsonb,boolean,integer,integer,integer),
 kaname.test_metadata_retention_compile(jsonb,integer) TO `+pgx.Identifier{r.role}.Sanitize())
	require.NoError(t, err)
}

func seedMetadataRetentionTwoHolders(t *testing.T, r protocolRig) (recipient string, losing, surviving domain.AccessBindingID) {
	t.Helper()
	seed, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, seed)
	// Устанавливаем историческую строку в тестовой БД. Триггер
	// снова действует к моменту commit и входа runtime.
	_, err = seed.Exec(r.ctx, `ALTER TABLE kaname.accounts DISABLE TRIGGER access_labels_immutable`)
	require.NoError(t, err)
	var freshnessInstalled bool
	require.NoError(t, seed.QueryRow(r.ctx, `SELECT EXISTS(SELECT 1 FROM pg_trigger
 WHERE tgrelid='kaname.accounts'::regclass AND tgname='access_labels_000_commit_freshness' AND NOT tgisinternal)`).Scan(&freshnessInstalled))
	if freshnessInstalled {
		_, err = seed.Exec(r.ctx, `ALTER TABLE kaname.accounts DISABLE TRIGGER access_labels_000_commit_freshness`)
		require.NoError(t, err)
	}
	_, err = seed.Exec(r.ctx, `UPDATE kaname.accounts SET access_labels='{"team":"before","keep":"yes"}'::jsonb WHERE id=$1`, r.a)
	require.NoError(t, err)
	_, err = seed.Exec(r.ctx, `ALTER TABLE kaname.accounts ENABLE TRIGGER access_labels_immutable`)
	require.NoError(t, err)
	if freshnessInstalled {
		_, err = seed.Exec(r.ctx, `ALTER TABLE kaname.accounts ENABLE TRIGGER access_labels_000_commit_freshness`)
		require.NoError(t, err)
	}
	clusterOwner := bindingPublicOwner(t, r)
	_, _, err = kanamepg.NewClusterAdminGrantWriter(r.admin).Grant(r.ctx, seed, domain.GrantSubjectTypeUser, domain.SubjectID(clusterOwner), clusterOwner)
	require.NoError(t, err)
	require.NoError(t, kanamepg.NewFGAOutboxEmitter().EmitWriteTx(r.ctx, seed, fgaTuplesGrantSystemAdmin(clusterOwner)))
	require.NoError(t, seed.Commit(r.ctx))
	recipient = seedMemberUser(t, r.ctx, r.admin, r.a, "retention-two-holder-recipient")
	// На корневом аккаунте кластерная область даёт вклад
	// по селектору без отдельной ветви scope_self.
	scope := domain.ScopeAnchor{Type: "cluster", ID: domain.ClusterSingletonID}
	losing = scopedGroupLifecycleBinding(t, r, scope, recipient, "retention_old_reader", domain.Rule{
		Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"},
		MatchAccessLabels: map[string]string{"team": "before"},
	})
	surviving = scopedGroupLifecycleBinding(t, r, scope, recipient, "retention_keep_reader", domain.Rule{
		Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"},
		MatchAccessLabels: map[string]string{"keep": "yes"},
	})
	// Штатный материализатор создаёт участника и журнал.
	// В relation_fact журнал сворачивает ярус viewer.
	source := rolePolicyCatalog(t, r)
	engine := reconcile.New(kanamepg.NewReconcileAdapter(r.admin, source), slog.Default(), source)
	for _, id := range []domain.AccessBindingID{losing, surviving} {
		require.NoError(t, engine.ReconcileBinding(r.ctx, id))
	}
	return recipient, losing, surviving
}
