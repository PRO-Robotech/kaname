// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// interactive_client_secret_material_writer_injection_test.go — способность
// гейта G (`TestInteractiveClientSecretMaterialHasOneWriter`) упасть и
// смолчать. Каждая сцена — синтетический пакет, отличающийся от законного
// ОДНИМ фактом; законный пакет — положительный контроль.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// lawfulClientMaterialPackage — пакет той же формы, что настоящий: вставка
// кладёт строку, материал и момент одним оператором; снятие присваивает пустую
// строку; чтение называет колонку.
const lawfulClientMaterialPackage = `package pg

const icCols = "id, name, client_id, token_endpoint_auth_method"

type InteractiveClientRepo struct{ pool pooler }

type OAuthCeremonyRepo struct{ pool pooler }

type pooler interface{ Exec(q string, args ...any) error }

func (r *InteractiveClientRepo) Insert(id, material string) error {
	const q = ` + "`" + `INSERT INTO interactive_clients (
		id, name, client_id, token_endpoint_auth_method, secret_verifier, secret_verifier_set_at)
		VALUES ($1, $2, $3, $4, $5, CASE WHEN $5::text = '' THEN NULL ELSE now() END)
		RETURNING ` + "` + icCols" + `
	return r.pool.Exec(q, id, material)
}

func (r *OAuthCeremonyRepo) ClearClientSecretVerifier(clientID string) error {
	return r.pool.Exec(` + "`" + `
		UPDATE kaname.interactive_clients
		   SET secret_verifier = '', secret_verifier_set_at = NULL
		 WHERE client_id = $1` + "`" + `, clientID)
}

func (r *OAuthCeremonyRepo) ClientSecretVerifier(clientID string) error {
	return r.pool.Exec("SELECT secret_verifier FROM kaname.interactive_clients WHERE client_id = $1", clientID)
}
`

func writeClientMaterialPackage(t *testing.T, extra map[string]string, edit func(string) string) string {
	t.Helper()
	dir := t.TempDir()
	body := lawfulClientMaterialPackage
	if edit != nil {
		body = edit(body)
	}
	require.NoError(t, os.WriteFile(filepath.Join(dir, "repo.go"), []byte(body), 0o600))
	for name, src := range extra {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(src), 0o600))
	}
	return dir
}

func TestClientMaterialGate_LawfulPackageIsSilent(t *testing.T) {
	findings, census, err := auditClientMaterialWriters(writeClientMaterialPackage(t, nil, nil))
	require.NoError(t, err)
	t.Log(census)
	require.Empty(t, findings, "законный пакет обязан молчать — иначе красное в сценах ничего не доказывает")
	require.Equal(t, []string{"InteractiveClientRepo.Insert @ repo.go:11"}, census.writers,
		"перепись обязана назвать законного писателя с координатой")
	require.Equal(t, 1, census.clears, "снятие материала — законный близнец, и перепись обязана его видеть")
	require.True(t, census.writerStamps)
}

func TestClientMaterialGate_Injection(t *testing.T) {
	for _, sc := range []struct {
		name        string
		extra       map[string]string
		edit        func(string) string
		wantFinding string
	}{
		{
			// Сама форма дефекта, ради которого гейт заведён: вставка, затем
			// отдельная запись материала.
			name: "вставка, затем отдельная запись материала",
			extra: map[string]string{"verifier.go": `package pg

func (r *OAuthCeremonyRepo) SetClientSecretVerifier(clientID, material string) error {
	return r.pool.Exec(` + "`" + `UPDATE kaname.interactive_clients
		   SET secret_verifier = $2, secret_verifier_set_at = now()
		 WHERE client_id = $1` + "`" + `, clientID, material)
}
`},
			wantFinding: "OAuthCeremonyRepo.SetClientSecretVerifier @ verifier.go:3: второй писатель материала",
		},
		{
			name: "второй писатель через склейку константы пакета",
			extra: map[string]string{"verifier.go": `package pg

const setMaterial = "UPDATE interactive_clients SET " + "secret_verifier = $2"

func (r *OAuthCeremonyRepo) Rotate(clientID, material string) error {
	return r.pool.Exec(setMaterial+" WHERE client_id = $1", clientID, material)
}
`},
			wantFinding: "OAuthCeremonyRepo.Rotate @ verifier.go:5: второй писатель материала",
		},
		{
			name: "второй писатель: схема и имена в кавычках",
			extra: map[string]string{"verifier.go": `package pg

func (r *OAuthCeremonyRepo) Put(clientID, material string) error {
	return r.pool.Exec("UPDATE \"kaname\".\"interactive_clients\" SET \"secret_verifier\" = $2 WHERE client_id = $1", clientID, material)
}
`},
			wantFinding: "OAuthCeremonyRepo.Put @ verifier.go:3: второй писатель материала",
		},
		{
			name: "вторая вставка, называющая колонку материала",
			extra: map[string]string{"seed.go": `package pg

func seed(p pooler, material string) error {
	return p.Exec("INSERT INTO kaname.interactive_clients (id, secret_verifier, secret_verifier_set_at) VALUES ($1, $2, now())", "ic", material)
}
`},
			wantFinding: "seed @ seed.go:3: второй писатель материала",
		},
		// ЗАКОННЫЕ ФОРМЫ ЗАПИСИ, КОТОРЫХ ПРЕЖНИЙ РАСПОЗНАВАТЕЛЬ НЕ ЗНАЛ (круг 1
		// сборки 435, опыты b405_1 и b405_5 проверяющего): прежний отбор требовал
		// «interactive_clients SET» подряд и «INSERT INTO interactive_clients (»,
		// и каждая форма ниже проходила зелёной при втором писателе. Формы
		// перечислены по грамматике операторов записи Postgres 16, а не по памяти:
		// UPDATE [ONLY] таблица [[AS] псевдоним] SET (колонка = … | (колонки) = …),
		// INSERT INTO таблица [AS псевдоним] (колонки) … [ON CONFLICT … DO UPDATE SET …],
		// MERGE INTO таблица [[AS] псевдоним] … THEN UPDATE SET … | THEN INSERT (колонки).
		{
			name: "второй писатель: UPDATE с псевдонимом через AS",
			extra: map[string]string{"verifier.go": `package pg

func (r *OAuthCeremonyRepo) SetAliased(clientID, material string) error {
	return r.pool.Exec("UPDATE kaname.interactive_clients AS c SET secret_verifier = $2 WHERE c.client_id = $1", clientID, material)
}
`},
			wantFinding: "OAuthCeremonyRepo.SetAliased @ verifier.go:3: второй писатель материала",
		},
		{
			name: "второй писатель: UPDATE с псевдонимом без AS",
			extra: map[string]string{"verifier.go": `package pg

func (r *OAuthCeremonyRepo) SetBareAlias(clientID, material string) error {
	return r.pool.Exec("UPDATE interactive_clients c SET secret_verifier = $2 WHERE c.client_id = $1", clientID, material)
}
`},
			wantFinding: "OAuthCeremonyRepo.SetBareAlias @ verifier.go:3: второй писатель материала",
		},
		{
			name: "второй писатель: UPDATE ONLY",
			extra: map[string]string{"verifier.go": `package pg

func (r *OAuthCeremonyRepo) SetOnly(clientID, material string) error {
	return r.pool.Exec("UPDATE ONLY interactive_clients SET secret_verifier = $2 WHERE client_id = $1", clientID, material)
}
`},
			wantFinding: "OAuthCeremonyRepo.SetOnly @ verifier.go:3: второй писатель материала",
		},
		{
			name: "второй писатель: SET кортежем",
			extra: map[string]string{"verifier.go": `package pg

func (r *OAuthCeremonyRepo) SetTuple(clientID, material string) error {
	return r.pool.Exec("UPDATE interactive_clients SET (secret_verifier, secret_verifier_set_at) = ($2, now()) WHERE client_id = $1", clientID, material)
}
`},
			wantFinding: "OAuthCeremonyRepo.SetTuple @ verifier.go:3: второй писатель материала",
		},
		{
			name: "второй писатель: вставка с псевдонимом таблицы",
			extra: map[string]string{"seed.go": `package pg

func seedAliased(p pooler, material string) error {
	return p.Exec("INSERT INTO kaname.interactive_clients AS ic (id, secret_verifier, secret_verifier_set_at) VALUES ($1, $2, now())", "ic", material)
}
`},
			wantFinding: "seedAliased @ seed.go:3: второй писатель материала",
		},
		{
			name: "второй писатель: upsert ON CONFLICT DO UPDATE SET",
			extra: map[string]string{"verifier.go": `package pg

func (r *OAuthCeremonyRepo) Upsert(id, material string) error {
	return r.pool.Exec("INSERT INTO interactive_clients (id, name) VALUES ($1, 'n') "+
		"ON CONFLICT (id) DO UPDATE SET secret_verifier = EXCLUDED.secret_verifier", id, material)
}
`},
			wantFinding: "OAuthCeremonyRepo.Upsert @ verifier.go:3: второй писатель материала",
		},
		{
			name: "второй писатель: MERGE … THEN UPDATE SET",
			extra: map[string]string{"verifier.go": `package pg

func (r *OAuthCeremonyRepo) Merge(id, material string) error {
	return r.pool.Exec(` + "`" + `MERGE INTO kaname.interactive_clients AS t
		USING (SELECT $1::text AS id) s ON t.id = s.id
		WHEN MATCHED THEN UPDATE SET secret_verifier = $2` + "`" + `, id, material)
}
`},
			wantFinding: "OAuthCeremonyRepo.Merge @ verifier.go:3: второй писатель материала",
		},
		{
			name: "второй писатель: MERGE … THEN INSERT с колонкой материала",
			extra: map[string]string{"verifier.go": `package pg

func (r *OAuthCeremonyRepo) MergeInsert(id, material string) error {
	return r.pool.Exec(` + "`" + `MERGE INTO interactive_clients t
		USING (SELECT $1::text AS id) s ON t.id = s.id
		WHEN NOT MATCHED THEN INSERT (id, secret_verifier) VALUES (s.id, $2)` + "`" + `, id, material)
}
`},
			wantFinding: "OAuthCeremonyRepo.MergeInsert @ verifier.go:3: второй писатель материала",
		},
		{
			// Та же слепая зона, что у переписи писателей сессии (круг 1, 382):
			// обход судил только тела объявлений функций.
			name: "второй писатель литералом функции уровня пакета",
			extra: map[string]string{"verifier.go": `package pg

var rotateMaterial = func(p pooler, material string) error {
	return p.Exec("UPDATE interactive_clients SET secret_verifier = $1", material)
}
`},
			wantFinding: "rotateMaterial @ verifier.go:3: второй писатель материала",
		},
		{
			name: "вставка без материала",
			edit: func(s string) string {
				return strings.Replace(s, "token_endpoint_auth_method, secret_verifier, secret_verifier_set_at)",
					"token_endpoint_auth_method)", 1)
			},
			wantFinding: "InteractiveClientRepo.Insert: вставка строки клиента материала не кладёт",
		},
		{
			name: "вставка материала без момента установки",
			edit: func(s string) string {
				return strings.Replace(s, "secret_verifier, secret_verifier_set_at)", "secret_verifier)", 1)
			},
			wantFinding: "InteractiveClientRepo.Insert @ repo.go:11: вставка кладёт материал, но не момент",
		},
		{
			name: "законный близнец: второе снятие материала пустой строкой",
			extra: map[string]string{"clear.go": `package pg

func (r *OAuthCeremonyRepo) ClearAll() error {
	return r.pool.Exec("UPDATE interactive_clients SET secret_verifier = ''::text, secret_verifier_set_at = NULL")
}
`},
		},
		{
			name: "законный близнец: писатель назван в комментарии и в строке ошибки",
			extra: map[string]string{"doc.go": `package pg

import "errors"

// UPDATE interactive_clients SET secret_verifier = $2 — так писать нельзя.
var errDoc = errors.New("secret_verifier is written by the insert only")
`},
		},
		{
			name: "законный близнец: снятие через псевдоним",
			extra: map[string]string{"clear.go": `package pg

func (r *OAuthCeremonyRepo) ClearAliased(clientID string) error {
	return r.pool.Exec("UPDATE kaname.interactive_clients AS c SET secret_verifier = '', secret_verifier_set_at = NULL WHERE c.client_id = $1", clientID)
}
`},
		},
		{
			name: "законный близнец: снятие кортежем",
			extra: map[string]string{"clear.go": `package pg

func (r *OAuthCeremonyRepo) ClearTuple(clientID string) error {
	return r.pool.Exec("UPDATE interactive_clients SET (secret_verifier, secret_verifier_set_at) = ('', NULL) WHERE client_id = $1", clientID)
}
`},
		},
		{
			name: "законный близнец: upsert реестра, не трогающий материал",
			extra: map[string]string{"upsert.go": `package pg

func (r *OAuthCeremonyRepo) Rename(id, name string) error {
	return r.pool.Exec("INSERT INTO interactive_clients (id, name) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name", id, name)
}
`},
		},
		{
			name: "законный близнец: upsert другой таблицы с той же колонкой",
			extra: map[string]string{"upsert.go": `package pg

func (r *OAuthCeremonyRepo) Archive(id, material string) error {
	return r.pool.Exec("INSERT INTO interactive_clients_archive (id) VALUES ($1) ON CONFLICT (id) DO UPDATE SET secret_verifier = $2", id, material)
}
`},
		},
		{
			name: "законный близнец: реестр — источник FROM, а не цель",
			extra: map[string]string{"copy.go": `package pg

func (r *OAuthCeremonyRepo) CopyOut() error {
	return r.pool.Exec("UPDATE client_audit a SET secret_verifier = ic.secret_verifier FROM interactive_clients ic WHERE ic.id = a.id")
}
`},
		},
		{
			name: "законный близнец: чтение под замком FOR UPDATE",
			extra: map[string]string{"lock.go": `package pg

func (r *OAuthCeremonyRepo) Lock(id string) error {
	return r.pool.Exec("SELECT secret_verifier FROM interactive_clients WHERE id = $1 FOR UPDATE", id)
}
`},
		},
		{
			name: "законный близнец: запись другой таблицы с той же колонкой",
			extra: map[string]string{"other.go": `package pg

func (r *OAuthCeremonyRepo) Other(material string) error {
	return r.pool.Exec("UPDATE interactive_clients_archive SET secret_verifier = $1", material)
}
`},
		},
	} {
		t.Run(sc.name, func(t *testing.T) {
			findings, census, err := auditClientMaterialWriters(writeClientMaterialPackage(t, sc.extra, sc.edit))
			require.NoError(t, err)
			t.Log(census)
			t.Logf("находки: %q", findings)
			if sc.wantFinding == "" {
				require.Empty(t, findings, "законный близнец обязан молчать")
				return
			}
			require.NotEmpty(t, findings, "внесённый дефект обязан быть найден")
			require.Contains(t, strings.Join(findings, "\n"), sc.wantFinding, "находка обязана называть координату")
		})
	}
}

// TestClientMaterialGate_EmptyPackageIsNotClean — пустой обход не зелёный.
func TestClientMaterialGate_EmptyPackageIsNotClean(t *testing.T) {
	_, _, err := auditClientMaterialWriters(t.TempDir())
	require.Error(t, err)
	require.Contains(t, err.Error(), "не выполнилось")
}
