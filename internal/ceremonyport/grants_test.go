// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// grants_test.go — адаптер порта отзыва гранта (задача PRO-Robotech/kaname#396,
// K1) и крючок чеканки идентификатора гранта.
package ceremonyport_test

import (
	"context"
	"errors"
	"go/parser"
	"go/token"
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/oauthceremony"

	"github.com/PRO-Robotech/kaname/internal/ceremonyport"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// recordingFamilies — подставка писателя отзыва семейства. Причину судит ТЕМ
// ЖЕ кодом, что настоящий (`domain.FamilyRevocationReason.Validate`), — дублёр
// не снисходительнее хранилища, чьё ограничение схемы отвергло бы причину вне
// словаря.
type recordingFamilies struct {
	calls []familyCall
	rows  int64
	err   error
}

type familyCall struct {
	familyID string
	reason   domain.FamilyRevocationReason
}

func (r *recordingFamilies) RevokeFamily(_ context.Context, familyID string, reason domain.FamilyRevocationReason) (int64, error) {
	r.calls = append(r.calls, familyCall{familyID: familyID, reason: reason})
	if r.err != nil {
		return 0, r.err
	}
	if err := reason.Validate(); err != nil {
		return 0, err
	}
	return r.rows, nil
}

// reasonsAwaitingAServiceWord — причины фундамента, у которых ЕЩЁ НЕТ слова в
// закрытом словаре службы, с предметом, который это слово заводит.
//
// Перечень истекает сам в обе стороны: причина, получившая слово, но стоящая
// здесь, — находка (запись пережила предмет); причина без слова и без записи —
// находка (путь отзыва не исполняется ни при каком входе, и никто этого не
// назвал). Пустой перечень — цель, а не отказ.
//
// `client-revoke`: слова нет ни в `domain.FamilyRevocationReasons()`, ни в
// ограничении `token_families_revoked_reason_ck`; оба заводятся одним
// изменением со своей приёмкой и миграцией — задачей PRO-Robotech/kaname#406.
// До тех пор отзыв клиентом отказывает операцией, не тронув семейства
// (`TestK1_ClientRevokeRefusesLoudlyWhileTheWordIsMissing`).
var reasonsAwaitingAServiceWord = map[oauthceremony.RevocationReason]string{
	oauthceremony.RevocationClientRevoke: "PRO-Robotech/kaname#406 (K1, путь отзыва клиентом)",
}

// issueRef — ссылка на задачу службы.
var issueRef = regexp.MustCompile(`PRO-Robotech/kaname#[0-9]+`)

// adaptersIssue — задача, которую закрывают сами адаптеры: её называет первая
// ссылка шапки пакета (`doc.go`). Выведена разбором шапки, а не выписана здесь:
// шапка сменит задачу — проба пойдёт за ней.
//
// Запись ожидания, названная этой задачей, — отсрочка, чьим владельцем стоит
// изменение, которое её и закрывает: после посадки маркер «пока слова нет»
// остаётся без предмета, и гейт перечня зеленеет на закрытой задаче.
func adaptersIssue(t *testing.T) string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "doc.go", nil, parser.ParseComments|parser.PackageClauseOnly)
	require.NoError(t, err, "НЕ ВЫПОЛНИЛОСЬ: шапка пакета не разобрана")
	require.NotNil(t, f.Doc, "НЕ ВЫПОЛНИЛОСЬ: у пакета нет шапки")
	own := issueRef.FindString(f.Doc.Text())
	require.NotEmpty(t, own, "НЕ ВЫПОЛНИЛОСЬ: шапка пакета не называет своей задачи")
	return own
}

// Всякая причина закрытого словаря фундамента имеет слово в закрытом словаре
// службы — ТЕМ ЖЕ написанием (фундамент сопрягает словари по значению), —
// либо названа перечнем ожидающих с предметом.
func TestGrants_EveryCeremonyReasonHasAFamilyWordOrANamedSubject(t *testing.T) {
	reasons := oauthceremony.RevocationReasons()
	require.NotEmpty(t, reasons, "НЕ ВЫПОЛНИЛОСЬ: словарь причин фундамента пуст")
	mapped := 0
	for _, r := range reasons {
		word, ok := ceremonyport.FamilyReasonOf(r)
		subject, awaiting := reasonsAwaitingAServiceWord[r]
		switch {
		case ok && awaiting:
			t.Errorf("причина %q получила слово службы, а запись ожидания (%s) стоит — снимите её", r, subject)
		case !ok && !awaiting:
			t.Errorf("причина фундамента %q без слова службы и без предмета: этот путь отзыва "+
				"не исполняется ни при каком входе", r)
		case ok:
			mapped++
			require.Equal(t, string(r), string(word), "сопряжение не по значению")
			require.NoErrorf(t, word.Validate(), "слово %q вне закрытого словаря службы", word)
		}
	}
	own := adaptersIssue(t)
	for r, subject := range reasonsAwaitingAServiceWord {
		require.Truef(t, r.Declared(), "запись ожидания %q не называет причины фундамента", r)
		ref := issueRef.FindString(subject)
		require.NotEmptyf(t, ref, "запись ожидания %q не называет задачу формой PRO-Robotech/kaname#N: %q", r, subject)
		require.NotEqualf(t, own, ref, "запись ожидания %q названа задачей самих адаптеров (%s): после её "+
			"закрытия у неисполненного пути отзыва не останется владельца", r, own)
	}
	t.Logf("осмотрено: причин фундамента %d · сопряжено %d · ожидают слова %d",
		len(reasons), mapped, len(reasonsAwaitingAServiceWord))
	require.Positive(t, mapped, "НЕ ВЫПОЛНИЛОСЬ: не сопряжено ни одной причины")

	_, ok := ceremonyport.FamilyReasonOf(oauthceremony.RevocationReason(""))
	require.False(t, ok, "«причина не названа» сопряжена со словом службы")
	_, ok = ceremonyport.FamilyReasonOf(oauthceremony.RevocationReason("session-ended"))
	require.False(t, ok, "слово службы вне словаря фундамента принято за причину фундамента")
}

// Оба метода порта отзывают СЕМЕЙСТВО гранта с причиной, которую назвала
// церемония, и отдают названный исход.
func TestGrants_RevokeTheFamilyWithTheCeremonyReason(t *testing.T) {
	for _, method := range []struct {
		name string
		call func(*ceremonyport.Grants, string, oauthceremony.RevocationReason) (oauthceremony.StoreOutcome, error)
	}{
		{"RevokeGrantRefreshTokens", func(g *ceremonyport.Grants, id string, r oauthceremony.RevocationReason) (oauthceremony.StoreOutcome, error) {
			return g.RevokeGrantRefreshTokens(context.Background(), id, r)
		}},
		{"RevokeGrantAccessTokens", func(g *ceremonyport.Grants, id string, r oauthceremony.RevocationReason) (oauthceremony.StoreOutcome, error) {
			return g.RevokeGrantAccessTokens(context.Background(), id, r)
		}},
	} {
		for _, reason := range oauthceremony.RevocationReasons() {
			if _, awaiting := reasonsAwaitingAServiceWord[reason]; awaiting {
				continue
			}
			t.Run(method.name+"/"+string(reason), func(t *testing.T) {
				families := &recordingFamilies{rows: 1}
				g, err := ceremonyport.NewGrants(families)
				require.NoError(t, err)

				out, err := method.call(g, testFamily, reason)
				require.NoError(t, err)
				require.True(t, out.Declared(), "исход отзыва не назван")
				require.EqualValues(t, 1, out.Rows())
				require.Equal(t, []familyCall{{familyID: testFamily, reason: domain.FamilyRevocationReason(reason)}},
					families.calls)

				// Повтор уже отозванного — ноль строк, законный исход, не отказ.
				families.rows = 0
				out, err = method.call(g, testFamily, reason)
				require.NoError(t, err)
				require.True(t, out.Declared())
				require.EqualValues(t, 0, out.Rows())
			})
		}
	}
}

// Вход, который отзывом не является, отвергается ДО записи: писатель не зван.
// Отказ хранилища — отказ операции, а не названный исход.
func TestGrants_RefuseBeforeAnyWrite(t *testing.T) {
	for _, tc := range []struct {
		name    string
		grantID string
		reason  oauthceremony.RevocationReason
	}{
		{"причина не названа", testFamily, ""},
		{"причина вне словаря фундамента", testFamily, "session-ended"},
		{"причина фундамента без слова службы", testFamily, oauthceremony.RevocationClientRevoke},
		{"грант без идентификатора", "", oauthceremony.RevocationCodeReplay},
	} {
		t.Run(tc.name, func(t *testing.T) {
			families := &recordingFamilies{rows: 1}
			g, err := ceremonyport.NewGrants(families)
			require.NoError(t, err)
			out, err := g.RevokeGrantRefreshTokens(context.Background(), tc.grantID, tc.reason)
			require.Error(t, err)
			require.False(t, out.Declared(), "при отказе назван исход записи")
			require.Empty(t, families.calls, "писатель зван на входе, который отзывом не является")
		})
	}

	t.Run("отказ хранилища", func(t *testing.T) {
		families := &recordingFamilies{err: errors.New("хранилище недоступно")}
		g, err := ceremonyport.NewGrants(families)
		require.NoError(t, err)
		out, err := g.RevokeGrantAccessTokens(context.Background(), testFamily, oauthceremony.RevocationCodeReplay)
		require.Error(t, err)
		require.False(t, out.Declared())
	})

	_, err := ceremonyport.NewGrants(nil)
	require.Error(t, err, "адаптер без писателя собран")
}

// Идентификатор гранта чеканит служба — формой, которую держит ограничение
// схемы семейств (`token_families_id_form_ck`), и каждый раз новый.
func TestNewGrantID_MintsTheFamilyKeyForm(t *testing.T) {
	familyForm := regexp.MustCompile(`^tfm-[0-9a-hjkmnp-tv-z]{17}$`)
	seen := map[string]bool{}
	for range 64 {
		id, err := ceremonyport.NewGrantID(context.Background())
		require.NoError(t, err)
		require.Regexp(t, familyForm, id, "идентификатор гранта вне формы ключа семейства")
		require.False(t, seen[id], "идентификатор гранта повторился")
		seen[id] = true
	}
}
