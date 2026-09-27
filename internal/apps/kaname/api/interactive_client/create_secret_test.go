// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package interactiveclient

// create_secret_test.go — секрет конфиденциального клиента на пути `Create`
// (приёмка confidential-interactive-client-secret-shown-once, задача
// PRO-Robotech/kaname#405), на слое, который владеет РАЗВЕДЕНИЕМ тел и
// согласием тройки «способ ⟺ материал ⟺ секрет».
//
// Порты — дублёры, и это решение, а не упрощение: здесь судится порядок и
// форма того, что уходит в строку операции и что уходит вызывающему, а
// настоящее хранилище сделало бы тело, переданное в терминальную запись,
// ненаблюдаемым. Хранилище судят пробы слоя доступа
// (`internal/repo/kaname/pg/interactive_client_secret_integration_test.go`).

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/logbuf"
)

// probeSecret — секрет, которого ни одна строка кода не знает: проба ищет его
// ПО ЗНАЧЕНИЮ. Образец имени (`client_secret`) совпал бы с законным значением
// способа `client_secret_basic` и краснел бы на верном ответе.
const probeSecret = "S-probe-7Qm2vK9xT4nW8cR1bZ6yH3jL5pD0fA"

// probeClientID — имя клиента, которое отдаёт дублёр реестра.
const probeClientID = "oic-probe0000000000000"

// probeVerifierPHC — значение ФОРМЫ проверочного значения; сверяться с ним
// здесь нечему — порт хранилища дублёр.
const probeVerifierPHC = "$argon2id$v=19$m=65536,t=3,p=4$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

// secretRegistry — дублёр реестра, выдающий клиента той формы, которую
// назначает проба: способ, секрет, проверочное значение — по отдельности, чтобы
// каждое сочетание тройки было выразимо.
type secretRegistry struct {
	method       string
	secret       string
	verifier     bool
	deregErr     error
	deregistered []string
}

func (p *secretRegistry) Register(_ context.Context, in ProviderClientSpec) (ProviderClient, error) {
	pc := ProviderClient{
		ClientID:                probeClientID,
		GrantTypes:              append([]string(nil), in.GrantTypes...),
		TokenEndpointAuthMethod: p.method,
		Audiences:               append([]string(nil), in.Audiences...),
	}
	if p.secret != "" {
		s, err := NewClientSecret(p.secret)
		if err != nil {
			return ProviderClient{}, err
		}
		pc.Secret = s
	}
	if p.verifier {
		v, err := domain.NewLoginVerifier(probeVerifierPHC)
		if err != nil {
			return ProviderClient{}, err
		}
		pc.SecretVerifier = v
	}
	return pc, nil
}

func (p *secretRegistry) Deregister(_ context.Context, id string) error {
	p.deregistered = append(p.deregistered, id)
	return p.deregErr
}

// confidential — реестр, заводящий клиента так, как требует Р1: способ
// секретом, секрет и его проверочное значение.
func confidential() *secretRegistry {
	return &secretRegistry{method: "client_secret_basic", secret: probeSecret, verifier: true}
}

// insertRecordingRepo — хранилище, записывающее каждую вставку вместе с
// материалом и каждое снятие строки.
type insertRecordingRepo struct {
	fakeRepo
	inserted  []domain.InteractiveClient
	materials []domain.LoginVerifier
	deleted   []domain.InteractiveClientID
	insertErr error
}

func (r *insertRecordingRepo) Insert(_ context.Context, c domain.InteractiveClient, m domain.LoginVerifier) (domain.InteractiveClient, error) {
	r.inserted = append(r.inserted, c)
	r.materials = append(r.materials, m)
	if r.insertErr != nil {
		return domain.InteractiveClient{}, r.insertErr
	}
	c.CreatedAt = time.Unix(1_800_000_000, 0).UTC()
	return c, nil
}

func (r *insertRecordingRepo) Delete(_ context.Context, id domain.InteractiveClientID) (domain.InteractiveClient, bool, error) {
	r.deleted = append(r.deleted, id)
	return domain.InteractiveClient{ID: id}, true, nil
}

// executeCreate — глагол как есть, без суждения о форме ответа: пробы, чей
// предмет не форма ответа, не краснеют на ней.
func executeCreate(repo clientRepo, reg ProviderClients, ops *fakeOps, logger *slog.Logger) (*operationpb.Operation, error) {
	return NewCreateUseCase(repo, reg, ops, []string{"https://api.example"}, logger).
		Execute(context.Background(), createReq())
}

func createWith(t *testing.T, repo clientRepo, reg ProviderClients, ops *fakeOps, logger *slog.Logger) (*iamv1.CreateInteractiveClientResponse, error) {
	t.Helper()
	op, err := executeCreate(repo, reg, ops, logger)
	if err != nil {
		if op != nil {
			t.Fatalf("отказ заведения обязан быть синхронным и без операции, а вернулась операция %q", op.GetId())
		}
		return nil, err
	}
	if !op.GetDone() || op.GetError() != nil {
		t.Fatalf("заведение обязано завершаться на пути запроса без ошибки: done=%t error=%v", op.GetDone(), op.GetError())
	}
	var resp iamv1.CreateInteractiveClientResponse
	if uerr := op.GetResponse().UnmarshalTo(&resp); uerr != nil {
		t.Fatalf("ответ операции Create обязан быть CreateInteractiveClientResponse (Р4): %v", uerr)
	}
	return &resp, nil
}

// TestCreate_IC01_SecretIsShownInTheAnswerOfTheCall — IC-SECRET-01 на слое
// use-case: ответ вызова несёт ресурс и секрет, а вставка получила материал.
func TestCreate_IC01_SecretIsShownInTheAnswerOfTheCall(t *testing.T) {
	repo := &insertRecordingRepo{}
	resp, err := createWith(t, repo, confidential(), &fakeOps{}, nil)
	if err != nil {
		t.Fatalf("заведение конфиденциального клиента отказало: %v", err)
	}
	ic := resp.GetInteractiveClient()
	if ic.GetClientId() != probeClientID || ic.GetTokenEndpointAuthMethod() != "client_secret_basic" {
		t.Errorf("ресурс в ответе не тот, что завёл реестр: client_id=%q method=%q", ic.GetClientId(), ic.GetTokenEndpointAuthMethod())
	}
	if resp.GetClientSecret() != probeSecret {
		t.Errorf("ответ вызова Create обязан нести выданный секрет, а несёт %d знаков", len(resp.GetClientSecret()))
	}
	if len(repo.materials) != 1 || repo.materials[0].IsZero() {
		t.Error("вставка строки не получила проверочного значения: клиенту со способом секретом нечего будет предъявить (Р5)")
	}
}

// TestCreate_IC02_OperationRowNeverCarriesTheSecret — IC-SECRET-02 на слое
// use-case: тело, переданное в MarkDone, секрета не несёт ни полем, ни
// подстрокой; тело вызывающему — несёт. Отличие близнецов в одном факте: какое
// из двух тел читается.
func TestCreate_IC02_OperationRowNeverCarriesTheSecret(t *testing.T) {
	ops := &fakeOps{}
	shown, err := createWith(t, &insertRecordingRepo{}, confidential(), ops, nil)
	if err != nil {
		t.Fatalf("заведение отказало: %v", err)
	}
	if !ops.doneMarked || ops.doneResp == nil {
		t.Fatal("терминальная запись не состоялась — судить её тело нечего")
	}
	if !bytes.Contains(ops.doneResp.GetValue(), []byte(probeClientID)) {
		t.Fatal("ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: тело строки операции не несёт даже имени клиента — «секрета нет» значило бы «ответа нет»")
	}
	if bytes.Contains(ops.doneResp.GetValue(), []byte(probeSecret)) {
		t.Error("тело, записанное в строку операции, несёт секрет подстрокой: «показан один раз» стало «лежит в базе»")
	}
	var stored iamv1.CreateInteractiveClientResponse
	if uerr := ops.doneResp.UnmarshalTo(&stored); uerr != nil {
		t.Fatalf("тело строки операции не CreateInteractiveClientResponse: %v", uerr)
	}
	if stored.GetClientSecret() != "" {
		t.Error("поле client_secret тела строки операции непусто")
	}
	if shown.GetClientSecret() != probeSecret {
		t.Error("БЛИЗНЕЦ: ответ вызова обязан нести секрет — иначе проба выше зеленела бы на заведении, которое секрета не выдало")
	}
}

// TestCreate_ShownBodyThatCannotBeBuiltIsAnErrorNotADone — условие поверхности
// п.1: срыв сборки тела С СЕКРЕТОМ — терминальная ошибка, а не `done`; секрета
// нет ни в ответе, ни в тексте отказа; строка, уже записанная этим вызовом,
// снимается, а заведение у реестра — отзывается (несостоявшееся заведение не
// оставляет клиента, которого никто не может доказать).
//
// Срыв подан настоящим: строка proto3 обязана быть UTF-8, и секрет с
// недопустимыми байтами `anypb.New` не упакует — тело без секрета при этом
// пакуется, то есть сорвалось ровно второе тело.
func TestCreate_ShownBodyThatCannotBeBuiltIsAnErrorNotADone(t *testing.T) {
	broken := "\xff\xfe" + probeSecret
	reg := &secretRegistry{method: "client_secret_basic", secret: broken, verifier: true}
	repo := &insertRecordingRepo{}
	ops := &fakeOps{}

	_, err := createWith(t, repo, reg, ops, nil)

	if err == nil {
		t.Fatal("тело с секретом не собралось, а заведение объявлено успешным")
	}
	st, _ := status.FromError(err)
	if st.Code() != codes.Internal || st.Message() != "internal error" {
		t.Errorf("отказ обязан быть INTERNAL фиксированным текстом, а пришло %v %q", st.Code(), st.Message())
	}
	if strings.Contains(err.Error(), probeSecret) {
		t.Error("текст отказа несёт секрет")
	}
	if ops.doneMarked {
		t.Error("операция помечена done, хотя тело вызывающему не собралось")
	}
	if !ops.errMarked {
		t.Error("операция не помечена ошибкой")
	}
	if len(repo.inserted) != 1 {
		t.Fatalf("ПРЕДУСЛОВИЕ: вставка обязана была состояться (срыв — после неё), вставок %d", len(repo.inserted))
	}
	if len(repo.deleted) != 1 || repo.deleted[0] != repo.inserted[0].ID {
		t.Errorf("строка, записанная сорвавшимся заведением, не снята: %v", repo.deleted)
	}
	if len(reg.deregistered) != 1 || reg.deregistered[0] != probeClientID {
		t.Errorf("заведение у реестра не отозвано: %v", reg.deregistered)
	}
}

// TestCreate_SecretMaterialMustAgreeWithTheMethod — условие поверхности п.8:
// способ секретом без секрета либо без проверочного значения, способ `none` с
// ними, способ вне словаря — отказ `INTERNAL` фиксированным текстом ДО вставки;
// строки нет, секрета в ответе нет.
func TestCreate_SecretMaterialMustAgreeWithTheMethod(t *testing.T) {
	for _, tc := range []struct {
		name    string
		reg     *secretRegistry
		refused bool
	}{
		{"законный близнец: способ секретом, секрет и материал", confidential(), false},
		{"законный близнец: публичный клиент без секрета и материала", &secretRegistry{method: "none"}, false},
		{"способ секретом без проверочного значения", &secretRegistry{method: "client_secret_basic", secret: probeSecret}, true},
		{"способ секретом без секрета", &secretRegistry{method: "client_secret_basic", verifier: true}, true},
		{"способ секретом в форме без секрета и материала", &secretRegistry{method: "client_secret_post"}, true},
		{"способ none с секретом и материалом", &secretRegistry{method: "none", secret: probeSecret, verifier: true}, true},
		{"способ none с одним материалом", &secretRegistry{method: "none", verifier: true}, true},
		{"способ вне словаря", &secretRegistry{method: "private_key_jwt", secret: probeSecret, verifier: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			repo := &insertRecordingRepo{}
			ops := &fakeOps{}
			op, err := executeCreate(repo, tc.reg, ops, nil)
			if !tc.refused {
				if err != nil {
					t.Fatalf("законное сочетание отвергнуто: %v", err)
				}
				if len(repo.inserted) != 1 {
					t.Fatalf("законное сочетание не дошло до вставки")
				}
				return
			}
			if err == nil {
				t.Fatalf("несогласная тройка принята: клиент со способом %q получил строку и операцию %q",
					tc.reg.method, op.GetId())
			}
			st, _ := status.FromError(err)
			if st.Code() != codes.Internal || st.Message() != "internal error" {
				t.Errorf("отказ обязан быть INTERNAL фиксированным текстом, а пришло %v %q", st.Code(), st.Message())
			}
			if strings.Contains(err.Error(), probeSecret) {
				t.Error("текст отказа несёт секрет")
			}
			if len(repo.inserted) != 0 {
				t.Error("строка записана при несогласной тройке")
			}
			if !ops.errMarked || ops.doneMarked {
				t.Errorf("операция обязана быть помечена ошибкой: errMarked=%t doneMarked=%t", ops.errMarked, ops.doneMarked)
			}
		})
	}
}

// TestCreate_IC11_PublicClientAnswersWithAnEmptySecret — IC-SECRET-11 на слое
// use-case: клиент, которого реестр завёл публичным, получает ответ того же
// типа с пустым секретом, и об отсутствии секрета говорит способ.
func TestCreate_IC11_PublicClientAnswersWithAnEmptySecret(t *testing.T) {
	resp, err := createWith(t, &insertRecordingRepo{}, &secretRegistry{method: "none"}, &fakeOps{}, nil)
	if err != nil {
		t.Fatalf("заведение публичного клиента отказало: %v", err)
	}
	if resp.GetInteractiveClient().GetTokenEndpointAuthMethod() != "none" {
		t.Errorf("способ публичного клиента = %q", resp.GetInteractiveClient().GetTokenEndpointAuthMethod())
	}
	if resp.GetClientSecret() != "" {
		t.Error("у публичного клиента в ответе непустой секрет")
	}
}

// secretForms — значение секрета во всех формах, в каких его может вывести
// общий путь печати: как есть, шестнадцатерично в обоих регистрах, base64 и
// пара Basic.
func secretForms(secret string) map[string]string {
	return map[string]string{
		"как есть":          secret,
		"hex":               fmt.Sprintf("%x", secret),
		"HEX":               fmt.Sprintf("%X", secret),
		"base64":            base64.StdEncoding.EncodeToString([]byte(secret)),
		"base64 пары":       base64.StdEncoding.EncodeToString([]byte(probeClientID + ":" + secret)),
		"base64url":         base64.RawURLEncoding.EncodeToString([]byte(secret)),
		"строка в кавычках": fmt.Sprintf("%q", secret),
	}
}

func requireNoSecretForm(t *testing.T, where, text, secret string) {
	t.Helper()
	for form, v := range secretForms(secret) {
		if strings.Contains(text, v) {
			t.Errorf("%s выдаёт секрет (форма %s)", where, form)
		}
	}
}

// TestClientSecret_PrintsNothingOfItself — условие поверхности п.2: носитель
// секрета не выдаёт значения ни одним общим путём печати — ни сам, ни полем
// порта исполнителя; единственный выход — поле ответа.
func TestClientSecret_PrintsNothingOfItself(t *testing.T) {
	s, err := NewClientSecret(probeSecret)
	if err != nil {
		t.Fatalf("носитель не построен: %v", err)
	}
	pc := ProviderClient{ClientID: probeClientID, TokenEndpointAuthMethod: "client_secret_basic", Secret: s}
	holder := struct {
		PC     ProviderClient
		Secret ClientSecret
	}{PC: pc, Secret: s}

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: выход есть, и он отдаёт ровно секрет. Без него
	// «печать не выдаёт» зеленело бы на носителе, который секрета не держит.
	var resp iamv1.CreateInteractiveClientResponse
	s.IntoResponse(&resp)
	if resp.GetClientSecret() != probeSecret {
		t.Fatalf("выход носителя отдал не секрет: %d знаков", len(resp.GetClientSecret()))
	}

	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d"} {
		requireNoSecretForm(t, "печать "+verb+" носителя", fmt.Sprintf(verb, s), probeSecret)
		requireNoSecretForm(t, "печать "+verb+" порта исполнителя", fmt.Sprintf(verb, pc), probeSecret)
		requireNoSecretForm(t, "печать "+verb+" структуры с носителем", fmt.Sprintf(verb, holder), probeSecret)
	}

	var buf logbuf.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	logger.Info("probe", "client_id", pc.ClientID, "secret", s, "client", pc, "holder", holder, slog.Any("any", s))
	requireNoSecretForm(t, "журнал JSON", buf.String(), probeSecret)
	if !strings.Contains(buf.String(), probeClientID) {
		t.Error("ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ журнала: запись не несёт даже имени клиента — захват ничего не видит")
	}

	if out, jerr := json.Marshal(s); jerr == nil {
		requireNoSecretForm(t, "json носителя", string(out), probeSecret)
		t.Errorf("JSON носителя обязан отказывать, а дал %q", out)
	}
	if out, jerr := json.Marshal(holder); jerr == nil {
		requireNoSecretForm(t, "json структуры с носителем", string(out), probeSecret)
	}
}

// TestCreate_JournalCarriesNoSecret — условие поверхности п.3 (IC-SECRET-13(а))
// на слое use-case: ни успешное заведение, ни компенсация сорвавшейся вставки,
// ни срыв терминальной записи не пишут в журнал секрета, пары Basic и
// искажённого секрета. Положительный контроль — строка о компенсации и о срыве
// записи называет клиента и операцию: захват видит журнал.
func TestCreate_JournalCarriesNoSecret(t *testing.T) {
	var buf logbuf.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Успех.
	if _, err := executeCreate(&insertRecordingRepo{}, confidential(), &fakeOps{}, logger); err != nil {
		t.Fatalf("заведение отказало: %v", err)
	}
	// Вставка сорвалась, прямое снятие у реестра — тоже: строка журнала есть.
	reg := confidential()
	reg.deregErr = errors.New("registry did not answer")
	failing := &insertRecordingRepo{insertErr: errors.New("storage refused the row")}
	if _, err := executeCreate(failing, reg, &fakeOps{}, logger); err == nil {
		t.Fatal("ПРЕДУСЛОВИЕ: сорвавшаяся вставка обязана дать отказ")
	}
	// Терминальная запись сорвалась: строка журнала есть.
	if _, err := executeCreate(&insertRecordingRepo{}, confidential(),
		&fakeOps{markDoneErr: errors.New("operations store did not answer")}, logger); err != nil {
		t.Fatalf("срыв терминальной записи после коммита ресурса не отказывает вызывающему: %v", err)
	}

	journal := buf.String()
	if !strings.Contains(journal, probeClientID) || !strings.Contains(journal, "operation_id") {
		t.Fatalf("ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: журнал не несёт строк о компенсации и о срыве записи — "+
			"«секрета нет» значило бы «журнала нет»:\n%s", journal)
	}
	requireNoSecretForm(t, "журнал заведения", journal, probeSecret)
	mangled := "X" + probeSecret[1:]
	requireNoSecretForm(t, "журнал заведения (искажённый секрет)", journal, mangled)
}
