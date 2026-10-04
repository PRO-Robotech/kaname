// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package manifest_test

// recipient_directory_test.go — строка `recipientDirectory` манифеста (приёмка
// NTF-3, kacho#2918: Р28, NTF3-50; замысел З27, CX3B-15, УК3-08).
//
// # Что утверждается
//
// Объявить читателя справочника адресов может только манифест `notify`, и только
// строкой `recipientDirectory: {readers: [notify]}`. Любое иное — находка
// «читатель справочника — только notify», называющая модуль и строку:
//
//	модуль не notify                    (NTF3-50, манифест storage);
//	readers не ровно [notify]           (NTF3-50, `[notify, storage]`);
//	документ назвался notify, но приехал
//	не своим ключом доставки             (УК3-08: правило происхождения).
//
// Положительный близнец каждого отрицания — та же строка манифеста `notify`,
// доставленная своим ключом: принята, находок ноль. Отрицание без близнеца
// зеленело бы на загрузчике, отвергающем строку целиком (а сегодня он её именно
// так и отвергает — неизвестным ключом), поэтому близнец стоит ПЕРВЫМ в каждой
// пробе: «отвергнуто» засчитывается, только когда законная форма той же строки
// принята.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/modulemanifest"

	"github.com/PRO-Robotech/kaname/internal/manifest"
)

const (
	// rdNotifyManifest — законная строка (Р28): модуль notify, читатель ровно notify.
	rdNotifyManifest = `apiVersion: iam/v1
module: notify
resources: []
recipientDirectory: {readers: [notify]}
`
	// rdStorageManifest — NTF3-50: та же строка в манифесте storage.
	rdStorageManifest = `apiVersion: iam/v1
module: storage
resources: []
recipientDirectory: {readers: [notify]}
`
	// rdNotifyTwoReaders — NTF3-50: манифест notify с лишним читателем.
	rdNotifyTwoReaders = `apiVersion: iam/v1
module: notify
resources: []
recipientDirectory: {readers: [notify, storage]}
`
	// rdNotifyNoLine — манифест notify без строки: контроль, что модуль
	// notify сам по себе разбор проходит (иначе близнец судил бы чужое).
	rdNotifyNoLine = `apiVersion: iam/v1
module: notify
resources: []
`

	rdFindingPhrase = "читатель справочника — только notify"
)

// TestNTF350_RecipientDirectoryLineIsTheNotifyManifestsAlone — NTF3-50 на
// загрузчике: законная строка принята; строка в манифесте storage и строка с
// лишним читателем — находка, называющая модуль и строку.
func TestNTF350_RecipientDirectoryLineIsTheNotifyManifestsAlone(t *testing.T) {
	// Контроль фикстуры: манифест notify без строки разбор проходит.
	if _, err := manifest.Load([]byte(rdNotifyNoLine)); err != nil {
		t.Fatalf("фикстура: манифест notify без строки отвергнут — вопрос пробы сломан: %v", err)
	}

	// Близнец: законная строка принята.
	if _, err := manifest.Load([]byte(rdNotifyManifest)); err != nil {
		t.Fatalf("законная строка `recipientDirectory: {readers: [notify]}` манифеста notify отвергнута "+
			"разбором (Р28): %v", err)
	}

	for _, tc := range []struct {
		name, doc, module, line string
	}{
		{"модуль storage", rdStorageManifest, "storage", "recipientDirectory: {readers: [notify]}"},
		{"лишний читатель storage", rdNotifyTwoReaders, "notify", "recipientDirectory: {readers: [notify, storage]}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := manifest.Load([]byte(tc.doc))
			if err == nil {
				t.Fatalf("строка принята: %s", tc.line)
			}
			msg := err.Error()
			for _, want := range []string{rdFindingPhrase, `"` + tc.module + `"`, tc.line} {
				if !strings.Contains(msg, want) {
					t.Fatalf("находка не называет %q (Р28: находка «%s» с именем модуля и строки); получено: %v",
						want, rdFindingPhrase, err)
				}
			}
		})
	}
}

// rdDeliver кладёт документы в каталог доставки под ключами.
func rdDeliver(t *testing.T, docs map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for key, body := range docs {
		if err := os.WriteFile(filepath.Join(root, key), []byte(body), 0o600); err != nil {
			t.Fatalf("фикстура: доставка %s не записана: %v", key, err)
		}
	}
	return root
}

// TestUK308_RecipientDirectoryLineFollowsTheDeliveryProvenance — УК3-08
// (CX3B-15): документ, назвавшийся `module: notify`, доставлен ключом storage, а
// настоящего манифеста notify в доставке нет — строка не применяется, находка.
// Близнец — тот же документ под ключом notify: находок ноль.
func TestUK308_RecipientDirectoryLineFollowsTheDeliveryProvenance(t *testing.T) {
	storageKey := modulemanifest.DeliveryKey("storage")
	notifyKey := modulemanifest.DeliveryKey("notify")

	// Контроль фикстуры: доставка без строки — годна под ключом notify.
	if r := manifest.CheckDelivery(rdDeliver(t, map[string]string{notifyKey: rdNotifyNoLine})); len(r.Findings) != 0 ||
		r.ManifestsRead != 1 {
		t.Fatalf("фикстура: доставка манифеста notify без строки дала находки %v (прочитано %d) — "+
			"вопрос пробы сломан", r.Findings, r.ManifestsRead)
	}

	// Близнец: та же строка, свой ключ.
	twin := manifest.CheckDelivery(rdDeliver(t, map[string]string{notifyKey: rdNotifyManifest}))
	if len(twin.Findings) != 0 || twin.ManifestsRead != 1 {
		t.Fatalf("законная строка, доставленная ключом %s, дала находки (прочитано %d): %v",
			notifyKey, twin.ManifestsRead, twin.Findings)
	}

	// Предмет: документ назвался notify, приехал ключом storage, настоящего нет.
	got := manifest.CheckDelivery(rdDeliver(t, map[string]string{storageKey: rdNotifyManifest}))
	t.Logf("перепись: прочитано %d, находок %d: %v", got.ManifestsRead, len(got.Findings), got.Findings)
	joined := strings.Join(got.Findings, "\n")
	if !strings.Contains(joined, rdFindingPhrase) || !strings.Contains(joined, storageKey) {
		t.Fatalf("строка `recipientDirectory` в документе ключа %s с объявленным модулем notify не отвергнута "+
			"правилом происхождения (находка обязана нести «%s» и ключ доставки); находки: %v",
			storageKey, rdFindingPhrase, got.Findings)
	}
}
