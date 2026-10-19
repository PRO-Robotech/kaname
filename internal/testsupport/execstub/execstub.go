// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package execstub — исполняемый двойник, которого проба пишет и тут же
// запускает.
//
// # Почему не `os.WriteFile(…, 0o700)`
//
// Ядро отвечает на запуск файла ETXTBSY («Text file busy»), пока у его inode
// есть открытый дескриптор записи — в любом процессе. Проба закрывает свой
// дескриптор до запуска, но соседняя параллельная проба того же процесса может
// успеть сделать `fork` в окне между открытием и закрытием: ребёнок наследует
// копию дескриптора и держит её до своего `exec` (O_CLOEXEC закрывает её лишь
// там). Запуск двойника в этот промежуток и падает ETXTBSY — отказ пробы,
// которого её предмет не вызывал (kaname#893: `bad interpreter: Text file busy`
// у двойника `gh` в TestImageProducerTagsALineHeadLikeTheTrunk).
//
// Переименование временного файла само по себе не спасает: ETXTBSY — свойство
// inode, а не имени, и переименованный файл — тот же inode. Спасает
// `syscall.ForkLock`: `fork` в Go берёт его на запись, поэтому окно записи
// под блокировкой на чтение не застаёт ни одного порождения. Временный файл с
// переименованием добавляет второе: двойник по итоговому имени появляется
// только целиком.
package execstub

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// whileWritable — шов пробы пакета: зовётся, пока дескриптор записи двойника
// открыт. В прод-пути не задан.
var whileWritable func()

// Write кладёт исполняемый двойник `body` по пути `path`, создавая каталог.
// Отказ записи — отказ пробы.
func Write(t testing.TB, path, body string) {
	t.Helper()
	if err := write(path, []byte(body)); err != nil {
		t.Fatalf("двойник %s не записан: %v", path, err)
	}
}

func write(path string, body []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}

	// Окно, в котором у процесса есть дескриптор записи двойника, целиком
	// под блокировкой на чтение: ни одна горутина не начнёт в нём `fork`.
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()

	f, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if whileWritable != nil {
		whileWritable()
	}
	_, werr := f.Write(body)
	merr := f.Chmod(0o700) // #nosec G302 -- двойник обязан исполняться
	cerr := f.Close()
	if err := errors.Join(werr, merr, cerr); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
