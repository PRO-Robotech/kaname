//go:build linux

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package standalonetargets

import (
	"errors"
	"os"
	"strings"
	"syscall"
)

// От Root берётся только сам удерживаемый каталог, без имени из marker.
func standaloneOpenNoFollow(root *os.Root, name string, directory bool) (*os.File, error) {
	parent, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	return standaloneOpenAt(parent, name, directory)
}

// Единственный basename открывает ядро: здесь нет разрешающего symlink retry os.Root.
func standaloneOpenAt(parent *os.File, name string, directory bool) (*os.File, error) {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\\x00") {
		return nil, errors.New("capture требует одного безопасного basename")
	}
	connection, err := parent.SyscallConn()
	if err != nil {
		return nil, err
	}
	flags := os.O_RDONLY | syscall.O_NOFOLLOW | syscall.O_NONBLOCK | syscall.O_CLOEXEC
	if directory {
		flags |= syscall.O_DIRECTORY
	}
	fd := -1
	// Новый descriptor принадлежит этой функции до явной передачи в os.File.
	// Defer закрывает его также при ошибке Control или panic после успешного openat.
	defer func() {
		if fd >= 0 {
			_ = syscall.Close(fd)
		}
	}()
	var openErr error
	controlErr := connection.Control(func(parentFD uintptr) {
		fd, openErr = syscall.Openat(int(parentFD), name, flags, 0)
	})
	if controlErr != nil {
		return nil, controlErr
	}
	if openErr != nil {
		return nil, openErr
	}
	file := os.NewFile(uintptr(fd), name)
	if file == nil {
		return nil, errors.New("capture descriptor не принят")
	}
	fd = -1
	return file, nil
}
