package api

import (
	"fmt"
	"net"
	"syscall"

	"github.com/fu5ha/vaultbroker/internal/broker"
)

func checkPeer(b *broker.Broker, conn net.Conn) error {
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("not a unix connection")
	}
	raw, err := unixConn.SyscallConn()
	if err != nil {
		return err
	}
	var uid uint32
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, err := syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
		if err != nil {
			credErr = err
			return
		}
		uid = cred.Uid
	}); err != nil {
		return err
	}
	if credErr != nil {
		return credErr
	}
	if !b.Config().AllowsUID(uid) {
		return fmt.Errorf("uid %d is not allowed to use this socket", uid)
	}
	return nil
}
