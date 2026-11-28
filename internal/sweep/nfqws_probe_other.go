//go:build !unix

package sweep

import (
	"fmt"
	"os"
	"os/exec"
)

func applyProbeCredential(cmd *exec.Cmd, uid, gid uint32) {
	_ = uid
	_ = gid
	// На не-unix платформах setuid недоступен; процесс запускается от текущего пользователя.
}

func killProcessGroup(pid int) error {
	if pid <= 0 {
		return nil
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}

func probeAlive(p *os.Process) error {
	if p == nil {
		return os.ErrProcessDone
	}
	// Windows: Signal(0) не поддерживается; считаем живым, пока Wait не завершён.
	return nil
}

func probeProcessRunning(p *os.Process) bool {
	return p != nil && probeAlive(p) == nil
}

func pidRunning(_ string, _ int) bool { return false }

func terminateOrphanPID(_ string, pid int) error {
	return fmt.Errorf("orphan process cleanup is unsupported on this OS (pid %d)", pid)
}
