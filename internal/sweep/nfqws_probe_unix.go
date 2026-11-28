//go:build unix

package sweep

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

func applyProbeCredential(cmd *exec.Cmd, uid, gid uint32) {
	// Не ставим Credential: NFQUEUE требует start от root, затем nfqws2
	// сам сбрасывает привилегии через --user= (см. buildArgs). Credential
	// до exec оставлял процесс без CAP_NET_ADMIN → мгновенный zombie на Keenetic.
	_ = uid
	_ = gid
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

func killProcessGroup(pid int) error {
	if pid <= 0 {
		return nil
	}
	// Отрицательный PID — вся группа процессов.
	return syscall.Kill(-pid, syscall.SIGTERM)
}

func probeAlive(p *os.Process) error {
	if p == nil {
		return os.ErrProcessDone
	}
	return p.Signal(syscall.Signal(0))
}

func probeProcessRunning(p *os.Process) bool {
	if p == nil {
		return false
	}
	if err := probeAlive(p); err != nil {
		return false
	}
	return pidRunning("/proc", p.Pid)
}

func pidRunning(procRoot string, pid int) bool {
	if pid <= 0 {
		return false
	}
	if procRoot == "" {
		procRoot = "/proc"
	}
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "stat"))
	if err != nil {
		if !os.IsNotExist(err) && procRoot == "/proc" {
			return syscall.Kill(pid, syscall.Signal(0)) == nil
		}
		return false
	}
	// Формат: pid (comm) state ... — state сразу после последней ')'.
	s := string(data)
	idx := strings.LastIndex(s, ") ")
	if idx < 0 || idx+2 >= len(s) {
		return true
	}
	state := s[idx+2]
	return state != 'Z' && state != 'X'
}

func terminateOrphanPID(procRoot string, pid int) error {
	if pid <= 0 {
		return nil
	}
	if err := syscall.Kill(-pid, syscall.SIGTERM); err != nil && err != syscall.ESRCH {
		_ = syscall.Kill(pid, syscall.SIGTERM)
	} else if err == syscall.ESRCH {
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}
	if waitPIDExit(procRoot, pid, 2*time.Second) {
		return nil
	}
	if err := syscall.Kill(-pid, syscall.SIGKILL); err != nil && err != syscall.ESRCH {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	} else if err == syscall.ESRCH {
		_ = syscall.Kill(pid, syscall.SIGKILL)
	}
	if waitPIDExit(procRoot, pid, time.Second) {
		return nil
	}
	return fmt.Errorf("процесс %d не завершился после SIGKILL", pid)
}

func waitPIDExit(procRoot string, pid int, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if !pidRunning(procRoot, pid) {
			return true
		}
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
}
