package binary_stream

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

type ShellExec struct {
	Env       map[string]string
	ShellName string
	Prompt    string
	rl        *ReadLine
}

var knownUnixCmds = map[string]bool{
	"ls": true, "ll": true, "cat": true, "cp": true, "mv": true, "rm": true,
	"mkdir": true, "rmdir": true, "touch": true, "chmod": true, "chown": true,
	"echo": true, "grep": true, "find": true, "head": true, "tail": true,
	"less": true, "more": true, "wc": true, "sort": true, "uniq": true,
	"diff": true, "patch": true, "sed": true, "awk": true, "cut": true,
	"tr": true, "tee": true, "xargs": true, "tar": true, "gzip": true,
	"zip": true, "unzip": true, "df": true, "du": true, "ps": true,
	"top": true, "kill": true, "ping": true, "curl": true, "wget": true,
	"ssh": true, "scp": true, "rsync": true, "git": true, "make": true,
	"go": true, "python": true, "python3": true, "node": true, "npm": true,
	"vim": true, "vi": true, "nano": true, "clear": true, "cls": true, "reset": true,
	"env": true, "export": true, "which": true, "whoami": true, "date": true, "id": true,
	"stat": true, "file": true, "ln": true, "basename": true, "dirname": true, "man": true,
	"history": true, "type": true,
}

var ttyCmdPrefix = map[string]string{
	"ls":     "ls -C",
	"ll":     "ls -C",
	"grep":   "grep --color=auto",
	"diff":   "diff --color=auto",
	"git":    "git --no-pager",
	"make":   "make",
	"docker": "docker",
}

var interactiveCmds = map[string]bool{
	"vim": true, "vi": true, "nano": true, "emacs": true,
	"less": true, "more": true, "most": true,
	"top": true, "htop": true, "btop": true,
	"ssh": true, "ftp": true, "telnet": true,
	"watch": true, "strace": true,
	"man": true, "info": true,
	"irb": true, "python": true, "python3": true,
	"node": true, "ruby": true, "perl": true,
	"mysql": true, "psql": true, "sqlite3": true,
	"mongosh": true, "redis-cli": true,
	"docker": true, "kubectl": true, "docker-compose": true,
	"bash": true, "sh": true, "zsh": true, "fish": true,
	"apt": true, "apt-get": true, "yum": true, "dnf": true,
	"zypper": true, "pacman": true, "snap": true,
	"systemctl": true, "service": true,
}

func NewShellExec(name string) *ShellExec {
	return &ShellExec{
		Env:       make(map[string]string),
		ShellName: name,
		Prompt:    name + ">> ",
	}
}

func (se *ShellExec) SetEnv(key, value string) *ShellExec {
	se.Env[key] = value
	return se
}

func (se *ShellExec) SetReader(rl *ReadLine) *ShellExec {
	se.rl = rl
	return se
}

func (se *ShellExec) ExecCommand(cmdLine string) bool {
	parts := strings.Fields(cmdLine)
	if len(parts) == 0 {
		return true
	}
	cmd := parts[0]
	args := parts[1:]

	switch cmd {
	case "cd":
		return se.execCD(args)
	case "pwd":
		return se.execPwd()
	case "alias":
		return se.execAlias(args)
	case "unset":
		return se.execUnset(args)
	default:
		return se.execSystem(cmd, args)
	}
}

func (se *ShellExec) output(format string, args ...interface{}) {
	if se.rl != nil {
		se.rl.Printf(format, args...)
	} else {
		fmt.Printf(format, args...)
	}
}

func (se *ShellExec) execCD(args []string) bool {
	if len(args) == 0 {
		home, _ := os.UserHomeDir()
		if home != "" {
			se.output("%s\n", home)
			os.Chdir(home)
		}
		return true
	}
	if err := os.Chdir(args[0]); err != nil {
		se.output("%s: cd: %s: %v\n", se.ShellName, args[0], err)
	}
	return true
}

func (se *ShellExec) execPwd() bool {
	dir, _ := os.Getwd()
	se.output("%s\n", dir)
	return true
}

func (se *ShellExec) execAlias(args []string) bool {
	if len(args) == 0 {
		for k, v := range se.Env {
			se.output("%s='%s'\n", k, v)
		}
		return true
	}
	for _, a := range args {
		kv := strings.SplitN(a, "=", 2)
		if len(kv) == 2 {
			se.Env[kv[0]] = kv[1]
		}
	}
	return true
}

func (se *ShellExec) execUnset(args []string) bool {
	for _, k := range args {
		delete(se.Env, k)
	}
	return true
}

func (se *ShellExec) execSystem(cmd string, args []string) bool {
	if !isLikelySystemCmd(cmd) {
		se.output("%s: 未知命令: %s，输入 help 查看帮助\n", se.ShellName, cmd)
		return true
	}

	if interactiveCmds[cmd] {
		se.output("%s: 请使用 exit 退出交互式命令\n", cmd)
		return true
	}

	fullCmd := buildTTYCommand(cmd, args)

	c := exec.Command("sh", "-c", fullCmd)
	c.Env = os.Environ()
	for k, v := range se.Env {
		c.Env = append(c.Env, fmt.Sprintf("%s=%s", k, v))
	}

	if se.rl != nil {
		stdout, err := c.StdoutPipe()
		if err != nil {
			se.output("%s: %s: %v\n", se.ShellName, cmd, err)
			return true
		}
		stderr, err := c.StderrPipe()
		if err != nil {
			se.output("%s: %s: %v\n", se.ShellName, cmd, err)
			return true
		}

		if err := c.Start(); err != nil {
			se.output("%s: %s: %v\n", se.ShellName, cmd, err)
			return true
		}

		buf := make([]byte, 4096)
		done := make(chan struct{})
		go func() {
			for {
				n, err := stdout.Read(buf)
				if n > 0 {
					se.output("%s", buf[:n])
				}
				if err != nil {
					break
				}
			}
			close(done)
		}()
		errBuf := make([]byte, 4096)
		go func() {
			for {
				n, err := stderr.Read(errBuf)
				if n > 0 {
					se.output("%s", errBuf[:n])
				}
				if err != nil {
					break
				}
			}
		}()
		c.Wait()
		<-done
	} else {
		c.Stdin = os.Stdin
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		if err := c.Run(); err != nil {
			se.output("%s: %s: %v\n", se.ShellName, cmd, err)
		}
	}
	return true
}

func buildTTYCommand(cmd string, args []string) string {
	if prefix, ok := ttyCmdPrefix[cmd]; ok {
		if len(args) == 0 {
			return prefix
		}
		return prefix + " " + strings.Join(args, " ")
	}
	if len(args) == 0 {
		return cmd
	}
	return cmd + " " + strings.Join(args, " ")
}

func isLikelySystemCmd(cmd string) bool {
	if len(cmd) == 0 {
		return false
	}
	if knownUnixCmds[cmd] {
		return true
	}
	if len(cmd) == 1 {
		return false
	}
	if len(cmd) <= 2 && cmd[0] >= 'a' && cmd[0] <= 'z' {
		return false
	}
	return true
}
