// Package vpn manages the openconnect subprocess that owns the VPN tunnel.
package vpn

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
)

// State represents the current VPN connection state.
type State int

const (
	StateDisconnected  State = iota
	StateConnecting          // openconnect launched, auth in progress
	StateConnected           // tunnel is up
	StateDisconnecting       // SIGTERM sent, waiting for process exit
	StateAuthFailed          // server returned auth-failed
	StateError               // unexpected error
)

func (s State) String() string {
	switch s {
	case StateDisconnected:
		return "Disconnected"
	case StateConnecting:
		return "Connecting…"
	case StateConnected:
		return "Connected"
	case StateDisconnecting:
		return "Disconnecting…"
	case StateAuthFailed:
		return "Auth failed"
	case StateError:
		return "Error"
	default:
		return "Unknown"
	}
}

// Manager owns the lifecycle of the openconnect subprocess and notifies the UI
// of state changes via the OnStateChange callback.
type Manager struct {
	mu            sync.Mutex
	state         State
	gateway       string // last known gateway
	cmd           *exec.Cmd
	cancelMonitor context.CancelFunc
	OnStateChange func(State, string) // state, gateway name
}

func New(onChange func(State, string)) *Manager {
	return &Manager{
		state:         StateDisconnected,
		OnStateChange: onChange,
	}
}

func (m *Manager) State() State {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state
}

func (m *Manager) Gateway() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.gateway
}

func (m *Manager) setState(s State, gw string) {
	m.mu.Lock()
	m.state = s
	if gw != "" {
		m.gateway = gw
	}
	m.mu.Unlock()
	if m.OnStateChange != nil {
		m.OnStateChange(s, gw)
	}
}

// findVpncScript returns the first vpnc-script path that exists on disk.
func findVpncScript() string {
	candidates := []string{
		"/usr/local/share/vpnc-scripts/vpnc-script",
		"/usr/local/sbin/vpnc-script",
		"/usr/share/vpnc-scripts/vpnc-script",
		"/usr/sbin/vpnc-script",
		"/etc/vpnc/vpnc-script",
		"/etc/openconnect/vpnc-script",
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return ""
}

// Connect launches `sudo openconnect --protocol=gp <gateway> --cookie-on-stdin`,
// writes the URL-encoded token to stdin, then monitors the process output to
// drive state transitions.
func (m *Manager) Connect(gateway, token string) error {
	m.mu.Lock()
	if m.state != StateDisconnected && m.state != StateAuthFailed && m.state != StateError {
		m.mu.Unlock()
		return fmt.Errorf("cannot connect: current state is %s", m.state)
	}
	m.mu.Unlock()

	m.setState(StateConnecting, gateway)

	args := []string{"-n", "openconnect",
		"--protocol=gp",
		"--cookie-on-stdin",
		"--pid-file", "/var/run/openconnect.lock",
		"--timestamp",
	}
	if script := findVpncScript(); script != "" {
		args = append(args, "--script", script)
	}
	args = append(args, gateway)

	cmd := exec.Command("sudo", args...)

	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		m.setState(StateDisconnected, "")
		return fmt.Errorf("stdin pipe: %w", err)
	}

	// Merge stdout + stderr so we catch all log lines.
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		m.setState(StateDisconnected, "")
		return fmt.Errorf("stdout pipe: %w", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		m.setState(StateDisconnected, "")
		return fmt.Errorf("stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		m.setState(StateDisconnected, "")
		return fmt.Errorf("start openconnect: %w", err)
	}

	m.mu.Lock()
	m.cmd = cmd
	m.mu.Unlock()

	// openconnect reads the cookie before making network calls so we can
	// write it immediately without any delay.
	go func() {
		fmt.Fprintln(stdinPipe, token)
		stdinPipe.Close()
	}()

	ctx, cancel := context.WithCancel(context.Background())
	m.mu.Lock()
	m.cancelMonitor = cancel
	m.mu.Unlock()

	// Monitor both pipes concurrently; feed all lines into a single channel.
	lines := make(chan string, 128)
	var wg sync.WaitGroup
	for _, r := range []io.Reader{stdoutPipe, stderrPipe} {
		wg.Add(1)
		go func(rd io.Reader) {
			defer wg.Done()
			sc := bufio.NewScanner(rd)
			for sc.Scan() {
				select {
				case lines <- sc.Text():
				case <-ctx.Done():
					return
				}
			}
		}(r)
	}
	go func() {
		wg.Wait()
		close(lines)
	}()

	go m.monitor(ctx, cancel, cmd, lines)

	return nil
}

// monitor runs in a goroutine, parses openconnect log output to drive state
// transitions, then waits for the process to exit before emitting the final state.
func (m *Manager) monitor(ctx context.Context, cancel context.CancelFunc, cmd *exec.Cmd, lines <-chan string) {
	defer cancel()

	authFailed := false
	everConnected := false

loop:
	for {
		select {
		case line, ok := <-lines:
			if !ok {
				break loop
			}
			m.parseLine(line, &authFailed, &everConnected)
		case <-ctx.Done():
			break loop
		}
	}

	_ = cmd.Wait()

	m.mu.Lock()
	m.cmd = nil
	m.mu.Unlock()

	switch {
	case authFailed:
		m.setState(StateAuthFailed, "")
	case !everConnected:
		m.setState(StateError, "")
	default:
		m.setState(StateDisconnected, "")
	}
}

// parseLine inspects a single log line and updates flags / state accordingly.
func (m *Manager) parseLine(line string, authFailed *bool, everConnected *bool) {
	switch {
	case strings.Contains(line, "GlobalProtect gateway refused") ||
		strings.Contains(line, "auth-failed"):
		*authFailed = true

	case strings.Contains(line, "Configured as "), strings.Contains(line, "Connected as "):
		*everConnected = true
		m.setState(StateConnected, "")

	case strings.Contains(line, "Received SIGTERM") ||
		strings.Contains(line, "Received SIGINT"):
		m.setState(StateDisconnecting, "")
	}
}

// Disconnect sends SIGTERM to the openconnect process via its PID file.
func (m *Manager) Disconnect() {
	m.mu.Lock()
	state := m.state
	m.mu.Unlock()

	if state == StateDisconnected || state == StateDisconnecting {
		return
	}

	m.setState(StateDisconnecting, "")

	go func() {
		pidData, err := os.ReadFile("/var/run/openconnect.lock")
		if err != nil {
			// Fall back to interrupting the sudo child process directly.
			m.mu.Lock()
			cmd := m.cmd
			m.mu.Unlock()
			if cmd != nil && cmd.Process != nil {
				_ = cmd.Process.Signal(os.Interrupt)
			}
			return
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(pidData)))
		if err != nil {
			return
		}
		_ = exec.Command("sudo", "-n", "kill", "-SIGTERM", strconv.Itoa(pid)).Run()
	}()
}
