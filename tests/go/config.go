package testfw

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// Config holds parsed values from config.ini.
type Config struct {
	MachineA struct {
		IP4   string
		IP6   string
		Iface string
	}
	MachineB struct {
		IP4   string
		IP6   string
		Iface string
	}
	Test struct {
		SleepMs       int
		Timeout       float64
		VerifyTimeout float64
		VerifyPolicy  string
	}
}

const (
	VerifyPolicyFail       = "fail"
	VerifyPolicyUnverified = "unverified"
)

// ConfigPaths implements flag.Value for repeatable --config flags.
type ConfigPaths []string

func (c *ConfigPaths) String() string {
	if c == nil {
		return ""
	}
	return strings.Join(*c, ",")
}

func (c *ConfigPaths) Set(value string) error {
	*c = append(*c, value)
	return nil
}

// DefaultConfig returns the framework defaults used when config files omit
// optional test settings.
func DefaultConfig() *Config {
	cfg := &Config{}
	cfg.Test.SleepMs = 100
	cfg.Test.Timeout = 5.0
	cfg.Test.VerifyTimeout = 120.0
	cfg.Test.VerifyPolicy = VerifyPolicyUnverified
	return cfg
}

func NormalizeVerifyPolicy(policy string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(policy)) {
	case "", VerifyPolicyUnverified:
		return VerifyPolicyUnverified, nil
	case VerifyPolicyFail:
		return VerifyPolicyFail, nil
	default:
		return "", fmt.Errorf("invalid verify policy %q (use %q or %q)",
			policy, VerifyPolicyFail, VerifyPolicyUnverified)
	}
}

// LoadConfig parses a simple INI file.
func LoadConfig(path string) (*Config, error) {
	return LoadConfigs(path)
}

// LoadConfigs parses simple INI files in order. Later files override earlier
// ones, which lets suite-local config files override shared defaults.
func LoadConfigs(paths ...string) (*Config, error) {
	cfg := DefaultConfig()
	if len(paths) == 0 {
		paths = []string{"config.ini"}
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		if err := loadConfigFile(cfg, path); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

func loadConfigFile(cfg *Config, path string) error {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil // missing file is not an error
		}
		return err
	}
	defer f.Close()

	section := ""
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(line[1 : len(line)-1])
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		val := strings.TrimSpace(parts[1])

		switch section + "." + key {
		case "machine_a.ip4":
			cfg.MachineA.IP4 = val
		case "machine_a.ip6":
			cfg.MachineA.IP6 = val
		case "machine_a.iface":
			cfg.MachineA.Iface = val
		case "machine_b.ip4":
			cfg.MachineB.IP4 = val
		case "machine_b.ip6":
			cfg.MachineB.IP6 = val
		case "machine_b.iface":
			cfg.MachineB.Iface = val
		case "test.sleep":
			if v, err := strconv.Atoi(val); err == nil {
				cfg.Test.SleepMs = v
			}
		case "test.timeout":
			if v, err := strconv.ParseFloat(val, 64); err == nil {
				cfg.Test.Timeout = v
			}
		case "test.verify_timeout", "test.verify-timeout":
			if v, err := strconv.ParseFloat(val, 64); err == nil {
				cfg.Test.VerifyTimeout = v
			}
		case "test.verify_policy", "test.verify-policy":
			cfg.Test.VerifyPolicy = val
		}
	}
	return scanner.Err()
}

var offloads = []string{"rx", "off", "tx", "off", "gso", "off", "gro", "off", "tso", "off"}

// DisableOffloads disables NIC offloads that hide checksum errors from BPF.
func DisableOffloads(iface string) error {
	args := append([]string{"-K", iface}, offloads...)
	cmd := sudoCmd("ethtool", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[offload] warning: ethtool -K %s: %s\n", iface, strings.TrimSpace(string(out)))
		return nil // warn, don't abort
	}
	fmt.Printf("[offload] disabled on %s: rx tx gso gro tso\n", iface)
	return nil
}

func sudoCmd(name string, args ...string) *exec.Cmd {
	if os.Getuid() == 0 {
		return exec.Command(name, args...)
	}
	return exec.Command("sudo", append([]string{name}, args...)...)
}

// AddLoRoute adds a route for cidr via the loopback interface so that
// rp_filter=2 does not drop packets whose source address was rewritten by a
// BPF program to an address in that range (e.g. RFC 5737 documentation nets).
func AddLoRoute(cidr string) {
	cmd := sudoCmd("ip", "route", "add", cidr, "dev", "lo")
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if !strings.Contains(msg, "File exists") {
			fmt.Fprintf(os.Stderr, "[route]  warning: ip route add %s dev lo: %s\n", cidr, msg)
		}
		return
	}
	fmt.Printf("[route]  added %s dev lo (rp_filter bypass for saddr-rewrite tests)\n", cidr)
}

// DelLoRoute removes the route previously added by AddLoRoute.
func DelLoRoute(cidr string) {
	sudoCmd("ip", "route", "del", cidr, "dev", "lo").Run()
}
