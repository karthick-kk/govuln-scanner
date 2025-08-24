package cislinuxthree

import (
	"log"
	"govuln-scanner/remexec"
	"strings"
)

var checkstat, cmd string

// Check represents a single CIS check
type Check struct {
	ID          string
	Description string
	Command     string
}

// CislinuxthreeOptimized Function - Optimized version with connection reuse
func CislinuxthreeOptimized(conn *remexec.SSHConnection) []Datastat {
	ServicesSlice := []Datastat{}

	// Define all checks with their commands
	checks := []Check{
		{
			ID:          "3.1.1",
			Description: "Ensure IP forwarding is disabled (Scored)",
			Command:     "if [[ `sudo sysctl net.ipv4.ip_forward|awk -F= '$2 == 0 {print}'` != '' && `sudo sysctl net.ipv6.conf.all.forwarding|awk -F= '$2 == 0 {print}'` != '' ]]; then echo ''; else echo 'ip forwarding enabled'; fi",
		},
		{
			ID:          "3.1.2",
			Description: "Ensure packet redirect sending is disabled (Scored)",
			Command:     "if [[ `sudo sysctl net.ipv4.conf.all.send_redirects|awk -F= '$2 == 0 {print}'` != '' && `sudo sysctl net.ipv4.conf.default.send_redirects|awk -F= '$2 == 0 {print}'` != '' ]]; then echo ''; else echo 'packet redirect enabled'; fi",
		},
		{
			ID:          "3.2.1",
			Description: "Ensure source routed packets are not accepted (Scored)",
			Command:     "if [[ `sudo sysctl net.ipv4.conf.all.accept_source_route|awk -F= '$2 == 0 {print}'` != '' && `sudo sysctl net.ipv4.conf.default.accept_source_route|awk -F= '$2 == 0 {print}'` != '' && `sudo sysctl net.ipv6.conf.all.accept_source_route|awk -F= '$2 == 0 {print}'` != '' && `sudo sysctl net.ipv6.conf.default.accept_source_route |awk -F= '$2 == 0 {print}'` != '' ]]; then echo ''; else echo 'source routed packets accepted'; fi",
		},
		{
			ID:          "3.2.2",
			Description: "Ensure ICMP redirects are not accepted (Scored)",
			Command:     "if [[ `sudo sysctl net.ipv4.conf.all.accept_redirects|awk -F= '$2 == 0 {print}'` != '' && `sudo sysctl net.ipv4.conf.default.accept_redirects|awk -F= '$2 == 0 {print}'` != '' && `sudo sysctl net.ipv6.conf.all.accept_redirects|awk -F= '$2 == 0 {print}'` != '' && `sudo sysctl net.ipv6.conf.default.accept_redirects |awk -F= '$2 == 0 {print}'` != '' ]]; then echo ''; else echo 'ICMP redirects accepted'; fi",
		},
		{
			ID:          "3.2.3",
			Description: "Ensure secure ICMP redirects are not accepted (Scored)",
			Command:     "if [[ `sudo sysctl net.ipv4.conf.all.secure_redirects|awk -F= '$2 == 0 {print}'` != '' && `sudo sysctl net.ipv4.conf.default.secure_redirects|awk -F= '$2 == 0 {print}'` != '' ]]; then echo ''; else echo 'secure icmp redirects accepted'; fi",
		},
		{
			ID:          "3.2.4",
			Description: "Ensure suspicious packets are logged (Scored)",
			Command:     "if [[ `sudo sysctl net.ipv4.conf.all.log_martians|awk -F= '$2 == 1 {print}'` != '' && `sudo sysctl net.ipv4.conf.default.log_martians|awk -F= '$2 == 1 {print}'` != '' ]]; then echo ''; else echo 'suspicious packets not logged'; fi",
		},
		{
			ID:          "3.2.5",
			Description: "Ensure broadcast ICMP requests are ignored (Scored)",
			Command:     "if [[ `sudo sysctl net.ipv4.icmp_echo_ignore_broadcasts|awk -F= '$2 == 1 {print}'` != '' ]]; then echo ''; else echo 'broadcast icmp not ignored'; fi",
		},
		{
			ID:          "3.2.6",
			Description: "Ensure bogus ICMP responses are ignored (Scored)",
			Command:     "if [[ `sudo sysctl net.ipv4.icmp_ignore_bogus_error_responses|awk -F= '$2 == 1 {print}'` != '' ]]; then echo ''; else echo 'bogus icmp not ignored'; fi",
		},
		{
			ID:          "3.2.7",
			Description: "Ensure Reverse Path Filtering is enabled (Scored)",
			Command:     "if [[ `sudo sysctl net.ipv4.conf.all.rp_filter|awk -F= '$2 == 1 {print}'` != '' && `sudo sysctl net.ipv4.conf.default.rp_filter|awk -F= '$2 == 1 {print}'` != '' ]]; then echo ''; else echo 'Reverse Path Filtering is not enabled'; fi",
		},
		{
			ID:          "3.2.8",
			Description: "Ensure TCP SYN Cookies is enabled (Scored)",
			Command:     "if [[ `sudo sysctl net.ipv4.tcp_syncookies|awk -F= '$2 == 1 {print}'` != '' ]]; then echo ''; else echo 'TCP SYN Cookies is not enabled'; fi",
		},
		{
			ID:          "3.2.9",
			Description: "Ensure IPv6 router advertisements are not accepted (Scored)",
			Command:     "if [[ `sudo sysctl net.ipv6.conf.all.accept_ra|awk -F= '$2 == 0 {print}'` != '' && `sudo sysctl net.ipv6.conf.default.accept_ra|awk -F= '$2 == 0 {print}'` != '' ]]; then echo ''; else echo 'IPv6 router advertisements are accepted'; fi",
		},
		{
			ID:          "3.3.1",
			Description: "Ensure TCP Wrappers is installed (Not Scored)",
			Command:     "if [[ `rpm -q tcp_wrappers 2>/dev/null` != '' || `dpkg -s tcpd 2>/dev/null` != '' ]]; then echo ''; else echo 'tcp wrappers not installed'; fi",
		},
		{
			ID:          "3.3.2",
			Description: "Ensure /etc/hosts.allow is configured (Not Scored)",
			Command:     "echo ''",
		},
		{
			ID:          "3.3.3",
			Description: "Ensure /etc/hosts.deny is configured (Not Scored)",
			Command:     "echo ''",
		},
		{
			ID:          "3.3.4",
			Description: "Ensure permissions on /etc/hosts.allow are configured (Scored)",
			Command:     "if [[ `stat /etc/hosts.allow 2>/dev/null| grep root|grep 0644` != '' ]]; then echo ''; else echo '/etc/hosts.allow permissions incorrect'; fi",
		},
		{
			ID:          "3.3.5",
			Description: "Ensure permissions on /etc/hosts.deny are configured (Scored)",
			Command:     "if [[ `stat /etc/hosts.deny 2>/dev/null| grep root|grep 0644` != '' ]]; then echo ''; else echo '/etc/hosts.deny permissions incorrect'; fi",
		},
		{
			ID:          "3.4.1",
			Description: "Ensure DCCP is disabled (Scored)",
			Command:     "if [[ `lsmod | grep dccp` == '' ]]; then echo ''; else echo 'DCCP is enabled'; fi",
		},
		{
			ID:          "3.4.2",
			Description: "Ensure SCTP is disabled (Scored)",
			Command:     "lsmod | grep sctp` == '' ]]; then echo ''; else echo 'SCTP is enabled'; fi",
		},
		{
			ID:          "3.4.3",
			Description: "Ensure RDS is disabled (Scored)",
			Command:     "lsmod | grep rds` == '' ]]; then echo ''; else echo 'rds is enabled'; fi",
		},
		{
			ID:          "3.4.4",
			Description: "Ensure TIPC is disabled (Scored)",
			Command:     "lsmod | grep tipc` == '' ]]; then echo ''; else echo 'tipc is enabled'; fi",
		},
		{
			ID:          "3.5.1.1",
			Description: "Ensure IPv6 default deny firewall policy (Scored)",
			Command:     "if [[ `sudo grep linux /boot/grub2/grub.cfg 2>/dev/null | grep -v ipv6.disable=1` == '' && `sudo grep 'linux' /boot/grub/grub.cfg 2>/dev/null | grep -v ipv6.disable=1` == '' ]]; then echo ''; else echo 'Missing IPv6 default deny firewall policy'; fi",
		},
		{
			ID:          "3.5.1.2",
			Description: "Ensure IPv6 loopback traffic is configured (Scored)",
			Command:     "if [[ `sudo grep linux /boot/grub2/grub.cfg 2>/dev/null | grep -v ipv6.disable=1` == '' && `sudo grep 'linux' /boot/grub/grub.cfg 2>/dev/null | grep -v ipv6.disable=1` == '' ]]; then echo ''; else echo 'IPv6 loopback traffic not configured'; fi",
		},
		{
			ID:          "3.5.1.3",
			Description: "Ensure IPv6 outbound and established connections are configured (Not Scored)",
			Command:     "if [[ `sudo grep linux /boot/grub2/grub.cfg 2>/dev/null | grep -v ipv6.disable=1` == '' && `sudo grep 'linux' /boot/grub/grub.cfg 2>/dev/null | grep -v ipv6.disable=1` == '' ]]; then echo ''; else echo 'IPv6 outbound and established connections not configured'; fi",
		},
		{
			ID:          "3.5.1.4",
			Description: "Ensure IPv6 firewall rules exist for all open ports (Not Scored)",
			Command:     "if [[ `sudo grep linux /boot/grub2/grub.cfg 2>/dev/null | grep -v ipv6.disable=1` == '' && `sudo grep 'linux' /boot/grub/grub.cfg 2>/dev/null | grep -v ipv6.disable=1` == '' ]]; then echo ''; else echo 'IPv6 firewall rules does not exist'; fi",
		},
		{
			ID:          "3.5.2.1",
			Description: " Ensure default deny firewall policy (Scored)",
			Command:     "case `for i in $( echo rpm dpkg pacman ); do which $i; done 2> /dev/null|awk -F'bin/' '{print $NF}'` in dpkg) if [[ `sudo ufw status verbose|grep Default|grep deny 2>/dev/null` != '' ]]; then echo ''; else echo 'default deny policy not set for firewall'; fi;; rpm) if [[ `sudo iptables -L|egrep -i 'INPUT|OUTPUT|FORWARD'|grep ACCEPT|wc -l 2>/dev/null` -ge 3 ]]; then echo ''; else echo 'default deny policy not set for iptables'; fi;; esac",
		},
		{
			ID:          "3.5.2.2",
			Description: "Ensure loopback traffic is configured (Scored)",
			Command:     "case `for i in $( echo rpm dpkg pacman ); do which $i; done 2> /dev/null|awk -F'bin/' '{print $NF}'` in dpkg) if [[ `sudo ufw status verbose|grep Default|grep deny 2>/dev/null` != '' ]]; then echo ''; else echo 'loopback traffic not configured'; fi;; rpm) if [[ `sudo iptables -L INPUT -v -n|grep lo 2>/dev/null` != '' ]]; then echo ''; else echo 'loopback traffic not configured'; fi;; esac",
		},
		{
			ID:          "3.5.2.3",
			Description: "Ensure outbound and established connections are configured (Not Scored)",
			Command:     "case `for i in $( echo rpm dpkg pacman ); do which $i; done 2> /dev/null|awk -F'bin/' '{print $NF}'` in dpkg) if [[ `sudo ufw status verbose|grep Default|grep deny 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure outbound and established connections are configured'; fi;; rpm) if [[ `sudo iptables -L INPUT -v -n|grep lo 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure outbound and established connections are configured'; fi;; esac",
		},
		{
			ID:          "3.5.2.4",
			Description: "Ensure firewall rules exist for all open ports (Scored)",
			Command:     "case `for i in $( echo rpm dpkg pacman ); do which $i; done 2> /dev/null|awk -F'bin/' '{print $NF}'` in dpkg) if [[ `sudo ufw status verbose|grep Default|grep deny 2>/dev/null` != '' ]]; then echo ''; else echo 'firewall rules not found for all open ports'; fi;; rpm) if [[ `ss -4tuln|awk '{print $5}'|grep -v Local|awk -F: '{print $NF}'|uniq|wc -l 2>/dev/null` -ge `sudo iptables -L INPUT -v -n|egrep 'tcp|udp'|wc -l 2>/dev/null` ]]; then echo ''; else echo 'firewall rules not found for all open ports'; fi;; esac",
		},
		{
			ID:          "3.5.3",
			Description: "Ensure iptables is installed (Scored)",
			Command:     "if [[ `rpm -q iptables 2>/dev/null` != '' || `dpkg -s iptables 2>/dev/null` != '' ]]; then echo ''; else echo 'iptables not installed'; fi",
		},
		{
			ID:          "3.6",
			Description: "Ensure wireless interfaces are disabled (Not Scored)",
			Command:     "if [[ `ip link show up|grep wl 2>/dev/null` == '' ]]; then echo ''; else echo 'wireless interface active'; fi",
		},
		{
			ID:          "3.7",
			Description: "Disable IPv6 (Not Scored)",
			Command:     "if [[ `sudo grep linux /boot/grub2/grub.cfg 2>/dev/null | grep -v ipv6.disable=1` == '' && `sudo grep 'linux' /boot/grub/grub.cfg 2>/dev/null | grep -v ipv6.disable=1` == '' ]]; then echo ''; else echo 'IPv6 enabled'; fi",
		},
	}

	// Extract commands for batch execution
	commands := make([]string, len(checks))
	for i, check := range checks {
		commands[i] = check.Command
	}

	// Execute all commands in a single batch
	log.Printf("DEBUG: Executing %d CIS cislinuxthree checks in batch\n", len(commands))
	batchResult := conn.RunCommandsBatch(commands)
	
	if batchResult.Error != nil {
		log.Printf("ERROR: Batch execution failed: %v\n", batchResult.Error)
		// Fallback to individual commands if batch fails
		return cislinuxthreeFallback(conn, checks)
	}

	// Process results
	for i, result := range batchResult.Results {
		var checkstat string
		if len(strings.TrimSpace(result.Output)) == 0 {
			checkstat = "PASS"
		} else {
			log.Printf("DEBUG: Check %s output: %s\n", checks[i].ID, result.Output)
			checkstat = "FAIL"
		}
		ServicesSlice = append(ServicesSlice, Datastat{
			checks[i].ID,
			checks[i].Description,
			checkstat,
		})
	}

	log.Printf("DEBUG: Completed %d CIS cislinuxthree checks via batch execution\n", len(ServicesSlice))
	return ServicesSlice
}

// Fallback function for individual command execution if batch fails
func cislinuxthreeFallback(conn *remexec.SSHConnection, checks []Check) []Datastat {
	ServicesSlice := []Datastat{}
	log.Println("DEBUG: Using fallback individual command execution")
	
	for _, check := range checks {
		out, err := conn.RunCommand(check.Command)
		if err != nil {
			log.Printf("ERROR: Command failed for %s: %v\n", check.ID, err)
		}
		
		var checkstat string
		if len(strings.TrimSpace(out)) == 0 {
			checkstat = "PASS"
		} else {
			log.Printf("DEBUG: Check %s output: %s\n", check.ID, out)
			checkstat = "FAIL"
		}
		ServicesSlice = append(ServicesSlice, Datastat{check.ID, check.Description, checkstat})
	}
	
	return ServicesSlice
}

// Original Cislinuxthree Function - Updated to use optimized connection handling
func Cislinuxthree(user string, host string, pass string, key string) []Datastat {
	// Create connection for this scan
	conn, err := remexec.NewSSHConnection(user, host, pass, key)
	if err != nil {
		log.Printf("ERROR: Failed to create SSH connection: %v\n", err)
		return []Datastat{}
	}
	defer conn.Close()
	
	return CislinuxthreeOptimized(conn)
}

// Datastat Type
type Datastat struct {
	Controlid string
	Check     string
	Status    string
}
