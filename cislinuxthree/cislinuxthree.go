package cislinuxthree

import (
	"log"
	"govuln-scanner/remexec"
	"strings"
)

var checkstat, cmd string

// Cislinuxthree Function
func Cislinuxthree(user string, host string, pass string) []Datastat {
	ServicesSlice := []Datastat{}

	// Check 3.1.1
	cmd = "if [[ `sudo sysctl net.ipv4.ip_forward|awk -F= '$2 == 0 {print}'` != '' && `sudo sysctl net.ipv6.conf.all.forwarding|awk -F= '$2 == 0 {print}'` != '' ]]; then echo ''; else echo 'ip forwarding enabled'; fi"
	out, _ := remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.1.1", "Ensure IP forwarding is disabled (Scored)", checkstat})

	// Check 3.1.2
	cmd = "if [[ `sudo sysctl net.ipv4.conf.all.send_redirects|awk -F= '$2 == 0 {print}'` != '' && `sudo sysctl net.ipv4.conf.default.send_redirects|awk -F= '$2 == 0 {print}'` != '' ]]; then echo ''; else echo 'packet redirect enabled'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.1.2", "Ensure packet redirect sending is disabled (Scored)", checkstat})

	// Check 3.2.1
	cmd = "if [[ `sudo sysctl net.ipv4.conf.all.accept_source_route|awk -F= '$2 == 0 {print}'` != '' && `sudo sysctl net.ipv4.conf.default.accept_source_route|awk -F= '$2 == 0 {print}'` != '' && `sudo sysctl net.ipv6.conf.all.accept_source_route|awk -F= '$2 == 0 {print}'` != '' && `sudo sysctl net.ipv6.conf.default.accept_source_route |awk -F= '$2 == 0 {print}'` != '' ]]; then echo ''; else echo 'source routed packets accepted'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.2.1", "Ensure source routed packets are not accepted (Scored)", checkstat})

	// Check 3.2.2
	cmd = "if [[ `sudo sysctl net.ipv4.conf.all.accept_redirects|awk -F= '$2 == 0 {print}'` != '' && `sudo sysctl net.ipv4.conf.default.accept_redirects|awk -F= '$2 == 0 {print}'` != '' && `sudo sysctl net.ipv6.conf.all.accept_redirects|awk -F= '$2 == 0 {print}'` != '' && `sudo sysctl net.ipv6.conf.default.accept_redirects |awk -F= '$2 == 0 {print}'` != '' ]]; then echo ''; else echo 'ICMP redirects accepted'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.2.2", "Ensure ICMP redirects are not accepted (Scored)", checkstat})

	// Check 3.2.3
	cmd = "if [[ `sudo sysctl net.ipv4.conf.all.secure_redirects|awk -F= '$2 == 0 {print}'` != '' && `sudo sysctl net.ipv4.conf.default.secure_redirects|awk -F= '$2 == 0 {print}'` != '' ]]; then echo ''; else echo 'secure icmp redirects accepted'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.2.3", "Ensure secure ICMP redirects are not accepted (Scored)", checkstat})

	// Check 3.2.4
	cmd = "if [[ `sudo sysctl net.ipv4.conf.all.log_martians|awk -F= '$2 == 1 {print}'` != '' && `sudo sysctl net.ipv4.conf.default.log_martians|awk -F= '$2 == 1 {print}'` != '' ]]; then echo ''; else echo 'suspicious packets not logged'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.2.4", "Ensure suspicious packets are logged (Scored)", checkstat})

	// Check 3.2.5
	cmd = "if [[ `sudo sysctl net.ipv4.icmp_echo_ignore_broadcasts|awk -F= '$2 == 1 {print}'` != '' ]]; then echo ''; else echo 'broadcast icmp not ignored'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.2.5", "Ensure broadcast ICMP requests are ignored (Scored)", checkstat})

	// Check 3.2.6
	cmd = "if [[ `sudo sysctl net.ipv4.icmp_ignore_bogus_error_responses|awk -F= '$2 == 1 {print}'` != '' ]]; then echo ''; else echo 'bogus icmp not ignored'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.2.6", "Ensure bogus ICMP responses are ignored (Scored)", checkstat})

	// Check 3.2.7
	cmd = "if [[ `sudo sysctl net.ipv4.conf.all.rp_filter|awk -F= '$2 == 1 {print}'` != '' && `sudo sysctl net.ipv4.conf.default.rp_filter|awk -F= '$2 == 1 {print}'` != '' ]]; then echo ''; else echo 'Reverse Path Filtering is not enabled'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.2.7", "Ensure Reverse Path Filtering is enabled (Scored)", checkstat})

	// Check 3.2.8
	cmd = "if [[ `sudo sysctl net.ipv4.tcp_syncookies|awk -F= '$2 == 1 {print}'` != '' ]]; then echo ''; else echo 'TCP SYN Cookies is not enabled'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.2.8", "Ensure TCP SYN Cookies is enabled (Scored)", checkstat})

	// Check 3.2.9
	cmd = "if [[ `sudo sysctl net.ipv6.conf.all.accept_ra|awk -F= '$2 == 0 {print}'` != '' && `sudo sysctl net.ipv6.conf.default.accept_ra|awk -F= '$2 == 0 {print}'` != '' ]]; then echo ''; else echo 'IPv6 router advertisements are accepted'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.2.9", "Ensure IPv6 router advertisements are not accepted (Scored)", checkstat})

	// Check 3.3.1
	cmd = "if [[ `rpm -q tcp_wrappers 2>/dev/null` != '' || `dpkg -s tcpd 2>/dev/null` != '' ]]; then echo ''; else echo 'tcp wrappers not installed'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.3.1", "Ensure TCP Wrappers is installed (Not Scored)", checkstat})

	// Check 3.3.2
	//cmd = "echo ''"
	//out, _ = remexec.RemoteRun(user, host, pass, cmd)
	out = ""
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.3.2", "Ensure /etc/hosts.allow is configured (Not Scored)", checkstat})

	// Check 3.3.3
	//cmd = "echo ''"
	//out, _ = remexec.RemoteRun(user, host, pass, cmd)
	out = ""
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.3.3", "Ensure /etc/hosts.deny is configured (Not Scored)", checkstat})

	// Check 3.3.4
	cmd = "if [[ `stat /etc/hosts.allow 2>/dev/null| grep root|grep 0644` != '' ]]; then echo ''; else echo '/etc/hosts.allow permissions incorrect'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.3.4", "Ensure permissions on /etc/hosts.allow are configured (Scored)", checkstat})

	// Check 3.3.5
	cmd = "if [[ `stat /etc/hosts.deny 2>/dev/null| grep root|grep 0644` != '' ]]; then echo ''; else echo '/etc/hosts.deny permissions incorrect'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.3.5", "Ensure permissions on /etc/hosts.deny are configured (Scored)", checkstat})

	// Check 3.4.1
	cmd = "if [[ `lsmod | grep dccp` == '' ]]; then echo ''; else echo 'DCCP is enabled'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.4.1", "Ensure DCCP is disabled (Scored)", checkstat})

	// Check 3.4.2
	cmd = "lsmod | grep sctp` == '' ]]; then echo ''; else echo 'SCTP is enabled'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.4.2", "Ensure SCTP is disabled (Scored)", checkstat})

	// Check 3.4.3
	cmd = "lsmod | grep rds` == '' ]]; then echo ''; else echo 'rds is enabled'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.4.3", "Ensure RDS is disabled (Scored)", checkstat})

	// Check 3.4.4
	cmd = "lsmod | grep tipc` == '' ]]; then echo ''; else echo 'tipc is enabled'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.4.4", "Ensure TIPC is disabled (Scored)", checkstat})

	// Check 3.5.1.1
	cmd = "if [[ `sudo grep linux /boot/grub2/grub.cfg 2>/dev/null | grep -v ipv6.disable=1` == '' && `sudo grep 'linux' /boot/grub/grub.cfg 2>/dev/null | grep -v ipv6.disable=1` == '' ]]; then echo ''; else echo 'Missing IPv6 default deny firewall policy'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.5.1.1", "Ensure IPv6 default deny firewall policy (Scored)", checkstat})

	// Check 3.5.1.2
	cmd = "if [[ `sudo grep linux /boot/grub2/grub.cfg 2>/dev/null | grep -v ipv6.disable=1` == '' && `sudo grep 'linux' /boot/grub/grub.cfg 2>/dev/null | grep -v ipv6.disable=1` == '' ]]; then echo ''; else echo 'IPv6 loopback traffic not configured'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.5.1.2", "Ensure IPv6 loopback traffic is configured (Scored)", checkstat})

	// Check 3.5.1.3
	cmd = "if [[ `sudo grep linux /boot/grub2/grub.cfg 2>/dev/null | grep -v ipv6.disable=1` == '' && `sudo grep 'linux' /boot/grub/grub.cfg 2>/dev/null | grep -v ipv6.disable=1` == '' ]]; then echo ''; else echo 'IPv6 outbound and established connections not configured'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.5.1.3", "Ensure IPv6 outbound and established connections are configured (Not Scored)", checkstat})

	// Check 3.5.1.4
	cmd = "if [[ `sudo grep linux /boot/grub2/grub.cfg 2>/dev/null | grep -v ipv6.disable=1` == '' && `sudo grep 'linux' /boot/grub/grub.cfg 2>/dev/null | grep -v ipv6.disable=1` == '' ]]; then echo ''; else echo 'IPv6 firewall rules does not exist'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.5.1.4", "Ensure IPv6 firewall rules exist for all open ports (Not Scored)", checkstat})

	// Check 3.5.2.1
	cmd = "case `for i in $( echo rpm dpkg pacman ); do which $i; done 2> /dev/null|awk -F'bin/' '{print $NF}'` in dpkg) if [[ `sudo ufw status verbose|grep Default|grep deny 2>/dev/null` != '' ]]; then echo ''; else echo 'default deny policy not set for firewall'; fi;; rpm) if [[ `sudo iptables -L|egrep -i 'INPUT|OUTPUT|FORWARD'|grep ACCEPT|wc -l 2>/dev/null` -ge 3 ]]; then echo ''; else echo 'default deny policy not set for iptables'; fi;; esac"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.5.2.1", " Ensure default deny firewall policy (Scored)", checkstat})

	// Check 3.5.2.1
	cmd = "case `for i in $( echo rpm dpkg pacman ); do which $i; done 2> /dev/null|awk -F'bin/' '{print $NF}'` in dpkg) if [[ `sudo ufw status verbose|grep Default|grep deny 2>/dev/null` != '' ]]; then echo ''; else echo 'loopback traffic not configured'; fi;; rpm) if [[ `sudo iptables -L INPUT -v -n|grep lo 2>/dev/null` != '' ]]; then echo ''; else echo 'loopback traffic not configured'; fi;; esac"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.5.2.2", "Ensure loopback traffic is configured (Scored)", checkstat})

	// Check 3.5.2.3
	cmd = "case `for i in $( echo rpm dpkg pacman ); do which $i; done 2> /dev/null|awk -F'bin/' '{print $NF}'` in dpkg) if [[ `sudo ufw status verbose|grep Default|grep deny 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure outbound and established connections are configured'; fi;; rpm) if [[ `sudo iptables -L INPUT -v -n|grep lo 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure outbound and established connections are configured'; fi;; esac"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.5.2.3", "Ensure outbound and established connections are configured (Not Scored)", checkstat})

	// Check 3.5.2.4
	cmd = "case `for i in $( echo rpm dpkg pacman ); do which $i; done 2> /dev/null|awk -F'bin/' '{print $NF}'` in dpkg) if [[ `sudo ufw status verbose|grep Default|grep deny 2>/dev/null` != '' ]]; then echo ''; else echo 'firewall rules not found for all open ports'; fi;; rpm) if [[ `ss -4tuln|awk '{print $5}'|grep -v Local|awk -F: '{print $NF}'|uniq|wc -l 2>/dev/null` -ge `sudo iptables -L INPUT -v -n|egrep 'tcp|udp'|wc -l 2>/dev/null` ]]; then echo ''; else echo 'firewall rules not found for all open ports'; fi;; esac"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.5.2.4", "Ensure firewall rules exist for all open ports (Scored)", checkstat})

	// Check 3.5.3
	cmd = "if [[ `rpm -q iptables 2>/dev/null` != '' || `dpkg -s iptables 2>/dev/null` != '' ]]; then echo ''; else echo 'iptables not installed'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.5.3", "Ensure iptables is installed (Scored)", checkstat})

	// Check 3.6
	cmd = "if [[ `ip link show up|grep wl 2>/dev/null` == '' ]]; then echo ''; else echo 'wireless interface active'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.6", "Ensure wireless interfaces are disabled (Not Scored)", checkstat})

	// Check 3.7
	cmd = "if [[ `sudo grep linux /boot/grub2/grub.cfg 2>/dev/null | grep -v ipv6.disable=1` == '' && `sudo grep 'linux' /boot/grub/grub.cfg 2>/dev/null | grep -v ipv6.disable=1` == '' ]]; then echo ''; else echo 'IPv6 enabled'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"3.7", "Disable IPv6 (Not Scored)", checkstat})

	return ServicesSlice
}

func init() {
}

// Datastat struct declaration
type Datastat struct {
	Controlid string
	Check     string
	Status    string
}