package cislinuxtwo

import (
	"log"
	"govuln-scanner/remexec"
	"strings"
)

var checkstat, cmd string

// Cislinuxtwo Function
func Cislinuxtwo(user string, host string, pass string) []Datastat {
	ServicesSlice := []Datastat{}

	// Check 2.1.1
	cmd = "grep -R \"^chargen\" /etc/inetd.*"
	out, _ := remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.1.1", "Ensure chargen services are not enabled (Scored)", checkstat})

	// Check 2.1.2
	cmd = "grep -R \"^daytime\" /etc/inetd.*"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.1.2", "Ensure daytime services are not enabled (Scored)", checkstat})

	// Check 2.1.3
	cmd = "grep -R \"^discard\" /etc/inetd.*"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.1.3", "Ensure discard services are not enabled (Scored)", checkstat})

	// Check 2.1.4
	cmd = "grep -R \"^echo\" /etc/inetd.*"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.1.4", "Ensure echo services are not enabled (Scored)", checkstat})

	// Check 2.1.5
	cmd = "grep -R \"^time\" /etc/inetd.*"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.1.5", "Ensure time services are not enabled (Scored)", checkstat})

	// Check 2.1.6
	cmd = "if [[ `grep -R \"^shell\" /etc/inetd.* 2>/dev/null` == '' && `grep -R \"^login\" /etc/inetd.* 2>/dev/null` == '' && `grep -R \"^exec\" /etc/inetd.* 2>/dev/null` == '' ]]; then echo ''; else echo 'rsh server enabled'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.1.6", "Ensure rsh server is not enabled (Scored)", checkstat})

	// Check 2.1.7
	cmd = "if [[ `grep -R \"^talk\" /etc/inetd.* 2>/dev/null` == '' && `grep -R \"^ntalk\" /etc/inetd.* 2>/dev/null` == '' ]]; then echo ''; else echo 'talk server enabled'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.1.7", "Ensure talk server is not enabled (Scored)", checkstat})

	// Check 2.1.8
	cmd = "grep -R \"^telnet\" /etc/inetd.*"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.1.8", "Ensure telnet server is not enabled (Scored)", checkstat})

	// Check 2.1.9
	cmd = "grep -R \"^tftp\" /etc/inetd.*"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.1.9", "Ensure tftp server is not enabled (Scored)", checkstat})

	// Check 2.2.1.1
	cmd = "case `for i in $( echo rpm dpkg pacman ); do which $i; done 2> /dev/null|awk -F'bin/' '{print $NF}'` in dpkg) if [[ `dpkg -s ntp 2>/dev/null` != '' || `dpkg -s chrony 2>/dev/null` != '' ]]; then echo ''; else echo 'time package not detected'; fi;; rpm) if [[ `rpm -q ntp 2>/dev/null` != '' || `rpm -q chrony 2>/dev/null` != '' ]]; then echo ''; else echo 'time package not detected'; fi;; esac"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.2.1.1", "Ensure time synchronization is in use (Not Scored)", checkstat})	

	// Check 2.2.1.2
	cmd = "if [[ `grep \"^restrict\" /etc/ntp.conf 2>/dev/null` != '' ]]; then echo ''; else echo 'ntp not configured correctly'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.2.1.2", " Ensure ntp is configured (Scored)", checkstat})	

	// Check 2.2.1.3
	cmd = "if [[ `grep -E \"^(server|pool)\" /etc/chrony.conf 2>/dev/null` != '' ]]; then echo ''; else echo 'chrony not installed/configured correctly'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.2.1.3", "Ensure chrony is configured (Scored)", checkstat})	

	// Check 2.2.1.4
	cmd = "if [[ `timedatectl status|grep synchronized|grep yes` != '' ]]; then echo ''; else echo 'time not synced'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.2.1.4", "Ensure systemd-timesyncd is configured (Scored)", checkstat})	

	// Check 2.2.2
	cmd = "if [[ `dpkg -s xserver-xorg 2>/dev/null` == '' && `rpm -q xorg-x11-server-Xorg 2>/dev/null` == '' ]]; then echo ''; else echo 'xorg installed'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.2.2", "Ensure X Window System is not installed (Scored)", checkstat})	

	// Check 2.2.3
	cmd = "if [[ `ls /etc/rc*.d | grep avahi-daemon|grep S` == '' ]]; then echo ''; else echo 'avahi-daemon running'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.2.3", "Ensure Avahi Server is not enabled (Scored)", checkstat})	

	// Check 2.2.4
	cmd = "if [[ `ls /etc/rc*.d | grep cups|grep S` == '' ]]; then echo ''; else echo 'cups running'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.2.4", "Ensure CUPS is not enabled (Scored)", checkstat})	

	// Check 2.2.5
	cmd = "if [[ `ls /etc/rc*.d | grep dhcpd|grep S` == '' ]]; then echo ''; else echo 'dhcpd running'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.2.5", "Ensure DHCP Server is not enabled (Scored)", checkstat})	

	// Check 2.2.6
	cmd = "if [[ `ls /etc/rc*.d | grep slapd|grep S` == '' ]]; then echo ''; else echo 'slapd running'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.2.6", "Ensure LDAP server is not enabled (Scored)", checkstat})	

	// Check 2.2.7
	cmd = "if [[ `ls /etc/rc*.d | grep nfs|grep S` == '' && `ls /etc/rc*.d | grep rpcbind|grep S` == '' ]]; then echo ''; else echo 'nfs/rpcbind running'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.2.7", "Ensure NFS and RPC are not enabled (Scored)", checkstat})	

	// Check 2.2.8
	cmd = "if [[ `ls /etc/rc*.d | grep named|grep S` == '' ]]; then echo ''; else echo 'named running'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.2.8", "Ensure DNS Server is not enabled (Scored)", checkstat})	

	// Check 2.2.9
	cmd = "if [[ `ls /etc/rc*.d | grep vsftpd|grep S` == '' ]]; then echo ''; else echo 'vsftpd running'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.2.9", "Ensure FTP Server is not enabled (Scored)", checkstat})	

	// Check 2.2.10
	cmd = "if [[ `ls /etc/rc*.d | grep httpd|grep S` == '' ]]; then echo ''; else echo 'httpd running'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.2.10", "Ensure HTTP server is not enabled (Scored)", checkstat})	

	// Check 2.2.11
	cmd = "if [[ `ls /etc/rc*.d | grep dovecot|grep S` == '' ]]; then echo ''; else echo 'dovecot running'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.2.11", "Ensure IMAP and POP3 server is not enabled (Scored)", checkstat})	

	// Check 2.2.12
	cmd = "if [[ `ls /etc/rc*.d | grep smb|grep S` == '' ]]; then echo ''; else echo 'smb running'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.2.12", "Ensure Samba is not enabled (Scored)", checkstat})	

	// Check 2.2.13
	cmd = "if [[ `ls /etc/rc*.d | grep squid|grep S` == '' ]]; then echo ''; else echo 'squid running'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.2.13", "Ensure HTTP Proxy Server is not enabled (Scored)", checkstat})	

	// Check 2.2.14
	cmd = "if [[ `ls /etc/rc*.d | grep snmpd|grep S` == '' ]]; then echo ''; else echo 'snmpd running'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.2.14", "Ensure SNMP Server is not enabled (Scored)", checkstat})	

	// Check 2.2.15
	cmd = "if [[ `ss -lntu | grep -E ':25\\s' | grep -E -v '\\s(127.0.0.1|::1):25\\s` == '' ]]; then echo ''; else echo 'MTA listening'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.2.15", "Ensure mail transfer agent is configured for local-only mode (Scored)", checkstat})	

	// Check 2.2.16
	cmd = "if [[ `ls /etc/rc*.d | grep rsyncd|grep S` == '' ]]; then echo ''; else echo 'rsyncd running'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.2.16", "Ensure rsync service is not enabled (Scored)", checkstat})	

	// Check 2.2.17
	cmd = "if [[ `ls /etc/rc*.d | grep ypserv|grep S` == '' ]]; then echo ''; else echo 'ypserv running'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.2.17", "Ensure NIS Server is not enabled (Scored)", checkstat})	

	// Check 2.3.1
	cmd = "if [[ `dpkg -s ypbind 2>/dev/null` == '' && `rpm -q ypbind 2>/dev/null` == '' ]]; then echo ''; else echo 'ypbind installed'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.3.1", "Ensure NIS Client is not installed (Scored)", checkstat})	

	// Check 2.3.2
	cmd = "if [[ `dpkg -s rsh 2>/dev/null` == '' && `rpm -q rsh 2>/dev/null` == '' ]]; then echo ''; else echo 'rsh installed'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.3.2", "Ensure rsh client is not installed (Scored)", checkstat})	

	// Check 2.3.3
	cmd = "if [[ `dpkg -s talk 2>/dev/null` == '' && `rpm -q talk 2>/dev/null` == '' ]]; then echo ''; else echo 'talk installed'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.3.3", "Ensure talk client is not installed (Scored)", checkstat})	

	// Check 2.3.4
	cmd = "if [[ `dpkg -s telnet 2>/dev/null` == '' && `rpm -q telnet 2>/dev/null` == '' ]]; then echo ''; else echo 'telnet installed'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.3.4", "Ensure telnet client is not installed (Scored)", checkstat})	

	// Check 2.3.5
	cmd = "if [[ `dpkg -s openldap-clients 2>/dev/null` == '' && `rpm -q openldap-clients 2>/dev/null` == '' ]]; then echo ''; else echo 'openldap-clients installed'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"2.3.5", "Ensure LDAP client is not installed (Scored)", checkstat})	

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
