package cislinuxfour

import (
	"log"
	"govuln-scanner/remexec"
	"strings"
)

var checkstat, cmd string

// Cislinuxfour Function
func Cislinuxfour(user string, host string, pass string) []Datastat {
	ServicesSlice := []Datastat{}

	// Check 4.1.1.1
	cmd = "if [[ `sudo grep max_log_file /etc/audit/auditd.conf 2>/dev/null` != '' ]]; then echo ''; else echo 'audit log storage size is not configured'; fi"
	out, _ := remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.1.1.1", "Ensure audit log storage size is configured (Scored)", checkstat})

	// Check 4.1.1.2
	cmd = "if [[ `sudo grep space_left_action /etc/audit/auditd.conf 2>/dev/null` != '' && `sudo grep action_mail_acct /etc/audit/auditd.conf 2>/dev/null` != '' && `sudo grep admin_space_left_action /etc/audit/auditd.conf 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure system is disabled when audit logs are full'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.1.1.2", "Ensure system is disabled when audit logs are full (Scored)", checkstat})

	// Check 4.1.1.3
	cmd = "if [[ `sudo grep max_log_file_action /etc/audit/auditd.conf 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure audit logs are not automatically deleted'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.1.1.3", "Ensure audit logs are not automatically deleted (Scored)", checkstat})

	// Check 4.1.2
	cmd = "if [[ `rpm -q audit audit-libs 2>/dev/null` != '' || `dpkg -s auditd audispd-plugins 2>/dev/null` != '' ]]; then echo ''; else echo 'auditd not installed'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.1.2", "Ensure auditd is installed (Scored)", checkstat})

	// Check 4.1.3
	cmd = "if [[ `ls /etc/rc*.d | grep auditd|grep S` != '' ]]; then echo ''; else echo 'auditd service not enabled'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.1.3", "Ensure auditd service is enabled (Scored)", checkstat})

	// Check 4.1.4
	cmd = "if [[ `sudo grep 'audit=1' /boot/grub/grub.cfg 2>/dev/null` != '' || `sudo grep 'audit=1' /boot/grub2/grub.cfg 2>/dev/null` != '' ]]; then echo ''; else echo 'auditd not enabled on boot'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.1.4", "Ensure auditing for processes that start prior to auditd is enabled (Scored)", checkstat})

	// Check 4.1.5
	cmd = "if [[ `sudo grep time-change /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure events that modify date and time information are collected'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.1.5", "Ensure events that modify date and time information are collected (Scored)", checkstat})

	// Check 4.1.6
	cmd = "if [[ `sudo grep identity /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure events that modify user/group information are collected'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.1.6", "Ensure events that modify user/group information are collected (Scored)", checkstat})

	// Check 4.1.7
	cmd = "if [[ `sudo grep system-locale /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure events that modify the system's network environment are collected'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.1.7", "Ensure events that modify the system's network environment are collected (Scored)", checkstat})

	// Check 4.1.8
	cmd = "if [[ `sudo grep MAC-policy /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure events that modify the system's Mandatory Access Controls are collected'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.1.8", "Ensure events that modify the system's Mandatory Access Controls are collected (Scored)", checkstat})

	// Check 4.1.9
	cmd = "if [[ `sudo grep logins /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure login and logout events are collected'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.1.9", "Ensure login and logout events are collected (Scored)", checkstat})

	// Check 4.1.10
	cmd = "if [[ `sudo grep -E '(session|logins)' /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure session initiation information is collected'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.1.10", "Ensure session initiation information is collected (Scored)", checkstat})

	// Check 4.1.11
	cmd = "if [[ `sudo grep auditctl -l | grep perm_mod /etc/audit/rules.d/*.rules	2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure discretionary access control permission modification events are collected'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.1.11", "Ensure discretionary access control permission modification events are collected (Scored)", checkstat})

	// Check 4.1.12
	cmd = "if [[ `sudo grep access /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure unsuccessful unauthorized file access attempts are collected'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.1.12", "Ensure unsuccessful unauthorized file access attempts are collected (Scored)", checkstat})

	// Check 4.1.13
	cmd = "if [[ `sudo find / -xdev -perm -4000 -o -perm -2000 -type f |wc -l` -ge 1  ]]; then if [[ `sudo grep 'auid!=-1' /etc/audit/rules.d/* 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure use of privileged commands is collected'; fi; else echo ''; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.1.13", "Ensure use of privileged commands is collected (Scored)", checkstat})

	// Check 4.1.14
	cmd = "if [[ `sudo grep mounts /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure successful file system mounts are collected'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.1.14", "Ensure successful file system mounts are collected (Scored)", checkstat})

	// Check 4.1.15
	cmd = "if [[ `sudo grep delete /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure file deletion events by users are collected'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.1.15", "Ensure file deletion events by users are collected (Scored)", checkstat})

	// Check 4.1.16
	cmd = "if [[ `sudo grep scope /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure changes to system administration scope (sudoers) is collected'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.1.16", "Ensure changes to system administration scope (sudoers) is collected (Scored)", checkstat})

	// Check 4.1.17
	cmd = "if [[ `sudo grep actions /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure system administrator actions (sudolog) are collected'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.1.17", "Ensure system administrator actions (sudolog) are collected (Scored)", checkstat})

	// Check 4.1.18
	cmd = "if [[ `sudo grep modules /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure kernel module loading and unloading is collected'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.1.18", "Ensure kernel module loading and unloading is collected (Scored)", checkstat})

	// Check 4.1.19
	cmd = "if [[ `sudo grep '-e 2' /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure the audit configuration is immutable'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.1.19", "Ensure the audit configuration is immutable (Scored)", checkstat})

	// Check 4.2.1.1
	cmd = "if [[ `rpm -q rsyslog 2>/dev/null` != '' || `dpkg -s rsyslog 2>/dev/null` != '' ]]; then echo ''; else echo 'rsyslog not installed'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.2.1.1", "Ensure rsyslog is installed (Scored)", checkstat})

	// Check 4.2.1.2
	cmd = "if [[ `ls /etc/rc*.d | grep rsyslog|grep S` != '' ]]; then echo ''; else echo 'rsyslog service not enabled'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.2.1.2", "Ensure rsyslog Service is enabled (Scored)", checkstat})

	// Check 4.2.1.3
	cmd = "if [[ `ls -l /var/log` != '' ]]; then echo ''; else echo 'logging not configured'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.2.1.3", "Ensure logging is configured (Not Scored)", checkstat})

	// Check 4.2.1.4
	cmd = "if [[ `grep FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf|grep 640 2>/dev/null` != '' ]]; then echo ''; else echo 'rsyslog default file permissions incorrect'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.2.1.4", "Ensure rsyslog default file permissions configured (Scored)", checkstat})

	// Check 4.2.1.5
	cmd = "if [[ `grep '^*.*[^I][^I]*@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null` != '' ]]; then echo ''; else echo 'remote log host not found'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.2.1.5", "Ensure rsyslog is configured to send logs to a remote log host (Scored)", checkstat})

	// Check 4.2.1.6
	cmd = "if [[ `grep '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null` != '' && `grep '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null` != '' ]]; then echo ''; else echo 'rsyslog not configured for destined log hosts'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.2.1.6", "Ensure remote rsyslog messages are only accepted on designated log hosts. (Not Scored)", checkstat})

	// Check 4.2.2.1
	cmd = "if [[ `grep -e ForwardToSyslog /etc/systemd/journald.conf 2>/dev/null` != '' ]]; then echo ''; else echo 'journald is not configured to send logs to rsyslog '; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.2.2.1", "Ensure journald is configured to send logs to rsyslog (Scored)", checkstat})

	// Check 4.2.2.2
	cmd = "if [[ `grep -e Compress /etc/systemd/journald.conf|grep -v # 2>/dev/null` != '' ]]; then echo ''; else echo 'journald is not configured to compress large log files'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.2.2.2", "Ensure journald is configured to compress large log files (Scored)", checkstat})

	// Check 4.2.2.3
	cmd = "if [[ `grep -e Storage /etc/systemd/journald.conf|grep persistent|grep -v # 2>/dev/null` != '' ]]; then echo ''; else echo 'journald is not configured to write logfiles to persistent disk'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.2.2.3", "Ensure journald is configured to write logfiles to persistent disk (Scored)", checkstat})

	// Check 4.2.3
	cmd = "found=0; for file in `sudo find /var/log -type f -ls|awk '{print $NF}'`; do if [[ `sudo stat $file|grep Access|egrep '0640|0600'` == '' ]]; then found=1; fi; done; if [[ found -eq 0 ]]; then echo ''; else echo 'logfiles permissions are incorrect'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.2.3", "Ensure permissions on all logfiles are configured (Scored)", checkstat})

	// Check 4.3
	cmd = "if [[ `ls -l /etc/logrotate.conf 2>/dev/null` != '' ]]; then echo ''; else echo 'logrotate not configured'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"4.3", "Ensure logrotate is configured (Not Scored)", checkstat})

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
