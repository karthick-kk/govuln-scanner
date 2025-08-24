package cislinuxfour

import (
	"govuln-scanner/remexec"
	"log"
	"strings"
)

type Check struct {
	ID          string
	Description string
	Command     string
}

func CislinuxfourOptimized(conn *remexec.SSHConnection) []Datastat {
	ServicesSlice := []Datastat{}

	checks := []Check{
		{
			ID:          "4.1.1.1",
			Description: "Ensure audit log storage size is configured (Scored)",
			Command:     "if [[ `sudo grep max_log_file /etc/audit/auditd.conf 2>/dev/null` != '' ]]; then echo ''; else echo 'audit log storage size is not configured'; fi",
		},
		{
			ID:          "4.1.1.2",
			Description: "Ensure system is disabled when audit logs are full (Scored)",
			Command:     "if [[ `sudo grep space_left_action /etc/audit/auditd.conf 2>/dev/null` != '' && `sudo grep action_mail_acct /etc/audit/auditd.conf 2>/dev/null` != '' && `sudo grep admin_space_left_action /etc/audit/auditd.conf 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure system is disabled when audit logs are full'; fi",
		},
		{
			ID:          "4.1.1.3",
			Description: "Ensure audit logs are not automatically deleted (Scored)",
			Command:     "if [[ `sudo grep max_log_file_action /etc/audit/auditd.conf 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure audit logs are not automatically deleted'; fi",
		},
		{
			ID:          "4.1.2",
			Description: "Ensure auditd is installed (Scored)",
			Command:     "if [[ `rpm -q audit audit-libs 2>/dev/null` != '' || `dpkg -s auditd audispd-plugins 2>/dev/null` != '' ]]; then echo ''; else echo 'auditd not installed'; fi",
		},
		{
			ID:          "4.1.3",
			Description: "Ensure auditd service is enabled (Scored)",
			Command:     "if [[ `ls /etc/rc*.d | grep auditd|grep S` != '' ]]; then echo ''; else echo 'auditd service not enabled'; fi",
		},
		{
			ID:          "4.1.4",
			Description: "Ensure auditing for processes that start prior to auditd is enabled (Scored)",
			Command:     "if [[ `sudo grep 'audit=1' /boot/grub/grub.cfg 2>/dev/null` != '' || `sudo grep 'audit=1' /boot/grub2/grub.cfg 2>/dev/null` != '' ]]; then echo ''; else echo 'auditd not enabled on boot'; fi",
		},
		{
			ID:          "4.1.5",
			Description: "Ensure events that modify date and time information are collected (Scored)",
			Command:     "if [[ `sudo grep time-change /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure events that modify date and time information are collected'; fi",
		},
		{
			ID:          "4.1.6",
			Description: "Ensure events that modify user/group information are collected (Scored)",
			Command:     "if [[ `sudo grep identity /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure events that modify user/group information are collected'; fi",
		},
		{
			ID:          "4.1.7",
			Description: "Ensure events that modify the system's network environment are collected (Scored)",
			Command:     "if [[ `sudo grep system-locale /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure events that modify the system's network environment are collected'; fi",
		},
		{
			ID:          "4.1.8",
			Description: "Ensure events that modify the system's Mandatory Access Controls are collected (Scored)",
			Command:     "if [[ `sudo grep MAC-policy /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure events that modify the system's Mandatory Access Controls are collected'; fi",
		},
		{
			ID:          "4.1.9",
			Description: "Ensure login and logout events are collected (Scored)",
			Command:     "if [[ `sudo grep logins /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure login and logout events are collected'; fi",
		},
		{
			ID:          "4.1.10",
			Description: "Ensure session initiation information is collected (Scored)",
			Command:     "if [[ `sudo grep -E '(session|logins)' /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure session initiation information is collected'; fi",
		},
		{
			ID:          "4.1.11",
			Description: "Ensure discretionary access control permission modification events are collected (Scored)",
			Command:     "if [[ `sudo grep auditctl -l | grep perm_mod /etc/audit/rules.d/*.rules	2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure discretionary access control permission modification events are collected'; fi",
		},
		{
			ID:          "4.1.12",
			Description: "Ensure unsuccessful unauthorized file access attempts are collected (Scored)",
			Command:     "if [[ `sudo grep access /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure unsuccessful unauthorized file access attempts are collected'; fi",
		},
		{
			ID:          "4.1.13",
			Description: "Ensure use of privileged commands is collected (Scored)",
			Command:     "if [[ `sudo find / -xdev -perm -4000 -o -perm -2000 -type f |wc -l` -ge 1  ]]; then if [[ `sudo grep 'auid!=-1' /etc/audit/rules.d/* 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure use of privileged commands is collected'; fi; else echo ''; fi",
		},
		{
			ID:          "4.1.14",
			Description: "Ensure successful file system mounts are collected (Scored)",
			Command:     "if [[ `sudo grep mounts /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure successful file system mounts are collected'; fi",
		},
		{
			ID:          "4.1.15",
			Description: "Ensure file deletion events by users are collected (Scored)",
			Command:     "if [[ `sudo grep delete /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure file deletion events by users are collected'; fi",
		},
		{
			ID:          "4.1.16",
			Description: "Ensure changes to system administration scope (sudoers) is collected (Scored)",
			Command:     "if [[ `sudo grep scope /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure changes to system administration scope (sudoers) is collected'; fi",
		},
		{
			ID:          "4.1.17",
			Description: "Ensure system administrator actions (sudolog) are collected (Scored)",
			Command:     "if [[ `sudo grep actions /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure system administrator actions (sudolog) are collected'; fi",
		},
		{
			ID:          "4.1.18",
			Description: "Ensure kernel module loading and unloading is collected (Scored)",
			Command:     "if [[ `sudo grep modules /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure kernel module loading and unloading is collected'; fi",
		},
		{
			ID:          "4.1.19",
			Description: "Ensure the audit configuration is immutable (Scored)",
			Command:     "if [[ `sudo grep '-e 2' /etc/audit/rules.d/*.rules 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure the audit configuration is immutable'; fi",
		},
		{
			ID:          "4.2.1.1",
			Description: "Ensure rsyslog is installed (Scored)",
			Command:     "if [[ `rpm -q rsyslog 2>/dev/null` != '' || `dpkg -s rsyslog 2>/dev/null` != '' ]]; then echo ''; else echo 'rsyslog not installed'; fi",
		},
		{
			ID:          "4.2.1.2",
			Description: "Ensure rsyslog Service is enabled (Scored)",
			Command:     "if [[ `ls /etc/rc*.d | grep rsyslog|grep S` != '' ]]; then echo ''; else echo 'rsyslog service not enabled'; fi",
		},
		{
			ID:          "4.2.1.3",
			Description: "Ensure logging is configured (Not Scored)",
			Command:     "if [[ `ls -l /var/log` != '' ]]; then echo ''; else echo 'logging not configured'; fi",
		},
		{
			ID:          "4.2.1.4",
			Description: "Ensure rsyslog default file permissions configured (Scored)",
			Command:     "if [[ `grep FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf|grep 640 2>/dev/null` != '' ]]; then echo ''; else echo 'rsyslog default file permissions incorrect'; fi",
		},
		{
			ID:          "4.2.1.5",
			Description: "Ensure rsyslog is configured to send logs to a remote log host (Scored)",
			Command:     "if [[ `grep '^*.*[^I][^I]*@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null` != '' ]]; then echo ''; else echo 'remote log host not found'; fi",
		},
		{
			ID:          "4.2.1.6",
			Description: "Ensure remote rsyslog messages are only accepted on designated log hosts. (Not Scored)",
			Command:     "if [[ `grep '$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null` != '' && `grep '$InputTCPServerRun' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null` != '' ]]; then echo ''; else echo 'rsyslog not configured for destined log hosts'; fi",
		},
		{
			ID:          "4.2.2.1",
			Description: "Ensure journald is configured to send logs to rsyslog (Scored)",
			Command:     "if [[ `grep -e ForwardToSyslog /etc/systemd/journald.conf 2>/dev/null` != '' ]]; then echo ''; else echo 'journald is not configured to send logs to rsyslog '; fi",
		},
		{
			ID:          "4.2.2.2",
			Description: "Ensure journald is configured to compress large log files (Scored)",
			Command:     "if [[ `grep -e Compress /etc/systemd/journald.conf|grep -v # 2>/dev/null` != '' ]]; then echo ''; else echo 'journald is not configured to compress large log files'; fi",
		},
		{
			ID:          "4.2.2.3",
			Description: "Ensure journald is configured to write logfiles to persistent disk (Scored)",
			Command:     "if [[ `grep -e Storage /etc/systemd/journald.conf|grep persistent|grep -v # 2>/dev/null` != '' ]]; then echo ''; else echo 'journald is not configured to write logfiles to persistent disk'; fi",
		},
		{
			ID:          "4.2.3",
			Description: "Ensure permissions on all logfiles are configured (Scored)",
			Command:     "found=0; for file in `sudo find /var/log -type f -ls|awk '{print $NF}'`; do if [[ `sudo stat $file|grep Access|egrep '0640|0600'` == '' ]]; then found=1; fi; done; if [[ found -eq 0 ]]; then echo ''; else echo 'logfiles permissions are incorrect'; fi",
		},
		{
			ID:          "4.3",
			Description: "Ensure logrotate is configured (Not Scored)",
			Command:     "if [[ `ls -l /etc/logrotate.conf 2>/dev/null` != '' ]]; then echo ''; else echo 'logrotate not configured'; fi",
		},
	}

	log.Printf("DEBUG: Executing %d CIS cislinuxfour checks individually\n", len(checks))
	
	for _, check := range checks {
		out, err := conn.RunCommand(check.Command)
		checkstat := remexec.EvalCommandResult(remexec.CommandResult{
			Output: out,
			Error:  err,
		})
		
		if err != nil {
			log.Printf("DEBUG: Check %s command error: %v; output: %s\n", check.ID, err, out)
		} else if len(strings.TrimSpace(out)) != 0 {
			log.Printf("DEBUG: Check %s output: %s\n", check.ID, out)
		}
		
		ServicesSlice = append(ServicesSlice, Datastat{check.ID, check.Description, checkstat})
	}

	log.Printf("DEBUG: Completed %d CIS cislinuxfour checks via individual execution\n", len(ServicesSlice))
	return ServicesSlice
}



func Cislinuxfour(user string, host string, pass string, key string) []Datastat {
	conn, err := remexec.NewSSHConnection(user, host, pass, key)
	if err != nil {
		log.Printf("ERROR: Failed to create SSH connection: %v\n", err)
		return []Datastat{}
	}
	defer conn.Close()

	return CislinuxfourOptimized(conn)
}

type Datastat struct {
	Controlid string
	Check     string
	Status    string
}
