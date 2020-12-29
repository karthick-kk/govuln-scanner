package cislinuxfive

import (
	"log"
	"govuln-scanner/remexec"
	"strings"
)

var checkstat, cmd string

// Cislinuxfive Function
func Cislinuxfive(user string, host string, pass string) []Datastat {
	ServicesSlice := []Datastat{}

	// Check 5.1.1
	cmd = "if [[ `ls /etc/rc*.d | grep crond|grep S` != '' ]]; then echo ''; else echo 'crond service not enabled'; fi"
	out, _ := remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.1.1", "Ensure cron daemon is enabled (Scored)", checkstat})

	// Check 5.1.2
	cmd = "if [[ `stat /etc/crontab 2>/dev/null| grep root|grep 0600` != '' ]]; then echo ''; else echo '/etc/crontab permissions incorrect'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.1.2", "Ensure permissions on /etc/crontab are configured (Scored)", checkstat})

	// Check 5.1.3
	cmd = "if [[ `stat /etc/cron.hourly	2>/dev/null| grep root|grep 0700` != '' ]]; then echo ''; else echo '/etc/cron.hourly permissions incorrect'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.1.3", "Ensure permissions on /etc/cron.hourly are configured (Scored)", checkstat})

	// Check 5.1.4
	cmd = "if [[ `stat /etc/cron.daily	2>/dev/null| grep root|grep 0700` != '' ]]; then echo ''; else echo '/etc/cron.daily permissions incorrect'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.1.4", "Ensure permissions on /etc/cron.daily are configured (Scored)", checkstat})

	// Check 5.1.5
	cmd = "if [[ `stat /etc/cron.weekly	2>/dev/null| grep root|grep 0700` != '' ]]; then echo ''; else echo '/etc/cron.weekly permissions incorrect'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.1.5", "Ensure permissions on /etc/cron.weekly are configured (Scored)", checkstat})

	// Check 5.1.6
	cmd = "if [[ `stat /etc/cron.monthly 2>/dev/null| grep root|grep 0700` != '' ]]; then echo ''; else echo '/etc/cron.monthly permissions incorrect'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.1.6", " Ensure permissions on /etc/cron.monthly are configured (Scored)", checkstat})

	// Check 5.1.7
	cmd = "if [[ `stat /etc/cron.d 2>/dev/null| grep root|grep 0700` != '' ]]; then echo ''; else echo '/etc/cron.d permissions incorrect'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.1.7", "Ensure permissions on /etc/cron.d are configured (Scored)", checkstat})

	// Check 5.1.8
	cmd = "if [[ `ls -l /etc/cron.deny 2>/dev/null` == '' && `ls -l /etc/at.deny 2>/dev/null` == '' && `stat /etc/cron.allow 2>/dev/null| grep root|grep 0600` != '' && `stat /etc/at.allow 2>/dev/null| grep root|grep 0600` != '' ]]; then echo ''; else echo 'at/cron permissions incorrect'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.1.8", "Ensure at/cron is restricted to authorized users (Scored)", checkstat})

	// Check 5.2.1
	cmd = "if [[ `stat /etc/ssh/sshd_config	2>/dev/null| grep root|grep 0600` != '' ]]; then echo ''; else echo '/etc/ssh/sshd_config permissions incorrect'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.2.1", "Ensure permissions on /etc/ssh/sshd_config are configured (Scored)", checkstat})

	// Check 5.2.2
	cmd = "found=1; for file in `find /etc/ssh -xdev -type f -name 'ssh_host_*_key'`; do if [[ `stat $file|grep root|grep 0600` != '' ]]; then found=1; else found=0; fi; done; if [[ $found == 1 ]]; then echo ''; else echo 'Ensure permissions on SSH private host key files are configured'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.2.2", "Ensure permissions on SSH private host key files are configured (Scored)", checkstat})

	// Check 5.2.3
	cmd = "found=1; for file in `find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub'`; do if [[ `stat $file|grep root|grep 0600` != '' ]]; then found=1; else found=0; fi; done; if [[ $found == 1 ]]; then echo ''; else echo 'Ensure permissions on SSH public host key files are configured'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.2.3", "Ensure permissions on SSH public host key files are configured	(Scored)", checkstat})

	// Check 5.2.4
	cmd = "if [[ ! -f /etc/ssh/sshd_config || `grep ^Protocol /etc/ssh/sshd_config|grep 2` != '' ]]; then echo ''; else echo 'SSH Protocol not set to 2'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.2.4", "Ensure SSH Protocol is set to 2 (Scored)", checkstat})

	// Check 5.2.5
	cmd = "if [[ ! -f /etc/ssh/sshd_config || `grep -i ^loglevel /etc/ssh/sshd_config|grep VERBOSE` != '' ]]; then echo ''; else echo 'SSH LogLevel not set to VERBOSE'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.2.5", "Ensure SSH LogLevel is appropriate (Scored)", checkstat})

	// Check 5.2.6
	cmd = "if [[ ! -f /etc/ssh/sshd_config || `grep -i ^x11forwarding /etc/ssh/sshd_config|grep no` != '' ]]; then echo ''; else echo 'SSH x11forwarding not set to no'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.2.6", "Ensure SSH X11 forwarding is disabled (Scored)", checkstat})

	// Check 5.2.7
	cmd = "if [[ ! -f /etc/ssh/sshd_config || `grep -i ^MaxAuthTries /etc/ssh/sshd_config|awk '{print $NF}'` -ge 4 ]]; then echo ''; else echo 'SSH MaxAuthTries not set to 4 or less'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.2.7", "Ensure SSH MaxAuthTries is set to 4 or less (Scored)", checkstat})

	// Check 5.2.8
	cmd = "if [[ ! -f /etc/ssh/sshd_config || `grep -i ^IgnoreRhosts /etc/ssh/sshd_config|grep yes` != '' ]]; then echo ''; else echo 'SSH IgnoreRhosts not set to yes'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.2.8", "Ensure SSH IgnoreRhosts is enabled (Scored)", checkstat})

	// Check 5.2.9
	cmd = "if [[ ! -f /etc/ssh/sshd_config || `grep -i ^HostbasedAuthentication /etc/ssh/sshd_config|grep no` != '' ]]; then echo ''; else echo 'SSH HostbasedAuthentication not set to no'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.2.9", "Ensure SSH HostbasedAuthentication is disabled (Scored)", checkstat})

	// Check 5.2.10
	cmd = "if [[ ! -f /etc/ssh/sshd_config || `grep -i ^PermitRootLogin /etc/ssh/sshd_config|grep no` != '' ]]; then echo ''; else echo 'SSH PermitRootLogin not set to no'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.2.10", "Ensure SSH root login is disabled (Scored)", checkstat})

	// Check 5.2.11
	cmd = "if [[ ! -f /etc/ssh/sshd_config || `grep -i ^PermitEmptyPasswords /etc/ssh/sshd_config|grep no` != '' ]]; then echo ''; else echo 'SSH PermitEmptyPasswords not set to no'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.2.11", "Ensure SSH PermitEmptyPasswords is disabled (Scored)", checkstat})

	// Check 5.2.12
	cmd = "if [[ ! -f /etc/ssh/sshd_config || `grep -i ^PermitUserEnvironment /etc/ssh/sshd_config|grep no` != '' ]]; then echo ''; else echo 'SSH PermitUserEnvironment not set to no'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.2.12", "Ensure SSH PermitUserEnvironment is disabled (Scored)", checkstat})

	// Check 5.2.13
	cmd = "if [[ ! -f /etc/ssh/sshd_config || `grep -i ^ciphers	/etc/ssh/sshd_config|grep aes256` != '' ]]; then echo ''; else echo 'Ensure only strong Ciphers are used'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.2.13", "Ensure only strong Ciphers are used (Scored)", checkstat})

	// Check 5.2.14
	cmd = "if [[ ! -f /etc/ssh/sshd_config || `grep -i ^MACs /etc/ssh/sshd_config|grep hmac-sha2-512` != '' ]]; then echo ''; else echo 'Ensure only strong MAC algorithms are used'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.2.14", "Ensure only strong MAC algorithms are used (Scored)", checkstat})

	// Check 5.2.15
	cmd = "if [[ ! -f /etc/ssh/sshd_config || `grep -i ^kexalgorithms /etc/ssh/sshd_config|grep hellman` != '' ]]; then echo ''; else echo 'Ensure only strong Key Exchange algorithms are used'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.2.15", "Ensure only strong Key Exchange algorithms are used (Scored)", checkstat})

	// Check 5.2.16
	cmd = "if [[ ! -f /etc/ssh/sshd_config || `grep -i ^ClientAliveInterval /etc/ssh/sshd_config|awk '{print $NF}'` -le 300 && `grep -i ^ClientAliveCountMax /etc/ssh/sshd_config|awk '{print $NF}'` -le 3 ]]; then echo ''; else echo 'Ensure SSH Idle Timeout Interval is configured'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.2.16", "Ensure SSH Idle Timeout Interval is configured (Scored)", checkstat})

	// Check 5.2.17
	cmd = "if [[ ! -f /etc/ssh/sshd_config || `grep -i ^LoginGraceTime /etc/ssh/sshd_config|awk '{print $NF}'` -le 60 ]]; then echo ''; else echo 'Ensure SSH LoginGraceTime is set to one minute or less'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.2.17", "Ensure SSH LoginGraceTime is set to one minute or less (Scored)", checkstat})

	// Check 5.2.18
	cmd = "if [[ ! -f /etc/ssh/sshd_config || `grep -i ^AllowUsers /etc/ssh/sshd_config` != '' || `grep -i ^AllowGroups /etc/ssh/sshd_config` != '' || `grep -i ^DenyUsers /etc/ssh/sshd_config` != '' || `grep -i ^DenyGroups /etc/ssh/sshd_config` != '' ]]; then echo ''; else echo 'Ensure SSH access is limited'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.2.18", "Ensure SSH access is limited (Scored)", checkstat})

	// Check 5.2.19
	cmd = "if [[ ! -f /etc/ssh/sshd_config || `grep -i ^banner /etc/ssh/sshd_config` != '' ]]; then echo ''; else echo 'Ensure SSH warning banner is configured'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.2.19", "Ensure SSH warning banner is configured (Scored)", checkstat})

	// Check 5.2.20
	cmd = "if [[ ! -f /etc/ssh/sshd_config || `grep -i ^usepam /etc/ssh/sshd_config|grep yes` != '' ]]; then echo ''; else echo 'Ensure SSH PAM is enabled'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.2.20", "Ensure SSH PAM is enabled (Scored)", checkstat})

	// Check 5.2.21
	cmd = "if [[ ! -f /etc/ssh/sshd_config || `grep -i ^AllowTcpForwarding /etc/ssh/sshd_config|grep no` != '' ]]; then echo ''; else echo 'Ensure SSH AllowTcpForwarding is disabled'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.2.21", "Ensure SSH AllowTcpForwarding is disabled (Scored)", checkstat})

	// Check 5.2.22
	cmd = "if [[ ! -f /etc/ssh/sshd_config || `grep -i ^maxstartups /etc/ssh/sshd_config` != '' ]]; then echo ''; else echo 'Ensure SSH MaxStartups is configured'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.2.22", "Ensure SSH MaxStartups is configured (Scored)", checkstat})

	// Check 5.2.23
	cmd = "if [[ ! -f /etc/ssh/sshd_config || `grep -i ^maxsessions /etc/ssh/sshd_config|awk '{print $NF}'` -le 4 ]]; then echo ''; else echo 'Ensure SSH MaxSessions is set to 4 or less'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.2.23", "Ensure SSH MaxSessions is set to 4 or less (Scored)", checkstat})

	// Check 5.3.1
	cmd = "if [[ `grep ^minlen /etc/security/pwquality.conf 2>/dev/null` != '' || `grep ^minlen /etc/pam.d/common-password 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure password creation requirements are configured'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.3.1", "Ensure password creation requirements are configured (Scored)", checkstat})

	// Check 5.3.2
	cmd = "if [[ `grep ^pam_faillock.so /etc/pam.d/common-auth 2>/dev/null` != '' || `grep ^pam_tally2.so /etc/pam.d/common-auth 2>/dev/null` != '' || `grep ^pam_faillock.so /etc/pam.d/system-auth 2>/dev/null` != '' || `grep ^pam_tally2.so /etc/pam.d/system-auth 2>/dev/null` != '' || `grep ^pam_faillock.so /etc/pam.d/password-auth 2>/dev/null` != '' || `grep ^pam_tally2.so /etc/pam.d/password-auth 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure lockout for failed password attempts is configured'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.3.2", "Ensure lockout for failed password attempts is configured (Not Scored)", checkstat})

	// Check 5.3.3
	cmd = "if [[ `grep ^pam_unix.so /etc/pam.d/common-password 2>/dev/null` != '' || `grep ^pam_unix.so /etc/pam.d/system-auth 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure password reuse is limited'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.3.3", "Ensure password reuse is limited (Not Scored)", checkstat})

	// Check 5.3.4
	cmd = "if [[ `grep ^sha512 /etc/pam.d/system-auth 2>/dev/null` != '' || `grep ^sha512 /etc/pam.d/password-auth 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure password hashing algorithm is SHA-512'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.3.4", "Ensure password hashing algorithm is SHA-512 (Not Scored)", checkstat})

	// Check 5.4.1.1
	cmd = "if [[ `grep ^PASS_MAX_DAYS /etc/login.defs 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure password expiration is 365 days or less'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.4.1.1", "Ensure password expiration is 365 days or less (Scored)", checkstat})

	// Check 5.4.1.2
	cmd = "if [[ `grep ^PASS_MIN_DAYS /etc/login.defs 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure minimum days between password changes is 7 or more'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.4.1.2", "Ensure minimum days between password changes is 7 or more (Scored)", checkstat})

	// Check 5.4.1.3
	cmd = "if [[ `grep ^PASS_WARN_AGE /etc/login.defs 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure password expiration warning days is 7 or more'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.4.1.3", "Ensure password expiration warning days is 7 or more (Scored)", checkstat})

	// Check 5.4.1.4
	cmd = "if [[ `sudo useradd -D | grep INACTIVE | awk -F= '{print $NF}'` -le 30 ]]; then echo ''; else echo 'Ensure inactive password lock is 30 days or less'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.4.1.4", "Ensure inactive password lock is 30 days or less (Scored)", checkstat})

	// Check 5.4.1.5
	cmd = "if [[ `for usr in $(sudo cut -d: -f1 /etc/shadow); do [[ $(sudo chage --list $usr | grep '^Last password change' | cut -d: -f2) > $(date) ]] && echo $usr :$(sudo chage --list $usr | grep '^Last password change' | cut -d: -f2); done` == '' ]]; then echo ''; else echo 'Ensure all users last password change date is in the past'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.4.1.5", "Ensure all users last password change date is in the past (Scored)", checkstat})

	// Check 5.4.2
	cmd = "command=$(cat /etc/passwd | while read entry; do if [[ `echo $entry|awk -F: '{print $3}'` -lt 1000 ]]; then if [[ `echo $entry| egrep -i 'nologin|false'` == '' && `echo $entry|awk -F: '{print $1}'|egrep -i 'root|sync|shutdown|halt'` == '' ]]; then echo 'insecure system account detected'; fi; fi; done); if [[ ! -n $command ]]; then echo ''; else echo 'Ensure password creation requirements are configured'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.4.2", "Ensure system accounts are secured (Scored)", checkstat})

	// Check 5.4.3
	cmd = "if [[ `grep '^root:' /etc/passwd | cut -f4 -d:` -eq 0 ]]; then echo ''; else echo 'Ensure default group for the root account is GID 0'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.4.3", "Ensure default group for the root account is GID 0 (Scored)", checkstat})

	// Check 5.4.4
	cmd = "if [[ `grep 'umask' /etc/bashrc|grep 027 2>/dev/null` != '' || `grep 'umask' /etc/profile /etc/profile.d/*.sh |grep 027 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure default user umask is 027 or more restrictive'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.4.4", "Ensure default user umask is 027 or more restrictive (Scored)", checkstat})

	// Check 5.4.5
	cmd = "if [[ `grep ^TMOUT /etc/bashrc|awk -F= '{print $NF}' 2>/dev/null` -le 900 || `grep ^TMOUT /etc/profile|awk -F= '{print $NF}' 2>/dev/null` -le 900 ]]; then echo ''; else echo 'Ensure default user shell timeout is 900 seconds or less'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.4.5", "Ensure default user shell timeout is 900 seconds or less (Scored)", checkstat})

	// Check 5.5
	cmd = "if [[ `grep ^tty /etc/securetty 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure root login is restricted to system console'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.5", "Ensure root login is restricted to system console (Not Scored)", checkstat})

	// Check 5.6
	cmd = "if [[ `grep ^pam_wheel.so /etc/pam.d/su 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure access to the su command is restricted'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"5.6", "Ensure access to the su command is restricted (Scored)", checkstat})

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
