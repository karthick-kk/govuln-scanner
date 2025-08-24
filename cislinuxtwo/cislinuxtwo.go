package cislinuxtwo

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

func CislinuxtwoOptimized(conn *remexec.SSHConnection) []Datastat {
	ServicesSlice := []Datastat{}

	checks := []Check{
		{
			ID:          "2.1.1",
			Description: "Ensure chargen services are not enabled (Scored)",
			Command:     "if ls /etc/inetd.* 1>/dev/null 2>&1; then grep -R \"^chargen\" /etc/inetd.* || true; else echo ''; fi",
		},
		{
			ID:          "2.1.2",
			Description: "Ensure daytime services are not enabled (Scored)",
			Command:     "if ls /etc/inetd.* 1>/dev/null 2>&1; then grep -R \"^daytime\" /etc/inetd.* || true; else echo ''; fi",
		},
		{
			ID:          "2.1.3",
			Description: "Ensure discard services are not enabled (Scored)",
			Command:     "if ls /etc/inetd.* 1>/dev/null 2>&1; then grep -R \"^discard\" /etc/inetd.* || true; else echo ''; fi",
		},
		{
			ID:          "2.1.4",
			Description: "Ensure echo services are not enabled (Scored)",
			Command:     "if ls /etc/inetd.* 1>/dev/null 2>&1; then grep -R \"^echo\" /etc/inetd.* || true; else echo ''; fi",
		},
		{
			ID:          "2.1.5",
			Description: "Ensure time services are not enabled (Scored)",
			Command:     "if ls /etc/inetd.* 1>/dev/null 2>&1; then grep -R \"^time\" /etc/inetd.* || true; else echo ''; fi",
		},
		{
			ID:          "2.1.6",
			Description: "Ensure rsh server is not enabled (Scored)",
			Command:     "if ls /etc/inetd.* 1>/dev/null 2>&1; then if [[ `grep -R \"^shell\" /etc/inetd.* 2>/dev/null` == '' && `grep -R \"^login\" /etc/inetd.* 2>/dev/null` == '' && `grep -R \"^exec\" /etc/inetd.* 2>/dev/null` == '' ]]; then echo ''; else echo 'rsh server enabled'; fi; else echo ''; fi",
		},
		{
			ID:          "2.1.7",
			Description: "Ensure talk server is not enabled (Scored)",
			Command:     "if ls /etc/inetd.* 1>/dev/null 2>&1; then if [[ `grep -R \"^talk\" /etc/inetd.* 2>/dev/null` == '' && `grep -R \"^ntalk\" /etc/inetd.* 2>/dev/null` == '' ]]; then echo ''; else echo 'talk server enabled'; fi; else echo ''; fi",
		},
		{
			ID:          "2.1.8",
			Description: "Ensure telnet server is not enabled (Scored)",
			Command:     "if ls /etc/inetd.* 1>/dev/null 2>&1; then grep -R \"^telnet\" /etc/inetd.* || true; else echo ''; fi",
		},
		{
			ID:          "2.1.9",
			Description: "Ensure tftp server is not enabled (Scored)",
			Command:     "if ls /etc/inetd.* 1>/dev/null 2>&1; then grep -R \"^tftp\" /etc/inetd.* || true; else echo ''; fi",
		},
		{
			ID:          "2.2.1.1",
			Description: "Ensure time synchronization is in use (Not Scored)",
			Command:     "case `for i in $( echo rpm dpkg pacman ); do which $i; done 2> /dev/null|awk -F'bin/' '{print $NF}'` in dpkg) if [[ `dpkg -s ntp 2>/dev/null` != '' || `dpkg -s chrony 2>/dev/null` != '' ]]; then echo ''; else echo 'time package not detected'; fi;; rpm) if [[ `rpm -q ntp 2>/dev/null` != '' || `rpm -q chrony 2>/dev/null` != '' ]]; then echo ''; else echo 'time package not detected'; fi;; esac",
		},
		{
			ID:          "2.2.1.2",
			Description: " Ensure ntp is configured (Scored)",
			Command:     "if [[ `grep \"^restrict\" /etc/ntp.conf 2>/dev/null` != '' ]]; then echo ''; else echo 'ntp not configured correctly'; fi",
		},
		{
			ID:          "2.2.1.3",
			Description: "Ensure chrony is configured (Scored)",
			Command:     "if [[ `grep -E \"^(server|pool)\" /etc/chrony.conf 2>/dev/null` != '' ]]; then echo ''; else echo 'chrony not installed/configured correctly'; fi",
		},
		{
			ID:          "2.2.1.4",
			Description: "Ensure systemd-timesyncd is configured (Scored)",
			Command:     "if [[ `timedatectl status|grep synchronized|grep yes` != '' ]]; then echo ''; else echo 'time not synced'; fi",
		},
		{
			ID:          "2.2.2",
			Description: "Ensure X Window System is not installed (Scored)",
			Command:     "if [[ `dpkg -s xserver-xorg 2>/dev/null` == '' && `rpm -q xorg-x11-server-Xorg 2>/dev/null` == '' ]]; then echo ''; else echo 'xorg installed'; fi",
		},
		{
			ID:          "2.2.3",
			Description: "Ensure Avahi Server is not enabled (Scored)",
			Command:     "if [[ `ls /etc/rc*.d | grep avahi-daemon|grep S` == '' ]]; then echo ''; else echo 'avahi-daemon running'; fi",
		},
		{
			ID:          "2.2.4",
			Description: "Ensure CUPS is not enabled (Scored)",
			Command:     "if [[ `ls /etc/rc*.d | grep cups|grep S` == '' ]]; then echo ''; else echo 'cups running'; fi",
		},
		{
			ID:          "2.2.5",
			Description: "Ensure DHCP Server is not enabled (Scored)",
			Command:     "if [[ `ls /etc/rc*.d | grep dhcpd|grep S` == '' ]]; then echo ''; else echo 'dhcpd running'; fi",
		},
		{
			ID:          "2.2.6",
			Description: "Ensure LDAP server is not enabled (Scored)",
			Command:     "if [[ `ls /etc/rc*.d | grep slapd|grep S` == '' ]]; then echo ''; else echo 'slapd running'; fi",
		},
		{
			ID:          "2.2.7",
			Description: "Ensure NFS and RPC are not enabled (Scored)",
			Command:     "if [[ `ls /etc/rc*.d | grep nfs|grep S` == '' && `ls /etc/rc*.d | grep rpcbind|grep S` == '' ]]; then echo ''; else echo 'nfs/rpcbind running'; fi",
		},
		{
			ID:          "2.2.8",
			Description: "Ensure DNS Server is not enabled (Scored)",
			Command:     "if [[ `ls /etc/rc*.d | grep named|grep S` == '' ]]; then echo ''; else echo 'named running'; fi",
		},
		{
			ID:          "2.2.9",
			Description: "Ensure FTP Server is not enabled (Scored)",
			Command:     "if [[ `ls /etc/rc*.d | grep vsftpd|grep S` == '' ]]; then echo ''; else echo 'vsftpd running'; fi",
		},
		{
			ID:          "2.2.10",
			Description: "Ensure HTTP server is not enabled (Scored)",
			Command:     "if [[ `ls /etc/rc*.d | grep httpd|grep S` == '' ]]; then echo ''; else echo 'httpd running'; fi",
		},
		{
			ID:          "2.2.11",
			Description: "Ensure IMAP and POP3 server is not enabled (Scored)",
			Command:     "if [[ `ls /etc/rc*.d | grep dovecot|grep S` == '' ]]; then echo ''; else echo 'dovecot running'; fi",
		},
		{
			ID:          "2.2.12",
			Description: "Ensure Samba is not enabled (Scored)",
			Command:     "if [[ `ls /etc/rc*.d | grep smb|grep S` == '' ]]; then echo ''; else echo 'smb running'; fi",
		},
		{
			ID:          "2.2.13",
			Description: "Ensure HTTP Proxy Server is not enabled (Scored)",
			Command:     "if [[ `ls /etc/rc*.d | grep squid|grep S` == '' ]]; then echo ''; else echo 'squid running'; fi",
		},
		{
			ID:          "2.2.14",
			Description: "Ensure SNMP Server is not enabled (Scored)",
			Command:     "if [[ `ls /etc/rc*.d | grep snmpd|grep S` == '' ]]; then echo ''; else echo 'snmpd running'; fi",
		},
		{
			ID:          "2.2.15",
			Description: "Ensure mail transfer agent is configured for local-only mode (Scored)",
			Command:     "if [[ `ss -lntu | grep -E ':25\\s' | grep -E -v '\\s(127.0.0.1|::1):25\\s` == '' ]]; then echo ''; else echo 'MTA listening'; fi",
		},
		{
			ID:          "2.2.16",
			Description: "Ensure rsync service is not enabled (Scored)",
			Command:     "if [[ `ls /etc/rc*.d | grep rsyncd|grep S` == '' ]]; then echo ''; else echo 'rsyncd running'; fi",
		},
		{
			ID:          "2.2.17",
			Description: "Ensure NIS Server is not enabled (Scored)",
			Command:     "if [[ `ls /etc/rc*.d | grep ypserv|grep S` == '' ]]; then echo ''; else echo 'ypserv running'; fi",
		},
		{
			ID:          "2.3.1",
			Description: "Ensure NIS Client is not installed (Scored)",
			Command:     "if [[ `dpkg -s ypbind 2>/dev/null` == '' && `rpm -q ypbind 2>/dev/null` == '' ]]; then echo ''; else echo 'ypbind installed'; fi",
		},
		{
			ID:          "2.3.2",
			Description: "Ensure rsh client is not installed (Scored)",
			Command:     "if [[ `dpkg -s rsh 2>/dev/null` == '' && `rpm -q rsh 2>/dev/null` == '' ]]; then echo ''; else echo 'rsh installed'; fi",
		},
		{
			ID:          "2.3.3",
			Description: "Ensure talk client is not installed (Scored)",
			Command:     "if [[ `dpkg -s talk 2>/dev/null` == '' && `rpm -q talk 2>/dev/null` == '' ]]; then echo ''; else echo 'talk installed'; fi",
		},
		{
			ID:          "2.3.4",
			Description: "Ensure telnet client is not installed (Scored)",
			Command:     "if [[ `dpkg -s telnet 2>/dev/null` == '' && `rpm -q telnet 2>/dev/null` == '' ]]; then echo ''; else echo 'telnet installed'; fi",
		},
		{
			ID:          "2.3.5",
			Description: "Ensure LDAP client is not installed (Scored)",
			Command:     "if [[ `dpkg -s openldap-clients 2>/dev/null` == '' && `rpm -q openldap-clients 2>/dev/null` == '' ]]; then echo ''; else echo 'openldap-clients installed'; fi",
		},
	}

	log.Printf("DEBUG: Executing %d CIS cislinuxtwo checks individually\n", len(checks))
	
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

	log.Printf("DEBUG: Completed %d CIS cislinuxtwo checks via individual execution\n", len(ServicesSlice))
	return ServicesSlice
}



func Cislinuxtwo(user string, host string, pass string, key string) []Datastat {
	conn, err := remexec.NewSSHConnection(user, host, pass, key)
	if err != nil {
		log.Printf("ERROR: Failed to create SSH connection: %v\n", err)
		return []Datastat{}
	}
	defer conn.Close()

	return CislinuxtwoOptimized(conn)
}

type Datastat struct {
	Controlid string
	Check     string
	Status    string
}
