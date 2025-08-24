package cislinuxone

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

func CislinuxoneOptimized(conn *remexec.SSHConnection) []Datastat {
	ServicesSlice := []Datastat{}

	checks := []Check{
		{
			ID:          "1.1.1.1",
			Description: "Ensure mounting of cramfs filesystems is disabled (Scored)",
			Command:     "lsmod|grep cramfs",
		},
		{
			ID:          "1.1.1.2",
			Description: "Ensure mounting of freevxfs filesystems is disabled (Scored)",
			Command:     "lsmod|grep freevxfs",
		},
		{
			ID:          "1.1.1.3",
			Description: "Ensure mounting of jffs2 filesystems is disabled (Scored)",
			Command:     "lsmod|grep jffs2",
		},
		{
			ID:          "1.1.1.4",
			Description: "Ensure mounting of hfs filesystems is disabled (Scored)",
			Command:     "lsmod|grep hfs",
		},
		{
			ID:          "1.1.1.5",
			Description: "Ensure mounting of hfsplus filesystems is disabled (Scored)",
			Command:     "lsmod|grep hfsplus",
		},
		{
			ID:          "1.1.1.6",
			Description: "Ensure mounting of squashfs filesystems is disabled (Scored)",
			Command:     "lsmod|grep squashfs",
		},
		{
			ID:          "1.1.1.7",
			Description: "Ensure mounting of udf filesystems is disabled (Scored)",
			Command:     "lsmod|grep udf",
		},
		{
			ID:          "1.1.1.8",
			Description: "Ensure mounting of FAT filesystems is limited (Not Scored)",
			Command:     "lsmod|grep vfat",
		},
		{
			ID:          "1.1.2",
			Description: "Ensure /tmp is configured (Scored)",
			Command:     "grep '/tmp' /etc/fstab",
		},
		{
			ID:          "1.1.3",
			Description: "Ensure nodev option set on /tmp partition (Scored)",
			Command:     "mount | grep '/tmp' | grep -v nodev",
		},
		{
			ID:          "1.1.4",
			Description: "Ensure nosuid option set on /tmp partition (Scored)",
			Command:     "mount | grep -E '/tmp' | grep -v nosuid",
		},
		{
			ID:          "1.1.5",
			Description: "Ensure noexec option set on /tmp partition (Scored)",
			Command:     "mount | grep -E '/tmp' | grep -v noexec",
		},
		{
			ID:          "1.1.6",
			Description: "Ensure separate partition exists for /var (Scored)",
			Command:     "mount | grep -E '/var'",
		},
		{
			ID:          "1.1.7",
			Description: "Ensure separate partition exists for /var/tmp (Scored)",
			Command:     "mount | grep /var/tmp",
		},
		{
			ID:          "1.1.8",
			Description: "Ensure nodev option set on /var/tmp partition (Scored)",
			Command:     "mount | grep -E '/var/tmp' | grep -v nodev",
		},
		{
			ID:          "1.1.9",
			Description: "Ensure nosuid option set on /var/tmp partition (Scored)",
			Command:     "mount | grep -E '/var/tmp' | grep -v nosuid",
		},
		{
			ID:          "1.1.10",
			Description: "Ensure noexec option set on /var/tmp partition (Scored)",
			Command:     "mount | grep -E '/var/tmp' | grep -v noexec",
		},
		{
			ID:          "1.1.11",
			Description: "Ensure separate partition exists for /var/log (Scored)",
			Command:     "mount | grep /var/log",
		},
		{
			ID:          "1.1.12",
			Description: "Ensure separate partition exists for /var/log/audit (Scored)",
			Command:     "mount | grep /var/log/audit",
		},
		{
			ID:          "1.1.13",
			Description: "Ensure separate partition exists for /home (Scored)",
			Command:     "mount | grep /home",
		},
		{
			ID:          "1.1.14",
			Description: "Ensure nodev option set on /home partition (Scored)",
			Command:     "mount | grep -E '/home' | grep -v nodev",
		},
		{
			ID:          "1.1.15",
			Description: "Ensure nodev option set on /dev/shm partition (Scored)",
			Command:     "mount | grep -E '/dev/shm' | grep -v nodev",
		},
		{
			ID:          "1.1.16",
			Description: "Ensure nosuid option set on /dev/shm partition (Scored)",
			Command:     " mount | grep -E '/dev/shm' | grep -v nosuid",
		},
		{
			ID:          "1.1.17",
			Description: "Ensure noexec option set on /dev/shm partition (Scored)",
			Command:     "mount | grep -E '/dev/shm' | grep -v noexec",
		},
		{
			ID:          "1.1.18",
			Description: "Ensure nodev option set on removable media partitions (Not Scored)",
			Command:     "if [[ `mount | grep /dev/sr0` != '' ]]; then if [[ `mount | grep /dev/sr0 |grep nodev`  != '' ]]; then echo ''; else echo 'insecure conf';fi; else echo ''; fi",
		},
		{
			ID:          "1.1.19",
			Description: "Ensure nosuid option set on removable media partitions (Not Scored)",
			Command:     "if [[ `mount | grep /dev/sr0` != '' ]]; then if [[ `mount | grep /dev/sr0 |grep nosuid`  != '' ]]; then echo ''; else echo 'insecure conf';fi; else echo ''; fi",
		},
		{
			ID:          "1.1.20",
			Description: "Ensure noexec option set on removable media partitions (Not Scored)",
			Command:     "if [[ `mount | grep /dev/sr0` != '' ]]; then if [[ `mount | grep /dev/sr0 |grep noexec`  != '' ]]; then echo ''; else echo 'insecure conf';fi; else echo ''; fi",
		},
		{
			ID:          "1.1.21",
			Description: "Ensure sticky bit is set on all world-writable directories (Scored)",
			Command:     "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d -perm -0002 -a ! -perm -1000 2>/dev/null",
		},
		{
			ID:          "1.1.22",
			Description: "Disable Automounting (Scored)",
			Command:     "ls /etc/rc*.d|grep autofs|grep S",
		},
		{
			ID:          "1.1.23",
			Description: "Disable USB Storage (Scored)",
			Command:     "lsmod | grep usb-storage",
		},
		{
			ID:          "1.2.1",
			Description: "Ensure package manager repositories are configured (Not Scored)",
			Command:     "if [[ `sudo yum repo-list 2>/dev/null` != '' || `sudo apt-cache policy 2>/dev/null` != '' ]]; then echo ''; else echo 'package system not configured';fi",
		},
		{
			ID:          "1.2.2",
			Description: "Ensure GPG keys are configured (Not Scored)",
			Command:     "if [[ `sudo rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\\n' 2>/dev/null` != '' || `sudo apt-key list 2>/dev/null` != '' ]]; then echo ''; else echo 'GPG keys not configured';fi",
		},
		{
			ID:          "1.3.1",
			Description: "Ensure AIDE is installed (Scored)",
			Command:     "if [[ `rpm -q aide 2>/dev/null` != '' || `dpkg -s aide 2>/dev/null` != '' ]]; then echo ''; else echo 'AIDE not configured';fi",
		},
		{
			ID:          "1.3.2",
			Description: "Ensure filesystem integrity is regularly checked (Scored)",
			Command:     "if [[ `sudo grep -i aide /etc/cron.* /etc/cron.*/* /etc/crontab  2>/dev/null` != '' ]]; then echo ''; else echo 'filesystem integrity is not configured';fi",
		},
		{
			ID:          "1.4.1",
			Description: "Ensure permissions on bootloader config are configured (Scored)",
			Command:     "bootcfg=''; if sudo test -f /boot/grub/grub.cfg; then bootcfg=/boot/grub/grub.cfg; else bootcfg=/boot/grub2/grub.cfg; fi; if [[ `sudo stat $bootcfg |grep Uid|awk -F: '{print $3}'|grep '0/'|grep root` != '' && `sudo stat $bootcfg  |grep Gid|awk -F: '{print $4}'|grep '0/'|grep root` != '' && `sudo stat $bootcfg  |grep Uid|awk -F: '{print $2}'|grep 0400` != '' ]]; then echo ''; else echo 'insecure boot';fi",
		},
		{
			ID:          "1.4.2",
			Description: "Ensure bootloader password is set (Scored)",
			Command:     "if [[ `sudo grep 'GRUB2_PASSWORD=' /boot/grub2/grub.cfg 2>/dev/null` != '' || `sudo grep 'password --md5' /boot/grub/menu.lst 2>/dev/null` != '' ]]; then echo ''; else echo 'bootloader password not configured';fi",
		},
		{
			ID:          "1.4.3",
			Description: " Ensure authentication required for single user mode (Scored)",
			Command:     "if [[ `sudo passwd -S root|grep NP 2>/dev/null` == '' ]]; then echo ''; else echo 'bootloader password not configured';fi",
		},
		{
			ID:          "1.4.4",
			Description: "Ensure interactive boot is not enabled (Not Scored)",
			Command:     "echo ''; if sudo test -f /etc/sysconfig/boot; then if [[ `grep '^PROMPT_FOR_CONFIRM=' /etc/sysconfig/boot` != '' ]]; then echo ''; else 'int mode enabled'; fi; fi",
		},
		{
			ID:          "1.5.1",
			Description: "Ensure core dumps are restricted (Scored)",
			Command:     "if [[ `sudo grep 'hard core' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null` != '' && `sudo sysctl fs.suid_dumpable` != '' && `sudo grep 'fs.suid_dumpable' /etc/sysctl.conf /etc/sysctl.d/* 2>/dev/null` != '' ]]; then echo ''; else echo 'coredump not installed/configured'; fi",
		},
		{
			ID:          "1.5.2",
			Description: "Ensure XD/NX support is enabled (Scored)",
			Command:     "if [[ `sudo journalctl | grep 'protection: active' 2>/dev/null` != '' ]]; then echo ''; else echo 'xd/nx support not enabled';fi",
		},
		{
			ID:          "1.5.4",
			Description: "Ensure address space layout randomization (ASLR) is enabled (Scored)",
			Command:     "if [[ `sudo grep 'kernel.randomize_va_space' /etc/sysctl.conf /etc/sysctl.d/* 2>/dev/null` != '' ]]; then echo ''; else echo 'ASLR not enabled';fi",
		},
		{
			ID:          "1.5.4",
			Description: "Ensure prelink is disabled (Scored)",
			Command:     "if [[ `rpm -q prelink 2>/dev/null` == '' && `dpkg -s prelink 2>/dev/null` == '' ]]; then echo ''; else echo 'prelink enabled';fi",
		},
		{
			ID:          "1.6.1.1",
			Description: "Ensure SELinux or AppArmor are installed (Scored)",
			Command:     "if [[ `dpkg -l|egrep -i 'libselinux1|apparmor' 2>/dev/null` != '' || `rpm -qa|egrep -i 'libselinux|apparmor' 2>/dev/null` != '' ]]; then echo ''; else echo 'SELinux or AppArmor are not installed';fi",
		},
		{
			ID:          "1.6.2.1",
			Description: " Ensure SELinux is not disabled in bootloader configuration (Scored)",
			Command:     "if [[ `sudo egrep -i 'selinux=0|enforcing=0' /boot/grub2/grub.cfg 2>/dev/null` == '' && `sudo egrep -i 'selinux=0|enforcing=0' /boot/grub/grub.cfg 2>/dev/null` == '' ]]; then echo ''; else echo 'selinux disabled on boot';fi",
		},
		{
			ID:          "1.6.2.2",
			Description: "Ensure the SELinux state is enforcing (Scored)",
			Command:     "if [[ `sudo grep SELINUX=enforcing /etc/selinux/config 2>/dev/null` != '' ]]; then echo ''; else echo 'selinux not enforced';fi",
		},
		{
			ID:          "1.6.2.3",
			Description: "Ensure SELinux policy is configured (Scored)",
			Command:     "if [[ `sudo grep SELINUXTYPE=targeted /etc/selinux/config 2>/dev/null` != '' ]]; then echo ''; else echo 'selinux policy not configured';fi",
		},
		{
			ID:          "1.6.2.4",
			Description: "Ensure SETroubleshoot is not installed (Scored)",
			Command:     "if [[ `rpm -q setroubleshoot	2>/dev/null` != '' || `dpkg -s setroubleshoot 2>/dev/null` != '' ]]; then echo ''; else echo 'setroubleshoot not found';fi",
		},
		{
			ID:          "1.6.2.5",
			Description: "Ensure the MCS Translation Service (mcstrans) is not installed (Scored)",
			Command:     "if [[ `rpm -q mcstrans|grep -v 'not installed' 2>/dev/null` == '' && `dpkg -s mcstrans 2>/dev/null` == '' ]]; then echo ''; else echo 'mcstrans found';fi",
		},
		{
			ID:          "1.6.2.6",
			Description: "Ensure no unconfined daemons exist (Scored)",
			Command:     "if [[ `sudo ps -eZ | grep -E 'initrc' | grep -E -v -w 'tr|ps|grep|bash|awk' | tr ':' ' ' | awk '{ print $NF }'` == '' ]]; then echo ''; else echo 'unconfined daemons exist';fi",
		},
		{
			ID:          "1.6.3.1",
			Description: "Ensure AppArmor is not disabled in bootloader configuration (Scored)",
			Command:     "bootcfg=''; if sudo test -f /boot/grub/grub.cfg; then bootcfg=/boot/grub/grub.cfg; else bootcfg=/boot/grub2/grub.cfg; fi; if [[ `sudo grep 'apparmor=0' $bootcfg` == '' ]]; then echo ''; else echo 'insecure boot';fi",
		},
		{
			ID:          "1.6.3.2",
			Description: "Ensure all AppArmor Profiles are enforcing (Scored)",
			Command:     "if [[ `sudo apparmor_status 2>/dev/null` != '' ]]; then echo ''; else echo 'apparmor module not loaded';fi",
		},
		{
			ID:          "1.7.1.1",
			Description: "Ensure message of the day is configured properly (Scored)",
			Command:     "if [[ -f /etc/motd ]]; then if [[ `egrep '(\\v|\\r|\\m|\\s)' /etc/motd` == '' ]]; then echo ''; else echo 'motd not configured properly'; fi; else echo 'motd not configured'; fi",
		},
		{
			ID:          "1.7.1.2",
			Description: "Ensure local login warning banner is configured properly	(Scored)",
			Command:     "if [[ `egrep '(\\\\v|\\\\r|\\\\m|\\\\s)' /etc/issue` == '' ]]; then echo ''; else echo '/etc/issue not configured properly';fi",
		},
		{
			ID:          "1.7.1.3",
			Description: "Ensure remote login warning banner is configured properly (Scored)",
			Command:     "if [[ `grep -i authorized /etc/issue 2>/dev/null` != '' ]]; then echo ''; else echo 'remote login banner not configured';fi",
		},
		{
			ID:          "1.7.1.4",
			Description: "Ensure permissions on /etc/motd are configured (Scored)",
			Command:     "if [[ -f /etc/motd ]]; then if [[ `stat /etc/motd|grep root|grep 0644 2>/dev/null` != '' ]]; then echo ''; else echo 'insecure /etc/motd'; fi; else echo 'motd not configured'; fi",
		},
		{
			ID:          "1.7.1.5",
			Description: "Ensure permissions on /etc/issue are configured (Scored)",
			Command:     "if [[ `stat /etc/issue|grep root|grep 0644 2>/dev/null` != '' ]]; then echo ''; else echo 'insecure /etc/issue';fi",
		},
		{
			ID:          "1.7.1.6",
			Description: "Ensure permissions on /etc/issue.net are configured (Scored)",
			Command:     "if [[ `stat /etc/issue.net|grep root|grep 0644 2>/dev/null` != '' ]]; then echo ''; else echo 'insecure /etc/issue.net';fi",
		},
		{
			ID:          "1.7.2",
			Description: "Ensure GDM login banner is configured (Scored)",
			Command:     "if sudo test -f /etc/gdm3/greeter.dconf-defaults; then if [[ `grep -i banner /etc/gdm3/greeter.dconf-defaults` != '' ]]; then echo ''; else echo 'insecure gdm config'; fi; else echo ''; fi",
		},
		{
			ID:          "1.8",
			Description: "Ensure updates, patches, and additional security software are installed (Not Scored)",
			Command:     "echo ''",
		},
	}

	log.Printf("DEBUG: Executing %d CIS cislinuxone checks individually\n", len(checks))
	
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

	log.Printf("DEBUG: Completed %d CIS cislinuxone checks via individual execution\n", len(ServicesSlice))
	return ServicesSlice
}



func Cislinuxone(user string, host string, pass string, key string) []Datastat {
	conn, err := remexec.NewSSHConnection(user, host, pass, key)
	if err != nil {
		log.Printf("ERROR: Failed to create SSH connection: %v\n", err)
		return []Datastat{}
	}
	defer conn.Close()

	return CislinuxoneOptimized(conn)
}

type Datastat struct {
	Controlid string
	Check     string
	Status    string
}
