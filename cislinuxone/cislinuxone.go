package cislinuxone

import (
	"log"
	"govuln-scanner/remexec"
	"strings"
)

var checkstat, cmd string

// Cislinuxone Function
func Cislinuxone(user string, host string, pass string) []Datastat {
	ServicesSlice := []Datastat{}

	cmd = "lsmod|grep cramfs"
	out, _ := remexec.RemoteRun(user, host, pass, cmd)
	if out == "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.1.1", "Ensure mounting of cramfs filesystems is disabled (Scored)", checkstat})

	// Check 1.1.1.2
	cmd = "lsmod|grep freevxfs"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out == "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.1.2", "Ensure mounting of freevxfs filesystems is disabled (Scored)", checkstat})

	// Check 1.1.1.3
	cmd = "lsmod|grep jffs2"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out == "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.1.3", "Ensure mounting of jffs2 filesystems is disabled (Scored)", checkstat})

	// Check 1.1.1.4
	cmd = "lsmod|grep hfs"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out == "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.1.4", "Ensure mounting of hfs filesystems is disabled (Scored)", checkstat})

	// Check 1.1.1.5
	cmd = "lsmod|grep hfsplus"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out == "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.1.5", "Ensure mounting of hfsplus filesystems is disabled (Scored)", checkstat})

	// Check 1.1.1.6
	cmd = "lsmod|grep squashfs"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out == "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.1.6", "Ensure mounting of squashfs filesystems is disabled (Scored)", checkstat})

	// Check 1.1.1.7
	cmd = "lsmod|grep udf"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out == "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.1.7", "Ensure mounting of udf filesystems is disabled (Scored)", checkstat})

	// Check 1.1.1.8
	cmd = "lsmod|grep vfat"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out == "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.1.8", "Ensure mounting of FAT filesystems is limited (Not Scored)", checkstat})

	// Check 1.1.2
	cmd = "grep '/tmp' /etc/fstab"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out != "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.2", "Ensure /tmp is configured (Scored)", checkstat})

	// Check 1.1.3
	cmd = "mount | grep '/tmp' | grep -v nodev"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out == "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.3", "Ensure nodev option set on /tmp partition (Scored)", checkstat})

	// Check 1.1.4
	cmd = "mount | grep -E '/tmp' | grep -v nosuid"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out == "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.4", "Ensure nosuid option set on /tmp partition (Scored)", checkstat})

	// Check 1.1.5
	cmd = "mount | grep -E '/tmp' | grep -v noexec"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out == "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.5", "Ensure noexec option set on /tmp partition (Scored)", checkstat})

	// Check 1.1.6
	cmd = "mount | grep -E '/var'"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out != "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.6", "Ensure separate partition exists for /var (Scored)", checkstat})

	// Check 1.1.7
	cmd = "mount | grep /var/tmp"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out != "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.7", "Ensure separate partition exists for /var/tmp (Scored)", checkstat})

	// Check 1.1.8
	cmd = "mount | grep -E '/var/tmp' | grep -v nodev"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out == "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.8", "Ensure nodev option set on /var/tmp partition (Scored)", checkstat})

	// Check 1.1.9
	cmd = "mount | grep -E '/var/tmp' | grep -v nosuid"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out == "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.9", "Ensure nosuid option set on /var/tmp partition (Scored)", checkstat})

	// Check 1.1.10
	cmd = "mount | grep -E '/var/tmp' | grep -v noexec"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out == "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.10", "Ensure noexec option set on /var/tmp partition (Scored)", checkstat})

	// Check 1.1.11
	cmd = "mount | grep /var/log"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out != "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.11", "Ensure separate partition exists for /var/log (Scored)", checkstat})

	// Check 1.1.12
	cmd = "mount | grep /var/log/audit"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out != "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.12", "Ensure separate partition exists for /var/log/audit (Scored)", checkstat})

	// Check 1.1.13
	cmd = "mount | grep /home"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out == "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.13", "Ensure separate partition exists for /home (Scored)", checkstat})

	// Check 1.1.14
	cmd = "mount | grep -E '/home' | grep -v nodev"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out == "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.14", "Ensure nodev option set on /home partition (Scored)", checkstat})

	// Check 1.1.15
	cmd = "mount | grep -E '/dev/shm' | grep -v nodev"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out == "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.15", "Ensure nodev option set on /dev/shm partition (Scored)", checkstat})

	// Check 1.1.16
	cmd = " mount | grep -E '/dev/shm' | grep -v nosuid"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out == "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.16", "Ensure nosuid option set on /dev/shm partition (Scored)", checkstat})

	// Check 1.1.17
	cmd = "mount | grep -E '/dev/shm' | grep -v noexec"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out == "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.17", "Ensure noexec option set on /dev/shm partition (Scored)", checkstat})

	// Check 1.1.18
	cmd = "if [[ `mount | grep /dev/sr0` != '' ]]; then if [[ `mount | grep /dev/sr0 |grep nodev`  != '' ]]; then echo ''; else echo 'insecure conf';fi; else echo ''; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out != "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.18", "Ensure nodev option set on removable media partitions (Not Scored)", checkstat})

	// Check 1.1.19
	cmd = "if [[ `mount | grep /dev/sr0` != '' ]]; then if [[ `mount | grep /dev/sr0 |grep nosuid`  != '' ]]; then echo ''; else echo 'insecure conf';fi; else echo ''; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out != "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.19", "Ensure nosuid option set on removable media partitions (Not Scored)", checkstat})

	// Check 1.1.20
	cmd = "if [[ `mount | grep /dev/sr0` != '' ]]; then if [[ `mount | grep /dev/sr0 |grep noexec`  != '' ]]; then echo ''; else echo 'insecure conf';fi; else echo ''; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out != "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.20", "Ensure noexec option set on removable media partitions (Not Scored)", checkstat})

	// Check 1.1.21
	cmd = "df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type d -perm -0002 -a ! -perm -1000 2>/dev/null"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out == "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.21", "Ensure sticky bit is set on all world-writable directories (Scored)", checkstat})

	// Check 1.1.22
	cmd = "ls /etc/rc*.d|grep autofs|grep S"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out == "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.22", "Disable Automounting (Scored)", checkstat})

	// Check 1.1.23
	cmd = "lsmod | grep usb-storage"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if out == "" {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.1.23", "Disable USB Storage (Scored)", checkstat})

	// Check 1.2.1
	cmd = "if [[ `sudo yum repo-list 2>/dev/null` != '' || `sudo apt-cache policy 2>/dev/null` != '' ]]; then echo ''; else echo 'package system not configured';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.2.1", "Ensure package manager repositories are configured (Not Scored)", checkstat})

	// Check 1.2.2
	cmd = "if [[ `sudo rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n' 2>/dev/null` != '' || `sudo apt-key list 2>/dev/null` != '' ]]; then echo ''; else echo 'GPG keys not configured';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.2.2", "Ensure GPG keys are configured (Not Scored)", checkstat})

	// Check 1.3.1
	cmd = "if [[ `rpm -q aide 2>/dev/null` != '' || `dpkg -s aide 2>/dev/null` != '' ]]; then echo ''; else echo 'AIDE not configured';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.3.1", "Ensure AIDE is installed (Scored)", checkstat})

	// Check 1.3.2
	cmd = "if [[ `sudo grep -i aide /etc/cron.* /etc/cron.*/* /etc/crontab  2>/dev/null` != '' ]]; then echo ''; else echo 'filesystem integrity is not configured';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.3.2", "Ensure filesystem integrity is regularly checked (Scored)", checkstat})

	// Check 1.4.1
	cmd = "bootcfg=''; if sudo test -f /boot/grub/grub.cfg; then bootcfg=/boot/grub/grub.cfg; else bootcfg=/boot/grub2/grub.cfg; fi; if [[ `sudo stat $bootcfg |grep Uid|awk -F: '{print $3}'|grep '0/'|grep root` != '' && `sudo stat $bootcfg  |grep Gid|awk -F: '{print $4}'|grep '0/'|grep root` != '' && `sudo stat $bootcfg  |grep Uid|awk -F: '{print $2}'|grep 0400` != '' ]]; then echo ''; else echo 'insecure boot';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.4.1", "Ensure permissions on bootloader config are configured (Scored)", checkstat})

	// Check 1.4.2
	cmd = "if [[ `sudo grep 'GRUB2_PASSWORD=' /boot/grub2/grub.cfg 2>/dev/null` != '' || `sudo grep 'password --md5' /boot/grub/menu.lst 2>/dev/null` != '' ]]; then echo ''; else echo 'bootloader password not configured';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.4.2", "Ensure bootloader password is set (Scored)", checkstat})

	// Check 1.4.3
	cmd = "if [[ `sudo passwd -S root|grep NP 2>/dev/null` == '' ]]; then echo ''; else echo 'bootloader password not configured';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.4.3", " Ensure authentication required for single user mode (Scored)", checkstat})

	// Check 1.4.4
	cmd = "echo ''; if sudo test -f /etc/sysconfig/boot; then if [[ `grep '^PROMPT_FOR_CONFIRM=' /etc/sysconfig/boot` != '' ]]; then echo ''; else 'int mode enabled'; fi; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.4.4", "Ensure interactive boot is not enabled (Not Scored)", checkstat})

	// Check 1.5.1
	cmd = "if [[ `sudo grep 'hard core' /etc/security/limits.conf /etc/security/limits.d/* 2>/dev/null` != '' && `sudo sysctl fs.suid_dumpable` != '' && `sudo grep 'fs.suid_dumpable' /etc/sysctl.conf /etc/sysctl.d/* 2>/dev/null` != '' ]]; then echo ''; else echo 'coredump not installed/configured'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.5.1", "Ensure core dumps are restricted (Scored)", checkstat})

	// Check 1.5.2
	cmd = "if [[ `sudo journalctl | grep 'protection: active' 2>/dev/null` != '' ]]; then echo ''; else echo 'xd/nx support not enabled';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.5.2", "Ensure XD/NX support is enabled (Scored)", checkstat})

	// Check 1.5.3
	cmd = "if [[ `sudo grep 'kernel.randomize_va_space' /etc/sysctl.conf /etc/sysctl.d/* 2>/dev/null` != '' ]]; then echo ''; else echo 'ASLR not enabled';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.5.4", "Ensure address space layout randomization (ASLR) is enabled (Scored)", checkstat})

	// Check 1.5.4
	cmd = "if [[ `rpm -q prelink 2>/dev/null` == '' && `dpkg -s prelink 2>/dev/null` == '' ]]; then echo ''; else echo 'prelink enabled';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.5.4", "Ensure prelink is disabled (Scored)", checkstat})

	// Check 1.6.1.1
	cmd = "if [[ `dpkg -l|egrep -i 'libselinux1|apparmor' 2>/dev/null` != '' || `rpm -qa|egrep -i 'libselinux|apparmor' 2>/dev/null` != '' ]]; then echo ''; else echo 'SELinux or AppArmor are not installed';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.6.1.1", "Ensure SELinux or AppArmor are installed (Scored)", checkstat})

	// Check 1.6.2.1
	cmd = "if [[ `sudo egrep -i 'selinux=0|enforcing=0' /boot/grub2/grub.cfg 2>/dev/null` == '' && `sudo egrep -i 'selinux=0|enforcing=0' /boot/grub/grub.cfg 2>/dev/null` == '' ]]; then echo ''; else echo 'selinux disabled on boot';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.6.2.1", " Ensure SELinux is not disabled in bootloader configuration (Scored)", checkstat})

	// Check 1.6.2.2
	cmd = "if [[ `sudo grep SELINUX=enforcing /etc/selinux/config 2>/dev/null` != '' ]]; then echo ''; else echo 'selinux not enforced';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.6.2.2", "Ensure the SELinux state is enforcing (Scored)", checkstat})

	// Check 1.6.2.3
	cmd = "if [[ `sudo grep SELINUXTYPE=targeted /etc/selinux/config 2>/dev/null` != '' ]]; then echo ''; else echo 'selinux policy not configured';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.6.2.3", "Ensure SELinux policy is configured (Scored)", checkstat})

	// Check 1.6.2.4
	cmd = "if [[ `rpm -q setroubleshoot	2>/dev/null` != '' || `dpkg -s setroubleshoot 2>/dev/null` != '' ]]; then echo ''; else echo 'setroubleshoot not found';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.6.2.4", "Ensure SETroubleshoot is not installed (Scored)", checkstat})

	// Check 1.6.2.5
	cmd = "if [[ `rpm -q mcstrans|grep -v 'not installed' 2>/dev/null` == '' && `dpkg -s mcstrans 2>/dev/null` == '' ]]; then echo ''; else echo 'mcstrans found';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.6.2.5", "Ensure the MCS Translation Service (mcstrans) is not installed (Scored)", checkstat})

	// Check 1.6.2.6
	cmd = "if [[ `sudo ps -eZ | grep -E 'initrc' | grep -E -v -w 'tr|ps|grep|bash|awk' | tr ':' ' ' | awk '{ print $NF }'` == '' ]]; then echo ''; else echo 'unconfined daemons exist';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.6.2.6", "Ensure no unconfined daemons exist (Scored)", checkstat})

	// Check 1.6.3.1
	cmd = "bootcfg=''; if sudo test -f /boot/grub/grub.cfg; then bootcfg=/boot/grub/grub.cfg; else bootcfg=/boot/grub2/grub.cfg; fi; if [[ `grep 'apparmor=0' $bootcfg` == '' ]]; then echo ''; else echo 'insecure boot';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.6.3.1", "Ensure AppArmor is not disabled in bootloader configuration (Scored)", checkstat})

	// Check 1.6.3.2
	cmd = "if [[ `sudo apparmor_status 2>/dev/null` != '' ]]; then echo ''; else echo 'apparmor module not loaded';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.6.3.2", "Ensure all AppArmor Profiles are enforcing (Scored)", checkstat})

	// Check 1.7.1.1
	cmd = "if [[ `egrep '(\\v|\\r|\\m|\\s)' /etc/motd` == '' ]]; then echo ''; else echo 'motd not configured properly';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.7.1.1", "Ensure message of the day is configured properly (Scored)", checkstat})

	// Check 1.7.1.2
	cmd = "if [[ `egrep '(\\v|\\r|\\m|\\s)' /etc/issue` == '' ]]; then echo ''; else echo '/etc/issue not configured properly';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.7.1.2", "Ensure local login warning banner is configured properly	(Scored)", checkstat})

	// Check 1.7.1.3
	cmd = "if [[ `grep -i authorized /etc/issue 2>/dev/null` != '' ]]; then echo ''; else echo 'remote login banner not configured';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.7.1.3", "Ensure remote login warning banner is configured properly (Scored)", checkstat})

	// Check 1.7.1.4
	cmd = "if [[ `stat /etc/motd|grep root|grep 0644 2>/dev/null` != '' ]]; then echo ''; else echo 'insecure /etc/motd';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.7.1.4", "Ensure permissions on /etc/motd are configured (Scored)", checkstat})

	// Check 1.7.1.5
	cmd = "if [[ `stat /etc/issue|grep root|grep 0644 2>/dev/null` != '' ]]; then echo ''; else echo 'insecure /etc/issue';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.7.1.5", "Ensure permissions on /etc/issue are configured (Scored)", checkstat})

	// Check 1.7.1.6
	cmd = "if [[ `stat /etc/issue.net|grep root|grep 0644 2>/dev/null` != '' ]]; then echo ''; else echo 'insecure /etc/issue.net';fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.7.1.6", "Ensure permissions on /etc/issue.net are configured (Scored)", checkstat})

	// Check 1.7.2
	cmd = "if sudo test -f /etc/gdm3/greeter.dconf-defaults; then if [[ `grep -i banner /etc/gdm3/greeter.dconf-defaults` != '' ]]; then echo ''; else echo 'insecure gdm config'; fi; else echo ''; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.7.2", "Ensure GDM login banner is configured (Scored)", checkstat})

	// Check 1.8
	cmd = "echo ''"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"1.8", "Ensure updates, patches, and additional security software are installed (Not Scored)", checkstat})

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
