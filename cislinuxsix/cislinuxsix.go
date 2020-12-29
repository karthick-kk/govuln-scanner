package cislinuxsix

import (
	"log"
	"govuln-scanner/remexec"
	"strings"
)

var checkstat, cmd string

// Cislinuxsix Function
func Cislinuxsix(user string, host string, pass string) []Datastat {
	ServicesSlice := []Datastat{}

	// Check 6.1.1
	cmd = "if [[ `uname -a` != '' ]]; then echo ''; else echo 'Audit system file permissions'; fi"
	out, _ := remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.1.1", "Audit system file permissions (Not Scored)", checkstat})

	// Check 6.1.2
	cmd = "if [[ `stat /etc/passwd 2>/dev/null| grep root|grep 0644` != '' ]]; then echo ''; else echo 'Ensure permissions on /etc/passwd are configured'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.1.2", "Ensure permissions on /etc/passwd are configured (Scored)", checkstat})

	// Check 6.1.3
	cmd = "if [[ `sudo stat /etc/shadow 2>/dev/null| grep root|grep 0640` != '' ]]; then echo ''; else echo 'Ensure permissions on /etc/shadow are configured'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.1.3", "Ensure permissions on /etc/shadow are configured (Scored)", checkstat})

	// Check 6.1.4
	cmd = "if [[ `stat /etc/group 2>/dev/null| grep root|grep 0644` != '' ]]; then echo ''; else echo 'Ensure permissions on /etc/group are configured'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.1.4", "Ensure permissions on /etc/group are configured (Scored)", checkstat})

	// Check 6.1.5
	cmd = "if [[ `stat /etc/gshadow 2>/dev/null| grep root|grep 0640` != '' ]]; then echo ''; else echo 'Ensure permissions on /etc/gshadow are configured'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.1.5", "Ensure permissions on /etc/gshadow are configured (Scored)", checkstat})

	// Check 6.1.6
	cmd = "if [[ `sudo stat /etc/passwd- 2>/dev/null| grep root|grep 0600` != '' ]]; then echo ''; else echo 'Ensure permissions on /etc/passwd- are configured'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.1.6", "Ensure permissions on /etc/passwd- are configured (Scored)", checkstat})

	// Check 6.1.7
	cmd = "if [[ `sudo stat /etc/shadow- 2>/dev/null| grep root|grep 0640` != '' ]]; then echo ''; else echo 'Ensure permissions on /etc/shadow- are configured'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.1.7", "Ensure permissions on /etc/shadow- are configured (Scored)", checkstat})

	// Check 6.1.8
	cmd = "if [[ `stat /etc/group- 2>/dev/null| grep root|grep 0644` != '' ]]; then echo ''; else echo 'Ensure permissions on /etc/group- are configured'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.1.8", "Ensure permissions on /etc/group- are configured (Scored)", checkstat})

	// Check 6.1.9
	cmd = "if [[ `sudo stat /etc/gshadow- 2>/dev/null| grep root|grep 0640` != '' ]]; then echo ''; else echo 'Ensure permissions on /etc/gshadow- are configured'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.1.9", "Ensure permissions on /etc/gshadow- are configured (Scored)", checkstat})

	// Check 6.1.10
	cmd = "if [[ `sudo df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure no world writable files exist'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.1.10", "Ensure no world writable files exist (Scored)", checkstat})

	// Check 6.1.11
	cmd = "if [[ `sudo df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure no unowned files or directories exist'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.1.11", "Ensure no unowned files or directories exist (Scored)", checkstat})

	// Check 6.1.12
	cmd = "if [[ `sudo df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure no ungrouped files or directories exist'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.1.12", "Ensure no ungrouped files or directories exist (Scored)", checkstat})

	// Check 6.1.13
	cmd = "if [[ `sudo df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000 2>/dev/null` == '' ]]; then echo ''; else echo ''; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.1.13", "Audit SUID executables (Not Scored)", checkstat})

	// Check 6.1.14
	cmd = "if [[ `sudo df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000 2>/dev/null` == '' ]]; then echo ''; else echo ''; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.1.14", "Audit SGID executables (Not Scored)", checkstat})

	// Check 6.2.1
	cmd = "if [[ `sudo awk -F: '{if ( length($2)==0 ) print $0;}' /etc/shadow` == '' ]]; then echo ''; else echo 'Ensure password fields are not empty'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.2.1", "Ensure password fields are not empty (Scored)", checkstat})

	// Check 6.2.2
	cmd = "if [[ `grep '^+:' /etc/passwd` == '' ]]; then echo ''; else echo 'Ensure no legacy " + " entries exist in /etc/passwd'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.2.2", "Ensure no legacy " + " entries exist in /etc/passwd (Scored)", checkstat})

	// Check 6.2.3
	cmd = "if [[ `sudo grep '^+:' /etc/shadow` == '' ]]; then echo ''; else echo 'Ensure no legacy " + " entries exist in /etc/shadow'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.2.3", "Ensure no legacy " + " entries exist in /etc/shadow (Scored)", checkstat})

	// Check 6.2.4
	cmd = "if [[ `sudo grep '^+:' /etc/group` == '' ]]; then echo ''; else echo 'Ensure no legacy " + " entries exist in /etc/group'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.2.4", "Ensure no legacy " + " entries exist in /etc/group (Scored)", checkstat})

	// Check 6.2.5
	cmd = "if [[ `awk -F: '($3 == 0) { print $1 }' /etc/passwd|grep root|wc -l` -eq 1 ]]; then echo ''; else echo 'Ensure root is the only UID 0 account'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.2.5", "Ensure root is the only UID 0 account (Scored)", checkstat})

	// Check 6.2.6
	cmd = "found=0; if [[ `echo $PATH|grep ::` != '' || `echo $PATH|grep :?` != '' ]]; then found=0; else found=1; fi; p=$(echo $PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'); for d in $p; do if [[ `ls -ld $d|cut -d ' ' -f1|awk '{print substr($0, 6, 1);}'` != '-' || `ls -ld $d|cut -d ' ' -f1|awk '{print substr($0, 9, 1);}'` != '-' ]]; then found=0; else found=1; fi; done; if [[ $found == 0 ]]; then echo ''; else echo 'Ensure root PATH Integrity'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.2.6", "Ensure root PATH Integrity (Scored)", checkstat})

	// Check 6.2.7
	cmd = "found=0; cat /etc/passwd | while read entry; do if [[ `echo $entry|grep -v nobody|awk -F: '{print $3}'` -ge 1000 ]]; then dir=`echo $entry|awk -F: '{print $6}'`; if [[ ! -d $dir ]]; then found=1; fi; fi; done; if [[ $found == 0 ]]; then echo ''; else echo 'missing home dir(s)'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.2.7", "Ensure all users' home directories exist (Scored)", checkstat})

	// Check 6.2.8
	cmd = "found=0; cat /etc/passwd | while read entry; do if [[ `echo $entry|grep -v nobody|awk -F: '{print $3}'` -ge 1000 ]]; then dir=`echo $entry|awk -F: '{print $6}'`; if [[ `ls -ld $dir 2>/dev/null|cut -d ' ' -f1|awk '{print substr($0, 8, 3);}'` != '---' ]]; then found=1; fi; fi; done; if [[ $found == 1 ]]; then echo ''; else echo 'home dir permissions incorrect'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.2.8", "Ensure users' home directories permissions are 750 or more restrictive (Scored)", checkstat})

	// Check 6.2.9
	cmd = "found=0; cat /etc/passwd | while read entry; do if [[ `echo $entry|grep -v nobody|awk -F: '{print $3}'` -ge 1000 ]]; then dir=`echo $entry|awk -F: '{print $6}'`; user=`echo $entry|awk -F: '{print $1}'`; if [[ `stat -L -c %U $dir` != $user ]]; then found=1; fi; fi; done; if [[ $found == 0 ]]; then echo ''; else echo 'home dir ownership incorrect'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.2.9", "Ensure users own their home directories (Scored)", checkstat})

	// Check 6.2.10
	cmd = "found=0; cat /etc/passwd | while read entry; do if [[ `echo $entry|grep -v nobody|awk -F: '{print $3}'` -ge 1000 ]]; then dir=`echo $entry|awk -F: '{print $6}'`; for file in $dir/.[A-Za-z0-9]*; do if [[ `ls -ld $file|cut -d ' ' -f1|awk '{print substr($0, 6, 1);}'` != '-' || `ls -ld $file|cut -d ' ' -f1|awk '{print substr($0, 9, 1);}'` != '-' ]]; then echo found=1; fi; done;fi; done; if [[ $found == 0 ]]; then echo ''; else echo 'dot files are not group or world writable'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.2.10", "Ensure users dot files are not group or world writable (Scored)", checkstat})

	// Check 6.2.11
	cmd = "found=0; cat /etc/passwd | while read entry; do if [[ `echo $entry|grep -v nobody|awk -F: '{print $3}'` -ge 1000 ]]; then dir=`echo $entry|awk -F: '{print $6}'`; if [[ `ls -l $dir/.forward 2>/dev/null` != '' ]]; then found=1; fi; fi; done; if [[ $found == 0 ]]; then echo ''; else echo 'users have .forward files'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.2.11", "Ensure no users have .forward files (Scored)", checkstat})

	// Check 6.2.12
	cmd = "found=0; cat /etc/passwd | while read entry; do if [[ `echo $entry|grep -v nobody|awk -F: '{print $3}'` -ge 1000 ]]; then dir=`echo $entry|awk -F: '{print $6}'`; if [[ `ls -l $dir/.netrc 2>/dev/null` != '' ]]; then found=1; fi; fi; done; if [[ $found == 0 ]]; then echo ''; else echo 'users have .netrc files'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.2.12", "Ensure no users have .netrc files (Scored)", checkstat})

	// Check 6.2.13
	cmd = "found=0; cat /etc/passwd | while read entry; do if [[ `echo $entry|grep -v nobody|awk -F: '{print $3}'` -ge 1000 ]]; then dir=`echo $entry|awk -F: '{print $6}'`; if [[ `ls -l $dir/.netrc 2>/dev/null` != '' ]]; then found=1; fi; fi; done; if [[ $found == 0 ]]; then echo ''; else echo 'users have .netrc files'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.2.13", "Ensure users .netrc Files are not group or world accessible (Scored)", checkstat})

	// Check 6.2.14
	cmd = "found=0; cat /etc/passwd | while read entry; do if [[ `echo $entry|grep -v nobody|awk -F: '{print $3}'` -ge 1000 ]]; then dir=`echo $entry|awk -F: '{print $6}'`; if [[ `ls -l $dir/.rhosts 2>/dev/null` != '' ]]; then found=1; fi; fi; done; if [[ $found == 0 ]]; then echo ''; else echo 'users have .rhosts files'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.2.14", "Ensure no users have .rhosts files (Scored)", checkstat})

	// Check 6.2.15
	cmd = "found=0; for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do if [[ `cat /etc/group|awk -F: '{print $3}'|grep -w $i` == '' ]]; then found=1; fi; done; if [[ $found == 0 ]]; then echo ''; else echo 'Ensure all groups in /etc/passwd exist in /etc/group'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.2.15", "Ensure all groups in /etc/passwd exist in /etc/group (Scored)", checkstat})

	// Check 6.2.16
	cmd = "if [[ `awk -F: '{print $3}' /etc/passwd| sort -n|uniq| wc -l` -eq `cat /etc/passwd|wc -l` ]]; then echo ''; else echo 'Ensure no duplicate UIDs exist'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.2.16", "Ensure no duplicate UIDs exist (Scored)", checkstat})

	// Check 6.2.17
	cmd = "if [[ `awk -F: '{print $3}' /etc/group| sort -n|uniq| wc -l` -eq `cat /etc/group|wc -l` ]]; then echo ''; else echo 'Ensure no duplicate GIDs exist'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.2.17", "Ensure no duplicate UIDs exist (Scored)", checkstat})

	// Check 6.2.18
	cmd = "if [[ `awk -F: '{print $1}' /etc/passwd| sort -n|uniq| wc -l` -eq `cat /etc/passwd|wc -l` ]]; then echo ''; else echo 'Ensure no duplicate usernames exist'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.2.18", "Ensure no duplicate user names exist (Scored)", checkstat})

	// Check 6.2.19
	cmd = "if [[ `awk -F: '{print $1}' /etc/group| sort -n|uniq| wc -l` -eq `cat /etc/group|wc -l` ]]; then echo ''; else echo 'Ensure no duplicate groupnamesIDs exist'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.2.19", "Ensure no duplicate group names exist (Scored)", checkstat})

	// Check 6.2.20
	cmd = "if [[ `grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group` == '' ]]; then echo ''; else echo 'Ensure shadow group is empty'; fi"
	out, _ = remexec.RemoteRun(user, host, pass, cmd)
	if len(strings.TrimSpace(out)) == 0 {
		checkstat = "PASS"
	} else {
		log.Println(out)
		checkstat = "FAIL"
	}
	ServicesSlice = append(ServicesSlice, Datastat{"6.2.20", "Ensure shadow group is empty (Scored)", checkstat})

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
