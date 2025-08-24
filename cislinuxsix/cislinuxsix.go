package cislinuxsix

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

func CislinuxsixOptimized(conn *remexec.SSHConnection) []Datastat {
	ServicesSlice := []Datastat{}

	checks := []Check{
		{
			ID:          "6.1.1",
			Description: "Audit system file permissions (Not Scored)",
			Command:     "if [[ `uname -a` != '' ]]; then echo ''; else echo 'Audit system file permissions'; fi",
		},
		{
			ID:          "6.1.2",
			Description: "Ensure permissions on /etc/passwd are configured (Scored)",
			Command:     "if [[ `stat /etc/passwd 2>/dev/null| grep root|grep 0644` != '' ]]; then echo ''; else echo 'Ensure permissions on /etc/passwd are configured'; fi",
		},
		{
			ID:          "6.1.3",
			Description: "Ensure permissions on /etc/shadow are configured (Scored)",
			Command:     "if [[ `sudo stat /etc/shadow 2>/dev/null| grep root|grep 0640` != '' ]]; then echo ''; else echo 'Ensure permissions on /etc/shadow are configured'; fi",
		},
		{
			ID:          "6.1.4",
			Description: "Ensure permissions on /etc/group are configured (Scored)",
			Command:     "if [[ `stat /etc/group 2>/dev/null| grep root|grep 0644` != '' ]]; then echo ''; else echo 'Ensure permissions on /etc/group are configured'; fi",
		},
		{
			ID:          "6.1.5",
			Description: "Ensure permissions on /etc/gshadow are configured (Scored)",
			Command:     "if [[ `stat /etc/gshadow 2>/dev/null| grep root|grep 0640` != '' ]]; then echo ''; else echo 'Ensure permissions on /etc/gshadow are configured'; fi",
		},
		{
			ID:          "6.1.6",
			Description: "Ensure permissions on /etc/passwd- are configured (Scored)",
			Command:     "if [[ `sudo stat /etc/passwd- 2>/dev/null| grep root|grep 0600` != '' ]]; then echo ''; else echo 'Ensure permissions on /etc/passwd- are configured'; fi",
		},
		{
			ID:          "6.1.7",
			Description: "Ensure permissions on /etc/shadow- are configured (Scored)",
			Command:     "if [[ `sudo stat /etc/shadow- 2>/dev/null| grep root|grep 0640` != '' ]]; then echo ''; else echo 'Ensure permissions on /etc/shadow- are configured'; fi",
		},
		{
			ID:          "6.1.8",
			Description: "Ensure permissions on /etc/group- are configured (Scored)",
			Command:     "if [[ `stat /etc/group- 2>/dev/null| grep root|grep 0644` != '' ]]; then echo ''; else echo 'Ensure permissions on /etc/group- are configured'; fi",
		},
		{
			ID:          "6.1.9",
			Description: "Ensure permissions on /etc/gshadow- are configured (Scored)",
			Command:     "if [[ `sudo stat /etc/gshadow- 2>/dev/null| grep root|grep 0640` != '' ]]; then echo ''; else echo 'Ensure permissions on /etc/gshadow- are configured'; fi",
		},
		{
			ID:          "6.1.10",
			Description: "Ensure no world writable files exist (Scored)",
			Command:     "if [[ `sudo df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure no world writable files exist'; fi",
		},
		{
			ID:          "6.1.11",
			Description: "Ensure no unowned files or directories exist (Scored)",
			Command:     "if [[ `sudo df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nouser 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure no unowned files or directories exist'; fi",
		},
		{
			ID:          "6.1.12",
			Description: "Ensure no ungrouped files or directories exist (Scored)",
			Command:     "if [[ `sudo df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -nogroup 2>/dev/null` != '' ]]; then echo ''; else echo 'Ensure no ungrouped files or directories exist'; fi",
		},
		{
			ID:          "6.1.13",
			Description: "Audit SUID executables (Not Scored)",
			Command:     "if [[ `sudo df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000 2>/dev/null` == '' ]]; then echo ''; else echo ''; fi",
		},
		{
			ID:          "6.1.14",
			Description: "Audit SGID executables (Not Scored)",
			Command:     "if [[ `sudo df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000 2>/dev/null` == '' ]]; then echo ''; else echo ''; fi",
		},
		{
			ID:          "6.2.1",
			Description: "Ensure password fields are not empty (Scored)",
			Command:     "if [[ `sudo awk -F: '{if ( length($2)==0 ) print $0;}' /etc/shadow` == '' ]]; then echo ''; else echo 'Ensure password fields are not empty'; fi",
		},
		{
			ID:          "6.2.2",
			Description: "Ensure no legacy + entries exist in /etc/passwd (Scored)",
			Command:     "if [[ `grep '^+:' /etc/passwd` == '' ]]; then echo ''; else echo 'Ensure no legacy + entries exist in /etc/passwd'; fi",
		},
		{
			ID:          "6.2.3",
			Description: "Ensure no legacy + entries exist in /etc/shadow (Scored)",
			Command:     "if [[ `sudo grep '^+:' /etc/shadow` == '' ]]; then echo ''; else echo 'Ensure no legacy + entries exist in /etc/shadow'; fi",
		},
		{
			ID:          "6.2.4",
			Description: "Ensure no legacy + entries exist in /etc/group (Scored)",
			Command:     "if [[ `sudo grep '^+:' /etc/group` == '' ]]; then echo ''; else echo 'Ensure no legacy + entries exist in /etc/group'; fi",
		},
		{
			ID:          "6.2.5",
			Description: "Ensure root is the only UID 0 account (Scored)",
			Command:     "if [[ `awk -F: '($3 == 0) { print $1 }' /etc/passwd|grep root|wc -l` -eq 1 ]]; then echo ''; else echo 'Ensure root is the only UID 0 account'; fi",
		},
		{
			ID:          "6.2.6",
			Description: "Ensure root PATH Integrity (Scored)",
			Command:     "found=0; if [[ `echo $PATH|grep ::` != '' || `echo $PATH|grep :?` != '' ]]; then found=0; else found=1; fi; p=$(echo $PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'); for d in $p; do if [[ `ls -ld $d|cut -d ' ' -f1|awk '{print substr($0, 6, 1);}'` != '-' || `ls -ld $d|cut -d ' ' -f1|awk '{print substr($0, 9, 1);}'` != '-' ]]; then found=0; else found=1; fi; done; if [[ $found == 0 ]]; then echo ''; else echo 'Ensure root PATH Integrity'; fi",
		},
		{
			ID:          "6.2.7",
			Description: "Ensure all users' home directories exist (Scored)",
			Command:     "found=0; cat /etc/passwd | while read entry; do if [[ `echo $entry|grep -v nobody|awk -F: '{print $3}'` -ge 1000 ]]; then dir=`echo $entry|awk -F: '{print $6}'`; if [[ ! -d $dir ]]; then found=1; fi; fi; done; if [[ $found == 0 ]]; then echo ''; else echo 'missing home dir(s)'; fi",
		},
		{
			ID:          "6.2.8",
			Description: "Ensure users' home directories permissions are 750 or more restrictive (Scored)",
			Command:     "found=0; cat /etc/passwd | while read entry; do if [[ `echo $entry|grep -v nobody|awk -F: '{print $3}'` -ge 1000 ]]; then dir=`echo $entry|awk -F: '{print $6}'`; if [[ `ls -ld $dir 2>/dev/null|cut -d ' ' -f1|awk '{print substr($0, 8, 3);}'` != '---' ]]; then found=1; fi; fi; done; if [[ $found == 1 ]]; then echo ''; else echo 'home dir permissions incorrect'; fi",
		},
		{
			ID:          "6.2.9",
			Description: "Ensure users own their home directories (Scored)",
			Command:     "found=0; cat /etc/passwd | while read entry; do if [[ `echo $entry|grep -v nobody|awk -F: '{print $3}'` -ge 1000 ]]; then dir=`echo $entry|awk -F: '{print $6}'`; user=`echo $entry|awk -F: '{print $1}'`; if [[ `stat -L -c %U $dir` != $user ]]; then found=1; fi; fi; done; if [[ $found == 0 ]]; then echo ''; else echo 'home dir ownership incorrect'; fi",
		},
		{
			ID:          "6.2.10",
			Description: "Ensure users dot files are not group or world writable (Scored)",
			Command:     "found=0; cat /etc/passwd | while read entry; do if [[ `echo $entry|grep -v nobody|awk -F: '{print $3}'` -ge 1000 ]]; then dir=`echo $entry|awk -F: '{print $6}'`; for file in $dir/.[A-Za-z0-9]*; do if [[ `ls -ld $file|cut -d ' ' -f1|awk '{print substr($0, 6, 1);}'` != '-' || `ls -ld $file|cut -d ' ' -f1|awk '{print substr($0, 9, 1);}'` != '-' ]]; then echo found=1; fi; done;fi; done; if [[ $found == 0 ]]; then echo ''; else echo 'dot files are not group or world writable'; fi",
		},
		{
			ID:          "6.2.11",
			Description: "Ensure no users have .forward files (Scored)",
			Command:     "found=0; cat /etc/passwd | while read entry; do if [[ `echo $entry|grep -v nobody|awk -F: '{print $3}'` -ge 1000 ]]; then dir=`echo $entry|awk -F: '{print $6}'`; if [[ `ls -l $dir/.forward 2>/dev/null` != '' ]]; then found=1; fi; fi; done; if [[ $found == 0 ]]; then echo ''; else echo 'users have .forward files'; fi",
		},
		{
			ID:          "6.2.12",
			Description: "Ensure no users have .netrc files (Scored)",
			Command:     `awk -F: '$3>=1000 && $1!="nobody" {print $6}' /etc/passwd | while read -r home; do [ -f "$home/.netrc" ] && echo 'users have .netrc files' && break; done`,
		},
		{
			ID:          "6.2.13",
			Description: "Ensure users .netrc Files are not group or world accessible (Scored)",
			Command:     "found=0; cat /etc/passwd | while read entry; do if [[ `echo $entry|grep -v nobody|awk -F: '{print $3}'` -ge 1000 ]]; then dir=`echo $entry|awk -F: '{print $6}'`; if [[ `ls -l $dir/.netrc 2>/dev/null` != '' ]]; then found=1; fi; fi; done; if [[ $found == 0 ]]; then echo ''; else echo 'users have .netrc files'; fi",
		},
		{
			ID:          "6.2.14",
			Description: "Ensure no users have .rhosts files (Scored)",
			Command:     "found=0; cat /etc/passwd | while read entry; do if [[ `echo $entry|grep -v nobody|awk -F: '{print $3}'` -ge 1000 ]]; then dir=`echo $entry|awk -F: '{print $6}'`; if [[ `ls -l $dir/.rhosts 2>/dev/null` != '' ]]; then found=1; fi; fi; done; if [[ $found == 0 ]]; then echo ''; else echo 'users have .rhosts files'; fi",
		},
		{
			ID:          "6.2.15",
			Description: "Ensure all groups in /etc/passwd exist in /etc/group (Scored)",
			Command:     "found=0; for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do if [[ `cat /etc/group|awk -F: '{print $3}'|grep -w $i` == '' ]]; then found=1; fi; done; if [[ $found == 0 ]]; then echo ''; else echo 'Ensure all groups in /etc/passwd exist in /etc/group'; fi",
		},
		{
			ID:          "6.2.16",
			Description: "Ensure no duplicate UIDs exist (Scored)",
			Command:     "if [[ `awk -F: '{print $3}' /etc/passwd| sort -n|uniq| wc -l` -eq `cat /etc/passwd|wc -l` ]]; then echo ''; else echo 'Ensure no duplicate UIDs exist'; fi",
		},
		{
			ID:          "6.2.17",
			Description: "Ensure no duplicate UIDs exist (Scored)",
			Command:     "if [[ `awk -F: '{print $3}' /etc/group| sort -n|uniq| wc -l` -eq `cat /etc/group|wc -l` ]]; then echo ''; else echo 'Ensure no duplicate GIDs exist'; fi",
		},
		{
			ID:          "6.2.18",
			Description: "Ensure no duplicate user names exist (Scored)",
			Command:     "if [[ `awk -F: '{print $1}' /etc/passwd| sort -n|uniq| wc -l` -eq `cat /etc/passwd|wc -l` ]]; then echo ''; else echo 'Ensure no duplicate usernames exist'; fi",
		},
		{
			ID:          "6.2.19",
			Description: "Ensure no duplicate group names exist (Scored)",
			Command:     "if [[ `awk -F: '{print $1}' /etc/group| sort -n|uniq| wc -l` -eq `cat /etc/group|wc -l` ]]; then echo ''; else echo 'Ensure no duplicate groupnamesIDs exist'; fi",
		},
		{
			ID:          "6.2.20",
			Description: "Ensure shadow group is empty (Scored)",
			Command:     "if [[ `grep ^shadow:[^:]*:[^:]*:[^:]+ /etc/group` == '' ]]; then echo ''; else echo 'Ensure shadow group is empty'; fi",
		},
	}

	log.Printf("DEBUG: Executing %d CIS cislinuxsix checks individually\n", len(checks))
	
	for _, check := range checks {
		log.Printf("DEBUG: Executing check %s\n", check.ID)
		
		output, err := conn.RunCommand(check.Command)
		
		result := remexec.CommandResult{
			Command: check.Command,
			Output:  output,
			Error:   err,
		}
		
		checkstat := remexec.EvalCommandResult(result)
		
		if result.Error != nil {
			log.Printf("DEBUG: Check %s command error: %v; output: %s\n", check.ID, result.Error, result.Output)
		}
		if len(strings.TrimSpace(result.Output)) != 0 {
			log.Printf("DEBUG: Check %s output: %s\n", check.ID, result.Output)
		}
		
		ServicesSlice = append(ServicesSlice, Datastat{
			check.ID,
			check.Description,
			checkstat,
		})
	}

	log.Printf("DEBUG: Completed %d CIS cislinuxsix checks via individual execution\n", len(ServicesSlice))
	return ServicesSlice
}

func Cislinuxsix(user string, host string, pass string, key string) []Datastat {
	conn, err := remexec.NewSSHConnection(user, host, pass, key)
	if err != nil {
		log.Printf("ERROR: Failed to create SSH connection: %v\n", err)
		return []Datastat{}
	}
	defer conn.Close()

	return CislinuxsixOptimized(conn)
}

type Datastat struct {
	Controlid string
	Check     string
	Status    string
}
