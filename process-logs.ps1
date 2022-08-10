<#
	.SYNOPSIS
		Process Event logs
	.DESCRIPTION
		Process Windows Event Logs - convert evt, evtx to csv files then search them for common vulnerabilities.
	.Parameter computername
		Name of the computer host - used to name the files.
	.PARAMETER basedir
		Directory to place the logs
	.Parameter logfiles
		Directory which contains the logs files
	.EXAMPLE
		> .\process-logs.ps1 "ComputerHost" 's:\bgr\systems\computerhost\' 'f:\windows\system32\winevt\logs\'
	.NOTES
	Author: Tom Willett 
	Date: 8/24/2021
	V1.0
	Date: 2/11/2022
	V1.1 - Updated to normalize date and add computername to csv files.
#>
	Param([Parameter(Mandatory=$True)][string]$Computername,
	[Parameter(Mandatory=$True)][string]$basedir,
	[Parameter(Mandatory=$True)][string]$logfiles)

<#
  Configuration Information
#>

. ($psscriptroot + '.\process-lib.ps1')

function get-eventlogs {
<#

.SYNOPSIS

Reads a windows event log file (evtx) and converts it to a csv file with filtering capability

.DESCRIPTION

Reads evt and evtx windows log files and outputs a powershell object. You can filter on error level, 
time/date, eventid, userid, and LogSourceType.

It returns DateTime, EventID, Level, ShortEvent, User, Event, LogSource, LogSourceType, and Machine.

Evt logs can sometimes get corrupted and you will get the error "The data is invalid".  Run fixevt.exe
to fix the log file.  http://www.whiteoaklabs.com/computer-forensics.html

.PARAMETER logFile

logfile is required -- the path to the log file.

.EXAMPLE

 .\get-eventlogs.ps1 c:\windows\system32\winevt\application.evtx | export-csv -notype c:\temp\app.csv

 Reads the log file at c:\windows\system32\winevt\application.evtx and puts the output in c:\temp\app.csv

 .EXAMPLE

 get-childitem *.evtx |.\get-eventlog.ps1 | export-csv -notype c:\temp\log.csv

 converts all the evtx logs puts the output in c:\temp\app.csv
 
.NOTES

Author: Tom Willett 
Date: 5/19/2021

#>

Param([Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$FullName)

	process {
		$fext = [system.io.path]::getextension($FullName)
		$filter = @{Path="$FullName"}
		if ($fext -eq ".evt") {
			$old = $true
		} else {
			$old = $false
		}
		get-winevent -oldest:$old -filterhashtable $filter | 
		select-object @{Name="DateTime";Expression={$_.timecreated}},@{Name="EventID";Expression={$_.ID}},Level,@{Name="ShortEvent";Expression={$_.TaskDisplayName}},@{Name="User";Expression={$_.UserId}}, @{Name="Event";Expression={(($_.message).replace("`n", " ")).replace("`t"," ")}}, @{Name="Properties";Expression={([string]::Join(" - ",$_.properties.value)).replace(',',';')}}, @{Name="Record";Expression={$_.RecordID}}, @{Name="LogSource";Expression={$_.logname}}, @{Name="LogSourceType";Expression={$_.ProviderName}},@{Name="Machine";Expression={$_.MachineName}}
	}
}

function check-logRecordID {
<#
	.Synopsis
		Checks Event Logs for evidence of tampering
	.Description
		Checks Event Logs for evidence of tampering by checking for consistent RecordIDs
	.Parameter logfile
		logfile to check
	.NOTES
		Author: Tom Willett
		Date: 6/1/2021
#>

	Param([Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$LogFile)
	write-debug "Checking $logfile for gaps in record ID"
	begin {
		$BoundaryEvents = @()
	}

	process {
		$events = import-csv $logfile

		$RecID0 = $Events[0].Record

		foreach ($event in $Events) {
			if ($RecID0 -ne $event.Record) {
				if ($RecID0 - $event.record -eq 1) {
					$RecID0 = $event.record
				} else {
					# save the event record id's that bound the hole in the event log
					# also save them to the ":list of holes"
					$temp = [pscustomobject]@{
						After = $RecID0
						Before = $event.record
					}
					$BoundaryEvents += $temp
					$RecID0 = $event.record
				}
			}
		}
	}
	end {
		if ($BoundaryEvents) {
			$out = $logfile + "`r`n"
			$out += "---------------------`r`n"
			foreach ($evt in $BoundaryEvents) {
				$out += "Begin=" + $evt.before + "  " + "End=" + $evt.after + "`r`n"
			}
			write-log $out
		}
	}
}

function get-logsearches {
<#
	.Synopsis
		Checks Event Logs for common vulnerabilities
	.Description
		Checks Event Logs for common vulnerabilities found on IR engagements
	.Parameter Computername
		Computer name to label the log files with
	.Parameter logsearches
		The directory in which to place the log search files
	.Parameter csvdir
		The directory where the csv file versions of the log files are kept
	.NOTES
		Author: Tom Willett
		Date: 8/24/2021
#>
	Param([Parameter(Mandatory=$True)][string]$Computername,
	[Parameter(Mandatory=$True)][string]$logsearches,
	[Parameter(Mandatory=$True)][string]$csvdir)
	
	push-location $LogSearches

	write-log "Processing Security Log" "yellow"
	write-log "Gathering Events" "cyan"
	write-debug "Searching log: $csvdir$computername~security.csv"
	$t = import-csv ($csvdir + ($computername + '~security.csv'))
	$t | where-object {$_.eventid -in (4624,4625,4776,4672,4634)} | export-csv -notype ($computername + '~logonEvents.csv')
	$t | where-object {$_.eventid -eq 4648} | export-csv -notype ($computername + '~ExplicitLogon.csv')
	$t | where-object {$_.eventid -eq 4798 -or $_.eventid -eq 4799} | export-csv -notype ($computername + '~groupenumeration.csv')
	$t | where-object {$_.eventid -in (4725,4722,4723,4726,4767)} | export-csv -notype ($computername + '~useraccountchanges.csv')
	$t | where-object {($_.eventid -eq 4657 -or $_.eventid -eq 4663) -and $_.event -like '*Object Name*'} | export-csv -notype ($computername + '~fileordirectorychange.csv')
	$t | where-object {$_.eventid -in (4738,4735)} | export-csv -notype ($computername + '~usergroupchanges.csv')
	$t | where-object {$_.eventid -eq (1102,517)} | export-csv -notype ($computername + '~eventlogscleared.csv')
	write-log "Searching for LOLBins" "cyan"
	$t | where-object {$_.eventid -eq 4688 -and ($_.event -like '*cmd.exe*' -or $_.event -like '*powershell.exe*'  -or $_.event -like '*cipher.exe*' -or $_.event -like '*WMIC.EXE*' -or $_.event -like '*NET.EXE*' -or 
	$_.event -like '*REGSVR32.EXE*' -or $_.event -like '*MSHTA.EXE*' -or $_.event -like '*msbuild.exe*' -or $_.event -like '*wmic.exe*' -or $_.event -like '*cscript.exe*')} | export-csv -notype ($computername + '~lolbins.csv')
	$report = @()
	write-debug "Searching log: $computername~lolbins.csv"
	$l = import-csv ($computername + '~lolbins.csv')
	$l |foreach-object{$tmp = "" | select-object DateTime,Process,CreatorProcess,CmdLine;$tmp.datetime = $_.datetime; $_.event | Select-String 'New Process Name: (.+?) Token Elevation Type: .+? Mandatory Label:\s+?\S+?\s+?Creator Process ID: .+?  Creator Process Name: (.+?)  Process Command Line:(.+?) ' | foreach-object{$tmp.process=$_.matches.groups.captures[1].value;$tmp.Creatorprocess=$_.matches.groups.captures[2].value;$tmp.cmdline=$_.matches.groups.captures[3].value;$report+=$tmp}}
	$report | export-csv -notype ($computername + '~lolbins-sum.csv')
	$l | Select-String 'New Process Name: (.+?) ' | foreach-object{$_.matches.groups.captures[1].value} | Group-Object | select-object count,name | Sort-Object count -desc | format-table -wrap > .\lolbin-histo.txt
	$t | where-object {$_.event -like "*certutil -urlcache*" -or $_.event -like "*certutil -decode*" -or $_.event -like "*certutil -verifyctl*" -or $_.event -like "*certutil -encode*" -or $_.event -like "certutil -addstore -f -user ROOT"} | export-csv -notype ($computername + '~certutilusage.csv')
	write-log "Gathering Possible Kerberoasting Events" "cyan"
	$t | where-object {$_.eventid -eq 4769 -and $_.event -like '*Ticket Encryption Type: 0x17*' -and $_.event -like '*Failure Code:  0x0*'} | export-csv -notype ($computername + '~Kerberoasting.csv')
	write-log "Gathering possible Pass-the-Hash and Zerologon events" "cyan"
	$t | where-object {$_.eventid -eq 4624 -and $_.event -like '* Negotiat*' -and $_.event -like '*Logon Type:  9*' -and $_.event -like '*seclogo*'} | export-csv -notype ($computername + '~PassTheHash.csv')
	$t | where-object {$_.eventid -eq 4742 -or $_.eventid -eq 5805 -or $_.eventid -eq 4724} | export-csv -notype ($computername + '~ZeroLogon.csv')
	write-log "Looking for MimiKatz" "cyan"
	#stupid tricks to get past Windows Defender
	$t | where-object {$_.event -like "*eo" + ".o" + "e.k" + "iwi*" -or $_.event -like "*<3" + " eo" + ".oe*" -or $_.event -like "*mi" + "mi" + "lib*" -or $_.event -like "*mi" + "mika" + "tz*" -or $_.event -like "*priv" + "ile" + "ge::" + "debug*" -or $_.event -like "*sek" + "urlsa::Lo" + "gonPassw" + "ords*"} | export-csv -notype ($computername + '~mimikatz.csv')
	$dte = get-date($t[0].DateTime)
	Write-log "Checking for Log Tampering" "cyan"
	"Log Date Gaps greater than 6 hours." | add-content -enc utf8 LogTampering.txt
	"Security Log" | add-content -enc utf8 LogTampering.txt
	$t| foreach-object{$dte2 = get-date($_.datetime);if (($dte - $dte2).totalhours -gt 6) {$dte2.tostring() + ' - ' + $dte.tostring()};$dte = $dte2} | add-content LogTampering.txt
	write-log "Analyzing Security Logs" "cyan"
	$report = @()
	write-log "Analyzing Logon Events" "cyan"
	write-debug "Searching log: $computername ~logonEvents.csv"
	$t = import-csv ($computername + '~logonEvents.csv')
	[System.GC]::Collect()
	$t | where-object {$_.eventid -eq 4624} | foreach-object{$tmp=""|select-object datetime,user,LogonType,host,ip;$tmp.datetime=$_.datetime;$_.event | Select-String 'Logon Type: {1,4}(\d{1,2}).+?Account Name: (.+?) .+?Workstation Name: (.+?) Source Network Address: (-|::1|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' | foreach-object{$tmp.user=$_.matches.groups.captures[2].value;$tmp.logontype=$_.matches.groups.captures[1].value;$tmp.host=$_.matches.groups.captures[3].value;$tmp.ip=$_.matches.groups.captures[4].value};$report+=$tmp}
	$report | export-csv -notype ($computername + '~logons.csv')
	$report = @()
	$t | where-object {$_.eventid -eq 4624} | foreach-object{$tmp=""|select-object datetime,EventID,user,LogonType,host,ip,LogonID;$tmp.datetime=$_.datetime;$tmp.EventID=$_.eventid;$_.event | Select-String 'Logon Type: {1,4}(\d{1,2}).+?Account Name: {1,3}(.+?) .+?Logon ID: {1,3}(.{3,14}) .+?Workstation Name: (.+?) .+?Source Network Address: (-|::1|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' | foreach-object{$tmp.user=$_.matches.groups.captures[2].value;$tmp.logontype=$_.matches.groups.captures[1].value;$tmp.LogonID=$_.matches.groups.captures[3].value;$tmp.host=$_.matches.groups.captures[4].value;$tmp.ip=$_.matches.groups.captures[5].value};$report+=$tmp}
	$t | where-object {$_.eventid -eq 4625} | foreach-object{$tmp=""|select-object datetime,EventID,user,LogonType,host,ip,LogonID;$tmp.datetime=$_.datetime;$tmp.EventID=$_.eventid;$_.event | Select-String 'Logon Type: {1,4}(\d{1,2}).+?Account Name: {1,3}(.+?) .+?Workstation Name: (.+?) .+?Source Network Address: (-|::1|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' | foreach-object{$tmp.user=$_.matches.groups.captures[2].value;$tmp.logontype=$_.matches.groups.captures[1].value;$tmp.LogonID=$_.matches.groups.captures[3].value;$tmp.host=$_.matches.groups.captures[4].value;$tmp.ip=$_.matches.groups.captures[5].value};$report+=$tmp}
	$t | where-object {$_.eventid -in (4672,4634)} | foreach-object{$tmp=""|select-object datetime,EventID,user,LogonType,host,ip,LogonID;$tmp.datetime=$_.datetime;$tmp.EventID=$_.eventid;$_.event | Select-String 'Account Name: {1,3}(.+?) .+?Logon ID: {1,3}(.{3,14}) ' | foreach-object{$tmp.user=$_.matches.groups.captures[1].value;$tmp.LogonID=$_.matches.groups.captures[2].value};$report+=$tmp}
	$t | where-object {$_.eventid -eq 4776} | foreach-object{$tmp=""|select-object datetime,EventID,user,LogonType,host,ip,LogonID;$tmp.datetime=$_.datetime;$tmp.EventID=$_.eventid;$_.event | Select-String ' Logon Account: (.+?) Source Workstation: (.+?) ' | foreach-object{$tmp.user=$_.matches.groups.captures[1].value;$tmp.host=$_.matches.groups.captures[2].value};$report+=$tmp}
	$rpt = @()
	$report | foreach-object{if ($_.eventid -eq 4624){$_.eventid = '4624 Logon'};if ($_.eventid -eq 4625){$_.eventid = '4625 Logon Failure'};if ($_.eventid -eq 4634){$_.eventid = '4634 Logoff'};if ($_.eventid -eq 4672){$_.eventid = '4672 Special Privileges'};if ($_.eventid -eq 4776){$_.eventid = '4776 Logon Attempt'};$rpt += $_}
	$report = @()
	$rpt | foreach-object{if ($_.logontype -eq 2){$_.logontype = '2 Interactive'};if ($_.logontype -eq 3){$_.logontype = '3 Network (SMB)'};if ($_.logontype -eq 4){$_.logontype = '4 Batch'};if ($_.logontype -eq 5){$_.logontype = '5 Service'};if ($_.logontype -eq 7){$_.logontype = '7 Unlock'};if ($_.logontype -eq 8){$_.logontype = '8 Network Clear Text'};if ($_.logontype -eq 9){$_.logontype = '9 RDP New Creds'};if ($_.logontype -eq 10){$_.logontype = '10 RDP'};if ($_.logontype -eq 11){$_.logontype = '11 Cached Creds'};$report+=$_}
	$report | export-csv -notype ($computername + '~LogonLogoff-summary.csv')
	$t | where-object {$_.eventid -eq 4624} | Select-String 'Logon Type: {1,4}(\d{1,2})' | foreach-object{$_.matches.groups.captures[1].value} | Group-Object | select-object count,name | Sort-Object count -desc > LogonTypes-histo.txt
	$t | where-object {$_.eventid -eq 4624} | Select-String 'Account Name: (.+?) ' | foreach-object{$_.matches.groups.captures[1].value} | Group-Object | select-object count,name | Sort-Object count -desc | Format-Table -wrap > logonusers-histo.txt
	$t | where-object {$_.eventid -eq 4624} | Select-String 'Source Network Address: (-|::1|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' | foreach-object{$_.matches.groups.captures[1].value} | Group-Object | select-object count,name | Sort-Object count -desc | Format-Table -wrap > LogonSourceIP-histo.txt
	write-log "Processing Terminal Services" "cyan"
	write-debug "Searching log: $csvdir$computername~Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.csv"
	import-csv ($csvdir + ($computername + '~Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.csv')) | where-object {$_.eventid -in (21,23,24,25)} | export-csv -notype ($computername + '~TerminalServicesLogins.csv')
	$report = @()
	write-debug "Searching log: $computername~TerminalServicesLogins.csv"
	$t = import-csv ($computername + '~TerminalServicesLogins.csv')
	[System.GC]::Collect()
	$t | where-object {$_.eventid -in (21,24,25)} | foreach-object{$tmp=""|select-object DateTime,User,IP,EventID,Session;$tmp.datetime=$_.datetime;$tmp.Eventid=$_.EventID;$_.event | Select-String 'User: (.+?) Session ID:\s{1,2}(\d{1,3})\s{1,3}Source Network Address: (.{2,15})' | foreach-object{$tmp.user=$_.matches.groups.captures[1].value;$tmp.Session=$_.matches.groups.captures[2].value;$tmp.IP=$_.matches.groups.captures[3].value};$report+=$tmp}
	$t | where-object {$_.eventid -eq 23} |  foreach-object{$tmp=""|select-object DateTime,User,IP,EventID,Session;$tmp.datetime=$_.datetime;$tmp.Eventid=$_.EventID;$_.event | Select-String 'User: (.+?) Session ID:\s{1,2}(\d{1,3})' | foreach-object{$tmp.user=$_.matches.groups.captures[1].value;$tmp.Session=$_.matches.groups.captures[2].value};$report+=$tmp}
	$rpt = @()
	$report | foreach-object{if ($_.eventid -eq 21){$_.eventID = '21 Logon'};if ($_.eventid -eq 24){$_.eventID = '24 Disconnect'};if ($_.eventID -eq 25){$_.eventid = '25 Reconnect'};if ($_.eventid -eq 23){$_.eventid = '23 Logoff'};$rpt += $_}
	$rpt | export-csv -notype ($computername + '~TermServLogins-summary.csv')
	write-log "Processing System Log" "cyan"
	write-debug "Searching log: $csvdir$computername~system.csv"
	$t = import-csv ($csvdir + ($computername + '~system.csv'))
	[System.GC]::Collect()
	write-log "Analyzing System Log" "cyan"
	$t | where-object {$_.eventid -eq 7045} | export-csv -notype ($computername + '~NewService.csv')
	$t | where-object {$_.eventid -in (7045,7040,7000,7022,7024,7031,7034,7035,7036)} | export-csv -notype ($computername + '~serviceactivity.csv')
	$t | where-object {$_.eventid -eq 104 -and $_.event -like '*was cleared*'} | export-csv -notype -append ($computername + '~eventlogscleared.csv')
	$dte = get-date($t[0].DateTime)
	"System Log" | add-content -enc utf8 LogTampering.txt
	$t | foreach-object{$dte2 = get-date($_.datetime);if (($dte - $dte2).totalhours -gt 6) {$dte2.tostring() + ' - ' + $dte.tostring()};$dte = $dte2} | add-content LogTampering.txt
	write-log "Processing Application Log" "cyan"
	write-debug "Searching log: $csvdir$computername~application.csv"
	$a = import-csv ($csvdir + ($computername + '~application.csv'))
	$a | where-object {($_.eventid -in (325,326,327,216)) -and ($_.LogSourceType -eq 'ESENT') -and $_.event -like '*ntds*'} | export-csv -notype ntds.dit-dumping.csv
	$a | where-object {$_.eventid -eq 1000 -and $_.ShortEvent -eq 'Application Crashing Events'} | export-csv -notype ($computername + '~applicationcrash.csv')
	write-debug "Searching log: $computername~applicationcrash.csv"
	$t = import-csv ($computername + '~applicationcrash.csv')
	$t | Select-String 'Faulting application name: (.+?), ' | foreach-object{$_.matches.groups.captures[1].value} | Group-Object | select-object count,name | Sort-Object count -desc > appcrash-histo.txt
	$report = @()
	$t | foreach-object{$temp = "" | select-object DateTime,Application;$temp.DateTime = $_.DateTIme;$_.event | Select-String 'Faulting application name: (.+?), ' | foreach-object{$temp.application = $_.matches.groups.captures[1].value;$report += $temp}}
	$report | export-csv -notype ($computername + '~AppCrash-summary.csv')
	"Appplication Log" | add-content -enc utf8 LogTampering.txt
	$dte = get-date($a[0].DateTime)
	$a | foreach-object{$dte2 = get-date($_.datetime);if (($dte - $dte2).totalhours -gt 6) {$dte2.tostring() + ' - ' + $dte.tostring()};$dte = $dte2} | add-content LogTampering.txt
	write-log "Processing PowerShell Logs" "cyan"
	write-debug "Searching log: $csvdir$computername~Windows PowerShell.csv"
	$t = import-csv ($csvdir + ($computername + '~Windows PowerShell.csv'))
	[System.GC]::Collect()
	write-debug "Searching log: $csvdir$computername~Microsoft-Windows-PowerShell%4Operational.csv"
	$t += import-csv ($csvdir + ($computername + '~Microsoft-Windows-PowerShell%4Operational.csv'))
	#stupid tricks to get past Windows Defender
	$t | where-object {$_.event -like "*Net.WebClient*" -or $_.event -like "*DownloadFile*"	-or $_.event -like "*DownloadString*"	-or $_.event -like "*Invoke-WebRequest*"	-or $_.event -like "*Inv" + "oke-Shel" + "lcode*"	-or $_.event -like "*http:"} | export-csv -notype ($computername + '~powershellDownloads.csv')
	$t | where-object {$_.eventid -eq 800} | export-csv -notype -append ($computername + '~PowerShell.csv')
	#stupid tricks to get past Windows Defender
	$t | where-object {($_.eventid -ne 600) -and ($_.event -like '*IO.Str" + "eamReader*' -or $_.event -like '*[ref" + "lection.as" + "sembly]*' -or $_.event -like '*Convert]::FromBase64String*')} | export-csv -notype -append ($computername + '~PowerShell.csv')
	$t | where-object {$_.event -like '*var_code*' -or $_.event -like '*DoIt*' -or $_.event -like '*IEX \$DoIt*' -or $_.event -like '*IO.StreamReader*' -or $_.event -like '*IEX \(New" + "-Object IO.Str" + "eamReader*'} | export-csv -notype ($computername + '~CobaltStrike.csv')
	write-log "Processing Run/Runonce, Applocker, Office Alerts, Winrm, Scheduled Tasks" "cyan"
	write-debug "Searching log: $csvdir$computername~Microsoft-Windows-Shell-Core%4Operational.csv"
	import-csv ($csvdir + ($computername + '~Microsoft-Windows-Shell-Core%4Operational.csv')) | where-object {$_.eventid -in (9707,9708)} | export-csv -notype ($computername + '~run-runonce.csv')
	write-debug "Searching log: $csvdir$computername~OAlerts.csv.csv"
	import-csv ($csvdir + ($computername + '~OAlerts.csv')) | where-object {$_.eventid -eq 300} | export-csv -notype ($computername + '~office-alerts.csv')
	write-log "Getting Applocker and Software Restriction"
	write-debug "Searching log: $csvdir$computername~~Microsoft-Windows-AppLocker%4EXE and DLL.csv"
	import-csv ($csvdir + ($computername + '~Microsoft-Windows-AppLocker%4EXE and DLL.csv')) | export-csv -notype ($computername + '~applocker.csv')
	write-debug "Searching log: $csvdir$computername~Microsoft-Windows-AppLocker%4MSI and Script.csv"
	import-csv ($csvdir + ($computername + '~Microsoft-Windows-AppLocker%4MSI and Script.csv')) | export-csv -notype -append ($computername + '~applocker.csv')
	write-debug "Searching log: $csvdir$computername~Microsoft-Windows-AppLocker%4Packaged app-Deployment.csv"
	import-csv ($csvdir + ($computername + '~Microsoft-Windows-AppLocker%4Packaged app-Deployment.csv')) | export-csv -notype -append ($computername + '~applocker.csv')
	write-debug "Searching log: $csvdir$computername~Microsoft-Windows-AppLocker%4Packaged app-Execution.csv"
	import-csv ($csvdir + ($computername + '~Microsoft-Windows-AppLocker%4Packaged app-Execution.csv')) | export-csv -notype -append ($computername + '~applocker.csv')
	write-debug "Searching log: $csvdir$computername~Microsoft-Windows-WinRM%4Operational.csv"
	import-csv ($csvdir + ($computername + '~Microsoft-Windows-WinRM%4Operational.csv')) | where-object {$_.eventid -in (6,91)} | export-csv -notype ($computername + '~winrm.csv')
	write-debug "Searching log: $csvdir$computername~Microsoft-Windows-TaskScheduler%4Operational.csv"
	$t = import-csv ($csvdir + ($computername + '~Microsoft-Windows-TaskScheduler%4Operational.csv'))
	$t | where-object {$_.eventid -eq 106} | export-csv -notype ($computername + '~NewTask.csv')
	$t | where-object {$_.eventid -in (140,141,200)} | export-csv -notype ($computername + '~ScheduleTask.csv')
	write-log "Checking for Log Tampering" "cyan"
	check-logRecordID ($csvdir + ($computername + '~security.csv')) | add-content LogTampering.txt
	check-logRecordID ($csvdir + ($computername + '~system.csv')) | add-content LogTampering.txt
	check-logRecordID ($csvdir + ($computername + '~application.csv')) | add-content LogTampering.txt
$outstring = @"
For Kerberoasting see https://adsecurity.org/?p=3458
For PassTheHash see https://blog.stealthbits.com/how-to-detect-pass-the-hash-attacks/
	Source Host
	4648 – A logon was attempted using explicit credentials.
	4624 – An account was successfully logged on. (Logon type = 9 Logon Process = Seclogo)
	4672 – Special privileges assigned to new logon. (Logged on user, not impersonated user)
	Target Host
	4672 – Special privileges assigned to new logon.
	4624 – An account was successfully logged on. Logon Type 3, NTLM
	Domain Controller
	4776 – The computer attempted to validate the credentials for an account.
For ZeroLogon 4742 is Anonymous login 5805 Authentication Failure
	4624 followed by successful 4724 (Reset Password)
	See https://www.kroll.com/en/insights/publications/cyber/cve-2020-1472-zerologon-exploit-detection-cheat-sheet
"@
	$outstring | add-content -enc utf8 PTH-Kerberosting-ZeroLogon.txt

$outstring = @"
Type 2 ? Interactive ? GUI
Type 3 ? Network ? Net Use
Type 4 ? Batch
Type 5 ? Service
Type 7 ? Unlock
Type 8 ? Network Clear Text
Type 9 ? New Credentials (RDP Tools)
Type 10 ? Remote Interactive (RDP)
Type 11 ? Cached Interactive (laptops)
"@
	$outstring | add-content -enc utf8 LogonTypes.txt
	get-childitem *.csv | where-object {$_.length -eq 0} | remove-item

pop-location
}

function check-persistence {
<#
	.Synopsis
		Checks Event logs for signs of peristence
	.Description
		Checks Event logs for signs of peristence
	.Parameter Computername
		Computer name to label the log files with
	.Parameter csvdir
		The directory where the csv file versions of the log files are kept
	.NOTES
		Author: Tom Willett
		Date: 8/10/2022
#>
Param([Parameter(Mandatory=$True)][string]$Computername,
[Parameter(Mandatory=$True)][string]$csvdir)

$system = import-csv ($csvdir + ($computername + '~system.csv'))
	$stnum = ($system | where-object {$_.eventid -eq 7045 -and [datetime]::parse($_.datetime) -ge [datetime]::parse($imagedate).adddays(-30)}).length
	if ($stnum -gt 0) {
		write-persistence "$stnum New Services created in last 30 days"
	}
	$stnum = ($system | where-object {$_.eventid -eq 7045 -and $_.event -like '*powershell.exe*'}).length
	if ($stnum -gt 0) {
		write-persistence "$stnum New Services created running PowerShell command."
	}
	$stnum = ($system | where-object {$_.eventid -eq 4720 -and [datetime]::parse($_.datetime) -ge [datetime]::parse($imagedate).adddays(-30)}).length
	if ($stnum -gt 0) {
		write-persistence "$stnum New Users created in last 30 days"
	}
	$stnum = ($system | where-object {($_.eventid -eq 4738 -or $_.eventid -eq 4735) -and [datetime]::parse($_.datetime) -ge [datetime]::parse($imagedate).adddays(-30)}).length
	if ($stnum -gt 0) {
		write-persistence "$stnum User or Group changes in last 30 days"
	}
	$stnum = ($system | where-object {$_.eventid -eq 4688 -and [datetime]::parse($_.datetime) -ge [datetime]::parse($imagedate).adddays(-30) -and ($_.event -like '*cmd.exe*' -or $_.event -like '*powershell.exe*' -or $_.event -like '*cipher.exe*' -or $_.event -like '*WMIC.EXE*' -or $_.event -like '*NET.EXE*' -or $_.event -like '*REGSVR32.EXE*' -or $_.event -like '*MSHTA.EXE*' -or $_.event -like '*msbuild.exe*' -or $_.event -like '*wmic.exe*' -or $_.event -like '*cscript.exe*')}).length
	if ($stnum -gt 0) {
		write-persistence "$stnum lolbins used in last 30 days"
	}
	
}

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	write-log "Must be run with Administrator Permissions" "red"
	exit
}

# And it begins
#########
if ($debug) {
	$ErrorActionPreference = "Continue"
	write-debug "process-logs.ps1"
	write-debug "Parameters:"
	write-debug "Computername = $Computername"
	write-debug "Basedir = $basedir"
	write-debug "Logfiles = $logfiles"
} else {
	$ErrorActionPreference = "SilentlyContinue"
}

#Resize Window
$w = $Host.UI.RawUI.windowsize
$w.height = 20
$w.width = 100
$Host.UI.RawUI.windowsize = $w
$b = $Host.UI.RawUI.buffersize
$b.height = 20
$b.width = 100
$Host.UI.RawUI.buffersize = $b

$host.ui.RawUI.WindowTitle="Processing Log Files for $computername"

write-log "Processing Event Logs for $computername"

$basedir = get-path $basedir
$logfiles = get-path $logfiles
$log = $basedir + 'messages.txt'

write-log "Converting Event Logs to CSV" -fore "green"

push-location $basedir
mkdir logs-csv >> $null
mkdir logsearches >> $null
$logcsv = $computername + '-logs.csv'
get-childitem $logfiles | foreach-object{write-log "Processing: $_"
		$tmp = get-eventlogs $_.fullname
		$tmp | foreach-object{$_.datetime = [datetime]::parse($_.datetime).tostring('yyyy-MM-dd HH:mm:ss')}
		$tmp | export-csv -notype $logcsv -append
		$tmp | export-csv -notype ('logs-csv\' + $computername + '~' + $_.basename + '.csv')
	}
#get-childitem $logfiles | where-object {$_.length -gt 69632} | foreach-object{write-log "Processing: $_"; $tmp = get-eventlogs $_.fullname; $tmp | foreach-object{$_.datetime = [datetime]::parse($_.datetime).tostring('yyyy-MM-dd HH:mm:ss')} -ErrorAction SilentlyContinue;  $tmp | export-csv -notype $logcsv -append; $tmp | export-csv -notype ('logs-csv\' + $computername + '~' + $_.basename + '.csv')}
get-childitem .\logs-csv\ | where-object {$_.length -eq 0} | remove-item

write-log "Performing log searches for common vulnerabilities"

get-logsearches $computername ($basedir + 'logsearches\') ($basedir + 'logs-csv\')
write-log 'Finished Processing Event Log Searches'
write-log "Searching for Persistence."
check-persistence

$outstring = @"
S-1-5-7	Anonymous
S-1-5-18	Local System
S-1-5-19	NT Authority
S-1-5-20	NT Authority
S-1-5-21-domain-500	Administrator
S-1-5-21-domain-512	Domain Admins
S-1-5-32-544	Local Admins
S-1-5-80	Service Accounts
"@
$outstring | add-content -enc utf8 WindowsCommonRids.txt
write-log "Finished Processing Logs"
pop-location

