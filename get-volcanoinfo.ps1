<#
	.Synopsis
		Collects Information about artifacts collected with Volcano
	.Description
		Collects information from the registry and file system and logs from 
		artifacts collected by volcano. The information is placed back in the folder
		that contains the collected artifacts. Log files are automatically processed
		and added to logs.csv. After Processing the logs they are searched for common
		vulnerabilities.
		The following data is collected in CSV files:
			Application Compatability Cache
			AmCache
			Jump Lists
			Recent File Cache
			ESE Database Dumper (srum)
			ShellBags
			MFT
			USNJrnl
	.Parameter Dir
		The directory with the volcano data
	.Notes
		Tom Willett
		8/11/2021
		V1.0
#>

Param([String][Parameter(Mandatory=$true)]$Dir)

<#
  Configuration Information
#>
#basic configuration 
$Version = '2.0'
$ScriptName = $MyInvocation.MyCommand.name
$ScriptPath = $MyInvocation.MyCommand.path
$ScriptDir = split-path -parent $ScriptPath
. ($ScriptDir + '\process-lib.ps1')

function get-computername {
	<#
	.Synopsis
		Gets computer name from api json
	.Description
		Gets computer name from api getcomputername.jsonl
	.NOTES
		Author: Tom Willett
		Date: 10/7/2021
	#>
	$computername = (get-content ($workingdir + 'api\windows\getComputerName.jsonl') | convertfrom-json).result
	write-host $computername
	$computername
}

#api conversion functions
function convertfrom-json2-csv {
	Param([Parameter(Mandatory=$True)][String]$path)
	$path
	$tmp = get-content ('.\Windows\' + $path + '.jsonl') | convertfrom-json
	$tmp | export-csv -notype ($path + '.csv')
}

function convertfrom-json1-csv {
	Param([Parameter(Mandatory=$True)][String]$path)
	$path
	$tmp = get-content ('.\Windows\' + $path + '.jsonl') | convertfrom-json
	$tmp.result | export-csv -notype ($path + '.csv')
}

function convertfrom-json0-txt {
	Param([Parameter(Mandatory=$True)][String]$path)
	$path
	(get-content ('.\Windows\' + $path + '.jsonl') | convertfrom-json).result | add-content ($path + '.txt')
}

#api functions
$api0 = 'GetLogicalDriveStrings','GetWindowsDirectory','GetSystemDirectory','GetSystemWindowsDirectory','QueryDosDevice','GetComputerName'
$api1 = 'RtlGetVersion','CreateToolhelp32Snapshot_TH32CS_SNAPPROCESS','DnsGetCacheDataTable','GetAdaptersAddresses','GetExtendedTcpTable','GetExtendedUdpTable','GetIpForwardTable','GetIpNetTable','GlobalMemoryStatusEx','MmGetPhysicalMemoryRanges','GetNetworkParams','GetTcp6Table','GetTimeZoneInformation','GetUdp6Table','GetUdpTable','GetVolumeInformation','GetTcpTable'
$api2 = 'GetDriveType','GetSystemDEPPolicy','GetTickCount64','NtQuerySystemInformation'

# And it begins
#########
$ErrorActionPreference = "SilentlyContinue"
write-log "$ScriptName - V $Version"

#Trap code to write Error Messages to the debug.log and display on screen if enabled with the $debug variable
trap {
	"###+++###" | out-debug
	$scriptname | out-debug
	$error[0] | out-debug
	($PSItem.InvocationInfo).positionmessage | out-debug
}

#########
if (test-path $dir) {
	set-location $dir
	$workingdir = get-path (get-location).path
	$computername = get-computername
	set-location ..
	rename-item $workingdir $computername
	set-location $computername
	$workingdir = get-path (get-location).path
} else {
	write-host "Invalid path $dir" -fore red
	out-debug "Invalid path $dir"
	exit
}

$ScriptName = [system.io.path]::GetFilenameWithoutExtension($ScriptPath)

$basedir = get-path ($workingdir + 'files')
$logdir = get-path ($basedir + 'c\windows\system32\winevt\logs\')
$userinfo = get-path ($basedir + 'UserInfo')

out-debug "computername = $computername"
out-debug "workingdir = $workingdir"
out-debug "basedir = $basedir"
out-debug "logdir = $logdir"

write-log "Processing Volcano at $workingdir" Green

write-log "Processing API jsons"
push-location API
foreach($api in $api0) {
	convertfrom-json0-txt $api
}
foreach($api in $api1) {
	convertfrom-json1-csv $api
}
foreach($api in $api2) {
	convertfrom-json2-csv $api
}
copy-item CreateToolhelp32Snapshot_TH32CS_SNAPPROCESS.csv ('..\files\' + $computername + '-ProcessList.csv')
copy-item GetExtendedTcpTable.csv ('..\files\' + $computername + '-networkconnections.csv')
pop-location

push-location $basedir
out-debug "$basedir is location now"

$host.ui.RawUI.WindowTitle="Processing Volcano output for $computername"

$script = $scriptdir + '\process-logs.ps1'

out-debug "Setting ImageDate"
[datetime]::parse((get-date)).tostring('yyyy-MM-dd HH:mm:ss') | set-content ($basedir + 'ImageDate.txt')
$s = (get-childitem $logdir).lastwritetime
($s | sort-object)[$s.length-1] | set-content ($basedir + 'ImageDate.txt')
$imagedate = [datetime]::parse((get-content ($basedir + 'ImageDate.txt'))).adddays(-30)

$arg = "-noprofile -command $script '$computername' '$basedir' '$logdir'"
start-process "$pshome\powershell.exe" -argumentlist $arg
out-debug "$scriptname - Executing command: powershell.exe $arg"
write-log "Starting Log Analysis"

$script = $scriptdir + '\process-registries.ps1'
$config = $basedir + 'c\windows\System32\config\'
$userdir = $basedir + 'c\users'
out-debug "$scriptname - Executing command: $script $computername $basedir $config $userdir $userinfo"
& $script $computername $basedir $config $userdir $userinfo

$windir = $basdir + 'c\windows\'
$script = $scriptdir + '\process-systeminfo.ps1'
out-debug "$scriptname - Executing command: $script $computername $basedir $windir $userdir"
& $script $computername $basedir $windir $userdir

$script = $scriptdir + '\process-userinfo.ps1'
out-debug "$scriptname - Executing command: $script $computername $basedir $userdir $userinfo"
& $script $computername $basedir $userdir $userinfo

$tmp = get-childitem ((get-date).year.tostring() + "*")
move-item (".\" + $tmp.Name + "\*") .
remove-item -recurse (".\" + $tmp.Name)

push-location userinfo
$tmp = get-childitem ((get-date).year.tostring() + "*")
move-item (".\" + $tmp.Name + "\*") .
remove-item -recurse (".\" + $tmp.Name)
pop-location

set-location $basedir

$mftfile = $basedir+ 'c\$MFT'
if (test-path $mftfile) {
	write-log "Parsing MFT"
	$outfile = $basedir + $computername + '~mft.csv'
	out-debug "$scriptname - Executing command: $mft -f $mftfile --csv '.' --csvf $outfile"
	& $mft -f $mftfile --csv '.' --csvf $outfile  | out-debug
	######### Normalizing Dates in MFT ########
	write-log "$scriptname - Normalizing dates in MFT" -fore "Green"
	Normalize-Date $outfile 'LastModified0x10,Created0x10,Created0x30,LastModified0x10,LastModified0x30,LastRecordChange0x10,LastRecordChange0x30,LastAccess0x10,LastAccess0x30' 
	######### Searching for IOCs in MFT ########
	write-log "$scriptname - Searching for IOCs in MFT" -fore "Green"
	$mftinfo = import-csv ($computername + '~mft.csv') | Where-Object {[datetime]::parse($_.LastModified0x10) -gt $imagedate}
	$poc = $mftinfo | Where-Object {$_.ParentPath -eq '.\ProgramData' -and ($_.extension -eq 'exe' -or $_.extension -eq 'dll' -or $_.extension -eq 'ocx' -or $_.extension -eq 'cmd' -or $_.extension -eq 'bat' -or $_.extension -eq 'ps1')}
	if ($poc.length -gt 0) {
			write-ioc "Check the executables in the root of c:\ProgramData"
	}
	if ($mftinfo | Where-Object {$_.ParentPath -like '.\Users\Public*' -and ($_.extension -eq 'exe' -or $_.extension -eq 'dll' -or $_.extension -eq 'ocx' -or $_.extension -eq 'cmd' -or $_.extension -eq 'bat' -or $_.extension -eq 'ps1')}) {
			write-ioc "Check the executables in c:\Users\Public\"
	}
	$mftinfo = import-csv ($computername + '~mft.csv')
	if ($mftinfo | where-object {$_.FileName -eq 'Adfind.exe'}) {
		write-ioc "Check for Adfind.exe"
	}
	if ($mftinfo | where-object {$_.FileName -like '*kerberoast*'}) {
		write-ioc "Check for invoke-kerberoast.ps1"
	}
	if ($mftinfo | where-object {$_.FileName -like '*rufus*'}) {
		write-ioc "Check for rufus.exe"
	}
	if ($mftinfo | where-object {$_.FileName -like '*netscan*'}) {
		write-ioc "Check for netscan.exe"
	}
	if ($mftinfo | where-object {$_.FileName -like '*PowerSploit*'}) {
		write-ioc "Check for PowerSploit"
	}
	if ($mftinfo | where-object {$_.FileName -like '*proxifier*'}) {
		write-ioc "Check for Proxifier"
	}
	if ($mftinfo | where-object {$_.FileName -like '*PowerUpSQL*'}) {
		write-ioc "Check for PowerUpSQL"
	}
	if ($mftinfo | where-object {$_.FileName -like '*rclone*'}) {
		write-ioc "Check for rclone"
	}
	if ($mftinfo | where-object {$_.FileName -like '*routerscan*'}) {
		write-ioc "Check for Routerscan"
	}
	if ($mftinfo | where-object {$_.FileName -like '*ShareFinder*'}) {
		write-ioc "Check for invoke-sharefinder.ps1"
	}
	if ($mftinfo | where-object {$_.FileName -like '*SMBAutoBrute*'}) {
		write-ioc "Check for SMBAutoBrute"
	}
	if ($mftinfo | where-object {$_.FileName -like '*pchunter*'}) {
		write-ioc "Check for pchunter"
	}
	if ($mftinfo | where-object {$_.FileName -like '*Powertool*'}) {
		write-ioc "Check for Powertool"
	}
	if ($mftinfo | where-object {$_.FileName -like '*net-gpppassword*'}) {
		write-ioc "Check for Net-GPPPassword.exe"
	}
}

set-location ..\..
write-log "Finished Main Processing"
write-log "Finished processing $computername except for logs" -fore yellow

function Haiku {
	$num = get-random(3,2,1)
	write-host ""
	switch ($num) {
		1 {write-host "my work is finished" -fore red
			write-host "you must unravel the mystery" -fore red
			write-host "your work begins now" -fore red}
		2 {write-host "When the wind blows hard" -fore red
			write-host "The nuts fall from the tree" -fore red
			write-host "Collect all the nuts" -fore red}
		3 {write-host "bits and bytes mixed up" -fore red
			write-host "they are now put in order"  -fore red
			write-host "find the answer here" -fore red}
	}
}
Haiku

write-host "Check _ThingsToCheck.txt for some obvious things" -fore green