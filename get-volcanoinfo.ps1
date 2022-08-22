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

#lab setup
$ScriptPath = $MyInvocation.MyCommand.Path
$ScriptDir = split-path -parent $ScriptPath

<#
  Configuration Information
#>
#basic configuration 
. ($psscriptroot + '.\process-lib.ps1')

get-childitem *destinations.csv | foreach-object{
	Write-Debug "Normalizing the dates for: $_.Name"
	Normalize-Date $_.name 'SourceCreated' 'SourceCreated,SourceFile,SourceModified,SourceAccessed,AppId,AppIdDescription,DestListVersion,LastUsedEntryNumber,MRU,EntryNumber,CreationTime,LastModified,Hostname,MacAddress,Path,InteractionCount,PinStatus,FileBirthDroid,FileDroid,VolumeBirthDroid,VolumeDroid,TargetCreated,TargetModified,TargetAccessed,FileSize,RelativePath,WorkingDirectory,FileAttributes,HeaderFlags,DriveType,VolumeSerialNumber,VolumeLabel,LocalPath,CommonPath,TargetIDAbsolutePath,TargetMFTEntryNumber,TargetMFTSequenceNumber,MachineID,MachineMACAddress,TrackerCreatedOn,ExtraBlocksPresent,Arguments,Notes'
}

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

function write-log {
	param([Parameter(Mandatory=$True)][string]$msg,[Parameter(Mandatory=$false)][string]$fore="white")
	$msglog = $basedir + '\ProgressLog.txt'
	$dte = get-date
	write-host $msg -fore $fore
	$dte.tostring("M-d-yyyy h:m") + ' - ' + $msg | add-content $msglog
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

$ErrorActionPreference = "SilentlyContinue"
#Trap code to write Error Messages to the debug.log and display on screen if enabled with the $debug variable
trap {
	"###+++###" | Write-Debug
	$error[0] | write-debug
	($PSItem.InvocationInfo).positionmessage | write-debug
}

#########
if (test-path $dir) {
	set-location $dir
	$workingdir = (get-location).path + '\'
	$computername = get-computername
	set-location ..
	rename-item $workingdir $computername
	set-location $computername
	$workingdir = (get-location).path + '\'
} else {
	"Invalid path $dir"
	exit
}

$basedir = $workingdir + '\files\'

write-log "Processing Volcano at $workingdir"

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

push-location files

mkdir 'userinfo' >> $null
$userinfo = (get-item 'userinfo').fullname
if (-not $userinfo.endswith('\')){$userinfo += '\'}

$host.ui.RawUI.WindowTitle="Processing Volcano output for $computername"

$logdir = $basedir + 'c\windows\system32\winevt\logs\'
$script = $scriptdir + '\process-logs.ps1'

[datetime]::parse((get-date)).tostring('yyyy-MM-dd HH:mm:ss') | set-content ($basedir + 'ImageDate.txt')
$s = (get-childitem $logdir).lastwritetime
($s | sort-object)[$s.length-1] | set-content ($basedir + 'ImageDate.txt')
$imagedate = [datetime]::parse((get-content ($basedir + 'ImageDate.txt'))).adddays(-30)

$arg = "-noprofile -command $script '$computername' '$basedir' '$logdir'"
start-process "$pshome\powershell.exe" -argumentlist $arg
Write-Debug "Executing command: powershell.exe $arg"
write-log "Starting Log Analysis"

$script = $scriptdir + '\process-registries.ps1'
$config = $basedir + 'c\windows\System32\config\'
$userdir = $basedir + 'c\users'
Write-Debug "Executing command: $script $computername $basedir $config $userdir $userinfo"
& $script $computername $basedir $config $userdir $userinfo

$windir = $basdir + 'c\windows\'
$script = $scriptdir + '\process-systeminfo.ps1'
Write-Debug "Executing command: $script $computername $basedir $windir $userdir"
& $script $computername $basedir $windir $userdir

$mftfile = $workingdir + 'files\c\$MFT'
if (test-path $mftfile) {
	write-log "Parsing MFT"
	$outfile = $computername + '-mft.csv'
	Write-Debug "Executing command: $mft -f $mftfile --csv '.' --csvf $outfile"
	& $mft -f $mftfile --csv '.' --csvf $outfile  > logfile.txt
	$mftinfo = import-csv $outfile | Where-Object {$_.LastModified0x10 -gt $imagedate}
	$poc = $mftinfo | Where-Object {$_.ParentPath -eq '.\ProgramData' -and ($_.extension -eq 'exe' -or $_.extension -eq 'dll' -or $_.extension -eq 'ocx' -or $_.extension -eq 'cmd' -or $_.extension -eq 'bat' -or $_.extension -eq 'ps1')}
	if ($poc.length -gt 0) {
			write-ioc "Check the executables in the root of c:\ProgramData"
			write-ioc '      Filename   -   Parent   -   Created0x10   -   LastModified0x10   -   LastAccess0x10'
			$poc | foreach-object{"    " + $_.Filename + ' - ' + $_.parent + ' - ' + $_.Created0x10 + ' - ' + $_.LastModified0x10 + ' - ' + $_.LastAccess0x10 | write-ioc} 
	}
	$poc = $mftinfo | Where-Object {$_.ParentPath -like '.\Users\Public*' -and ($_.extension -eq 'exe' -or $_.extension -eq 'dll' -or $_.extension -eq 'ocx' -or $_.extension -eq 'cmd' -or $_.extension -eq 'bat' -or $_.extension -eq 'ps1')}
	if ($poc.length -gt 0) {
			write-ioc "Check the executables in c:\Users\Public\"
			write-ioc '      Filename   -   Parent   -   Created0x10   -   LastModified0x10   -   LastAccess0x10'
			$poc | ForEach-Object{"    " + $_.Filename + ' - ' + $_.parent + ' - ' + $_.Created0x10 + ' - ' + $_.LastModified0x10 + ' - ' + $_.LastAccess0x10 | write-ioc } 
	}
}

$script = $scriptdir + '\process-userinfo.ps1'
Write-Debug "Executing command: $script $computername $basedir $userdir $userinfo"
& $script $computername $basedir $userdir $userinfo

$tmp = get-childitem ((get-date).year.tostring() + "*")
move-item (".\" + $tmp.Name + "\*") .
remove-item -recurse (".\" + $tmp.Name)

push-location userinfo
$tmp = get-childitem ((get-date).year.tostring() + "*")
move-item (".\" + $tmp.Name + "\*") .
remove-item -recurse (".\" + $tmp.Name)
pop-location

set-location ..\..
write-log "Finished processing $computername except for logs" -fore yellow
