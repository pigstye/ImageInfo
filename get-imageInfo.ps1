<#
	.Synopsis
		Collects Information about a Mounted Image
	.Description
		Collects information from the registry and file system and logs 
		about a mounted disk image. The registry hives System, Software, NTUser.dat
		are collected from the image. The information is put in a zip file
		with the name of the computer. Log files are automatically processed
		and added to logs.csv. After Processing the logs they are searched for common
		vulnerabilities.
		The following data is collected in CSV files:
			Application Compatability Cache
			AmCache
			Jump Lists
			Link Files
			Prefetch
			Recent File Cache
			Browsing History
			Chrome Cache
			IE Cache
			Firefox Downloads
			Mozilla Cache
			ESE Database Dumpter (srum)
			ShellBags
	.Parameter drive
		The drive the images is mounted on
	.Notes
		Tom Willett
		4/28/21
	Refactored 8/6/2021
	Rebuilt 8/25/2021
	V1.0
#>
Param([String][Parameter(Mandatory=$true)]$drive)

<#
  Configuration Information
#>
#basic configuration 
. ($psscriptroot + '.\process-lib.ps1')


function get-regvalue {
	Param([Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$Hive,
		[Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$RegKey,
		[Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$Value)
	
	$s = & $recmd -f $Hive --kn $RegKey --vn $Value
	$t = ($s | select-string 'Value Data:').tostring()
	if ($t.indexof('(') -gt 0){
		$value = $t.substring(12,$t.indexof('(')-13)
	} else {
		$value = $t.substring(12).trim(' ')
	}
	return $value
}

function get-computername {
	<#
	.Synopsis
		Gets computer name from SYSTEM hive
	.Description
		Gets computer name from SYSTEM hive create directory with name of host and set-location there
	.Parameter drv
		Drive to check for hive
	.NOTES
		Author: Tom Willett
		Date: 8/1/2021
	#>
	Param([Parameter(Mandatory=$True)][string]$drv)
	$computername = get-regvalue ($drv + ':\Windows\System32\config\SYSTEM') '\Controlset001\control\computername\Computername\' 'ComputerName'
	$computername = $computername.trim()
	if(-not ((split-path ((get-location).tostring()) -leaf) -eq $computername)) {
		if (-not (test-path $computername)) {
			mkdir $computername  >> $null
		}
		set-location $computername
	}
	write-host $computername
	$computername
}

# And it begins
#########
$ErrorActionPreference = "SilentlyContinue"
#Trap code to write Error Messages to the debug.log and display on screen if enabled with the $debug variable
trap {
	"###+++###" | out-debug
	$error[0] | out-debug
	($PSItem.InvocationInfo).positionmessage | out-debug
}


$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	Write-host "Must be run with Administrator Permissions" -fore red
	exit
}

$drive = $drive[0]

$computername = get-computername $drive

$host.ui.RawUI.WindowTitle="Processing $computername"

#Lets set up the directory structure

$basedir = get-path (get-location).path
out-debug "Basedir = $basedir"
$windir = get-path ($drive + ':\windows')
out-debug "Windir = $windir"
$userDir = ($drive + ':\users\')
if (-not (test-path $userDir)) {
	$userDir = ($drive + ':\Documents and Settings\')
}
out-debug "Userdir = $userdir"
mkdir 'userinfo' >> $null
$userinfo = get-path 'userinfo'
out-debug "Logdir = $logdir"
$logdir = get-path 'logs'

write-log "Copying Event Logs"
$evtlogs = $windir + "system32\winevt\logs\"
if (test-path $evtlogs) {
	$evtlogs = $evtlogs + "*"
} else {
	$evtlogs = $windir + 'system32\config\*.evt'
}
copy-item $evtlogs $logdir

$s = (get-childitem $logdir).lastwritetime
($s | sort-object)[$s.length-1] | add-content ($basedir + 'ImageDate.txt')
$imagedate = [datetime]::parse((get-content ($basedir + 'ImageDate.txt'))).adddays(-30)
$script = $scriptdir + '\process-logs.ps1'
if ($debug) {
	$arg = '-noexit '
} else {
	$arg = ''
}
$arg += "-noprofile -command $script '$computername' '$basedir' '$logdir'"
out-debug $arg
start-process "$pshome\powershell.exe" -argumentlist $arg
write-log "Starting Log Analysis"

####################################
if (test-path ($drive + ':\inetpub')) {
	$script = $scriptdir + '\process-iislogs.ps1'
	$inetpub = $drive + ':\inetpub\'
	$httperr = $windir + 'System32\LogFiles\'
	$iisLogDir = get-path 'IISLogs'
	if ($debug) {
		$arg = '-noexit '
	} else {
		$arg = ''
	}
	$arg += "-noprofile -command $script '$computername' '$basedir' '$inetpub' '$httperr' '$iisLogDir'"
	out-debug $arg
	start-process "$pshome\powershell.exe" -argumentlist $arg
	write-log "Starting IIS Log Analysis"
}

$script = $scriptdir + '\process-registries.ps1'
$config = $windir + 'System32\config\'
out-debug "$script $computername $basedir $config $userdir $userinfo"
& $script $computername $basedir $config $userdir $userinfo


$script = $scriptdir + '\process-systeminfo.ps1'
out-debug "$script $computername $basedir $windir $userdir"
& $script $computername $basedir $windir $userdir

$users = @()
(get-childitem $userdir -dir | select-object name) | foreach-object {$users += $_.name}

set-location $userinfo
write-log 'Copying User Registry Files'

foreach($user in $users) {
	mkdir $user >> $null
	copy-item ($userdir + $user + "\NTUSER.DAT") $user -force
	copy-item ($userDir + $user +"\NTUSER.DAT.LOG*") $User -force
	get-childitem $User -force | foreach-object{$_.Attributes = 'Normal'}
}
set-location ..

$script = $scriptdir + '\process-userinfo.ps1'
out-debug "$script $computername $basedir $userdir $userinfo"
& $script $computername $basedir $userdir $userinfo

set-location $basedir
Write-Log 'Exporting MFT'
($basedir + $computername + '~mft.csv')
& $mft -f ($drive + ':\$MFT') --csv $basedir --csvf ($computername + '~mft.csv')
Normalize-Date ($computername + '~mft.csv') 'LastModified0x10,Created0x10,Created0x30,LastModified0x10,LastModified0x30,LastRecordChange0x10,LastRecordChange0x30,LastAccess0x10,LastAccess0x30' 

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

get-childitem * | where-object { $_.length -eq 0} | remove-item

write-host "Compressing files to create zip for easy import into Splunk"
compress-archive -Path ($computername + '*.csv') -DestinationPath ('..\' + $computername + '-splunk_in.zip')
compress-archive -Path ('.\UserInfo\' + $computername + '*.csv') -DestinationPath ('..\' + $computername + '-splunk_in.zip') -Update
compress-archive -Path ('.\Sumdatabase\' + $computername + '*.csv') -DestinationPath ('..\' + $computername + '-splunk_in.zip') -Update
compress-archive -Path ('.\Sumdatabase\Current\' + $computername + '*.csv') -DestinationPath ('..\' + $computername + '-splunk_in.zip') -Update
compress-archive -Path ('.\SRUM\' + $computername + '*.csv') -DestinationPath ('..\' + $computername + '-splunk_in.zip') -Update
compress-archive -Path ('.\Shellbags\' + $computername + '*.csv') -DestinationPath ('..\' + $computername + '-splunk_in.zip') -Update
compress-archive -Path ('.\UserInfo\' + $computername + '*.csv') -DestinationPath ('..\' + $computername + '-splunk_in.zip') -Update

set-location ..

write-log "Finished Main Processing"
write-host "When the logs are finished, processing will be complete for $computername" -fore yellow
Write-host "You can dismount the image and start looking at the other things now." -fore green

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