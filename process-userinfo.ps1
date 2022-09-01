<#
	.SYNOPSIS
		Process miscellaneous user artifacts 
	.DESCRIPTION
		Process miscellaneous user artifacts
	.Parameter computername
		Name of the computer host - used to name the files.
	.PARAMETER basedir
		Base Directory to place information
	.Parameter userdir
		Directory which contains user registries e.g. C:\Users
	.NOTES
	Author: Tom Willett 
	Date: 8/25/2021
	V1.0
#>
Param([Parameter(Mandatory=$True)][string]$Computername,
	[Parameter(Mandatory=$True)][string]$basedir,
	[Parameter(Mandatory=$True)][string]$userdir,
	[Parameter(Mandatory=$True)][string]$userinfo)

<#
  Configuration Information
#>
$Version = '2.0'
$ScriptName = $MyInvocation.MyCommand.name
$ScriptPath = $MyInvocation.MyCommand.path
$ScriptDir = split-path -parent $ScriptPath
. ($ScriptDir + '\process-lib.ps1')

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	Write-host "Must be run with Administrator Permissions" -fore red
	exit
}

# And it begins
#########
$ErrorActionPreference = "SilentlyContinue"
write-log "$ScriptName - V $Version"
$imagedate = [datetime]::parse((get-content ($basedir + 'ImageDate.txt'))).adddays(-30)

#Trap code to write Error Messages to the debug.log and display on screen if enabled with the $debug variable
trap {
	"###+++###" | out-debug
	$scriptname | out-debug
	$error[0] | out-debug
	($PSItem.InvocationInfo).positionmessage | out-debug
}

if ($debug) {
	out-debug  "process-userinfo.ps1"
	out-debug  "Computername = $Computername"
	out-debug  "Basedir = $basedir"
	out-debug  "Userdir = $userdir"
	out-debug  "Userinfo = $userinfo"
}

$basedir = get-path $basedir


push-location $basedir

$userinfo = get-path $userinfo

write-log 'Started User Info Processing'

set-location $userinfo

write-log "Processing User Info" -fore yellow

$users = @()
(get-childitem $userdir -dir | Select-Object name) | ForEach-Object {$users += $_.name}
$username = ($users -join ', ')
$userName > UserNames.txt

write-log 'Processing Each User'

foreach ($user in $users) {
	trap {
		"###+++###" | out-debug
		$scriptname | out-debug
		$error[0] | out-debug
		($PSItem.InvocationInfo).positionmessage | out-debug
	}
	out-debug "$scriptname - User $user being processed"
	write-log "Getting $user Jump Lists"
	$jl = $userdir + $user + '\Appdata\Roaming\Microsoft\Windows\Recent'
	$fle = $computername + '~RecentFiles_' + $user + '.csv'
	out-debug "$scriptname - Executing command: $jleCmd -d $jl --all --fd --csv '.' --csvf $fle -q"
	& $jleCmd -d $jl --all --fd --csv "." --csvf $fle -q  | out-debug

	$chromeCache = $userdir + $user + '\AppData\Local\Google\Chrome\User Data\Default\Cache'
	If (test-path $chromeCache) {
		write-log "Getting $user Chrome Cache"
		$output = $computername + '~' + $user + '_ChromeCache.txt'
		out-debug "$scriptname - Executing command: $ccv /folder $chromeCache /stext $output"
		& $ccv /folder $chromeCache /stext $output
	}

	$chromeCookie = $userdir + $user + '\AppData\Local\Google\Chrome\User Data\Default\Cookies'
	If (test-path $chromeCookie) {
		write-log "Getting $user Chrome Cookies"
		$output = $computername + '~' + $user + '_ChromeCookies.csv'
		out-debug "$scriptname - Executing command: $ccov /CookiesFile $chromeCookie /scomma $output"
		& $ccov /CookiesFile $chromeCookie /scomma $output
	}

	$chromehistory = $userdir + $user + '\AppData\Local\Google\Chrome\User Data\Default\history'
	If (test-path $chromeHistory) {
		write-log "Getting $user Chrome History"
		$output = $computername + '~' + $user + '_Chromehistory.csv'
		out-debug "$scriptname - Executing command: $chv /UserHistoryFile 1 /HistoryFile $chromehistory /scomma $output"
		& $chv /UserHistoryFile 1 /HistoryFile $chromehistory /scomma $output
	}
	
	$edgeCookie = $userdir + $user + '\AppData\Local\Microsoft\Windows\WebCache\WebCacheV01.dat'
	If (test-path $edgeCookie) {
		write-log "Getting $user Edge Cookies"
		$output = $computername + '~' + $user + '_EdgeCookies.csv'
		out-debug "$scriptname - Executing command: $ecv /loadfrom 2 /DatabaseFilename $edgeCookie /scomma $output"
		& $ecv /loadfrom 2 /DatabaseFilename $edgeCookie /scomma $output
	}

	$ieCache = $userdir + $user + '\AppData\Local\Microsoft\Windows\WebCache'
	If (test-path $ieCache) {
		write-log "Getting $User IE Cache"
		$output = $computername + '~' + $user + '_IECache.txt'
		out-debug "$scriptname - Executing command: $iev -f $IECache /stext $output"
		& $iev -f $IECache /stext $output
	}

	if (test-path ($userdir + $user + '\AppData\Roaming\Mozilla\Firefox\Profiles\')) {
		write-log "Getting $user Firefox Downloads"
		$profiles = get-childitem ($userdir + $user + '\AppData\Roaming\Mozilla\Firefox\Profiles\')
		$i = 1
		foreach ($profile in $profiles) {
			$output = $computername + '~' + $user + '_firefoxDownloads' + $i + '.csv'
			out-debug "$scriptname - Executing command: $ffd /UseNewFirefoxDM 1 /profile $profile.fullname /scomma $output"
			& $ffd /UseNewFirefoxDM 1 /profile $profile.fullname /scomma $output
			$i += 1
		}
	}

	if (test-path ($userdir + $user + '\AppData\Local\ConnectedDevicesPlatform\L.' + $user + '\ActivitiesCache.db')) {
		write-log "Getting $user Win10 Activity"
		$profile1 = $userdir + $user + '\AppData\Local\ConnectedDevicesPlatform\L.' + $user + '\ActivitiesCache.db'
		$d = ".\" + $user
		out-debug "$scriptname - Executing command: $wtxcmd -f $profile1 --csv $d"
		& $wtxcmd -f $profile1 --csv $d
	}

}

####### Check for IOCs ########
write-log "$scriptname - Checking for IOCs" -fore "Green"
foreach ($user in $users) {
	trap {
		"###+++###" | out-debug
		$scriptname | out-debug
		$error[0] | out-debug
		($PSItem.InvocationInfo).positionmessage | out-debug
	}
	$PowerShellLog = '\AppData\roaming\Microsoft\Windows\PowerShell\psreadline\consolehost_history.txt'
	if (test-path ($userdir + $user + $PowerShellLog)) {
		write-ioc "Review PowerShell log for user $user"
	}

	$Startup = '\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\'
	if (Get-ChildItem ($userdir + $user + $startup)) {
		write-IOC "Check User Startup directory for $user."
	}
}
$uas = import-csv ($userinfo + $computername + '~UserActivity_UserAssist.csv') | Where-Object {[datetime]::parse($_.LastExecuted) -gt $imagedate}
if ($uas.length -gt 0) {
	write-ioc ("Check " + $computername + '~UserActivity_UserAssist.csv' + " for activity.")
}
$tsc = import-csv ($userinfo + $computername + '~UserActivity_TerminalServerClient.csv') | Where-Object {[datetime]::parse($_.LastModified) -gt $imagedate}
if ($tsc.length -gt 0){
	write-ioc ("Check " + $computername + '~UserActivity_TerminalServerClient.csv' + ' for activity.') 
}

###### Normalize Dates #######
set-location $userinfo
write-log "$scriptname - Normalizing Dates" -fore "Green"
get-childitem *_ChromeCookies.csv	| foreach-object{Normalize-Date $_.name 'Last Accessed,Created On,Expires'}
get-childitem *_Chromehistory.csv	| foreach-object{Normalize-Date $_ 'Visited On'}
get-childitem *_EdgeCookies.csv | foreach-object{Normalize-Date $_ 'Modified Time,Expire Time'}
get-childitem *_firefoxDownloads*	| foreach-object{Normalize-Date $_ 'Start Time,End Time'}
get-childitem *_activity.csv | foreach-object{Normalize-Date $_ 'LastModifiedTime'}
get-childitem *destinations.csv | foreach-object{Normalize-Date $_.name 'SourceCreated,SourceModified,SourceAccessed,CreationTime,LastModified,TargetCreated,TargetModified,TargetAccessed,TrackerCreatedOn'}


get-childitem * | where-object { $_.length -eq 0} | remove-item

write-log 'Finished User Info Processing'
set-location $basedir
