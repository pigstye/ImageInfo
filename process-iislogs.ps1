<#
	.SYNOPSIS
		Process IIS logs
	.DESCRIPTION
		Process IIS Logs - convert to csv and do a little analysis on them.
	.Parameter computername
		Name of the computer host - used to name the files.
	.PARAMETER basedir
		Directory to place the logs
	.Parameter inetpub
		Inetpub directory to process
	.Parameter httperr
		Location of HTTPErr files usually c:\Windows\System32\LogFiles\
	.EXAMPLE
		> .\process-logs.ps1 "ComputerHost" 'i:\intepub' 'i:\Windows\System32\LogFiles\'
	.NOTES
	Author: Tom Willett 
	Date: 8/25/2021
	V1.0
	Date: 2/11/2022 
	V1.1 - Updated to normalize date and add computername to iis logfile - updated import-iislogs function
#>
	Param([Parameter(Mandatory=$True)][string]$Computername,
	[Parameter(Mandatory=$True)][string]$basedir,
	[Parameter(Mandatory=$True)][string]$inetpub,
	[Parameter(Mandatory=$True)][string]$httperr,
	[Parameter(Mandatory=$false)][string]$logdir)

<#
  Configuration Information
#>

. ($psscriptroot + '.\process-lib.ps1')

function import-iislogs {
<#
	.SYNOPSIS
		Process IIS logs
	.DESCRIPTION
		Process IIS Logs - convert to csv and do a little analysis on them.
	.Parameter computername
		Name of the computer host - used to name the files.
	.PARAMETER basedir
		Directory to place the logs
	.Parameter inetpub
		Inetpub directory to process
	.Parameter httperr
		Location of HTTPErr files usually c:\Windows\System32\LogFiles\
	.EXAMPLE
		> .\process-logs.ps1 "ComputerHost" 'i:\intepub' 'i:\Windows\System32\LogFiles\'
	.NOTES
	Author: Tom Willett 
	Date: 2/11/2022 
	V1.1 - Added logic to ignore multiple field lines
#>
	Param([Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$Logfile)
	trap {
		"###+++###" | out-debug
		$error[0] | out-debug
		($PSItem.InvocationInfo).positionmessage | out-debug
	}
	
	$f = get-childitem $logfile
	$tmp = ((Select-String '#Fields:' $f.fullname).line).Substring(9)
	if ($tmp.length -gt 10) {$tmp > tmp.csv} else {$tmp[0] > tmp.csv}
	(Select-String -notmatch '^#' $f.fullname).line >> tmp.csv
	import-csv tmp.csv -delim ' ' | export-csv -notype ($f.basename + '.csv')
	remove-item tmp.csv
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

if ($debug) {
	out-debug "Process-iislogs.ps1"
	out-debug "Parameters:"
	out-debug "Computername = $Computername"
	out-debug "Basedir = $basedir"
	out-debug "Inetpub = $inetpub"
	out-debug "HTTPErr = $httperr"
	out-debug "logdir = $logdir"
}

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	Write-host "Must be run with Administrator Permissions" -fore red
	exit
}

#Resize Window
$w = $Host.UI.RawUI.windowsize
$w.height = 20
$w.width = 100
$Host.UI.RawUI.windowsize = $w
$host.ui.RawUI.WindowTitle="Processing IIS Logs for $computername"

#Set Up Directories
$basedir = get-path $basedir 
$inetpub = get-path $inetpub
$httperr = get-path $httperr

Push-Location $basedir

(get-date).tostring("yyyy-MM-dd HH:mm") + ' - Processing IIS Logs' | out-debug


if (test-path ($inetpub + 'logs' )) {
	write-log "Copying IIS Logs" "yellow"
	if (test-path $logdir) {
		$iislogs = get-path $logdir
	} else {
		$iislogs = get-path 'iislogs'
	}
	copy-item -Recurse ($inetpub + 'logs\*') $iislogs
	copy-item -Recurse ($httperr + 'httperr\*') $iislogs
#######
	write-log "Processing IIS Logs" "yellow"
	if (test-path 'iislogs\LogFiles') {
		push-location iislogs\LogFiles
	} else {
		push-location iislogs
	}
	$iiscsv = get-path 'csv'
	out-debug "iiscsv = $iiscsv"
	set-location $iiscsv
	write-log "Converting to CSV"
	get-childitem ..\*.log -recurse | foreach-object{Import-IISLogs $_.fullname}
	write-log "Gathering Logs together"
	get-childitem * | foreach-object{$s = import-csv $_.fullname
				$s | export-csv -notype -append ('..\tmp.csv')
			}
	set-location ..

	$s = import-csv tmp.csv
	$s | foreach-object{$_.date = $_.date + ' ' + $_.time}
	$fields = get-content tmp.csv -head 1
	$fields = $fields -replace '"time",',''
	$fields = $fields -replace '"',''
	$s | select-object ($fields -split ',') | export-csv -notype ($computername + '~IISLogs.csv')
	remove-item temp.csv
	write-log "Analyzing IIS Logs"
	$s |foreach-object{$_.'s-ip' >> s-ip.txt;$_.'c-ip' >> c-ip.txt}
	get-content s-ip.txt | Group-Object | select-object count,name | Sort-Object count -desc > s-ip-histo.txt
	get-content c-ip.txt | Group-Object | select-object count,name | Sort-Object count -desc > c-ip-histo.txt
	pop-location
	start-sleep -s 5
}

(get-date).tostring("yyyy-MM-dd HH:mm") + ' - Finished processing IIS Logs' | out-debug
pop-location
