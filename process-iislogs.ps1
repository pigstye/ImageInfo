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
$ScriptName = [system.io.path]::GetFilenameWithoutExtension($ScriptPath)
$imagedate = [datetime]::parse((get-content ($basedir + 'ImageDate.txt'))).adddays(-30)

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
		$scriptname | out-debug
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
	$scriptname | out-debug
	$error[0] | out-debug
	($PSItem.InvocationInfo).positionmessage | out-debug
}

$drive = $inetpub[0]
if (test-path ($drive + ":\Windows\system32\inetsrv\config\applicationHost.config")) {
	[xml]$iisconfig = gc ($drive + ":\windows\system32\inetsrv\config\applicationHost.config")
	$iislogdir = $iisconfig.configuration.'system.applicationhost'.log.centralbinarylogfile.directory
	$iislogdir = $iislogdir -replace '\%SystemDrive\%',($drive + ':')
} else {
	$iislogdir = $drive + ':\inetpub\logs\logFiles\'
}

if ($debug) {
	out-debug "Process-iislogs.ps1"
	out-debug "Parameters:"
	out-debug "Computername = $Computername"
	out-debug "Basedir = $basedir"
	out-debug "Inetpub = $inetpub"
	out-debug "IISLogdir = $iislogdir"
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

if (test-path ($iislogdir)) {
	write-log "Copying IIS Logs" "yellow"
	if (test-path $logdir) {
		$iislogs = get-path $logdir
	} else {
		$iislogs = get-path 'iislogs'
	}
	get-childitem $iislogdir | %{copy-item -recurse $_.fullname $iislogs}
	mkdir ($iislogs + 'HTTPERR')
	copy-item -Recurse ($httperr + 'httperr\*') ($iislogs + 'HTTPERR')
#######
	write-log "Processing IIS Logs" "yellow"
	$il = Get-ChildItem $iislogs
	$il | foreach-object {
		trap {
			"###+++###" | out-debug
			$scriptname | out-debug
			$error[0] | out-debug
			($PSItem.InvocationInfo).positionmessage | out-debug
		}
		write-log "Converting $_ logs to CSV"
		set-location $_.fullname
		$iiscsv = get-path 'csv'
		set-location $iiscsv
		get-childitem ..\*.log -recurse | foreach-object{Import-IISLogs $_.fullname}
		set-location $iislogs
		$logscsv = dir $iiscsv
		$fields = gc $logscsv[1].fullname -head 1
		$fields = $fields -replace '"time",',''
		$outcsv = $iislogs + $_.name + '.csv'
		write-log "Gathering all the CSV for $_ into $outcsv"
		$logscsv | foreach-object {
			$tmpcsv = import-csv $_.fullname
			$tmpcsv | foreach-object{$_.date = $_.date + ' ' + $_.time}
			$tmpcsv | select-object ($fields -split ',') | export-csv -notype -append $outcsv
		}
		$sqli = @()
		Write-log "Looking at $_ for possible SQLi"
		write-debug "Looking for possible SQLI in $_ ALTER, CREATE, DELETE, DROP, EXEC(UTE), INSERT( +INTO), MERGE, SELECT, UPDATE, UNION( +ALL)"
		import-csv $outcsv | ForEach-Object{if($_.'cs-uri-stem' | Select-String '(ALTER|CREATE|DELETE|DROP|EXEC(UTE){0,1}|INSERT( +INTO){0,1}|MERGE|SELECT|UPDATE|UNION( +ALL){0,1})') { $sqli += $_.'cs-uri-stem'}}
		if ($sqli) {
			write-ioc "Looking at $_ IIS Logs for SQLi"
		}
	}
	start-sleep -s 5
}

(get-date).tostring("yyyy-MM-dd HH:mm") + ' - Finished processing IIS Logs' | out-debug
