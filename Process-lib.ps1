<#
	.Synopsis
		Library of configuration data and common functions for the Volcano Scripts
	.Description
		Library of configuration data and common functions for the Volcano Scripts
	.Notes
		Tom Willett
		2/12/2022
		V1.0
#>
#basic configuration 
$Version = '2.0'

#These configuration lines list the location the script will look for the auxiliarly programs - these can be changed
#to reflect a custom configuration. The only caveat is the Eric Zimmeramn registry batch files *.reb are custom versions 
#and expected to be at $recmddir. You can move them or leave that configuration alone.
$FFd = $scriptdir + '\Nirsoft\FireFoxDownloadsview.exe'
$RBCmd = $scriptdir + '\ericzimmerman\RBcmd.exe'
$appCacheCmd = $scriptdir + "\EricZimmerman\AmcacheParser.exe"
$appCompCmd = $scriptdir + "\EricZimmerman\AppCompatCacheParser.exe"
$appcrash = $scriptdir + '\Nirsoft\appcrashview.exe'
$bhv = $scriptdir + '\Nirsoft\browsinghistoryview.exe'
$ccov = $scriptdir + '\Nirsoft\ChromeCookiesview.exe'
$ccv = $scriptdir + '\Nirsoft\ChromeCacheview.exe'
$chv = $scriptdir + '\Nirsoft\ChromeHistoryview.exe'
$ecv = $scriptdir + '\Nirsoft\EdgeCookiesview.exe'
$iev = $scriptdir + '\Nirsoft\IECacheview.exe'
$jleCmd = $scriptdir + '\ericzimmerman\jlecmd.exe'
$leCmd = $scriptdir + '\ericzimmerman\lecmd.exe'
$mcv = $scriptdir + '\Nirsoft\MozillaCacheview.exe'
$mft = $scriptdir + '\ericzimmerman\mftecmd.exe'
$peCmd = $scriptdir + '\ericzimmerman\pecmd.exe'
$rfc = $scriptdir + '\EricZimmerman\recentfilecacheparser.exe'
$sb = $scriptdir + '\ericzimmerman\ShellBagsExplorer\SBECmd.exe'
$srum = $scriptdir + '\ese2csv\ese2csv.exe'
$wmi = $scriptdir + '\WMI_Forensics\CCM_RUA_Finder.exe'
$wmi2 = $scriptdir + '\WMI_Forensics\PyWMIPersistenceFinder.exe'
$wtxcmd = $scriptdir + '\ericzimmerman\WxTCmd.exe'
$recmd = $scriptdir + "\EricZimmerman\registryexplorer\recmd.exe" 
$recmddir = $scriptdir + "\EricZimmerman\registryexplorer\"
$bits = $scriptdir + '\BitsParser\BitsParser.exe'
$nese = $ScriptDir + '\Nirsoft\esedatabaseview.exe'

##----------------
$debug = $false
##----------------

function out-debug {
	Param([Parameter(Mandatory=$false,ValueFromPipeline=$true)][string]$msg='nil')
	if ($debug -and $msg -ne 'nil') {
			$dte = Get-Date
			write-host -ForegroundColor Yellow $msg
			$dte.tostring("M-d-yyyy h:mm") + ' - ' + $msg | add-content ($basedir + 'debuglog.txt')
	}
}

function update-systemstatuslog {
	<#
		.Synopsis
			Update System Status Log
		.Description
			Updates the SystemStatus.log with status messages
		.Parameter msg
			Message to add
		.Notes
			Tom Willett
			10/8/2021
	#>
	param([Parameter][string]$msg="Nothing")
	$DateTime = (get-date).tostring("M-d-yyyy h:mm")
	$statusLog = $localpath + 'SystemStatusLog.txt'
	$DateTime + ' - ' + $msg | add-content $statusLog
	out-debug ("Status: " + $msg)
}

function write-log {
	param([Parameter(Mandatory=$false)][string]$msg='nil',[Parameter(Mandatory=$false)][string]$fore="white")
	if ($msg -ne 'nil' -and $msg -ne "") {
		$msglog = $basedir + '\ProgressLog.txt'
		$dte = get-date
		write-host $msg -fore $fore
		$dte.tostring("M-d-yyyy h:mm") + ' - ' + $msg | add-content $msglog
		out-debug ($dte.tostring("M-d-yyyy h:mm") + ' - ' + $msg)
	}
}

function write-Hostlog {
	<#
		.Synopsis
			Update Host log
		.Description
			Updates the HostLog.csv when specific processing steps have been accomplished
		.Parameter msg
			Message to add
		.Notes
			Tom Willett
			9/18/2021
	#>
	param([Parameter(Mandatory=$True)][string]$msg)
	$msglog = $lava_dir + $engagement + '\HostLog.csv'
	if (-not (test-path $msglog)) {
		"time,host,status" | add-content $msglog
	}
	$dte = get-date
	$dte.tostring("M-d-yyyy HH:mm") + ',' + $msg | add-content $msglog
	out-debug  $msg
}

function add-slash {
	Param([Parameter(Mandatory=$True)][string]$path)
	if (-not $path.endswith('\')){$path += '\'}
	return $path
}

function get-path {
	Param([Parameter(Mandatory=$True)][string]$path)
	if (-not (test-path $path)) {
		mkdir $path >> $null
	}
	$tmp = add-slash (get-item $path).fullname
	if ($debug) {
		write-host ("Path: " + $tmp)
	}
	return $tmp
}

function write-ioc {
<#
.Synopsis
	Records information from all modules that might be evidence of compromise
.Description
	Records information from all modules that might be evidence of compromise and saves them in a file in the basedir called _ThingsToCheck.txt
.Parameter msg
	Notification to save 
.NOTES
	Author: Tom Willett
	Date: 8/10/2022
#>
	Param([Parameter(Mandatory=$true,ValueFromPipeline=$true)][string]$msg)
	add-content -path ($basedir + '_ThingsToCheck.txt') -value $msg
}

function Normalize-Date {
<#
.Synopsis
	Reads a csv and outputs a modified csv with date first field and in normal format
.Description
	Reads a csv and outputs a modified csv with date first field and in normal format
	This was added to make it easier to import all the data into Splunk
.Parameter csvfile
	csv file to modify
.Parameter datefield
	field containing the date
.Parameter fields
	lits of fields in file comma seperated
.NOTES
	Author: Tom Willett
	Date: 2/11/2022
#>
Param([Parameter(Mandatory=$True)][string]$csvfile,
	[Parameter(Mandatory=$false)][string]$dateFields)

	if (test-path $csvfile) {
		$n = 1
		$s = import-csv $csvfile
		$s | add-member -NotePropertyName EntryID -NotePropertyValue 0
		$s | ForEach-Object{$_.entryid=$n;$n+=1}
		if ($datefields.length -gt 0) {
			$s | ForEach-object{
				foreach($datefield in ($dateFields -split ',')) {
					if ($_.datefield -as [datetime]) {
					$_.$dateField = [datetime]::parse($_.$dateField).tostring('yyyy-MM-dd HH:mm:ss.fffffff')
					}
				}
			}
		}
		$flds = get-content $csvfile -head 1
		$flds = $flds -replace '"',''
		if ($datefields.length -gt 0) {
			if ($datefields.indexof(',') -gt 0) {
				$df = ($datefields -split ',')[0]
			} else {
				$df = $datefields
			}
			$df += ','
			$flds = $flds -replace $df,''
			$fields = $df + 'EntryID,' + $flds
		} else {
			$fields = 'EntryID,' + $flds
		}
		$s | select-object ($fields -split ',') | export-csv -notype $csvfile
	}
}

Function Test-FileLocked {
    [cmdletbinding()]
    Param (
        [parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelineByPropertyName=$True)]
        [Alias('FullName','PSPath')]
        [string[]]$Path
    )
    Process {
        ForEach ($Item in $Path) {
            #Ensure this is a full path
            $Item = Convert-Path $Item
            #Verify that this is a file and not a directory
            If ([System.IO.File]::Exists($Item)) {
                Try {
                    $FileStream = [System.IO.File]::Open($Item,'Open','Write')
                    $FileStream.Close()
                    $FileStream.Dispose()
                    $IsLocked = $False
                } Catch [System.UnauthorizedAccessException] {
                    $IsLocked = 'AccessDenied'
                } Catch {
                    $IsLocked = $True
                }
                    $IsLocked
            }
        }
    }
}

