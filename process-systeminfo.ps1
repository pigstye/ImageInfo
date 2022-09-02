<#
	.SYNOPSIS
		Process miscellaneous system artifacts 
	.DESCRIPTION
		Process miscellaneous system artifacts, Application Compatability Cache, 
	.Parameter computername
		Name of the computer host - used to name the files.
	.PARAMETER basedir
		Directory to place the logs
	.Parameter windir
		Windows Directory
	.Parameter userdir
		Directory which contains user registries
	.NOTES
	Author: Tom Willett 
	Date: 8/25/2021
	V1.0
#>
Param([Parameter(Mandatory=$True)][string]$Computername,
	[Parameter(Mandatory=$True)][string]$basedir,
	[Parameter(Mandatory=$True)][string]$windir,
	[Parameter(Mandatory=$True)][string]$userdir)

<#
  Configuration Information
#>
$Version = '2.0'
$ScriptName = $MyInvocation.MyCommand.name
$ScriptPath = $MyInvocation.MyCommand.path
$ScriptDir = split-path -parent $ScriptPath
. ($ScriptDir + '\process-lib.ps1')

function Get-DOLog {
<#
	.Synopsis
		Processes the Delivery Optimization Logs
	.Description
		Processes the Delivery Optimization Logs on Windows 10
		The logs are at one of the following depending on version.
		C:\Windows\Logs\dosvc
		C:\Windows\ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs
	.Parameter Logname
		The name and path of the log file
	.Example
		$logs | get-DOLog | export-csv -notype DOLogs.csv Where $logs contains a listing of the logs
	.NOTES
		Author: Tom Willett
		Date: 5/27/2021
	.Outputs
		an object containing the data
	.Inputs
		A logname
#>
Param([Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$logname)
	begin {
		$DeliveryOptimizationLog = @()
		$ErrorActionPreference = "SilentlyContinue"
	}
	process {
		tracerpt $logname -o tmp.xml -of xml -lr -y | out-debug
		[xml]$do = get-content .\tmp.xml
		$DeliveryOptimizationLog = @()
		foreach ($evt in $do.Events.Event) {
			$temp = [pscustomobject]@{
				TimeCreated = ""
				ProcessId = ""
				ThreadId = ""
				Level = ""
				LevelName = ""
				Message = ""
				Function = ""
				LineNumber = ""
				ErrorCode = ""
			}
			$temp.TimeCreated = $evt.system.timecreated.systemtime
			$temp.ProcessId   = $evt.system.execution.processid
			$temp.ThreadId    = $evt.system.execution.threadid
			$temp.Level       = $evt.system.level
			$temp.Message     = $evt.eventdata.data."#text"[0]
			$temp.Function    = $evt.eventdata.data."#text"[1]
			$temp.LineNumber  = $evt.eventdata.data."#text"[2]
			$temp.ErrorCode   = $evt.eventdata.data."#text"[3]
			if ($temp.level -eq '4') {
				$temp.LevelName = "Info"
			} elseif ($temp.level -eq '3') {
				$temp.LevelName = "Warning"
			} else {
				$temp.LevelName = "Error"
			}
			$DeliveryOptimizationLog += $temp
		}
	}
	end {
		remove-item tmp.xml
		$DeliveryOptimizationLog
	}
}

function get-task {
	<#
	.Synopsis
		Converts XML Tasks from Windows to PSObject
	.Description
		Given a filename it parses the XML task and converts it to a PSObject Suitable for placing in CSV
	.Parameter FileName
		Full path to the xml task
	.NOTES
		Author: Tom Willett
		Date: 7/1/2021
	#>

	Param([Parameter(Mandatory=$True,ValueFromPipeline=$True,ValueFromPipelinebyPropertyName=$True)][string]$filename)


	function get-properties {
		<#
			.Synopsis
				Converts the Properties from an XML Task to PSObject
			.Description
				Given a property name it parses the XML task and converts it to a PSObject Suitable for placing in CSV
			.Parameter PropName
				Property Name
			.NOTES
				Author: Tom Willett
				Date: 7/1/2021
		#>
		Param([Parameter(Mandatory=$True)][string]$propname)

		trap {
			"###+++###" | out-debug
			$scriptname | out-debug
			$error[0] | out-debug
			($PSItem.InvocationInfo).positionmessage | out-debug
		}
		
		$node = $task.task.$propname
		$properties = ($node | get-member -MemberType property).name
		$info = ""
		foreach($prop in $properties) {
			if ($node.$prop.gettype().name -eq "String") {
				if ($info -ne "") { $info += "`r`n" }
				$info += $prop + " : " + $node.$prop
			} else {
				$properties1 = ($node.$prop | get-member -MemberType property).name
				foreach($prop1 in $properties1) {
					if ($node.$prop.$prop1.gettype().name -eq "String") {
						if ($info -ne "") { $info += "`r`n" }
						$info += $prop + '-' + $prop1 + " : " + $node.$prop.$prop1
					} else {
						$properties2 = ($node.$prop.$prop1 | get-member -MemberType property).name
						foreach($prop2 in $properties2) {
							if ($info -ne "") { $info += "`r`n" }
							$info += $prop + '-' + $prop1 + "-" + $prop2 + " : " + $node.$prop.$prop1.$prop2
						}
					}
				}
			}
		}
		$info
	}

	$fl = get-childitem $filename

	[xml]$task = get-content $fl.fullname
	$tmp = "" | select-object CreationDate,ModifiedDate,FileName,RegistrationInfo,Triggers,Settings,Actions,Principals
	$tmp.CreationDate = $fl.creationtime
	$tmp.ModifiedDate = $fl.lastwritetime
	$tmp.FileName = $fl.fullname
	$tmp.registrationinfo = get-properties('RegistrationInfo')
	$tmp.triggers = get-properties('Triggers')
	$tmp.settings = get-properties('Settings')
	$tmp.actions = get-properties('Actions')
	$tmp.Principals = get-properties('Principals')
	$tmp
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
	out-debug  "Process-SystemInfo.ps1"
	out-debug  "Parameters:"
	out-debug  "Computername = $Computername"
	out-debug  "Basedir = $basedir"
	out-debug  "Windir = $windir"
	out-debug  "Userdir = $userdir"
}

$basedir = get-path $basedir
$windir = get-path $windir
$drive = (get-item $windir).parent.name[0]

push-location $basedir

write-log 'Getting Systeminfo'

write-log "Getting Application Compatability Cache (ShimCache)"
$outfile = $computername + '~AppCompatCache.csv'
out-debug "$scriptname - Executing command: $appCompCmd -f $windir'System32\config\SYSTEM' --csv . --csvf $outfile"
& $appCompCmd -f ($windir + 'System32\config\SYSTEM') --csv . --csvf $outfile | out-debug

write-log "Getting AmCache"
$outfile = $computername + '~AmCache.csv'
out-debug "$scriptname - Executing command: $appCacheCmd -f $windir'appcompat\programs\Amcache.hve' --csv . --csvf $outfile"
& $appCacheCmd -f ($windir + 'appcompat\programs\Amcache.hve') --csv . --csvf $outfile | out-debug

write-log "Getting Recent File Cache"
$recentFC = $windir + 'AppCompat\Programs\RecentFileCache.bcf'
$outfile = $computername + '~RecentFileCache.csv'
out-debug "$scriptname - Executing command: $rfc -f $recentFC --csv . --csvf $outfile"
& $rfc -f $recentFC --csv "." --csvf $outfile | out-debug

write-log "Getting Recycle Bin"
$RB = $drive + ':\$Recycle.Bin'
$outfile = $computername + '~RecycleBin.csv'
out-debug "$scriptname - Executing command: $RBCMD -d $RB --csv . --csvf $outfile"
& $RBCMD -d $RB --csv "." --csvf $outfile | out-debug

write-log "Getting Browser History"
$outfile = $computername + '~browserhistory.csv'
out-debug "$scriptname - Executing command: $bhv e /scomma $outfile /HistorySource 3 /HistorySourceFolder ($userDir)"
& $bhv e /scomma $outfile /HistorySource 3 /HistorySourceFolder ($userDir)  | out-debug

write-log "Getting Application Crash Info"
$outfile = $computername + '~AppCrash.txt'
out-debug "$scriptname - Executing command: $appcrash /profilesfolder $userdir /stext $outfile"
& $appcrash /profilesfolder $userdir /stext $outfile

write-log 'Getting Scheduled Tasks'
$outfile = $computername + '~ScheduledTasks.csv'
$taskdir = $windir + 'system32\tasks'
get-childitem $taskdir -recurse -file | foreach-object{get-task $_.fullname | export-csv -notype -append $outfile}


write-log 'Getting Prefetch'
$outfile = $computername + '~Prefetch.csv'
out-debug "$scriptname - Executing command: $pecmd -d $windir'prefetch' --csv . --csvf $outfile"
& $pecmd -d ($windir + 'prefetch') --csv '.' --csvf $outfile | out-debug

if (test-path ($windir + 'system32\sru\srudb.dat')) {
	write-log 'Getting SRUM data'
	out-debug "$scriptname - Getting SRUM data"
	mkdir Srum  >> $null
	set-location srum
	$sdb = ($windir + 'system32\sru\srudb.dat')
	#Download tables
	out-debug "$scriptname - Getting Tables"
	out-debug "$scriptname - Getting Map Table"
	& $nese /table $sdb 'SruDbIDMapTable' /SaveDirect /scomma ($computername + '-SruDbIDMapTable.csv') | out-debug
	start-sleep -seconds 3
	out-debug "$scriptname - Getting Network Usage Table"
	& $nese /table $sdb '{973F5D5C-1D90-4944-BE8E-24B94231A174}' /SaveDirect /scomma ($computername + '-NetworkUsage.csv') | out-debug
	start-sleep -seconds 3
	out-debug "$scriptname - Getting Push Notification Table"
	& $nese /table $sdb '{D10CA2FE-6FCF-4F6D-848E-B2E99266FA86}' /SaveDirect /scomma ($computername + '-PushNotification.csv') | out-debug
	start-sleep -seconds 3
	out-debug "$scriptname - Getting Network Connections Table"
	& $nese /table $sdb '{DD6636C4-8929-4683-974E-22C046A43763}' /SaveDirect /scomma ($computername + '-NetworkConnection.csv') | out-debug
	start-sleep -seconds 3
	out-debug "$scriptname - Getting TimeLine Provider Table"
	& $nese /table $sdb '{5C8CF1C7-7257-4F13-B223-970EF5939312}' /SaveDirect /scomma ($computername + '-TimelineProvider.csv') | out-debug
	start-sleep -seconds 3
	out-debug "$scriptname - Getting App Resource Info Table"
	& $nese /table $sdb '{D10CA2FE-6FCF-4F6D-848E-B2E99266FA89}' /SaveDirect /scomma ($computername + '-AppResourceInfo.csv') | out-debug
	start-sleep -seconds 3
	out-debug "$scriptname - Getting Energy Usage Long Term Table"
	& $nese /table $sdb '{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}LT' /SaveDirect /scomma ($computername + '-EnergyUsage-LongTerm.csv') | out-debug
	start-sleep -seconds 3
	out-debug "$scriptname - Getting Energy Usage Table"
	& $nese /table $sdb '{FEE4E14F-02A9-4550-B5CE-5FA2DA202E37}' /SaveDirect /scomma ($computername + '-EnergyUsage.csv') | out-debug
	start-sleep -seconds 3
	out-debug "$scriptname - Getting Vfprov Table"
	& $nese /table $sdb '{7ACBBAA3-D029-4BE4-9A7A-0885927F1D8F}' /SaveDirect /scomma ($computername + '-Vfuprov.csv') | out-debug
	start-sleep -seconds 3

	out-debug "$scriptname - Processing Map Table"
	#Start processing with Map Table
	$tmpdb = import-csv ($computername + '-SruDbIDMapTable.csv')
	$tmpdb | foreach-object {
		if ($_.idType -eq 3){
			# Convert userSID
			[byte[]]$t = $_.idblob -split ' ' | ForEach-Object{[byte]([convert]::toint16($_,16))}
			$_.idblob = (New-Object System.Security.Principal.SecurityIdentifier($t,0)).Value
		} else {
			# Convert UTF-16 Blob
			$s = $_.idblob
			$_.idblob = (($s -split ' ') | ForEach-Object{[char][byte]([convert]::toint16($_,16))}) -join ''
		}
	}
	$tmpdb | export-csv -notype ($computername + '-SruDbIDMapTable.csv')
	#Create Hash Table for easy access
	out-debug "$scriptname - Creating Hastable from SRUM map table"
	$srudb = $tmpdb | group-object -ashashtable -asstring -property idIndex

	$tables = @('-NetworkUsage.csv','-PushNotification.csv','-NetworkConnection.csv','-TimelineProvider.csv','-AppResourceInfo.csv','-EnergyUsage-LongTerm.csv','-EnergyUsage.csv','-Vfuprov.csv')
	foreach($tbl in $tables){
		$tmp = import-csv ($computername + $tbl)
		out-debug "$scriptname - Processing $computername$tbl"
		$tmp | ForEach-Object{
			$id = $_.Userid 
			if (($srudb.$id).idblob) {
				$_.userid = ($srudb.$id).idblob
			}
			$id = $_.AppID 
			if (($srudb.$id).idblob) {
				$_.AppID = ($srudb.$id).idblob
			}
		}
		$tmp | export-csv -notype ($computername + $tbl)
	}
	
	set-location ..
} else {
	write-log "Did not find SRUM data"
}

$polfile = $scriptdir + '\parse-polfile.ps1'
. $polfile
write-log "Local Group Policy saved to $computername~LocalGroupPolicy.txt"
out-debug ("$scriptname - Local Group Policy saved to " + $computername + "~LocalGroupPolicy.txt")
get-childitem ($windir + 'system32\grouppolicy\*.pol') -recurse | foreach-object{parse-polfile $_ | out-file ($computername + '~LocalGroupPolicy.txt') -append}
get-childitem ($windir + 'system32\grouppolicy\*.xml') -recurse | foreach-object{get-content $_ | out-file ($computername + '~LocalGroupPolicy.txt') -append}

write-log 'Getting WMI data'
out-debug "$scriptname - Executing command: $wmi -i $windir  system32\wbem\repository\objects.data -o $computername ~wmi.csv)"
& $wmi -i ($windir + 'system32\wbem\repository\objects.data') -o ($computername + '~wmi.csv') | out-debug 2> $null
out-debug "$scriptname - Executing command: $wmi2 $windir system32\wbem\repository\objects.data > $computername ~wmi.txt"
& $wmi2 ($windir + 'system32\wbem\repository\objects.data') > ($computername + '~wmi.txt')
if (test-path ($windir + 'system32\wbem\repository\fs\objects.data')) {
	out-debug "$scriptname - Executing command: $wmi -i $windir'system32\wbem\repository\objects.data' -o $computername'~wmi-fs.csv'"
	& $wmi -i ($windir + 'system32\wbem\repository\objects.data') -o ($computername + '~wmi-fs.csv') | out-debug 2> $null
	out-debug "$scriptname - Executing command: $wmi2 $windir'system32\wbem\repository\objects.data' >> $computername'~wmi.txt'"
	& $wmi2 ($windir + 'system32\wbem\repository\objects.data') >> ($computername + '~wmi.txt')
}
#Convert tab delimited to comma delimited
import-csv ($computername + '~wmi.csv') -delim "`t" | export-csv -notype tmp.csv
remove-item ($computername + '~wmi.csv')
move-item tmp.csv ($computername + '~wmi.csv')

If (Test-path ($drive + '\ProgramData\Microsoft\Network\Downloader\')) {
	write-log 'Getting BITS data'
	out-debug "$scriptname - Executing command: $bits -i $drive'\ProgramData\Microsoft\Network\Downloader\' --carveall > $computername'~bits.json'"
	& $bits -i ($drive + '\ProgramData\Microsoft\Network\Downloader\') --carveall > ($computername + '~bits.json')
}

If (Test-path ($windir + 'System32\LogFiles\Sum\')) {
	write-log 'Processing Sum databases'
	out-debug "$scriptname - Processing Sum databases"
	mkdir SumDatabase >> $null
	set-location SumDatabase
	copy-item ($windir + 'System32\LogFiles\Sum\*.mdb') .
	out-debug "$scriptname - Processing SystemIdentity.mdb"
	& $nese /table SystemIdentity.mdb 'chained_databases' /SaveDirect /scomma ($computername + '-ChainedDatabases.csv') | out-debug 
	& $nese /table SystemIdentity.mdb 'role_ids' /SaveDirect /scomma ($computername + '-RoleIDS.csv') | out-debug 
	mkdir Current >> $null
	move-item current.mdb Current
	set-location Current
	out-debug "$scriptname - Processing current.mdb"
	& $nese /table current.mdb 'Clients' /SaveDirect /scomma ($computername + '-Clients.csv') | out-debug 
	& $nese /table Current.mdb 'DNS' /SaveDirect /scomma ($computername + '-DNS.csv') | out-debug 
	& $nese /table Current.mdb 'VIRTUALMACHINES' /SaveDirect /scomma ($computername + '-VIRTUALMACHINES.csv')| out-debug 
	set-location ..
	$l = import-csv ($computername + '-CHAINEDDATABASES.csv')
	out-debug "$scriptname - Processing Chained Databases"
	foreach($r in $l) {mkdir $r.year  >> $null;move-item $r.filename $r.year}
	foreach($r in $l) {
		set-location $r.year
		& $nese /table $r.Filename 'Clients' /SaveDirect /scomma ($computername + '-Clients.csv') | out-debug 
		& $nese /table $r.Filename 'DNS' /SaveDirect /scomma ($computername + '-DNS.csv') | out-debug 
		& $nese /table $r.Filename 'VIRTUALMACHINES' /SaveDirect /scomma ($computername + '-VIRTUALMACHINES.csv') | out-debug 
		set-location ..
	}
	set-location ..
} else {
	write-log 'Did not find SUM database'
}

$DOlogPath = ''
if (Test-Path ($windir + 'Logs\dosvc')) {$DOlogPath = $windir + 'Logs\dosvc'}
if (Test-Path ($windir + 'ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs')) {
	$DOlogPath = $windir + 'ServiceProfiles\NetworkService\AppData\Local\Microsoft\Windows\DeliveryOptimization\Logs'
}
if ($DOlogPath -ne '') {
	write-log "Getting Delivery Optimization Logs"
	out-debug "$scriptname - Getting Delivery Optimization Logs"
	$outfile = $computername + '~DeliveryOptimization.csv'
	$DOLogs = get-childitem ($DOlogPath + '\*.etl')
	$DOLogs | Get-DOLog | export-csv -notype $outfile
	$DOLog = select-string '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}' -allmatches $outfile | foreach-object{$_.matches} | foreach-object{$_.value}
	$DOLog | group-object | select-object count,name | sort-object count -desc > ($computername + '~DeliveryOptimization-IP-Histo.txt')
} else {
	write-log 'Did not find Delivery Optimization Logs'
}

if ((get-item $windir).parent.name -ne 'C') {
	write-log 'Getting Lnk Files'
	out-debug "$scriptname - Getting LNK files"
	$outfile = $computername + '~LnkFiles.csv'
	out-debug "$scriptname - Executing: $leCmd -d ($drive + ':\') --csv "." --csvf $outfile"
	& $leCmd -d ($drive + ':\') --csv "." --csvf $outfile | out-debug
}

if (test-path ($windir + 'system32\dhcp')) {
	<#

	.SYNOPSIS

	Gets dhcp logs from a dhcp server.

	.DESCRIPTION

	Gets dhcp logs from a Microsoft dhcp server.  Assumes that the logs are at c:\windows\system32\dhcp
	Returns a Powershell Object

	Event ID  Meaning
	00        The log was started.
	01        The log was stopped.
	02        The log was temporarily paused due to low disk space.
	10        A new IP address was leased to a client.
	11        A lease was renewed by a client.
	12        A lease was released by a client.
	13        An IP address was found to be in use on the network.
	14        A lease request could not be satisfied because the scope's
			  address pool was exhausted.
	15        A lease was denied.
	16        A lease was deleted.
	17        A lease was expired.
	20        A BOOTP address was leased to a client.
	21        A dynamic BOOTP address was leased to a client.
	22        A BOOTP request could not be satisfied because the scope's
			  address pool for BOOTP was exhausted.
	23        A BOOTP IP address was deleted after checking to see it was
			  not in use.
	24        IP address cleanup operation has began.
	25        IP address cleanup statistics.
	30        DNS update request to the named DNS server
	31        DNS update failed
	32        DNS update successful
	50+       Codes above 50 are used for Rogue Server Detection information.

	.NOTES
	Author: Tom Willett 
	Date: 10/8/2014
	#>

	out-debug "$scriptname - Getting DHCP Logs from $windir system32\dhcp\dhcpsrvlog*.log"
	write-log "Getting DHCP Logs"
	$logs = get-childitem ($windir + 'system32\dhcp\dhcpsrvlog*.log')
	$out = @()
	if ($logs) {
		foreach ($dhcplog in $logs) {
			$ln = 1
			$log = get-content $dhcplog.fullname
			foreach($line in $log) { if ($line.startswith("ID,Date,Time")) { break } else { $ln = $ln + 1 }}
			for($i=$ln; $i -lt $log.length; $i++) {
				$temp = "" | select-object TimeStamp,Date,Time,ID,Description,IP,HostName,MAC
				$fields = $log[$i].split(',')
				$temp.TimeStamp = ""
				$temp.Date = $fields[1]
				$temp.Time = $fields[2]
				$temp.ID = $fields[0].tostring()
				$temp.Description = $fields[3]
				$temp.IP = $fields[4]
				$temp.HostName = $fields[5]
				$temp.MAC = $fields[6]
				$out += $temp
			}
		}
	}
	$out | foreach-object{$_.TimeStamp = [datetime]::parse($_.date + ' ' + $_.time).tostring('yyyy-MM-dd HH:mm:ss')} -ErrorAction SilentlyContinue
	$out | select-object TimeStamp,ID,Description,IP,Hostname,MAC | export-csv -notype ($computername + '~dhcpLogs.csv')
} else {
	write-log 'DHCP Logs not Found'
}

if (test-path ($windir + 'system32\dns')) {
	<#

	.SYNOPSIS

	Gets dns debug logs from a dns server.

	.DESCRIPTION

	Gets dns logs from a Microsoft dns server.  Assumes that the logs are at c:\windows\system32\dns\dns.log
	Returns a Powershell Object

	Message logging key (for packets - other items use a subset of these fields):
		Field #  Information         Values
		-------  -----------         ------
		   1     Date
		   2     Time
		   3     Thread ID
		   4     Context
		   5     Internal packet identifier
		   6     UDP/TCP indicator
		   7     Send/Receive indicator
		   8     Remote IP
		   9     Xid (hex)
		  10     Query/Response      R = Response
									 blank = Query
		  11     Opcode              Q = Standard Query
									 N = Notify
									 U = Update
									 ? = Unknown
		  12     [ Flags (hex)
		  13     Flags (char codes)  A = Authoritative Answer
									 T = Truncated Response
									 D = Recursion Desired
									 R = Recursion Available
		  14     ResponseCode ]
		  15     Question Type
		  16     Question Name

	.NOTES
	Author: Tom Willett 
	Date: 10/8/2014
	#>
	write-log "Getting DNS Logs"
	out-debug "$scriptname - Getting DNS Logs from $windir system32\dns\dns.log"
	$out = @()
	$log = get-content ($windir + 'system32\dns\dns.log')
	if ($log) {
		foreach($line in $log) {
			if ( $line -match "^\d\d" -AND $line -notlike "*EVENT*") {
				$temp = "" | select-object TimeStamp,Date,Time,Protocol,Client,SendReceive,QueryType,RecordType,Query,Result
				$fields = $line.split(' ')
				$temp.Date = $fields[0]
				$TheReverseRegExString="\(\d\)in-addr\(\d\)arpa\(\d\)"
			   if ($_ -match $TheReverseRegExString) {
					$temp.QueryType="Reverse"
				}
				else {
					$temp.QueryType="Forward"
				}
				# Check log time format and set properties
				if ($line -match ":\d\d AM|:\d\d  PM") {
					$temp.Time=$fields[1,2] -join " "
					$temp.Protocol=$fields[7]
					$temp.Client=$fields[9]
					$temp.SendReceive=$fields[8]
					$temp.RecordType=(($line -split "]")[1] -split " ")[1]
					$temp.Query=($line.ToString().Substring(99)) -replace "\s" -replace "\(\d?\d\)","." -replace "^\." -replace "\.$"
					$temp.Result=(((($line -split "\[")[1]).ToString().Substring(9)) -split "]")[0] -replace " "
				}
				elseif ($line -match "^\d\d\d\d\d\d\d\d \d\d:") {
					$temp.Date=$temp.Date.Substring(0,4) + "-" + $temp.Date.Substring(4,2) + "-" + $temp.Date.Substring(6,2)
					$temp.Time=$fields[1]
					$temp.Protocol=$fields[6]
					$temp.Client=$fields[8]
					$temp.SendReceive=$fields[7]
					$temp.RecordType=(($line -split "]")[1] -split " ")[1]
					$temp.Query=($line.ToString().Substring(99)) -replace "\s" -replace "\(\d?\d\)","." -replace "^\." -replace "\.$"
					$temp.Result=(((($line -split "\[")[1]).ToString().Substring(9)) -split "]")[0] -replace " "
				}
				else {
					$temp.Time=$fields[1]
					$temp.Protocol=$fields[6]
					$temp.Client=$fields[8]
					$temp.SendReceive=$fields[7]
					$temp.RecordType=(($line -split "]")[1] -split " ")[1]
					$temp.Query=($line.ToString().Substring(99)) -replace "\s" -replace "\(\d?\d\)","." -replace "^\." -replace "\.$"
					$temp.Result=(((($line -split "\[")[1]).ToString().Substring(9)) -split "]")[0] -replace " "
				}

				$out += $temp
			}
		}
	}
	$out | foreach-object{$_.TimeStamp = [datetime]::parse($_.date + ' ' + $_.time).tostring('yyyy-MM-dd HH:mm:ss')} -ErrorAction SilentlyContinue
	$out | select-object TimeStamp,Protocol,Client,SendReceive,QueryType,RecordType,Query,Result | export-csv -notype ($computername + '~dnslogs.csv')
} else {
	write-log 'DNS Logs not Found'
}

write-log "Copying Registry Files"
Out-debug "$scriptname - Copying Registry Files"
copy-item ($windir + "system32\config\SYSTEM") .
get-childitem ($windir + "system32\config\SYSTEM.log*") -attributes hidden | foreach-object{copy-item $_ .}
copy-item ($windir + "system32\config\SECURITY") .
get-childitem ($windir + "system32\config\SECURITY.log*") -attributes hidden | foreach-object{copy-item $_ .}
copy-item ($windir + "system32\config\SOFTWARE") .
get-childitem ($windir + "system32\config\SOFTWARE.log*") -attributes hidden | foreach-object{copy-item $_ .}
copy-item ($windir + "system32\config\SAM") .
get-childitem ($windir + "system32\config\SAM.log*") -attributes hidden | foreach-object{copy-item $_ .}
get-childitem *.log* -attributes hidden | ForEach-Object{$_.Attributes = 'Normal'}

get-childitem -force | ForEach-Object{$_.Attributes = 'Normal'}
get-childitem * | where-object {$_.length -eq 0} | remove-item

$outstring = @"
Log Locations
\ProgramData\Avast Software\Persistent Data\Avast\Logs
\ProgramData\Malwarebytes\Malwarebytes Anti-Malware\Logs\
\ProgramData\McAfee\Endpoint Security\Logs\
\ProgramData\Symantec\Symantec Endpoint Protection\12.1.3001.165.105\Data\Logs\
\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs\AV\
\ProgramData\AVAST Software\Avast\log\
\ProgramData\McAfee\DesktopProtection\
\Program Files (x86)\Ipswitch\Logging Server\Logs\
\Program Files (x86)\Ipswitch\Logs\
\ProgramData\VIPRE Business Agent\Logs\
\ProgramData\Cylance\Optics\log\
\ProgramData\VMware\Logs\
\windows\Debug\
\ProgramData\Microsoft\Windows Defender\Support\
\Program Files (x86)\Fortinet\FortiClient\logs\
\ProgramData\SolarWinds\Logs\
\ProgramData\Cisco\Amp\
\ProgramData\Malwarebytes\Malwarebytes' Anti-Malware\
\ProgramData\Malwarebytes Anti-Exploit\Logs\
"@

out-debug "$scriptname - copying other logs"
$outstring | add-content -enc utf8 ($basedir + 'otherlogs\LogLocations.txt')

if ((get-item $windir).parent.name -ne 'C') {
	if (test-path ($windir + 'Debug')) {
		mkdir 'otherlogs\netlogon' >> $null
		copy-item ($windir + 'Debug\netlogon.log') otherlogs\netlogon\
	}
	if (test-path ($windir + 'dns')) {
		mkdir 'otherlogs\dns' >> $null
		copy-item ($windir + 'Dns\*') otherlogs\dns\
	}
	if (test-path ($windir + 'System32\dhcp')) {
		mkdir 'otherlogs\dhcp' >> $null
		copy-item ($windir + 'System32\dhcp\*') otherlogs\dhcp\
	}
	if (test-path ($drive + ':\Program Files\Cylance\Desktop\log')) {
		mkdir 'otherlogs\Cylance' >> $null
		copy-item ($drive + ':\Program Files\Cylance\Desktop\log\*') otherlogs\Cylance\
	}
	if (test-path ($drive + ':\ProgramData\Malwarebytes\Malwarebytes Anti-Malware\Logs\')) {
		mkdir 'otherlogs\Malwarebytes' >> $null
		copy-item ($drive + ':\ProgramData\Malwarebytes\Malwarebytes Anti-Malware\Logs\*') otherlogs\Malwarebytes\
	}
	if (test-path ($drive + ':\ProgramData\McAfee\Endpoint Security\Logs\')) {
		mkdir 'otherlogs\McAfee' >> $null
		copy-item ($drive + ':\ProgramData\McAfee\Endpoint Security\Logs\*') otherlogs\McAfee\
	}
	if (test-path ($drive + ':\ProgramData\sophos\Sophos Anti-Virus\logs\')) {
		mkdir 'otherlogs\Sophos' >> $null
		copy-item ($drive + ':\ProgramData\sophos\Sophos Anti-Virus\logs\*') otherlogs\Sophos\
	}
	if (test-path ($drive + ':\ProgramData\Microsoft\Windows Defender\Support\')) {
		mkdir 'otherlogs\Defender' >> $null
		copy-item ($drive + ':\ProgramData\Microsoft\Windows Defender\Support\*') otherlogs\Defender\
	}
	if (test-path ($drive + ':\ProgramData\VMware\Logs\')) {
		mkdir 'otherlogs\VMware' >> $null
		copy-item ($drive + ':\ProgramData\VMware\Logs\*') otherlogs\VMware\
	}
	if (test-path ($drive + ':\ProgramData\Cylance\Optics\log\')) {
		mkdir 'otherlogs\Cylance' >> $null
		copy-item ($drive + ':\ProgramData\Cylance\Optics\log\*') otherlogs\Cylance\
	}
	if (test-path ($drive + ':\ProgramData\VIPRE Business Agent\Logs\')) {
		mkdir 'otherlogs\VIPR' >> $null
		copy-item ($drive + ':\ProgramData\VIPRE Business Agent\Logs\*') otherlogs\VIPR\
	}
	if (test-path ($drive + ':\Program Files (x86)\Ipswitch\Logs\')) {
		mkdir 'otherlogs\Ipswitch' >> $null
		copy-item ($drive + ':\Program Files (x86)\Ipswitch\Logs\*') otherlogs\Ipswitch\
	}
	if (test-path ($drive + ':\Program Files (x86)\Ipswitch\Logging Server\Logs\')) {
		mkdir 'otherlogs\Ipswitch' >> $null
		copy-item ($drive + ':\Program Files (x86)\Ipswitch\Logging Server\Logs\*') otherlogs\Ipswitch\
	}
	if (test-path ($drive + ':\ProgramData\McAfee\DesktopProtection\')) {
		mkdir 'otherlogs\McAfee' >> $null
		copy-item ($drive + ':\ProgramData\McAfee\DesktopProtection\*') otherlogs\McAfee\
	}
	if (test-path ($drive + ':\ProgramData\AVAST Software\Avast\log')) {
		mkdir 'otherlogs\AVAST' >> $null
		copy-item ($drive + ':\ProgramData\AVAST Software\Avast\log\*') otherlogs\AVAST\
	}
	if (test-path ($drive + ':\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs\AV\')) {
		mkdir 'otherlogs\Symantec' >> $null
		copy-item ($drive + ':\ProgramData\Symantec\Symantec Endpoint Protection\CurrentVersion\Data\Logs\AV\*') otherlogs\Symantec\
	}
	if (test-path ($drive + ':\ProgramData\Symantec\Symantec Endpoint Protection\12.1.3001.165.105\Data\Logs\')) {
		mkdir 'otherlogs\Symantec' >> $null
		copy-item ($drive + ':\ProgramData\Symantec\Symantec Endpoint Protection\12.1.3001.165.105\Data\Logs\*') otherlogs\Symantec\
	}
	if (test-path ($drive + ':\Program Files (x86)\Fortinet\FortiClient\logs\')) {
		mkdir 'otherlogs\Fortinet' >> $null
		copy-item ($drive + ':\Program Files (x86)\Fortinet\FortiClient\logs\*') otherlogs\Fortinet\
	}
}

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

######### Check for IOCs ###########
set-location $basedir
Write-log "$scriptname - Checking for IOCs" -fore "Green"
write-log "$scriptname - Checking Browser History for IOCs" -fore "Yellow"
$brh = import-csv ($computername + '~browserhistory.csv')
if ($brh | where-object{$_.url -like "*ngrok*"}){
	write-ioc "Check for NGROK usage."
}
if ($brh | where-object{$_.url -like "*pCloud*"}){
	write-ioc "Check for pCloud usage."
}
if ($brh | where-object{$_.url -like "*mega.nz*"}){
	write-ioc "Check for uploads to Mega.nz."
}
write-log "$scriptname - Checking Scheduled Tasks for persistence" -fore "Yellow"
$st = import-csv ($computername + '~ScheduledTasks.csv') 
if ($st | Where-Object {$_.Actions -like '*.ps1*'}) {
	write-ioc "Check for Scheduled Task running a PowerShell script"
}
# Too noisy
#if ($st | Where-Object {$_.Actions -like '*.vbs*'}) {
#	write-ioc "Check for Scheduled Task running a Visual Basic Script (.vbs)"
#}
if ($st | Where-Object {$_.Actions -like '*plink*'}) {
	write-ioc "Check for Scheduled Task running plink"
}
$stnum = ($st | Where-Object {[datetime]::parse($_.CreationDate) -ge $imagedate}).length
if ($stnum -gt 0) {
	write-ioc "$stnum New Scheduled tasks in last 30 days."
}
write-log "$scriptname - Checking for WMI persistence." -fore "Yellow"
if (Get-ChildItem ($Computername + '~wmi.txt') | Where-Object length -gt 1670) {
	write-ioc "Check $Computername~wmi.txt"
}

######### Normalize Dates ###########

if (test-path ($basedir + 'Srum')) {
	push-location ($basedir + 'Srum')
	Write-log "$scriptname - Normalizing SRUM tables" -fore "yellow"
	normalize-date ($computername + '-NetworkUsage.csv') 'TimeStamp'
	normalize-date ($computername + '-PushNotification.csv') 'TimeStamp'
	normalize-date ($computername + '-NetworkConnection.csv') 'TimeStamp'
	normalize-date ($computername + '-TimelineProvider.csv') 'TimeStamp'
	normalize-date ($computername + '-AppResourceInfo.csv') 'TimeStamp'
	normalize-date ($computername + '-EnergyUsage-LongTerm.csv') 'TimeStamp'
	normalize-date ($computername + '-EnergyUsage.csv') 'TimeStamp'
	normalize-date ($computername + '-Vfuprov.csv') 'TimeStamp'
	pop-location
}
if (Test-Path ($computername + '~dnslogs.csv')) {
	Normalize-Date ($computername + '~dnslogs.csv') 'TimeStamp'
}
Write-log "$scriptname - Normalizing System Data" -fore "yellow"
Normalize-Date ($computername + '~AppCompatCache.csv')	'LastModifiedTimeUTC'
Normalize-Date ($computername + '~AmCache.csv') 'KeyLastWriteTimestamp'
Normalize-Date ($computername + '~AmCache_DevicePnps.csv') 'KeyLastWriteTimestamp,DriverVerDate'
Normalize-Date ($computername + '~AmCache_DriveBinaries.csv') 'KeyLastWriteTimestamp,DriverTimeStamp,DriverLastWriteTime'
Normalize-Date ($computername + '~AmCache_DriverPackages.csv') 'Date'
Normalize-Date ($computername + '~AmCache_ShortCuts.csv') 'KeyLastWriteTimestamp'
Normalize-Date ($computername + '~AmCache_UnassociatedFileEntries.csv') 'LinkDate,FileKeyLastWriteTimestamp'
Normalize-Date ($computername + '~AmCache_DeviceContainers.csv') 'KeyLastWriteTimestamp'
Normalize-Date ($computername + '~networkconnections.csv') ""
Normalize-date ($computername + '~ProcessList.csv') ''
Normalize-Date ($computername + '~RecentFileCache.csv') 'SourceCreated,SourceModified,SourceAccessed'
Normalize-Date ($computername + '~RecycleBin.csv') 'DeletedOn'
Normalize-Date ($computername + '~browserhistory.csv') 'Visit Time'
Normalize-Date ($computername + '~ScheduledTasks.csv') 'CreationDate,ModifiedDate'
Normalize-Date ($computername + '~Prefetch.csv') 'LastRun,SourceCreated,SourceModified,SourceAccessed,PreviousRun0,PreviousRun1,PreviousRun2,PreviousRun3,PreviousRun4,PreviousRun5,PreviousRun6,Volume0Created,Volume1Created'
Normalize-Date ($computername + '~Prefetch_Timeline.csv') 'RunTime'
Normalize-Date ($computername + '~wmi.csv') 'LastUsedTime,Timestamp1,Timestamp2'
Normalize-Date ($computername + '~DeliveryOptimization.csv') 'TimeCreated'
Normalize-Date ($computername + '~LnkFiles.csv') 'TargetAccessed,SourceCreated,SourceModified,SourceAccessed,TargetCreated,TargetModified'

write-log 'Finished getting Systeminfo'

