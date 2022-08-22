<#
	.SYNOPSIS
		Process System and User Registries
	.DESCRIPTION
		Process System Registries - System Audit Services and User Registries
	.Parameter computername
		Name of the computer host - used to name the files.
	.PARAMETER basedir
		Base Directory to place computer information files
	.Parameter systemdir
		Directory which contains system registries e.g k:\windows\system32\config
	.Parameter userdir
		Directory which contains user registries e.g. K:\Users
	.Parameter userinfo
		Directory to put the user information pulled from registries
	.EXAMPLE
		> .\process-Registries.ps1 "ComputerHost" 's:\bgr\systems\computerhost\' 'f:\windows\system32\config\' 'f:\users\' 's:\bgr\systems\computerhost\users\'
	.NOTES
	Author: Tom Willett 
	Date: 8/24/2021
	V1.0
#>
Param([Parameter(Mandatory=$True)][string]$Computername,
	[Parameter(Mandatory=$True)][string]$basedir,
	[Parameter(Mandatory=$True)][string]$systemdir,
	[Parameter(Mandatory=$True)][string]$userdir,
	[Parameter(Mandatory=$True)][string]$userinfo)

<#
  Configuration Information
#>

. ($psscriptroot + '.\process-lib.ps1')

$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (!$currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
	Write-host "Must be run with Administrator Permissions" -fore red
	exit
}

function get-regbatch {
	<#
	.Synopsis
		Run a regedit batch file to extract info
	.Description
		Use Eric Zimmermans regcmd to extract info from a registry with a batch cmd file
	.Parameter title
		Title of info being collected
	.Parameter computer
		Computer name
	.Parameter batch
		Name of batch file to run
	.Parameter path
		Path to registries
	.Parameter out
		Descriptive name for output file.
	.NOTES
		Author: Tom Willett
		Date: 8/1/2021
	#>
	Param([Parameter(Mandatory=$True)][string]$Title,
		[Parameter(Mandatory=$True)][string]$computer,
		[Parameter(Mandatory=$True)][string]$batch,
		[Parameter(Mandatory=$True)][string]$path,
		[Parameter(Mandatory=$True)][string]$out)
	
	trap {
		"###+++###" | out-debug
		$error[0] | out-debug
		($PSItem.InvocationInfo).positionmessage | out-debug
	}
	write-log "Getting $Title"
	$batchCmd = $recmddir + $batch
	$outfile = $computer + $out
	out-debug "Executing Command: $recmd -d $path --bn $batchCmd --csv . --csvf $outfile"
	& $recmd -d $path --bn $batchCmd --csv '.' --csvf $outfile | out-debug
}

function get-unquotedservicepaths 
{
	<#
	.Synopsis
		Checks all service paths for lack of quotes
	.Description
		Checks all service paths for lack of quotes and returns an PS Object if such paths exist
	.Parameter FileName
		Path to services.csv containing service information
	.NOTES
		Author: Tom Willett
		Date: 8/1/2021
	#>
	Param([Parameter(Mandatory=$True)][string]$filename)
	$s = import-csv $filename
	$report = @()
	$t = $s | where-object {$_.ValueName -eq 'ImagePath'} | where-object {$_.valuedata.contains(" ")}
	foreach($t1 in $t) {
		$result = 0
		while ($result -ne -1) {$start = $result+1;$result = $t1.valuedata.indexof('\',$start)}
		if ($t1.valuedata.substring(0,$start).contains(' ') -and $t1.valuedata.substring(0,1) -ne '"') {
			$tmp = "" | select-object Service,ImagePath
			$tmp.service = $t1.KeyPath
			$tmp.ImagePath = $t1.valuedata
			$report += $tmp
		}
	}
	$report
}

function Get-systeminfo {
	<#
	.Synopsis
		Creates Systeminfo and Environment Variables
	.Description
		Creates Systeminfo and Environment Variables
	.Parameter Computername
		Host name
	.Parameter basedir
		Base dir for the output
	.Parameter userdir
		Dir containing useractivity.csv
	.NOTES
		Author: Tom Willett
		Date: 8/24/2021
	#>
Param([Parameter(Mandatory=$True)][string]$Computername,
	[Parameter(Mandatory=$True)][string]$basedir,
	[Parameter(Mandatory=$True)][string]$userinfo,
	[Parameter(Mandatory=$True)][string]$userdir)

	trap {
		"###+++###" | out-debug
		$error[0] | out-debug
		($PSItem.InvocationInfo).positionmessage | out-debug
	}
	
	write-log "Creating SystemInfo.txt" -fore yellow
	$sinfo = import-csv ($basedir + $computername + '~systeminfo.csv') | where-object {$_.hivepath -notlike "*regback*" -and $_.keypath -notlike '*ControlSet002*'}
	$uinfo = import-csv ($userinfo + $computername + '~useractivity.csv')
	$sinfo | where-object {$_.description -eq 'Session Manager Environment' -and $_.keypath -like '*controlset001*' -and $_.hivepath -notlike '*regback*'} | select-object @{Name="Source";Expression={'System'}},@{Name="Variable";Expression={$_.ValueName}},@{Name="Value";Expression={$_.ValueData}} | export-csv -notype ($computername + '~EnvironmentVariable.csv')
	$u = $uinfo  | where-object {$_.description -eq 'Environment'}
	$u | foreach-object{$_.hivepath = $_.hivepath -replace '\\ntuser.dat','';$_.hivepath = $_.hivepath.substring($_.hivepath.lastindexof('\')+1)}
	$u | select-object @{Name="Source";Expression={'User: ' + $_.hivepath}},@{Name="Variable";Expression={$_.ValueName}},@{Name="Value";Expression={$_.ValueData}} | export-csv -notype -append ($computername + '~EnvironmentVariable.csv')
	$outfile = $computername + '~SystemInfo.txt'
	$out = "HostName`t" + $computername
	$out | out-file $outfile
	$out = "Operating System`t"
	$out += ($sinfo | where-object {$_.ValueName -eq 'ProductName'})[0].valuedata
	$out | out-file $outfile
	$out = "DHCP IP Address`t"
	$out += ($sinfo | where-object {$_.ValueName -eq 'DhcpIPAddress'})[0].valuedata
	$out += '/' 
	$out += ($sinfo | where-object {$_.ValueName -eq 'DhcpSubnetMask'})[0].valuedata
	$out | out-file $outfile -append
	$out = "DHCP Server`t"
	$out += ($sinfo | where-object {$_.ValueName -eq 'DhcpServer'})[0].valuedata
	$out | out-file $outfile -append
	$out = "DHCP Default Gateway`t"
	$out += ($sinfo | where-object {$_.ValueName -eq 'DhcpDefaultGateway'})[0].valuedata
	$out | out-file $outfile -append
	$out = "DHCP Name Server`t"
	$out += ($sinfo | where-object {$_.ValueName -eq 'DhcpNameServer'})[0].valuedata
	$out | out-file $outfile -append
	$out = "IP Address`t"
	$out += ($sinfo | where-object {$_.ValueName -eq 'IPAddress'})[0].valuedata
	$out += '/'
	$out += ($sinfo | where-object {$_.ValueName -eq 'SubnetMask'})[0].valuedata
	$out | out-file $outfile -append
	$out = "Default Gateway`t"
	$out += ($sinfo | where-object {$_.ValueName -eq 'DefaultGateway'})[0].valuedata
	$out | out-file $outfile -append
	$out = "Name Server`t"
	$n = $sinfo | where-object {$_.ValueName -eq 'NameServer'}
	foreach($x in $n) {if ($x.valuedata) {$out += $X.valuedata;break}}
	$out | out-file $outfile -append
	$out = "Domain`t"
	$out += ($sinfo | where-object {$_.ValueName -eq 'Domain'})[0].valuedata
	$out | out-file $outfile -append
	$out = "Time Zone`t"
	$out += ($sinfo | where-object {$_.ValueName -eq 'TimeZoneKeyName'})[0].valuedata
	$out | out-file $outfile -append
	$out = "Time Zone Offset`t"
	$out += -(($sinfo | where-object {$_.valuename -eq 'ActiveTimeBias'})[0].valuedata/60)
	$out | out-file $outfile -append
	$out = "Daylight Saving Bias`t"
	$out += -(($sinfo | where-object {$_.valuename -eq 'DaylightBias'})[0].valuedata/60)
	$out | out-file $outfile -append
	$out = "Shares`t"
	$sh = @()
	$sinfo | where-object {$_.Description -eq 'Shares'} | foreach-object {$sh += $_.ValueName}
	$out += ($sh -join ', ')
	$out | out-file $outfile -append
	$out = "Mounted Devices`t"
	$m = @()
	($sinfo | where-object {$_.Description -eq 'Mounted Devices' -and $_.Valuedata -like '*DosDevices*'})  | foreach-object {$m += $_.valuedata}
	$m = $m -replace 'Name: \\DosDevices\\',''
	$out += ($m -join ', ')
	$out | out-file $outfile -append
	$out = "Users`t"
	$u = @()
	(get-childitem $userdir | where-object { $_.PSIsContainer } | select-object name) | foreach-object {$u += $_.name}
	$out += ($u -join ', ')
	$out | out-file $outfile -append
	$out = "Local Admins`t"
	$da = @()
	($uinfo | where-object {$_.ValueData -eq 'S-1-5-32-544'})  | foreach-object {$hp=$_.HivePath -replace '\\ntuser.dat',''; $da += $hp.substring($hp.lastindexof('\')+1)}
	$out += ($da -join ', ')
	$out | out-file $outfile -append
	$out = "Domain Admins`t"
	$da = @()
	($uinfo | where-object {$_.ValueData -like 'S-1-5-21-*-512'})  | foreach-object {$hp=$_.HivePath -replace '\\ntuser.dat',''; $da += $hp.substring($hp.lastindexof('\')+1)}
	$out += ($da -join ', ')
	$out | out-file $outfile -append
	$out = "Schema Admins`t"
	$da = @()
	($uinfo | where-object {$_.ValueData -like 'S-1-5-21-*-518'})  | foreach-object {$hp=$_.HivePath -replace '\\ntuser.dat',''; $da += $hp.substring($hp.lastindexof('\')+1)}
	$out += ($da -join ', ')
	$out | out-file $outfile -append
	$out = "Enterprise Admins`t"
	$da = @()
	($uinfo | where-object {$_.ValueData -like 'S-1-5-21-*-519'})  | foreach-object {$hp=$_.HivePath -replace '\\ntuser.dat',''; $da += $hp.substring($hp.lastindexof('\')+1)}
	$out += ($da -join ', ')
	$out | out-file $outfile -append
	$out = "Group Policy Admins`t"
	$da = @()
	($uinfo | where-object {$_.ValueData -like 'S-1-5-21-*-520'})  | foreach-object {$hp=$_.HivePath -replace '\\ntuser.dat',''; $da += $hp.substring($hp.lastindexof('\')+1)}
	$out += ($da -join ', ')
	$out | out-file $outfile -append
	$Usersids = $sinfo | where-object {$_.valuename -eq 'ProfileImagePath'}
	"User SIDs:"  | out-file $outfile -append
	foreach($Usr in $Usersids) {
		$user = $usr.valuedata.substring($usr.valuedata.lastindexof('\')+1)
		$sid = $usr.keypath.substring($usr.keypath.lastindexof('\')+1)
		$out = "`t" + $user + ' - ' + $sid
		$out | out-file $outfile -append
	}	
}

function get-auditinfo {
	<#
	.Synopsis
		Creates Auditinfo.txt
	.Description
		Reads audit information from the registry
	.Parameter Computername
		Host name
	.Parameter basedir
		Base dir for the output
	.NOTES
		Author: Tom Willett
		Date: 8/24/2021
	#>
	Param([Parameter(Mandatory=$True)][string]$Computer,
	[Parameter(Mandatory=$True)][string]$basedir)
	
	trap {
		"###+++###" | out-debug
		$error[0] | out-debug
		($PSItem.InvocationInfo).positionmessage | out-debug
	}
	write-log "Creating AuditInfo.txt" -fore green
	$audit = import-csv ($basedir + $computer + '~audit.csv')
	$outfile = ($computer + '~auditinfo.txt')
	$out = 'SMB Settings'
	$out | out-file $outfile
	$out = "`tWorkstation Enable SMB Signing`t"
	if (($audit | where-object {$_.keypath -like "*ControlSet001\Services\LanmanWorkstation*" -and $_.ValueName -eq 'enablesecuritysignature'}).valuedata -eq 1) {
		$out += 'Enabled'
	} else {
		$out += 'Disabled'
	}
	$out | out-file $outfile -append
	$out = "`tWorkstation Require SMB Signing`t"
	if (($audit | where-object {$_.keypath -like "*ControlSet001\Services\LanmanWorkstation*" -and $_.ValueName -eq 'requiresecuritysignature'}).valuedata -eq 1) {
		$out += 'Enabled'
	} else {
		$out += 'Disabled'
	}
	$out | out-file $outfile -append
	$out = "`tWorkstation Allow Plain Text Passwords`t"
	if (($audit | where-object {$_.keypath -like "*ControlSet001\Services\LanmanWorkstation*" -and $_.ValueName -eq 'EnablePlainTextPassword'}).valuedata -eq 1) {
		$out += 'Enabled'
	} else {
		$out += 'Disabled'
	}
	$out | out-file $outfile -append
	$out = "`tWorkstation Allow Insecure Guest Auth`t"
	if (($audit | where-object {$_.keypath -like "*ControlSet001\Services\LanmanWorkstation*" -and $_.ValueName -eq 'AllowInsecureGuestAuth'}).valuedata -eq 1) {
		$out += 'Enabled'
	} else {
		$out += 'Disabled'
	}
	$out | out-file $outfile -append
	$wsSMB1 = $audit | where-object {$_.keypath -like "*ControlSet001\Services\mrxsmb10*" -and $_.ValueName -eq 'Start'}.valuedata
	if ($wsSMB1 -eq 1) {
		"`tWorkstation SMBv1: Loaded by I/O subsystem. Specifies that the driver is loaded at kernel initialization." | out-file $outfile -append
	} elseif ($wsSMB1 -eq 2) {
		"`tWorkstation SMBv1: Loaded by Service Control Manager. Specifies that the service is loaded or started automatically." | out-file $outfile -append
	} elseif ($wsSMB1 -eq 3) {
		"`tWorkstation SMBv1: The service does not start until the user starts it manually, such as by using Services or Devices in Control Panel." | out-file $outfile -append
	} elseif ($wsSMB1 -eq 4) {
		"`tWorkstation SMBv1: Specifies that the service should not be started." | out-file $outfile -append
	}
	$out = "`tServer Enable SMB Signing`t"
	if (($audit | where-object {$_.keypath -like "*ControlSet001\Services\LanmanServer*" -and $_.ValueName -eq 'enablesecuritysignature'}).valuedata -eq 1) {
		$out += 'Enabled'
	} else {
		$out += 'Disabled'
	}
	$out | out-file $outfile -append
	$out = "`tServer Require SMB Signing`t"
	if (($audit | where-object {$_.keypath -like "*ControlSet001\Services\LanmanServer*" -and $_.ValueName -eq 'requiresecuritysignature'}).valuedata -eq 1) {
		$out += 'Enabled'
	} else {
		$out += 'Disabled'
	}
	$out | out-file $outfile -append
	$out = "`tServer Restrict null Sessions`t"
	if (($audit | where-object {$_.keypath -like "*ControlSet001\Services\LanmanServer*" -and $_.ValueName -eq 'restrictnullsessaccess'}).valuedata -eq 1) {
		$out += 'Enabled'
	} else {
		$out += 'Disabled'
	}
	$out | out-file $outfile -append
	$out = "`tServer Enable Win9x SMB Signing`t"
	if (($audit | where-object {$_.keypath -like "*ControlSet001\Services\LanmanServer*" -and $_.ValueName -eq 'enableW9xsecuritysignature'}).valuedata -eq 1) {
		$out += 'Enabled'
	} else {
		$out += 'Disabled'
	}
	$out | out-file $outfile -append
	$out = "`tServer SMBv1`t"
	if (($audit | where-object {$_.keypath -like "*ControlSet001\Services\LanmanServer*" -and $_.ValueName -eq 'SMB1'}).valuedata -eq 0) {
		$out += 'Disabled'
	} else {
		$out += 'Enabled'
	}

	$out | out-file $outfile -append
	$out = 'Windows Defender'
	$out | out-file $outfile -append
	if ($audit | where-object {$_.keypath -like "*Microsoft\Windows Defender*"}) {
		$out = "`tDefender Antivirus`t"
		if (($audit | where-object {$_.keypath -like "*Microsoft\Windows Defender*" -and $_.ValueName -eq 'DisableAntiVirus'}).valuedata -eq 1) {
			$out += 'Disabled'
		} else {
			$out += 'Enabled'
		}
		$out | out-file $outfile -append
		$out = "`tDefender AntiSpyware`t"
		if (($audit | where-object {$_.keypath -like "*Microsoft\Windows Defender*" -and $_.ValueName -eq 'DisableAntiSpyware'}).valuedata -eq 1) {
			$out += 'Disabled'
		} else {
			$out += 'Enabled'
		}
		$out | out-file $outfile -append
	}
	$out = "`tDefender Service`t"
	if (($audit | where-object {$_.keypath -like "*ControlSet001\Services\WinDefend*" -and $_.ValueName -eq 'Start'}).valuedata -eq 3) {
		$out += 'Disabled'
	} else {
		$out += 'Enabled'
	}
	$out | out-file $outfile -append
	$ex = $audit | where-object {$_.keypath -like '*Microsoft\Windows Defender\Exclusions*' -and $_.valuename -ne ""}
	if ($ex) {
		"Windows Defender Exclusions" | out-file $outfile -append
		foreach($e in $ex) {
			"`tExclusion`t" + $e.valuename | out-file $outfile -append
		}
	}
	if ($audit | where-object {$_.keypath -like "*Microsoft\Security Center\Provider*"}) {
		"Security Center AntiVirus Installed:" | out-file $outfile -append
		$out = ""
		($audit | where-object {$_.keypath -like "*Microsoft\Security Center\Provider*\AV\*" -and $_.ValueName -eq 'DisplayName'}).valuedata | foreach-object{("`t" + $_) | out-file $outfile -append}
	}
	if ($audit | where-object {$_.keypath -like "*CrowdStrike*"}) {
		"CrowdStrike Installed"  | out-file $outfile -append
	}
	if ($audit | where-object {$_.keypath -like "*McAfee*"}) {
		"McAfee Installed"  | out-file $outfile -append
	}
	if ($audit | where-object {$_.keypath -like "*Kaspersky*"}) {
		"Kaspersky Installed"  | out-file $outfile -append
	}
	if ($audit | where-object {$_.keypath -like "*Eset*"}) {
		"Eset Installed"  | out-file $outfile -append
	}
	if ($audit | where-object {$_.keypath -like "*Symantec*"}) {
		"Symantec Installed"  | out-file $outfile -append
	}
	if ($audit | where-object {$_.keypath -like "*Malwarebytes*"}) {
		"Malwarebytes Installed"  | out-file $outfile -append
	}
	if ($audit | where-object {$_.keypath -like "*CbDefense*"}) {
		"Carbon Black Installed"  | out-file $outfile -append
	}
		if ($audit | where-object {$_.keypath -like "*Sentinel Labs*"}) {
		"Sentinel One Installed"  | out-file $outfile -append
	}

	$out = 'Windows Firewall'
	$out | out-file $outfile -append
	$out = "`tWindows Firewall Public Profile`t"
	if (($audit | where-object {$_.keypath -like "*Policies\Microsoft\WindowsFirewall\PublicProfile*" -and $_.ValueName -eq 'EnableFirewall'}).valuedata -eq 1) {
		$out += 'Enabled'
	} else {
		$out += 'Disabled'
	}
	$out | out-file $outfile -append
	$out = "`tWindows Firewall Private Profile`t"
	if (($audit | where-object {$_.keypath -like "*Policies\Microsoft\WindowsFirewall\PrivateProfile*" -and $_.ValueName -eq 'EnableFirewall'}).valuedata -eq 1) {
		$out += 'Enabled'
	} else {
		$out += 'Disabled'
	}
	$out | out-file $outfile -append
	$out = "`tWindows Firewall Domain Profile`t"
	if (($audit | where-object {$_.keypath -like "*Policies\Microsoft\WindowsFirewall\DomainProfile*" -and $_.ValueName -eq 'EnableFirewall'}).valuedata -eq 1) {
		$out += 'Enabled'
	} else {
		$out += 'Disabled'
	}
	$out | out-file $outfile -append
	"Terminal Services" | out-file $outfile -append
	$securitylayer = ($audit | where-object {$_.keypath -like "*ControlSet001\Control\Terminal Server\WinStations\RDP-TCP*" -and $_.valuename -eq 'SecurityLayer'}).valuedata
	$UserAuthentication = ($audit | where-object {$_.keypath -like "*ControlSet001\Control\Terminal Server\WinStations\RDP-TCP*" -and $_.valuename -eq 'UserAuthentication'}).valuedata
	$fDenyTSConnections = ($audit | where-object {$_.keypath -like "*ControlSet001\Control\Terminal Server*" -and $_.valuename -eq 'fDenyTSConnections'}).valuedata
	$minencryption = ($audit | where-object {$_.keypath -like "*Policies\Microsoft\Windows NT\Terminal Services*" -and $_.valuename -eq 'MinEncryptionLevel'}).valuedata
	$fEncryptRPCTraffic = ($audit | where-object {$_.keypath -like "*Policies\Microsoft\Windows NT\Terminal Services*" -and $_.valuename -eq 'fEncryptRPCTraffic'}).valuedata
	$DisablePasswordSaving = ($audit | where-object {$_.keypath -like "*Policies\Microsoft\Windows NT\Terminal Services*" -and $_.valuename -eq 'DisablePasswordSaving'}).valuedata
	$fPromptForPassword = ($audit | where-object {$_.keypath -like "*Policies\Microsoft\Windows NT\Terminal Services*" -and $_.valuename -eq 'fPromptForPassword'}).valuedata

	If ($fDenyTSConnections -eq 1) {
		"`tTerminal Services`tdisabled" | out-file $outfile -append
	} else {
		"`tTerminal Services`tenabled" | out-file $outfile -append
		if ($securitylayer -eq 1) {
			"`tSecurity`tClient Negotiate" | out-file $outfile -append
		} elseif ($securitylayer -eq 2) {
			"`tSecurity`tTLS" | out-file $outfile -append
		} else {
			"`tSecurity`tRDP" | out-file $outfile -append
		}
		if ($UserAuthentication -eq 1) {
			"`tNetwork Level Authentication`tOn" | out-file $outfile -append
		} else {
			"`tNetwork Level Authentication`tOff" | out-file $outfile -append
		}
		if ($minencryption -eq 1) {
			"`tMin Encryption Level set Low" | out-file $outfile -append
		} elseif ($minencryption -eq 2) {
			"`tMin Encryption Level set to Client-compatible level of encryption" | out-file $outfile -append
		} elseif ($minencryption -eq 3) {
			"`tMin Encryption set to High" | out-file $outfile -append
		} elseif ($minencryption -eq 4) {
			"`tMin Encryption level set to FIPS-compliant encryption" | out-file $outfile -append
		}
		if ($fEncryptRPCTraffic -eq 1) {"`tRPC Traffic is Encrypted" | out-file $outfile -append}
		if ($DisablePasswordSaving -eq 1) {
			"`tPassword Saving`tDisabled" | out-file $outfile -append
		} else {
			"`tPassword Saving`tEnabled" | out-file $outfile -append
		}
		if ($fPromptForPassword -eq 1) {
			"`tPrompt for Password`tDisabled" | out-file $outfile -append
		} else {
			"`tPrompt for Password`tEnabled" | out-file $outfile -append
		}
	}

	if ((($audit | where-object {$_.keypath -like "*Microsoft\Windows\CurrentVersion\Internet Settings*" -and $_.valuename -eq 'ProxyEnable'}).valuedata) -eq 1) {
		"Proxy Enabled"  | out-file $outfile -append
		$out = "`tProxy Server`t"
		$out += ($audit | where-object {$_.keypath -like "*Microsoft\Windows\CurrentVersion\Internet Settings*" -and $_.valuename -eq 'ProxyServer'}).valuedata
		$out | out-file $outfile -append
	} else {
		"Proxy Disabled"  | out-file $outfile -append
	} 
	$logs = $audit | where-object {$_.keypath -like "*ControlSet001\Services\EventLog*"}
	"Log File Max Sizes"  | out-file $outfile -append
	$logs | foreach-object{$out = "`t" + $_.keypath.substring($_.keypath.lastindexof('\') + 1) + " log `t";$out += Format-HumanReadable($_.valuedata); $out | out-file $outfile -append}

	"PKICiphers" | out-file $outfile -append
	$ssl = $audit | where-object {$_.Description -eq "PKICiphers" -and $_.keypath -like "*ControlSet001*" -and $_.valuedata -ne "" -and $_.keypath -like '*ssl*'}
	if ($ssl) {
		"`tSSL Ciphers:"  | out-file $outfile -append
		foreach($ss in $ssl) {
			$ss.valuedata -replace " ",", "| out-file $outfile -append
		}
	}
	$ssl = $audit | where-object {$_.Description -eq "PKICiphers" -and $_.keypath -like "*ControlSet001*" -and $_.valuedata -ne "" -and $_.keypath -like '*Ciphers*'}
	if ($ssl) {
		"`tCiphers:"  | out-file $outfile -append
		foreach($ss in $ssl) {
			$ss.valuedata -replace " ",", "| out-file $outfile -append
		}
	}
	$ssl = $audit | where-object {$_.Description -eq "PKICiphers" -and $_.keypath -like "*ControlSet001*" -and $_.valuedata -ne "" -and $_.keypath -like '*Hashes*'}
	if ($ssl) {
		"`tHashes:"  | out-file $outfile -append
		foreach($ss in $ssl) {
			$ss.valuedata -replace " ",", "| out-file $outfile -append
		}
	}
	$ssl = $audit | where-object {$_.Description -eq "PKICiphers" -and $_.keypath -like "*ControlSet001*" -and $_.valuedata -ne "" -and $_.keypath -like '*Protocols*'}
	if ($ssl) {
		"`tProtocols:"  | out-file $outfile -append
		foreach($ss in $ssl) {
			$ss.valuedata -replace " ",", "| out-file $outfile -append
		}
	}
	$ssl = $audit | where-object {$_.Description -eq "PKICiphers" -and $_.keypath -like "*ControlSet001*" -and $_.valuedata -ne "" -and $_.keypath -like '*KeyExchangeAlgorithms*'}
	if ($ssl) {
		"`tKeyExchangeAlgorithms:"  | out-file $outfile -append
		foreach($ss in $ssl) {
			$ss.valuedata -replace " ",", "| out-file $outfile -append
		}
	}

	if ((($audit | where-object {$_.keypath -like "*Controlset001\Services\NetBT\Parameters\Interfaces*"}).valuedata) -ne 2) {
		"NetBios over TCP`tenabled" | out-file $outfile -append
	} else {
		"NetBios over TCP`tDisabled" | out-file $outfile -append
	}
	"Anonymous Shares" | out-file $outfile -append
	$lsa = $audit | where-object {$_.keypath -like "*ControlSet001\Control\LSA*" -and $_.HivePath -notlike '*RegBack*'}
	foreach($l in $lsa) {if ($l.valuedata -eq 0) {
		"`tAnonymous Shares - " + $l.valuename + "`tnot restricted" | out-file $outfile -append
	} else {
		"`tAnonymous Shares - " + $l.valuename + "`trestricted" | out-file $outfile -append}
	}
	if (($audit | where-object {$_.keypath -like "*ControlSet001\Control\LSA*" -and $_.valuename -eq 'NoLMHash'}).ValueData -eq 1) {
		"LM Hashes`tdisabled" | out-file $outfile -append
	} else {
		"LM Hashes`tenabled" | out-file $outfile -append
	}
	$lmlvl = $audit | where-object {$_.keypath -like "*ControlSet001\Control\LSA*" -and $_.valuename -eq 'LmCompatibilityLevel'}
	if ($lmlvl) {
		if ($lmlvl -eq 0) {
		"Send LM & NTLM responses" | out-file $outfile -append
		} elseif ($lmlvl -eq 1){
		"Send LM & NTLM - use NTLMv2 session security if negotiated" | out-file $outfile -append
		} elseif ($lmlvl -eq 2) {
			"Send NTLM response only" | out-file $outfile -append
		} elseif ($lmlvl -eq 3) {
			"Send NTLMv2 response only" | out-file $outfile -append
		} elseif ($lmlvl -eq 4) {
			"Send NTLMv2 response only. Refuse LM" | out-file $outfile -append
		} elseif ($lmlvl -eq 5) {
			"Send NTLMv2 response only. Refuse LM & NTLM" | out-file $outfile -append
		}
	}

	$applocker = $audit | where-object {$_.keypath -like "*Policies\Microsoft\Windows\SrpV2*"}
	if ($applocker) {
		"Applocker`tdeployed" | out-file $outfile -append
		"Applocker configuration" | out-file Applocker.txt
		"`tNote SID S-1-1-0 is Everyone" | out-file Applocker.txt -append
		foreach($app in $applocker) {
			$app.valuedata | out-file Applocker.txt -append
		}
	} else {
		"Applocker`tnot deployed" | out-file $outfile -append
	}
	"Cached Logons" | out-file $outfile -append
	$out = "`tCached Logons Count`t"
	$out += ($audit | where-object {$_.keypath -like "*Microsoft\Windows NT\CurrentVersion\Winlogon*" -and $_.valuename -eq 'CachedLogonsCount'  -and $_.HivePath -notlike '*RegBack*'}).ValueData
	$out | out-file $outfile -append
	$out = "`tNetwork Access`t"
	$dc= ($audit | where-object {$_.keypath -like "*ControlSet001\Control\LSA*" -and $_.valuename -eq'DisableDomainCreds'}).DisableDomainCreds
	if ($dc) {
		$out += "Disabled"
	} else {
		$out += "Enabled"
	}
	$out | out-file $outfile -append
	"WinRM" | out-file $outfile -append
	if (($audit | where-object {$_.keypath -like "*Policies\Microsoft\Windows\WinRM\Service*" -and $_.valuename -eq 'AllowBasic'}).ValueData -eq 1) {
		"`tPlain Text WinRM passwords`tenabled" | out-file $outfile -append
	} else {
		"`tPlain Text WinRM passwords`tdisabled" | out-file $outfile -append
	}
	if (($audit | where-object {$_.keypath -like "*Policies\Microsoft\Windows\WinRM\Service*" -and $_.valuename -eq 'AllowDigest'}).ValueData -eq 1) {
		"`tDigest WinRM passwords`tenabled" | out-file $outfile -append
	} else {
		"`tDigest WinRM passwords`tdisabled" | out-file $outfile -append
	}
	if (($audit | where-object {$_.keypath -like "*Policies\Microsoft\Windows\WinRM\Service*" -and $_.valuename -eq 'DisableRunAs'}).ValueData -eq 1) {
		"`tWinRM RunAs`tDisabled" | out-file $outfile -append
	} else {
		"`tWinRM RunAs`tEnabled" | out-file $outfile -append
	}
	$AllowUnencryptedTraffic = ($audit | where-object {$_.keypath -like "*Policies\Microsoft\Windows\WinRM\Client\*" -and $_.valuename -eq 'AllowUnencryptedTraffic'}).valuedata
	if ($AllowUnencryptedTraffic -eq 1) {
		"`tWinRM Client Allow Unencrypted Traffic`tEnabled" | out-file $outfile -append
	} else {
		"`tWinRM Client Allow Unencrypted Traffic`tDisabled" | out-file $outfile -append
	}
	"Credential Entry" | out-file $outfile -append
	if (($audit | where-object {$_.keypath -like "*Policies\Microsoft\Windows\System*" -and $_.valuename -eq 'EnumerateLocalUsers'}).ValueData -eq 1) {
		"`tLocal Users can be enumerated on Domain joined hosts" | out-file $outfile -append
	} else {
		"`tLocal Users cannot be enumerated on Domain joined hosts" | out-file $outfile -append
	}
	if (($audit | where-object {$_.keypath -like "*Policies\Microsoft\Windows\System*" -and $_.valuename -eq 'DontDisplayNetworkSelectionUI'}).ValueData -eq 1) {
		"`tNetwork UI not displayed before login" | out-file $outfile -append
	} else {
		"`tNetwork UI displayed before login" | out-file $outfile -append
	}
	if (($audit | where-object {$_.keypath -like "*Policies\Microsoft\Windows\CredUI*" -and $_.valuename -eq 'DisablePasswordReveal'}).ValueData -eq 1) {
		"`tPassword Reveal Button`tNot Displayed" | out-file $outfile -append
	} else {
		"`tPassword Reveal Button`tDisplayed" | out-file $outfile -append
	}
	if (($audit | where-object {$_.keypath -like "*Policies\Microsoft\Windows\CredUI*" -and $_.valuename -eq 'EnumerateAdministrators'}).ValueData -eq 1) {
		"`tAdmin Users can be enumerated" | out-file $outfile -append
	} else {
		"`tAdmin Users cannot be enumerated" | out-file $outfile -append
	}
	"User Account Control" | out-file $outfile -append
	if (($audit | where-object {$_.keypath -like "*Microsoft\Windows\CurrentVersion\Policies\System*" -and $_.valuename -eq 'FilterAdministratorToken'}).ValueData -eq 1) {
		"`tAdmin Approval Mode for the built-in Administrator account`tenabled" | out-file $outfile -append
	} else {
		"`tAdmin Approval Mode for the built-in Administrator account`tdisabled" | out-file $outfile -append
	}
	if (($audit | where-object {$_.keypath -like "*Microsoft\Windows\CurrentVersion\Policies\System*" -and $_.valuename -eq 'EnableUIADesktopToggle'}).ValueData -eq 1) {
		"`tAllow UIAccess applications to prompt for elevation without using the secure desktop`tenabled" | out-file $outfile -append
	} else {
		"`tAllow UIAccess applications to prompt for elevation without using the secure desktop`tdisabled" | out-file $outfile -append
	}
	$tmp = ($audit | where-object {$_.keypath -like "*Microsoft\Windows\CurrentVersion\Policies\System*" -and $_.valuename -eq 'ConsentPromptBehaviorAdmin'}).ValueData
	if ($tmp -eq 0) {
		"`tElevate without prompting" | out-file $outfile -append
	} elseif ($tmp -eq 1) {
		"`tPrompt for credentials on secure desktop" | out-file $outfile -append
	} elseif ($tmp -eq 2) {
		"`tPrompt for consent on secure desktop" | out-file $outfile -append
	} elseif ($tmp -eq 3) {
		"`tPrompt for credentials" | out-file $outfile -append
	} elseif ($tmp -eq 4) {
		"`tPrompt for consent" | out-file $outfile -append
	} else {
		"`tPrompt for consent for non-windows binaries" | out-file $outfile -append
	}
	$tmp = ($audit | where-object {$_.keypath -like "*Microsoft\Windows\CurrentVersion\Policies\System*" -and $_.valuename -eq 'ConsentPromptBehaviorUser'}).ValueData
	if ($tmp -eq 0) {
		"`tAutomatically deny elevation requests" | out-file $outfile -append
	} elseif ($tmp -eq 1) {
		"`tPrompt for credentials on secure desktop" | out-file $outfile -append
	} else {
		"`tPrompt for credentials" | out-file $outfile -append
	}
	if (($audit | where-object {$_.keypath -like "*Microsoft\Windows\CurrentVersion\Policies\System*" -and $_.valuename -eq 'EnableInstallerDetection'}).ValueData -eq 1) {
		"`tDetect application installations and prompt for elevation" | out-file $outfile -append
	} else {
		"`tDetect application installations and prompt for elevation`tdisabled" | out-file $outfile -append
	}
	if (($audit | where-object {$_.keypath -like "*Microsoft\Windows\CurrentVersion\Policies\System*" -and $_.valuename -eq 'ValidateAdminCodeSignatures'}).ValueData -eq 1) {
		"`tOnly elevate executables that are signed and validated`tenabled" | out-file $outfile -append
	} else {
		"`tOnly elevate executables that are signed and validated`tdisabled" | out-file $outfile -append
	}
	if (($audit | where-object {$_.keypath -like "*Microsoft\Windows\CurrentVersion\Policies\System*" -and $_.valuename -eq 'EnableSecureUIAPaths'}).ValueData -eq 1) {
		"`tOnly elevate UIAccess applications that are installed in secure locations`tenabled" | out-file $outfile -append
	} else {
		"`tOnly elevate UIAccess applications that are installed in secure locations`tdisabled" | out-file $outfile -append
	}
	if (($audit | where-object {$_.keypath -like "*Microsoft\Windows\CurrentVersion\Policies\System*" -and $_.valuename -eq 'EnableLUA'}).ValueData -eq 1) {
		"`tRun all administrators in Admin Approval Mode`tenabled" | out-file $outfile -append
	} else {
		"`tRun all administrators in Admin Approval Mode`tdisabled" | out-file $outfile -append
	}
	if (($audit | where-object {$_.keypath -like "*Microsoft\Windows\CurrentVersion\Policies\System*" -and $_.valuename -eq 'PromptOnSecureDesktop'}).ValueData -eq 1) {
		"`tSwitch to the secure desktop when prompting for elevation`tenabled" | out-file $outfile -append
	} else {
		"`tSwitch to the secure desktop when prompting for elevation`tdisabled" | out-file $outfile -append
	}
	if (($audit | where-object {$_.keypath -like "*Microsoft\Windows\CurrentVersion\Policies\System*" -and $_.valuename -eq 'EnableVirtualization'}).ValueData -eq 1) {
		"`tVirtualize file and registry write failures to per-user locations`tenabled" | out-file $outfile -append
	} else {
		"`tVirtualize file and registry write failures to per-user locations`tdisabled" | out-file $outfile -append
	}
	if (($audit | where-object {$_.keypath -like "*ControlSet001\Control\Session Manager\kernel*" -and $_.valuename -eq 'DisableExceptionChainValidation'}).ValueData -eq 1) {
		"Structured Exception Handling Overwrite Protection (SEHOP)`tdisabled" | out-file $outfile -append
	} else {
		"Structured Exception Handling Overwrite Protection (SEHOP)`tenabled" | out-file $outfile -append
	}
	if (($audit | where-object {$_.keypath -like "*Policies\Microsoft\Windows\Explorer*" -and $_.valuename -eq 'NoDataExecutionPrevention'}).ValueData -eq 1) {
		"Explorer DEP`tdisabled" | out-file $outfile -append
	} else {
		"Explorer DEP`tenabled" | out-file $outfile -append
	}
	if (($audit | where-object {$_.keypath -like "*Policies\Microsoft\Windows\Explorer*" -and $_.valuename -eq 'NoAutoplayfornonVolume'}).ValueData -eq 1) {
		"Autoplay`tenabled" | out-file $outfile -append
	} else {
		"Autoplay`tdisabled" | out-file $outfile -append
	}
	if (($audit | where-object {$_.keypath -like "*Microsoft\Windows\CurrentVersion\Policies\Explorer\*" -and $_.valuename -eq 'NoAutorun'}).ValueData -eq 1) {
		"Autorun`tdisabled" | out-file $outfile -append
	} else {
		"Autorun`tenabled" | out-file $outfile -append
	}
	if (($audit | where-object {$_.keypath -like "*Policies\Microsoft\Windows\Installer*" -and $_.valuename -eq 'AlwaysInstallElevated'}).ValueData -eq 1) {
		"Allways Install Elevated`tenabled" | out-file $outfile -append
	} else {
		"Allways Install Elevated`tdisabled" | out-file $outfile -append
	}
	"PowerShell" | out-file $outfile -append
	if (($audit | where-object {$_.keypath -like "*Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging*" -and $_.valuename -eq 'EnableScriptBlockLogging'}).ValueData -eq 1) {
		"`tPowerShell scriptblock logging`tenabled" | out-file $outfile -append
	} else {
		"`tPowerShell scriptblock logging`tdisabled" | out-file $outfile -append
	}
	if (($audit | where-object {$_.keypath -like "*Policies\Microsoft\Windows\PowerShell\ModuleLogging*" -and $_.valuename -eq 'EnableModuleLogging'}).ValueData -eq 1) {
		"`tPowerShell module logging`tenabled" | out-file $outfile -append
	} else {
		"`tPowerShell module logging`tdisabled" | out-file $outfile -append
	}
	if (($audit | where-object {$_.keypath -like "*Policies\Microsoft\Windows\PowerShell\Transcription*" -and $_.valuename -eq 'EnableTranscripting'}).ValueData -eq 1) {
		"`tPowerShell transcription`tenabled" | out-file $outfile -append
	} else {
		"`tPowerShell transcription`tdisabled" | out-file $outfile -append
	}
	if (($audit | where-object {$_.keypath -like "*Microsoft\Windows\CurrentVersion\Policies\System\Audit\*" -and $_.valuename -eq 'ProcessCreationIncludeCmdLine_Enabled'}).ValueData -eq 1) {
		"`tCommand line data included in process creation events`tenabled" | out-file $outfile -append
	} else {
		"`tCommand line data included in process creation events`tdisabled" | out-file $outfile -append
	}
}

function Format-HumanReadable([Parameter(Mandatory = $True)][int]$size) {
<#
	.Synopsis
		Formats a number to a human readable string kb mb tb etc
	.Description
		Formats a number to a human readable string kb mb gb tb etc
	.Parameter size
		A numeric string to convert
	.NOTES
		Author: Tom Willett
		Date: 6/14/2013
#>
	if ($size -ge 1PB) {
		$hsize = [string][math]::round(($size/1PB),0) + "P"
	} elseif ($size -ge 1TB) {
		$isize=[math]::round(($size/1TB),0)
		$hsize=[string]$isize + "T"
	} elseif ($size -ge 1GB) {
		$isize=[math]::round(($size/1GB),0)
		$hsize=[string]$isize + "G"
	} elseif ($size -ge 1MB) {
		$isize=[math]::round(($size/1MB),0)
		$hsize=[string]$isize + "M"
	} elseif ($size -ge 1KB) {
		$isize=[math]::round(($size/1KB),0)
		$hsize=[string]$isize + "K"
	}
	$hsize += "B"
	return $hsize
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
	out-debug "process-Registries.ps1"
	out-debug "Computername = $Computername"
	out-debug "Basedir = $basedir"
	out-debug "Systemdir = $systemdir"
	out-debug "Userdir = $userdir"
	out-debug "Userinfo = $userinfo"
}

$basedir = get-path $basedir

push-location $basedir

$userinfo = get-path $userinfo

$systemdir = get-path $systemdir

$userdir = get-path $userdir

$imagedate = [datetime]::parse((get-content ($basedir + 'ImageDate.txt'))).adddays(-30)

write-log "Processing System Registries for $computername" -fore yellow
out-debug "Processing SystemInfo with systeminfo.reb"
get-regbatch -title 'SystemInfo' -computer $computername -batch 'systeminfo.reb' -path $systemdir -out '~SystemInfo.csv'
out-debug "Processing AuditInfo with audit.reb"
get-regbatch -title 'AuditInfo' -computer $computername -batch 'audit.reb' -path $systemdir -out '~Audit.csv'
out-debug "Processing Services with services.reb"
get-regbatch -title 'Services' -computer $computername -batch 'services.reb' -path $systemdir -out '~services.csv'
out-debug "Processing unquoted service paths"
get-unquotedservicepaths(($computername + '~services.csv')) | export-csv -notype ($computername + '~unquotedservicepaths.csv')

out-debug "Processing 'Installed User Software' with installedsoftware.reb"
get-regbatch -title 'Installed User Software' -computer $computername -batch 'installedsoftware.reb' -path $userdir -out '~usersoftware.csv'

out-debug "Processing 'Installed System Software' with installedsoftware.reb"
get-regbatch -title 'Installed System Software' -computer $computername -batch 'installedsoftware.reb' -path $systemdir -out '~systemsoftware.csv'

mkdir Shellbags  >> $null
set-location ShellBags
	write-log "Getting Shellbags"
	out-debug "Executing command: & $sb -d ($userDir) --csv ."
	& $sb -d ($userDir) --csv . | out-debug
	get-childitem *.csv | foreach-object{$csvfile = $computername + '~' + $_.name
					move-item $_.name $csvfile
					Normalize-Date $csvfile 'LastInteracted,FirstInteracted,LastWriteTime'
				}
	get-childitem * |foreach-object{$g = $_.name | select-string '(^.*?~).*?Users(_.*)';$t = $g.matches.groups[1].value + 'Shellbags' + $g.matches.groups[2].value;move-item $_.name $t}
	get-childitem * | where-object length -eq 0 | remove-item
	get-childitem *.csv | ForEach-Object{$sbs += import-csv $_ | Where-Object {[datetime]::parse($_.Lastinteracted) -ge $imagedate}}
	if ($sbs) {
		$sbs | export-csv -notype ($computername + '~RecentShellbags.csv')
		write-ioc ('Check ' + $computername + '~RecentShellbags' + ' for activity.')
	}
set-location ..

set-location $userinfo

write-log "Processing  User Registries for $computername" -fore yellow

write-log "Getting User Info from Registries"
#get-regbatch -title 'UserSamInfo' -computer $computername -batch 'sam.reb' -path $systemdir -out '~UserSam.csv'

out-debug "Processing UserActivity with userActivity.reb"
get-regbatch -title 'UserActivity' -computer $computername -batch 'userActivity.reb' -path $userDir -out '~UserActivity.csv'

if (get-childitem *recentdocs.csv | where-object{import-csv $_ | where-object {$_.extension -eq '.iso'}}){
	write-ioc "ISO files have been opened - check *recentDocs.csv files"
}


set-location ..

get-systeminfo $computername $basedir $userinfo $userdir

get-auditinfo $computername $basedir

set-location $userinfo

get-childitem ((get-date).year.tostring() + "*") | foreach-object{
	copy-item (".\" + $_.Name + "\*") .
	remove-item -recurse (".\" + $_.Name)
}

import-csv ($computername + '~UserActivity.csv') | where-object {$_.valuename -eq 'RemotePath'} | select-object @{Name='User';Expression={$u = $_.HivePath -replace '\\NTUSER.DAT','';$u.substring($u.lastindexof('\')+1)}},@{Name='Drive';Expression={$_.keypath -replace '*\\Network\\',''}},@{Name="Path";Expression={$_.valuedata}} | export-csv -notype ($computername + '~mappedDrives.csv')

out-debug "Checking for common IOCs"
$usa = import-csv ($computername + '~UserActivity_UserAssist.csv')
if ($usa | Where-Object {$_.ProgramName -like ('*mi"+ "mik" + "atz*')}) {
	write-ioc "Check for mi" + "mik" + "atz usage"
}
if ($usa | Where-Object {$_.ProgramName -like '*CloudBerry*'}) {
	write-ioc "Check for CloudBerry Remote Assist activity"
}
if ($usa | Where-Object {$_.ProgramName -like ('*gme' + 'r*.exe*')}) {
	write-ioc "Check for gmer.exe activity"
}
if ($usa | Where-Object {$_.ProgramName -like ('*anx' + 'insec*.exe*')}) {
	write-ioc "Check for *anxinsec.exe activity"
}

$sinfo = import-csv ($basedir + $computername + '~SystemInfo.csv')
if ($sinfo | Where-Object {$_.keypath -like '*Image File Execution Options*' -and $_.ValueName -eq 'Debugger'}) {
	write-ioc "Check for Debugger Key on Image File Execution Options"
}
if ($sinfo | where-object {($_.keypath -eq '*\Microsoft\Windows\CurrentVersion\Run' -or $_.keypath -eq '*\Microsoft\Windows\CurrentVersion\RunOnce') -and [datetime]::parse($_.LastWriteTimestamp) -gt $imagedate}) {
	write-ioc "Check System Run keys"
}
if ($sinfo | where-object {$_.keypath -like '*\Microsoft\Windows NT\CurrentVersion\AeDebug'}){
	write-ioc "Found AeDebug entries under HKLM\Software\Microsoft\Windows NT\CurrentVersion\AeDebug that should be investigatied"
}
if ($sinfo | where-object {$_.keypath -like '*\Microsoft\Windows\Windows Error Reporting\Hangs' -and ($_.ValueName -eq 'Debugger' -or $_.ValueName -eq 'ReflectDebugger')}) {
	write-ioc "Check WER Debugger entry HKLM\Software\Microsoft\Windows\Windows Error Reporting\Hangs"
}
if ($sinfo | where-object {$_.keypath -like '*\Microsoft\Command Processor' -and $_.ValueName -eq 'AutoRun'}) {
	write-ioc "Check Command Processor Autorun key HKLM\Software\Microsoft\Command Processor "
}
if ($sinfo | where-object {$_.keypath -like '*\Microsoft\Windows NT\CurrentVersion\Windows' -and $_.Valuename -eq 'Load'}){
	write-ioc "Check Windows Load Key HKLM\Software\Microsoft\Windows NT\CurrentVersion\Windows"
}
if ($sinfo | where-object {$_.keypath -like '*\Microsoft\Windows NT\CurrentVersion\WinLogon' -and $_.Valuename -eq 'UserInit' -and $_.ValueData -ne 'C:\Windows\system32\userinit.exe,'}) {
	write-ioc "Check Winlogon Userinit property - It is not standard"
}
if ($sinfo | where-object {$_.keypath -like '*\Microsoft\Windows NT\CurrentVersion\WinLogon' -and $_.Valuename -eq 'Shell' -and $_.ValueData -ne 'explorer.exe'}) {
	write-ioc "Check Winlogon Shell property - It is not standard"
}
if ($sinfo | where-object {$_.keypath -like '*\Microsoft\Windows NT\CurrentVersion\WinLogon' -and $_.Valuename -eq 'mpnotify'}) {
	write-ioc "Check Winlogon MPnotify property - It is not standard"
}

$svcinfo = import-csv ($basedir + $computername + '~Services.csv')
if ($svcinfo | where-object {$_.ValueName -eq 'ImagePath' -and $_.valuedata -like '*tmp*'}){
	write-ioc "Check Service running from tempory path"
}
if ($svcinfo | where-object {$_.ValueName -eq 'ImagePath' -and $_.valuedata -like '*temp*'}){
	write-ioc "Check Service running from tempory path"
}
if ($svcinfo | where-object {$_.ValueName -eq 'ImagePath' -and $_.valuedata -like '*appdata*'}) {
	write-ioc "Check service running from Users APPDATA"
}
if ($svcinfo | where-object {$_.ValueName -eq 'ImagePath' -and $_.valuedata -like '*\users\*'}) {
	write-ioc "Check service running from User Directory"
}

$uinfo = import-csv ($userinfo + $computername + '~useractivity.csv')
if ($uinfo | where-object {($_.keypath -eq '*\SOFTWARE\Microsoft\Windows\CurrentVersion\Run' -or $_.keypath -eq '*\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce') -and [datetime]::parse($_.LastWriteTimestamp) -gt $imagedate}) {
	write-ioc "Check User Run Keys"
}



write-log 'Normalizing Data' -fore green
Normalize-Date ($computername + '~mappedDrives.csv') ""
Normalize-Date ($computername + '~UserActivity_FileExts.csv') ''
Normalize-Date ($computername + '~UserActivity.csv') 'LastWriteTimeStamp'
Normalize-Date ($computername + '~UserActivity_CIDSizeMRU.csv') 'OpenedOn'
Normalize-Date ($computername + '~UserActivity_LastVisitedPidlMRU.csv') 'OpenedOn'
Normalize-Date ($computername + '~UserActivity_RunMRU.csv') 'OpenedOn'
Normalize-Date ($computername + '~UserActivity_OfficeMRU.csv') 'LastClosed'
Normalize-Date ($computername + '~UserActivity_OpenSavePidlMRU.csv') 'OpenedOn'
Normalize-Date ($computername + '~UserActivity_FirstFolder.csv') 'OpenedOn'
Normalize-Date ($computername + '~UserActivity_RecentApps.csv') 'LastAccessed'
Normalize-Date ($computername + '~UserActivity_RecentDocs.csv') 'OpenedOn'
Normalize-Date ($computername + '~UserActivity_TrustedDocuments.csv') 'Timestamp'
Normalize-Date ($computername + '~UserActivity_TypedURLs.csv') 'Timestamp'
Normalize-Date ($computername + '~UserActivity_UserAssist.csv') 'LastExecuted'
Normalize-Date ($computername + '~UserActivity_WordWheelQuery.csv') 'LastWriteTimestamp'
Normalize-Date ($computername + '~UserActivity_TerminalServerClient.csv') 'LastModified'
Normalize-Date ($computername + '~UserActivity_Taskband.csv') ''

set-location $basedir

$gpu = import-csv ($computername + '~SystemInfo.csv') | Where-Object {$_.KeyPath -like "ROOT\Microsoft\Windows\CurrentVersion\Group Policy\DataStore\S*\0" -and $_.valuename -eq 'szName'}

$out = ($computername + '-GroupPolicyUsers.txt')
"Group Policy Users" | add-content $out
$gpu | foreach-object {$len = $_.keypath.lastindexof('\')-61;$_.ValueData + ' - ' + $_.keypath.substring(61,$len) | add-content $out}

get-childitem ((get-date).year.tostring() + "*") | foreach-object{
	copy-item (".\" + $_.Name + "\*") .
	remove-item -recurse (".\" + $_.Name)
}

Normalize-Date ($computername + '~unquotedservicepaths.csv') '' 
Normalize-Date ($computername + '~SystemInfo_TimeZoneInfo.csv') ''
Normalize-Date ($computername + '~SystemInfo_MountedDevices.csv') ''
Normalize-date ($computername + '~EnvironmentVariable.csv') ""
Normalize-Date ($computername + '~systemsoftware.csv') 'LastWriteTimeStamp'
Normalize-Date ($computername + '~usersoftware.csv') 'LastWriteTimeStamp'
Normalize-Date ($computername + '~services.csv') 'LastWriteTimeStamp'
Normalize-Date ($computername + '~Audit.csv') 'LastWriteTimeStamp'
Normalize-Date ($computername + '~SystemInfo.csv') 'LastWriteTimeStamp'
Normalize-Date ($computername + '~services_BluetoothBthPort.csv') 'LastSeen'
Normalize-Date ($computername + '~services_Services.csv') 'NameKeyLastWrite'

get-childitem *_BamDam.csv | foreach-object{
	Normalize-Date $_.name 'ExecutionTime'
}

##########
write-log 'Finished Processing System Registries'
pop-location
