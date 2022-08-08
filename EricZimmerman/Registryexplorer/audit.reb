Description: Audit Info
Author: Tom Willett
Version: 1
Id: 1e145fa4-70ca-478f-b0b9-a148e4ba1b90
Keys:
    -
        Description: Defender Disable
        HiveType: Software
        Category: Audit
        KeyPath: Microsoft\Windows Defender\
        ValueName: DisableAntiSpyware
        Recursive: false
        Comment: Set to 1 to disable
    -
        Description: Defender Exclusions
        HiveType: Software
        Category: Audit
        KeyPath: Microsoft\Windows Defender\Exclusions\*
        Recursive: true
        Comment: Set to 1 to disable
    -
        Description: Defender Disable
        HiveType: Software
        Category: Audit
        KeyPath: Microsoft\Windows Defender\
        ValueName: DisableAntiVirus
        Recursive: false
        Comment: Set to 1 to disable
    -
        Description: Defender Disable
        HiveType: Software
        Category: Audit
        KeyPath: ControlSet001\Services\WinDefend
        ValueName: Start
        Recursive: false
        Comment: Set to 3 to disable
    -
        Description: CrowdStrike
        HiveType: Software
        Category: Audit
        KeyPath: CrowdStrike\*\*
        Recursive: True
        Comment: 
    -
        Description: MalwareBytes
        HiveType: Software
        Category: Audit
        KeyPath: MalwareBytes\*
        Recursive: True
        Comment: 
    -
        Description: McAfee
        HiveType: Software
        Category: Audit
        KeyPath: McAfee\*
        Recursive: True
        Comment: 
    -
        Description: KasperskyLab
        HiveType: Software
        Category: Audit
        KeyPath: KasperskyLab\*
        Recursive: True
        Comment: 
    -
        Description: Eset
        HiveType: Software
        Category: Audit
        KeyPath: Eset\*
        Recursive: True
        Comment: 
    -
        Description: Symantec
        HiveType: Software
        Category: Audit
        KeyPath: Symantec\*
        Recursive: True
        Comment: 
    -
        Description: Symantec
        HiveType: Software
        Category: Audit
        KeyPath: MalwareBytes\*
        Recursive: True
        Comment: 
    -
        Description: PowerShell Script Block Logging
        HiveType: Software
        Category: Audit
        KeyPath: Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging\
        ValueName: EnableScriptBlockLogging
        Recursive: false
        Comment: 
    -
        Description: PowerShell Module Logging
        HiveType: Software
        Category: Audit
        KeyPath: Policies\Microsoft\Windows\PowerShell\ModuleLogging\
        ValueName: EnableModuleLogging
        Recursive: false
        Comment: 
    -
        Description: PowerShell Transcription
        HiveType: Software
        Category: Audit
        KeyPath: Policies\Microsoft\Windows\PowerShell\Transcription\
        ValueName: EnableTranscripting
        Recursive: false
        Comment: 
    -
        Description: Windows Firewall
        HiveType: Software
        Category: Audit
        KeyPath: Policies\Microsoft\WindowsFirewall\*
        ValueName: EnableFirewall
        Recursive: True
        Comment: Set to 1 to enable
    -
        Description: Terminal Services
        HiveType: Software
        Category: Audit
        KeyPath: Policies\Microsoft\Windows NT\Terminal Services\*
        Recursive: True
        Comment: Set MinEncryptionLevel to 3 for max encryption 
    -
        Description: Terminal Services
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Control\Terminal Server\WinStations\RDP-TCP\
        ValueName: SecurityLayer
        Recursive: False
        Comment:  0 Rdp Encryption 1 Client Negotiate 2 TLS Security
    -
        Description: Terminal Services
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Control\Terminal Server\WinStations\RDP-TCP\
        ValueName: UserAuthentication
        Recursive: False
        Comment:  Network Level Authentication 0 off 1 on
    -
        Description: Terminal Services
        HiveType: System
        Category: Audit
        KeyPath: Controlset001\Control\Terminal Server
        ValueName: fDenyTSConnections
        Recursive: False
        Comment: 0 Enable 1 Disable 
    -
        Description: Proxy Enable
        HiveType: Software
        Category: Audit
        KeyPath: Microsoft\Windows\CurrentVersion\Internet Settings
        ValueName: ProxyEnable
        Recursive: False
        Comment: Set to 1 to enable
    -
        Description: Proxy Server
        HiveType: Software
        Category: Audit
        KeyPath: Microsoft\Windows\CurrentVersion\Internet Settings
        ValueName: ProxyServer
        Recursive: False
        Comment: Set to 1 to enable
    -
        Description: Security Center
        HiveType: Software
        Category: Audit
        KeyPath: Microsoft\Security Center\provider\*\*
        Recursive: True
        Comment: 
    -
        Description: Defender Disable
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Services\WinDefend
        ValueName: Start
        Recursive: false
        Comment: Set to 3 to disable
    -
        Description: Log File Size
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Services\Eventlog\*
        ValueName: MaxSize
        Recursive: true
        Comment: Max log file size
    -
        Description: Shutdown Time
        HiveType: SYSTEM
        Category: Audit
        KeyPath: ControlSet001\Control\Windows
        ValueName: ShutdownTime
        Recursive: false
        Comment: Shutdown Time
    -
        Description: PKICiphers
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Control\SecurityProviders\SCHANNEL\Ciphers\*
        Recursive: true
        Comment: Ciphers installed on System
    -
        Description: PKICiphers
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Control\Cryptography\Configuration\Local\SSL\*
        Recursive: true
        Comment: Ciphers installed on System
    -
        Description: PKICiphers
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Control\SecurityProviders\SCHANNEL\Hashes\*
        Recursive: true
        Comment: Ciphers installed on System
    -
        Description: PKICiphers
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Control\SecurityProviders\SCHANNEL\Protocols\*
        Recursive: true
        Comment: Ciphers installed on System
    -
        Description: PKICiphers
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS\*
        Recursive: true
        Comment: Ciphers installed on System
    -
        Description: NetBios over TCP
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Services\NetBT\Parameters\Interfaces\*
        ValueName: NetBiosOptions
        Recursive: true
        Comment: Set to 2 to disable
    -
        Description: Anonymous Shares
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Control\LSA\
        ValueName: RestrictAnonymousSAM
        Recursive: false
        Comment: Set to 1 to Restrict
    -
        Description: Anonymous Shares
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Control\LSA\
        ValueName: RestrictAnonymous
        Recursive: false
        Comment: Set to 1 to Restrict
    -
        Description: SMB Signing
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Services\LanManWorkstation\Parameters
        ValueName: EnableSecuritySignature
        Recursive: false
        Comment: Set to 1 to Enable
    -
        Description: SMB Signing
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Services\LanManWorkstation\Parameters
        ValueName: EnablePlainTextPassword
        Recursive: false
        Comment: Set to 1 to Enable
    -
        Description: SMB Signing
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Services\LanManWorkstation\Parameters
        ValueName: AllowInsecureGuestAuth
        Recursive: false
        Comment: Set to 1 to Enable
    -
        Description: SMB Signing
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Services\LanManWorkstation\Parameters
        ValueName: RequireSecuritySignature
        Recursive: false
        Comment: Set to 1 to Enable
    -
        Description: SMB Signing
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Services\LanManServer\Parameters
        ValueName: EnableSecuritySignature
        Recursive: false
        Comment: Set to 1 to Enable
    -
        Description: SMB Signing
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Services\LanManServer\Parameters
        ValueName: RequireSecuritySignature
        Recursive: false
        Comment: Set to 1 to Enable
    -
        Description: SMB Signing
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Services\LanManServer\Parameters
        ValueName: enableW9xsecuritysignature
        Recursive: false
        Comment: Set to 1 to Enable
    -
        Description: SMB Signing
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Services\LanManServer\Parameters
        ValueName: RestrictNullSessAccess
        Recursive: false
        Comment: Set to 1 to Enable
    -
        Description: SMBv1
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Services\LanManServer\Parameters
        ValueName: SMB1
        Recursive: false
        Comment: Set to 0 to Disable
    -
        Description: Applocker
        HiveType: Software
        Category: Audit
        KeyPath: Policies\Microsoft\Windows\SrpV2\Appx\*
        Recursive: true
        Comment: 
    -
        Description: Applocker
        HiveType: Software
        Category: Audit
        KeyPath: Policies\Microsoft\Windows\SrpV2\Exe\*
        Recursive: true
        Comment: 
    -
        Description: Applocker
        HiveType: Software
        Category: Audit
        KeyPath: Policies\Microsoft\Windows\SrpV2\DLL\*
        Recursive: true
        Comment: 
    -
        Description: Applocker
        HiveType: Software
        Category: Audit
        KeyPath: Policies\Microsoft\Windows\SrpV2\MSI\*
        Recursive: true
        Comment: 
    -
        Description: Applocker
        HiveType: Software
        Category: Audit
        KeyPath: Policies\Microsoft\Windows\SrpV2\Script\*
        Recursive: true
        Comment: 
    -
        Description: Credential Caching
        HiveType: Software
        Category: Audit
        KeyPath: Microsoft\Windows NT\CurrentVersion\Winlogon
        ValueName: CachedLogonsCount
        Recursive: false
        Comment: Set to 1 - for domain logins if no DC available
    -
        Description: Credential Caching
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Control\LSA
        ValueName: DisableDomainCreds
        Recursive: false
        Comment: Set to 1 to disable cached creds for network logon
    -
        Description: Credential Entry
        HiveType: Software
        Category: Audit
        KeyPath: Policies\Microsoft\Windows\System
        ValueName: EnumerateLocalUsers
        Recursive: false
        Comment: Set to 1 to enumerate local users on domain joined host
    -
        Description: Credential Entry
        HiveType: Software
        Category: Audit
        KeyPath: Policies\Microsoft\Windows\System
        ValueName: DontDisplayNetworkSelectionUI
        Recursive: false
        Comment: Set to 1 to prevent users interacting with network UI before login
    -
        Description: Credential Entry
        HiveType: Software
        Category: Audit
        KeyPath: Policies\Microsoft\Windows\CredUI
        ValueName: DisablePasswordReveal
        Recursive: false
        Comment: Set to 1 to disable password reveal button
    -
        Description: Credential Entry
        HiveType: Software
        Category: Audit
        KeyPath: Policies\Microsoft\Windows\CredUI
        ValueName: EnumerateAdministrators
        Recursive: false
        Comment: Set to 1 to allow enumeration
    -
        Description: User Account Control
        HiveType: Software
        Category: Audit
        KeyPath: Microsoft\Windows\CurrentVersion\Policies\System\*
        Recursive: true
        Comment: 
    -
        Description: Exploit Protection
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Control\Session Manager\kernel\
        ValueName: DisableExceptionChainValidation
        Recursive: false
        Comment: Set to 0 to enable (SEHOP)
    -
        Description: Exploit Protection
        HiveType: Software
        Category: Audit
        KeyPath: Policies\Microsoft\Windows\Explorer
        ValueName: NoDataExecutionPrevention
        Recursive: false
        Comment: Set to 1 to disable DEP
    -
        Description: Install Elevated
        HiveType: Software
        Category: Audit
        KeyPath: Policies\Microsoft\Windows\Installer
        ValueName: AlwaysInstallElevated
        Recursive: false
        Comment: Set to 0 to prevent
    -
        Description: Autorun
        HiveType: Software
        Category: Audit
        KeyPath: Microsoft\Windows\CurrentVersion\Policies\Explorer\
        ValueName: NoAutoRun
        Recursive: false
        Comment: Set to 1 to enable
    -
        Description: Passwords
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Control\LSA\
        ValueName: NoLMHash
        Recursive: false
        Comment: Set to 1 to Restrict
    -
        Description: Passwords
        HiveType: System
        Category: Audit
        KeyPath: ControlSet001\Control\LSA\
        ValueName: LmCompatibilityLevel
        Recursive: false
        Comment: 
    -
        Description: Passwords
        HiveType: Software
        Category: Audit
        KeyPath: Policies\Microsoft\Windows\WinRM\Service\
        ValueName: AllowBasic
        Recursive: false
        Comment: Set to 0 to disable plain text passwords
    -
        Description: Passwords
        HiveType: Software
        Category: Audit
        KeyPath: Policies\Microsoft\Windows\WinRM\Service\
        ValueName: AllowDigest
        Recursive: false
        Comment: Set to 0 to disable plain text passwords
    -
        Description: Passwords
        HiveType: Software
        Category: Audit
        KeyPath: Policies\Microsoft\Windows\WinRM\Service\
        ValueName: DisableRunAs
        Recursive: false
        Comment: 
    -
        Description: Passwords
        HiveType: Software
        Category: Audit
        KeyPath: Policies\Microsoft\Windows\WinRM\Client\
        ValueName: AllowUnencryptedTraffic
        Recursive: false
        Comment: 
