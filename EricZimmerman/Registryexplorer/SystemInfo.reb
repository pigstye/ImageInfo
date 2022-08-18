Description: Basic System Information
Author: Troy Larson - Modified Tom Willett
Version: 1
Id: 1e145fa4-70ca-478f-b0b9-a148e4ba1b90
Keys:
    -
        Description: GroupPolicy Users
        HiveType: Software
        Category: User Info
        KeyPath: Microsoft\Windows\CurrentVersion\Group Policy\DataStore\*
        Recursive: True
        Comment: 0 key Under Each User SID contains username domain 
    -
        Description: WER Hangs Debugger
        HiveType: Software
        Category: Autoruns
        KeyPath: Microsoft\Windows\Windows Error Reporting\Hangs\*
        Recursive: True
        Comment: 
    -
        Description: WinLogon Key
        HiveType: Software
        Category: Autoruns
        KeyPath: Microsoft\Windows NT\CurrentVersion\WinLogon
        Recursive: True
        Comment: 
    -
        Description: AeDebug Key
        HiveType: Software
        Category: Autoruns
        KeyPath: Microsoft\Windows NT\CurrentVersion\AeDebug\
        ValueName: Debugger
        Recursive: False
        Comment: 
    -
        Description: Command Processor Autorun Key
        HiveType: Software
        Category: Autoruns
        KeyPath: Microsoft\Command Processor\
        ValueName: AutoRun
        Recursive: False
        Comment: 
    -
        Description: IsCloudDomainJoined
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Enterprise
        ValueName: IsCloudDomainJoined
        Recursive: false
        Comment: 
    -
        Description: RegistryScheduledTask
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tasks\*
        Recursive: True
        Comment: Scheduled Tasks
    -
        Description: RegistryScheduledTree
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\Schedule\Taskcache\Tree\*
        Recursive: True
        Comment: Scheduled Tasks Tree
    -
        Description: ServerFeatures
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Enterprise
        ValueName: ServerFeatures
        Recursive: false
        Comment: 
    -
        Description: PKICiphers
        HiveType: System
        Category: System Info
        KeyPath: ControlSet*\Control\SecurityProviders\SCHANNEL\Ciphers\*
        Recursive: true
        Comment: Ciphers installed on System
    -
        Description: PKICiphers
        HiveType: System
        Category: System Info
        KeyPath: ControlSet*\Control\Cryptography\Configuration\Local\SSL\*
        Recursive: true
        Comment: Ciphers installed on System
    -
        Description: PKICiphers
        HiveType: System
        Category: System Info
        KeyPath: ControlSet*\Control\SecurityProviders\SCHANNEL\Hashes\*
        Recursive: true
        Comment: Ciphers installed on System
    -
        Description: PKICiphers
        HiveType: System
        Category: System Info
        KeyPath: ControlSet*\Control\SecurityProviders\SCHANNEL\Protocols\*
        Recursive: true
        Comment: Ciphers installed on System
    -
        Description: PKICiphers
        HiveType: System
        Category: System Info
        KeyPath: ControlSet*\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\PKCS\*
        Recursive: true
        Comment: Ciphers installed on System
    -
        Description: IsCloudDomainJoined
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Enterprise
        ValueName: IsCloudDomainJoined
        Recursive: false
        Comment: 
    -
        Description: ServerFeatures
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Enterprise
        ValueName: ServerFeatures
        Recursive: false
        Comment: 
    -
        Description: AzureVMType
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Enterprise
        ValueName: AzureVMType
        Recursive: false
        Comment: 
    -
        Description: AzureOSIDPresent
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Enterprise
        ValueName: AzureOSIDPresent
        Recursive: false
        Comment: 
    -
        Description: IsDomainJoined
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Enterprise
        ValueName: IsDomainJoined
        Recursive: false
        Comment: 
    -
        Description: SystemCenterID
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Enterprise
        ValueName: SystemCenterID
        Recursive: false
        Comment: 
    -
        Description: MPNId
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Enterprise
        ValueName: MPNId
        Recursive: false
        Comment: 
    -
        Description: SCCMClientId
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Enterprise
        ValueName: SCCMClientId
        Recursive: false
        Comment: 
    -
        Description: IsDeviceProtected
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Enterprise
        ValueName: IsDeviceProtected
        Recursive: false
        Comment: 
    -
        Description: IsDERequirementMet
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Enterprise
        ValueName: IsDERequirementMet
        Recursive: false
        Comment: 
    -
        Description: IsEDPEnabled
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Enterprise
        ValueName: IsEDPEnabled
        Recursive: false
        Comment: 
    -
        Description: ComputerHardwareID
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Hardware
        ValueName: ComputerHardwareID
        Recursive: false
        Comment: 
    -
        Description: DeviceName
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Hardware
        ValueName: DeviceName
        Recursive: false
        Comment: 
    -
        Description: OEMManufacturerName
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Hardware
        ValueName: OEMManufacturerName
        Recursive: false
        Comment: 
    -
        Description: OEMModelNumber
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Hardware
        ValueName: OEMModelNumber
        Recursive: false
        Comment: 
    -
        Description: OEMSerialNumber
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Hardware
        ValueName: OEMSerialNumber
        Recursive: false
        Comment: 
    -
        Description: InventoryId
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Hardware
        ValueName: InventoryId
        Recursive: false
        Comment: 
    -
        Description: TPMVersion
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Hardware
        ValueName: TPMVersion
        Recursive: false
        Comment: 
    -
        Description: PowerPlatformRole
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Hardware
        ValueName: PowerPlatformRole
        Recursive: false
        Comment: 
    -
        Description: TelemetryLevel
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Hardware
        ValueName: TelemetryLevel
        Recursive: false
        Comment: 
    -
        Description: TotalPhysicalRAM
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Memory
        ValueName: TotalPhysicalRAM
        Recursive: false
        Comment: 
    -
        Description: TotalVisibleMemory
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Memory
        ValueName: TotalVisibleMemory
        Recursive: false
        Comment: 
    -
        Description: NetworkAdapterGUID
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Network
        ValueName: NetworkAdapterGUID
        Recursive: false
        Comment: 
    -
        Description: IsPortableOperatingSystem
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\OS
        ValueName: IsPortableOperatingSystem
        Recursive: false
        Comment: 
    -
        Description: IsSecureBootEnabled
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\OS
        ValueName: IsSecureBootEnabled
        Recursive: false
        Comment: 
    -
        Description: OSEdition
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\OS
        ValueName: OSEdition
        Recursive: false
        Comment: 
    -
        Description: InstallationType
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\OS
        ValueName: InstallationType
        Recursive: false
        Comment: 
    -
        Description: OSOOBEDateTime
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\OS
        ValueName: OSOOBEDateTime
        Recursive: false
        Comment: 
    -
        Description: OSUILocale
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\OS
        ValueName: OSUILocale
        Recursive: false
        Comment: 
    -
        Description: CompactOS
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\OS
        ValueName: CompactOS
        Recursive: false
        Comment: 
    -
        Description: ProductKeyID2
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\OS
        ValueName: ProductKeyID2
        Recursive: false
        Comment: 
    -
        Description: ServiceMachineIP
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\OS
        ValueName: ServiceMachineIP
        Recursive: false
        Comment: 
    -
        Description: ServiceProductKeyID
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\OS
        ValueName: ServiceProductKeyID
        Recursive: false
        Comment: 
    -
        Description: LanguagePacks
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\OS
        ValueName: LanguagePacks
        Recursive: false
        Comment: 
    -
        Description: InstallLanguage
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\OS
        ValueName: InstallLanguage
        Recursive: false
        Comment: 
    -
        Description: ActivationChannel
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\OS
        ValueName: ActivationChannel
        Recursive: false
        Comment: 
    -
        Description: GenuineState
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\OS
        ValueName: GenuineState
        Recursive: false
        Comment: 
    -
        Description: OSSKU
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\OS
        ValueName: OSSKU
        Recursive: false
        Comment: 
    -
        Description: OSInstallType
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\OS
        ValueName: OSInstallType
        Recursive: false
        Comment: 
    -
        Description: DeviceTimeZone
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\OS
        ValueName: DeviceTimeZone
        Recursive: false
        Comment: 
    -
        Description: ProcessorCores
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Processor
        ValueName: ProcessorCores
        Recursive: false
        Comment: 
    -
        Description: ProcessorPhysicalCores
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Processor
        ValueName: ProcessorPhysicalCores
        Recursive: false
        Comment: 
    -
        Description: SocketCount
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Processor
        ValueName: SocketCount
        Recursive: false
        Comment: 
    -
        Description: ProcessorArchitecture
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Processor
        ValueName: ProcessorArchitecture
        Recursive: false
        Comment: 
    -
        Description: ProcessorClockSpeed
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Processor
        ValueName: ProcessorClockSpeed
        Recursive: false
        Comment: 
    -
        Description: ProcessorManufacturer
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Processor
        ValueName: ProcessorManufacturer
        Recursive: false
        Comment: 
    -
        Description: ProcessorIdentifier
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Processor
        ValueName: ProcessorIdentifier
        Recursive: false
        Comment: 
    -
        Description: ProcessorModel
        HiveType: Amcache
        Category: System Info
        KeyPath: DeviceCensus\Processor
        ValueName: ProcessorModel
        Recursive: false
        Comment: 
    -
        Description: Account Aliases
        HiveType: SAM
        Category: System Info
        KeyPath: SAM\Domains\Account\Aliases\Members\*
        Recursive: true
        Comment: 
    -
        Description: Account Aliases
        HiveType: SAM
        Category: System Info
        KeyPath: SAM\Domains\Account\Aliases\Names\*
        Recursive: true
        Comment: 
    -
        Description: Account Groups
        HiveType: SAM
        Category: System Info
        KeyPath: SAM\Domains\Account\Groups\*
        Recursive: true
        Comment: 
    -
        Description: Account Groups
        HiveType: SAM
        Category: System Info
        KeyPath: SAM\Domains\Account\Groups\Names\*
        Recursive: true
        Comment: 
    -
        Description: Account Users
        HiveType: SAM
        Category: System Info
        KeyPath: SAM\Domains\Account\Users\*
        Recursive: true
        Comment: 
    -
        Description: Account Users
        HiveType: SAM
        Category: System Info
        KeyPath: SAM\Domains\Account\Users\Names\*
        Recursive: true
        Comment: 
    -
        Description: Machine SID
        HiveType: Security
        Category: System Info
        KeyPath: (Default)
        ValueName: Policy\PolAcDmS
        Recursive: false
        Comment: 
    -
        Description: Domain SID
        HiveType: Security
        Category: System Info
        KeyPath: Policy\PolPrDmS
        ValueName: (Default)
        Recursive: false
        Comment: 
    -
        Description: VM DhcpWithFabricAddressTime
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Virtual Machine\Guest
        ValueName: DhcpWithFabricAddressTime
        Recursive: false
        Comment: 
    -
        Description: VM GuestAgentVersion
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Virtual Machine\Guest
        ValueName: GuestAgentVersion
        Recursive: false
        Comment: 
    -
        Description: VM OSVersion
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Virtual Machine\Guest
        ValueName: OSVersion
        Recursive: false
        Comment: 
    -
        Description: VM GuestAgentStartTime
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Virtual Machine\Guest
        ValueName: GuestAgentStartTime
        Recursive: false
        Comment: 
    -
        Description: VM oobeSystem_PA_CompletionTime
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Virtual Machine\Guest
        ValueName: oobeSystem_PA_CompletionTime
        Recursive: false
        Comment: 
    -
        Description: VM oobeSystem_PA_OSVersion
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Virtual Machine\Guest
        ValueName: oobeSystem_PA_OSVersion
        Recursive: false
        Comment: 
    -
        Description: Windows Defender Exclusions
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows Defender\Exclusions\*
        Recursive: false
        Comment: 
    -
        Description: Defender Real-Time Protection
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows Defender\Real-Time Protection
        Recursive: false
        Comment: 
    -
        Description: BuildLab
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: BuildLab
        Recursive: false
        Comment: 
    -
        Description: BuildLabEx
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: BuildLabEx
        Recursive: false
        Comment: 
    -
        Description: BuildBranch
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: BuildBranch
        Recursive: false
        Comment: 
    -
        Description: BuildGUID
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: BuildGUID
        Recursive: false
        Comment: 
    -
        Description: CompositionEditionID
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: CompositionEditionID
        Recursive: false
        Comment: 
    -
        Description: CurrentBuild
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: CurrentBuild
        Recursive: false
        Comment: 
    -
        Description: CurrentBuildNumber
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: CurrentBuildNumber
        Recursive: false
        Comment: 
    -
        Description: CurrentMajorVersionNumber
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: CurrentMajorVersionNumber
        Recursive: false
        Comment: 
    -
        Description: CurrentMinorVersionNumber
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: CurrentMinorVersionNumber
        Recursive: false
        Comment: 
    -
        Description: CurrentType
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: CurrentType
        Recursive: false
        Comment: 
    -
        Description: CurrentVersion
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: CurrentVersion
        Recursive: false
        Comment: 
    -
        Description: Customizations
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: Customizations
        Recursive: false
        Comment: 
    -
        Description: EditionID
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: EditionID
        Recursive: false
        Comment: 
    -
        Description: InstallDate
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: InstallDate
        Recursive: false
        Comment: 
    -
        Description: ProductID
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: ProductID
        Recursive: false
        Comment: 
    -
        Description: ProductName
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: ProductName
        Recursive: false
        Comment: 
    -
        Description: RegisteredOrganization
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: RegisteredOrganization
        Recursive: false
        Comment: 
    -
        Description: RegisteredOwner
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: RegisteredOwner
        Recursive: false
        Comment: 
    -
        Description: NetworkCards ServiceName
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkCards
        ValueName: ServiceName
        Recursive: false
        Comment: 
    -
        Description: NetworkCards Description
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkCards\*
        ValueName: Description
        Recursive: false
        Comment: 
    -
        Description: NetworkList Profiles Category
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\*
        ValueName: Category
        Recursive: false
        Comment: 
    -
        Description: NetworkList Profiles Description
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\*
        ValueName: Description
        Recursive: false
        Comment: 
    -
        Description: NetworkList Profiles Managed
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\*
        ValueName: Managed
        Recursive: false
        Comment: 
    -
        Description: NetworkList Profiles NameType
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\*
        ValueName: NameType
        Recursive: false
        Comment: 
    -
        Description: NetworkList Profiles ProfileName
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\*
        ValueName: ProfileName
        Recursive: false
        Comment: 
    -
        Description: ProfileList Flags
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\ProfileList\*
        ValueName: Flags
        Recursive: false
        Comment: 
    -
        Description: ProfileList ProfileImagepath
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\ProfileList\*
        ValueName: ProfileImagepath
        Recursive: false
        Comment: 
    -
        Description: ProfileList RunLogonScriptsync
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\ProfileList\*
        ValueName: RunLogonScriptsync
        Recursive: false
        Comment: 
    -
        Description: ProfileList Sid
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\ProfileList\*
        ValueName: Sid
        Recursive: false
        Comment: 
    -
        Description: ProfileList State
        HiveType: Software
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\ProfileList\*
        ValueName: State
        Recursive: false
        Comment: 
    -
        Description: FirmwareBootDevice
        HiveType: System
        Category: System Info
        KeyPath: ControlSet*\Control
        ValueName: FirmwareBootDevice
        Recursive: false
        Comment: 
    -
        Description: SystemBootDevice
        HiveType: System
        Category: System Info
        KeyPath: ControlSet*\Control
        ValueName: SystemBootDevice
        Recursive: false
        Comment: 
    -
        Description: ComputerName
        HiveType: System
        Category: System Info
        KeyPath: ControlSet*\Control\ComputerName\*
        ValueName: ComputerName
        Recursive: false
        Comment: 
    -
        Description: DisableDeleteNotification
        HiveType: System
        Category: System Info
        KeyPath: ControlSet*\Control\FileSystem
        ValueName: DisableDeleteNotification
        Recursive: false
        Comment: Is TRIM disabled?
    -
        Description: NtfsEncryptPagingFile
        HiveType: System
        Category: System Info
        KeyPath: ControlSet*\Control\FileSystem
        ValueName: NtfsEncryptPagingFile
        Recursive: false
        Comment: 
    -
        Description: InstallLanguage
        HiveType: System
        Category: System Info
        KeyPath: ControlSet*\Control\Nls\Language
        ValueName: InstallLanguage
        Recursive: false
        Comment: 
    -
        Description: Session Manager Environment
        HiveType: System
        Category: System Info
        KeyPath: ControlSet*\Control\Session Manager\Environment
        Recursive: false
        Comment: 
    -
        Description: TimeZone Bias
        HiveType: System
        Category: System Info
        KeyPath: ControlSet*\Control\TimeZoneInformation
        ValueName: Bias
        Recursive: false
        Comment: 
    -
        Description: TimeZoneKeyName
        HiveType: System
        Category: System Info
        KeyPath: ControlSet*\Control\TimeZoneInformation
        ValueName: TimeZoneKeyName
        Recursive: false
        Comment: 
    -
        Description: Shares
        HiveType: System
        Category: System Info
        KeyPath: ControlSet*\Services\Lanmanserver\Shares
        Recursive: false
        Comment: 
    -
        Description: Tcpip Domain
        HiveType: System
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters
        ValueName: Domain
        Recursive: false
        Comment: 
    -
        Description: Tcpip Hostname
        HiveType: System
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters
        ValueName: Hostname
        Recursive: false
        Comment: 
    -
        Description: Tcpip4 Interfaces
        HiveType: System
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip\Parameters\Interfaces\*
        Recursive: false
        Comment: 
    -
        Description: Tcpip6 Interfaces
        HiveType: System
        Category: System Info
        KeyPath: ControlSet*\Services\Tcpip6\Parameters\Interfaces\*
        Recursive: false
        Comment: 
    -
        Description: Mounted Devices
        HiveType: System
        Category: System Info
        KeyPath: MountedDevices
        Recursive: false
        Comment: 
    -
        Description: SystemPartition
        HiveType: System
        Category: System Info
        KeyPath: Setup
        ValueName: SystemPartition
        Recursive: false
        Comment: 
    -
        Description: Tcpip Interfaces
        HiveType: System
        Category: System Info
        KeyPath: Select
        Recursive: false
        Comment: 
    -
        Description: AppCompatFlags CIT System
        HiveType: Software
        Category: Executables
        KeyPath: Microsoft\Windows NT\CurrentVersion\AppCompatFlags\CIT\System
        Recursive: false
        Comment: 
    -
        Description: AppCompatFlags CIT Module
        HiveType: Software
        Category: Executables
        KeyPath: Microsoft\Windows NT\CurrentVersion\AppCompatFlags\CIT\Module\*
        Recursive: true
        Comment: 
    -
        Description: Group Policy Run Key
        HiveType: SOFTWARE
        Category: Autoruns
        KeyPath: Microsoft\Windows\CurrentVersion\policies\Explorer\Run
        Recursive: false
        Comment: Group Policy Run Key
    -
        Description: System Run Key
        HiveType: SOFTWARE
        Category: Autoruns
        KeyPath: Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment: System Run Key
    -
        Description: System RunOnce Key
        HiveType: SOFTWARE
        Category: Autoruns
        KeyPath: Microsoft\Windows\CurrentVersion\RunOnce
        Recursive: false
        Comment: System RunOnce Key
    -
        Description: System RunOnceEx Key
        HiveType: SOFTWARE
        Category: Autoruns
        KeyPath: Microsoft\Windows\CurrentVersion\RunOnceEx
        Recursive: false
        Comment: System RunOnceEx Key
    -
        Description: System RunServicesEx Key
        HiveType: SOFTWARE
        Category: Autoruns
        KeyPath: Microsoft\Windows\CurrentVersion\RunServicesEx
        Recursive: false
        Comment: System RunServicesEx Key
    -
        Description: System Services Key
        HiveType: SOFTWARE
        Category: Autoruns
        KeyPath: Microsoft\Windows\CurrentVersion\RunServices
        Recursive: false
        Comment: System RunServices Key
    -
        Description: Winlogon Key
        HiveType: SOFTWARE
        Category: Autoruns
        KeyPath: Microsoft\Windows NT\CurrentVersion\Winlogon\*
        Recursive: true
        Comment: Winlogon Key
    -
        Description: Scripts Key
        HiveType: SOFTWARE
        Category: Autoruns
        KeyPath: Policies\Microsoft\Windows\System\Scripts
        Recursive: false
        Comment: Scripts Key
    -
        Description: Explorer Run
        HiveType: SOFTWARE
        Category: Autoruns
        KeyPath: Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
        Recursive: false
        Comment: Scripts Key
    -
        Description: Image Execution Options
        HiveType: SOFTWARE
        Category: Autoruns
        KeyPath: Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*
        Recursive: True
        Comment: Image Execution Options
    -
        Description: Pif Shell Open
        HiveType: SOFTWARE
        Category: Autoruns
        KeyPath: Classes\piffile\shell\open\command
        Recursive: false
        Comment: Pif Shell Open
    -
        Description: Exe Shell Open
        HiveType: SOFTWARE
        Category: Autoruns
        KeyPath: Classes\exefile\shell\open\command
        Recursive: false
        Comment: Exe Shell Open
    -
        Description: Hta Shell Open
        HiveType: SOFTWARE
        Category: Autoruns
        KeyPath: Classes\htafile\shell\open\command
        Recursive: false
        Comment: Hta Shell Open
    -
        Description: Portable Devices
        HiveType: SOFTWARE
        Category: Devices
        KeyPath: Microsoft\Windows Portable Devices\Devices\*
        Recursive: true
        Comment: Portable Devices
    -    
        Description: AppCompatCache
        HiveType: SYSTEM
        Category: Program Execution
        KeyPath: ControlSet00*\Control\Session Manager\AppCompatCache
        Recursive: false
        Comment: AppCompatCache
    -
        Description: Shutdown Time
        HiveType: SYSTEM
        Category: System Info
        KeyPath: ControlSet00*\Control\Windows
        ValueName: ShutdownTime
        Recursive: false
        Comment: Shutdown Time
