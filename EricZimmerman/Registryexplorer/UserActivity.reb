Description: User Configuration and Activity
Author: Troy Larson - Modified Tom Willett
Version: 1
Id: 87fafa06-0c44-48b1-9f2c-2eca469d1309
Keys:
    -
        Description: User Information
        HiveType: NtUser
        Category: User Activity
        KeyPath: Volatile Environment
        Recursive: True
        Comment: Contains username and environment
    -
        Description: Feature Usage
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FeatureUsage
        Recursive: True
        Comment: First 8 bytes TimeStamp - Enable Editing - Last Four 01 00 00 00 - Enable Content - FF FF FF 7F
    -
        Description: Office Usage
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Office\*\*\Security\Trusted Documents\TrustRecords
        Recursive: False
        Comment: First 8 bytes TimeStamp - Enable Editing - Last Four 01 00 00 00 - Enable Content - FF FF FF 7F
    -
        Description: Environment
        HiveType: NtUser
        Category: User Activity
        KeyPath: Environment
        Recursive: false
        Comment: ""
    -
        Description: Network
        HiveType: NtUser
        Category: User Activity
        KeyPath: Network
        Recursive: true
        Comment: ""
    -
        Description: Printer Connections
        HiveType: NtUser
        Category: User Activity
        KeyPath: Printers\Connections\*
        ValueName: Server
        Recursive: false
        Comment: 
    -
        Description: Printer Connections
        HiveType: NtUser
        Category: User Activity
        KeyPath: Printers\Settings\Wizard\ConnectMRU
        Recursive: false
        Comment: 
    -
        Description: Recent File List
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\*\*\Recent File List  
        Recursive: false
        Comment: 
    -
        Description: Recent Folder List
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\*\*\Recent Folder List 
        Recursive: false
        Comment: 
    -
        Description: Recent Document List
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\*\*\Settings\Recent Document List
        Recursive: false
        Comment: 
    -
        Description: 7-Zip
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\7-Zip\Compression
        Recursive: false
        Comment: See profile output.
    -
        Description: Adobe cRecentFiles
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Adobe\Acrobat Reader\DC\AVGeneral\cRecentFiles\*
        ValueName: tDIText
        Recursive: false
        Comment: 
    -
        Description: Adobe cRecentFolders
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Adobe\Acrobat Reader\DC\AVGeneral\cRecentFolders\*
        ValueName: tDIText
        Recursive: false
        Comment: 
    -
        Description: Recent
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\*\*\Recent  
        Recursive: false
        Comment: 
    -
        Description: RecentFind
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\*\*\RecentFind
        Recursive: false
        Comment: 
    -
        Description: Recent File List
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\*\Recent File List 
        Recursive: false
        Comment: 
    -
        Description: IE DOMStorage
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Internet Explorer\DOMStorage\*
        Recursive: false
        Comment: 
    -
        Description: IE TypedURLs
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Internet Explorer\TypedURLs
        Recursive: false
        Comment: See profile output.
    -
        Description: IE TypedURLsTime
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Internet Explorer\TypedURLsTime
        Recursive: false
        Comment: See profile output.
    -
        Description: Office MRU
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Office\*\*\User MRU\*\File MRU 
        Recursive: false
        Comment: 
    -
        Description: Office MRU
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Office\*\Common\Internet\Server Cache\*
        Recursive: True
        Comment: URL Opened by Office
    -
        Description: Office MRU
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Office\*\Common\Internet\WebServiceCache\*
        Recursive: True
        Comment: URL Opened By Office
    -
        Description: Office MRU
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Office\*\*\User MRU\*\Place MRU
        Recursive: false
        Comment: 
    -
        Description: Terminal Server Client
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Terminal Server Client
        Recursive: false
        Comment: See profile output.
    -
        Description: Terminal Server Client
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Terminal Server Client\Default
        Recursive: false
        Comment: MRU Computers RDP To
    -
        Description: Terminal Server Client
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Terminal Server Client\LocalDevices
        Recursive: false
        Comment: 
    -
        Description: Terminal Server Client
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Terminal Server Client\Servers\*
        ValueName: UsernameHint
        Recursive: false
        Comment: 
    -
        Description: VisualStudio FileMRUList
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\VisualStudio\*\FileMRUList
        Recursive: false
        Comment: 
    -
        Description: VisualStudio MRUItems 
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\VisualStudio\*\MRUItems\*\Items
        Recursive: false
        Comment: 
    -
        Description: VisualStudio MRUSettings
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\VisualStudio\*\NewProjectDialog\MRUSettingsLocalProjectLocationEntries
        Recursive: false
        Comment: 
    -
        Description: Recent File List
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\*\*\Recent File List
        Recursive: false
        Comment: 
    -
        Description: Applets Recent File List
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Applets\*\Recent File List
        Recursive: false
        Comment: 
    -
        Description: ComDlg32 CIDSizeMRU
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\CIDSizeMRU
        Recursive: false
        Comment: 
    -
        Description: ComDlg32 FirstFolder
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\FirstFolder
        Recursive: false
        Comment: 
    -
        Description: ComDlg32 LastVisitedMRU
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU
        Recursive: false
        Comment: 
    -
        Description: ComDlg32 LastVisitedPidlMRU
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRU
        Recursive: false
        Comment: 
    -
        Description: ComDlg32 LastVisitedPidlMRULegacy
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedPidlMRULegacy
        Recursive: false
        Comment: 
    -
        Description: ComDlg32 OpenSaveMRU
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSaveMRU 
        Recursive: true
        Comment: 
    -
        Description: ComDlg32 OpenSavePidlMRU
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\OpenSavePidlMRU
        Recursive: true
        Comment: 
    -
        Description: Explorer FileExts
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts
        Recursive: false
        Comment: See profile output.
    -
        Description: Explorer Map Network Drive MRU
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU
        Recursive: false
        Comment: 
    -
        Description: Mount Points
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\CPC\LocalMOF
        Comment: 
    -
        Description: Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs
        Recursive: true
        Comment: See profile output.
    -
        Description: Explorer\RunMRU
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU
        Recursive: false
        Comment: See profile output.
    -
        Description: Explorer StreamMRU
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\StreamMRU
        Recursive: false
        Comment: 
    -
        Description: Explorer Taskband
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband
        ValueName: Favorites
        Recursive: false
        Comment: 
    -
        Description: Explorer TypedPaths
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths
        Recursive: false
        Comment: 
    -
        Description: UserAssist
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\*\Count
        Recursive: false
        Comment:
    -
        Description: UserAssist Settings
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\Settings
        ValueName: NoLog
        Recursive: false
        Comment: 
    -
        Description: Explorer WordWheelQuery
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery
        Recursive: false
        Comment: 
    -
        Description: Group PolicyGroupMembership
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\GroupMembership
        Recursive: false
        Comment: 
    -
        Description: Group Policy History
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\History\*\*
        ValueName: DisplayName
        Recursive: false
        Comment: 
    -
        Description: Group Policy History
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\History\*\*
        ValueName: DSPath
        Recursive: false
        Comment: 
    -
        Description: Group Policy History
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\History\*\*
        ValueName: Extensions
        Recursive: false
        Comment: 
    -
        Description: Group Policy History
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\History\*\*
        ValueName: FileSysPath
        Recursive: false
        Comment: 
    -
        Description: Group Policy History
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\History\*\*
        ValueName: GPOLink
        Recursive: false
        Comment: 
    -
        Description: Group Policy History
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\History\*\*
        ValueName: GPOName
        Recursive: false
        Comment: 
    -
        Description: Group Policy History
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Group Policy\History\*\*
        ValueName: Link
        Recursive: false
        Comment: 
    -
        Description: Search RecentApps
        HiveType: NtUser
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Search\RecentApps
        Recursive: true
        Comment: 
    -
        Description: Edge Favorites
        HiveType: UsrClass
        Category: User Activity
        KeyPath: Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\Favorites
        Recursive: true
        Comment: 
    -
        Description: Edge TypedURLs
        HiveType: UsrClass
        Category: User Activity
        KeyPath: Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\TypedURLs
        Recursive: true
        Comment: 
    -
        Description: Edge TypedURLsTime
        HiveType: UsrClass
        Category: User Activity
        KeyPath: Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\TypedURLsTime
        Recursive: true
        Comment: 
    -
        Description: Edge TypedURLsVisitCount
        HiveType: UsrClass
        Category: User Activity
        KeyPath: Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\TypedURLsVisitCount
        Recursive: true
        Comment: 
    -
        Description: Modern App FileAssociations
        HiveType: UsrClass
        Category: User Activity
        KeyPath: Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\*\App\Capabilities\FileAssociations
        Recursive: true
        Comment: 
    -
        Description: Modern App URLAssociations
        HiveType: UsrClass
        Category: User Activity
        KeyPath: Local Settings\Software\Microsoft\Windows\CurrentVersion\AppModel\Repository\Packages\*\App\Capabilities\URLAssociations
        Recursive: true
        Comment: 
    -
        Description: Regedit.exe Last Run
        HiveType: NtUser
        Category: Executables
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Applets\Regedit
        Recursive: false
        Comment: 
    -
        Description: AppCompatFlags Compatibility Assistant Persisted
        HiveType: NtUser
        Category: Executables
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Compatibility Assistant\Persisted
        Recursive: false
        Comment: 
    -
        Description: AppCompatFlags Compatibility Assistant Store
        HiveType: NtUser
        Category: Executables
        KeyPath: Software\Microsoft\Windows Nt\CurrentVersion\AppCompatFlags\Compatibility Assistant\Store
        Recursive: false
        Comment: 
    -
        Description: AppCompatFlags Layers
        HiveType: NtUser
        Category: Executables
        KeyPath: Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers
        Recursive: false
        Comment: 
    -
        Description: Sysinternals Tools Run
        HiveType: NtUser
        Category: Executables
        KeyPath: Software\Sysinternals\*
        ValueName: EulaAccepted
        Recursive: false
        Comment: 
    -
        Description: User Run Key
        HiveType: NTUSER
        Category: Autoruns
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Run
        Recursive: false
        Comment: User Run Key
    -
        Description: User RunOnce Key
        HiveType: NTUSER
        Category: Autoruns
        KeyPath: Software\Microsoft\Windows\CurrentVersion\RunOnce
        Recursive: false
        Comment: User RunOnce Key
    -
        Description: User RunOnceEx Key
        HiveType: NTUSER
        Category: Autoruns
        KeyPath: Software\Microsoft\Windows\CurrentVersion\RunOnceEx
        Recursive: false
        Comment: User RunOnceEx Key
    -
        Description: Run
        HiveType: NTUSER
        Category: Program Execution
        KeyPath: SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run
        Recursive: false
        Comment: Run
    -
        Description: RunMRU
        HiveType: NTUSER
        Category: Program Execution
        KeyPath: SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\RunMRU
        Recursive: false
        Comment: RunMRU(Start>Run)
    -
        Description: Run
        HiveType: NTUSER
        Category: Program Execution
        KeyPath: SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
        ValueName: load
        Recursive: false
        Comment: Run
    -
        Description: Run
        HiveType: NTUSER
        Category: Program Execution
        KeyPath: SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows
        ValueName: run
        Recursive: false
        Comment: Run
    -
        Description: Run
        HiveType: NTUSER
        Category: Program Execution
        KeyPath: SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
        Recursive: true
        Comment: Run
    -
        Description: Run
        HiveType: NTUSER
        Category: Program Execution
        KeyPath: SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders
        Recursive: true
        Comment: Run
    -
        Description: Run
        HiveType: NTUSER
        Category: Program Execution
        KeyPath: SOFTWARE\Microsoft\Windows\CurrentVersion\Windows\Scripts
        Recursive: true
        Comment: Run
    -
        Description: Run
        HiveType: NTUSER
        Category: Program Execution
        KeyPath: SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\RecentDocs
        Recursive: true
        Comment: Run
    -
        Description: GroupPolicy
        HiveType: NTUSER
        Category: Permissions
        KeyPath: software\microsoft\windows\currentversion\grouppolicy\groupmembership
        Recursive: true
        Comment: GroupPolicy
