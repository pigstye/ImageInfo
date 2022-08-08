Description: Services batch file example
Author: Eric Zimmerman
Version: 1
Id: ab13eb5f-32db-6cdc-84df-58ec11dc1a
Keys:
    -
        Description: Services001
        HiveType: SYSTEM
        Category: Execution
        KeyPath: ControlSet001\Services\*
        DisablePlugin: false
        Recursive: true
        Comment: The list of services from 001
    -
        Description: Services002
        HiveType: SYSTEM
        Category: Execution
        KeyPath: ControlSet002\Services
        DisablePlugin: true
        Recursive: true
        Comment: The list of services from 002
    -
        Description: Bam
        HiveType: System
        Category: Executables
        KeyPath: ControlSet*\Services\bam\State\UserSettings\*
        Recursive: false
        Comment: 
    -
        Description: Bam
        HiveType: System
        Category: Executables
        KeyPath: ControlSet*\Services\bam\UserSettings\*
        Recursive: false
        Comment: 
    -
        Description: Dam
        HiveType: System
        Category: Executables
        KeyPath: ControlSet*\Services\dam\State\UserSettings\*
        Recursive: false
        Comment: 
    -
        Description: Dam
        HiveType: System
        Category: Executables
        KeyPath: ControlSet*\Services\dam\UserSettings\*
        Recursive: false
        Comment: 
