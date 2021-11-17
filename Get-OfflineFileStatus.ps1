function Get-TimeStamp {
    <#
        .SYNOPSIS
            Get a time stamp

        .DESCRIPTION
            Get a time date and time to create a custom time stamp

        .EXAMPLE
            None

        .NOTES
            Internal function
    #>

    [cmdletbinding()]
    param()
    return "[{0:MM/dd/yy} {0:HH:mm:ss}] -" -f (Get-Date)
}

function Save-Output {
    <#
    .SYNOPSIS
        Save output

    .DESCRIPTION
        Overload function for Write-Output

    .PARAMETER StringObject
        Inbound object to be printed and saved to log

    .PARAMETER InboundObject
        Inbound objects to be exported to csv

    .PARAMETER SaveFileOutput
        Flag for exporting the file object

    .EXAMPLE
        None

    .NOTES
        None
    #>

    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $True, Position = 0)]
        [string]
        $StringObject,

        [PSCustomObject]
        $InboundObject,

        [PSCustomObject]
        $FailureObject,

        [switch]
        $SaveFileOutput,

        [switch]
        $SaveFailureOutput
    )

    process {
        try {
            Write-Output $StringObject
            if ($InboundObject -and $SaveFileOutput.IsPresent) {
                $InboundObject | Export-Csv -Path (Join-Path -Path $EventLogSaveLocation -ChildPath $EventLogSaveFileName) -Append -NoTypeInformation -ErrorAction Stop
                return
            }

            if ($FailureObject -and $SaveFailureOutput.IsPresent) {
                $FailureObject | Export-Csv -Path (Join-Path -Path $LoggingDirectory -ChildPath $FailureLogSaveFileName) -Append -NoTypeInformation -ErrorAction Stop
                return
            }

            # Console and log file output
            Out-File -FilePath (Join-Path -Path $LoggingDirectory -ChildPath $LoggingFileName) -InputObject $StringObject -Encoding utf8 -Append -ErrorAction Stop
        }
        catch {
            Save-Output "$(Get-TimeStamp) ERROR: $_"
            return
        }
    }
}

function Get-OfflineFileStatus {
    <#
    .SYNOPSIS
        Check offline file sync status

    .DESCRIPTION
        Check offline file sync status and store reports in a share for review

    .PARAMETER Computers
        The computers you want to connect to

    .PARAMETER DisplayResultsOnConsole
        Shows all results to the console (noisy!)

    .PARAMETER DisableOfflineFileSyncDebugLogging
        Disable analytic logging locally or remotely

    .PARAMETER DomainComputers
        Search the entire domain for all computers to be scanned

    .PARAMETER EnableConsoleOutput
        Enable computer connection output to the console (noisy!)

    .PARAMETER EnableOfflineFileSyncDebugLogging
        By default analytic log is not enabled on computers. Enable it locally or remotely

    .PARAMETER EventLogSaveLocation
        Local or network share to save the computer event log entries

    .PARAMETER EventLogName
        Name of the event log we are scanning

    .PARAMETER EventLogSaveFileName
        Save file name

    .PARAMETER FailureLogSaveFileName
        Failure log save file name

    .PARAMETER Filter
        Search filter for searching all domain computers

    .PARAMETER FilterXml
        Pass in a custom WinEvent query string. Please see more information from here on -FilterXML https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.1#parameters

    .PARAMETER LoggingDirectory
        Logging directory

    .PARAMETER LoggingFileName
        Script execution log file

    .PARAMETER SaveEventLogsToLocation
        Switch to indicate you want to save results to a local or network location

    .PARAMETER UseCredentials
        Indicate that we need to pass administrator credentials

    .PARAMETER UserName
        Machine and user name that you want to connect as (Typically an administrator account)

    .EXAMPLE
        Get-OfflineFileStatus -DisplayErrors -SaveEventLogsToLocation -Computers Computer1, Computer2

        This will connect to Computer1 and Computer2 to search the event logs for events and display any warnings / errors found

    .EXAMPLE
        Get-OfflineFileStatus -DomainComputers -SaveEventLogsToLocation

        This will connect to to a domain controller and search for all computers based on filter and save the logs to a local or network share

    .EXAMPLE
        Get-OfflineFileStatus EnableOfflineFileSyncDebugLogging

        Enable offline sync debug logging on a local or remote machine

    .NOTES
        To search a domain this must be executed on a computer that has access to a domain controller or has RSAT installed to run Get-ADComputer

        Firewall port notes - These must be opened on the client inbound
        -------------------
        Remove Event Log Management (RPC-EPMAP)
        Remove Event Log Management (NP-In)
        Remove Event Log Management (RPC)
    #>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute("PSAvoidUsingConvertToSecureStringWithPlainText", "")]
    [CmdletBinding(DefaultParameterSetName = 'Default')]
    param (
        [object]
        $Computers,

        [switch]
        $DisplayResultsOnConsole,

        [switch]
        $DomainComputers,

        [Parameter(ParameterSetName = 'DebugLogging')]
        [switch]
        $DisableOfflineFileSyncDebugLogging,

        [switch]
        $EnableConsoleOutput,

        [Parameter(ParameterSetName = 'DebugLogging')]
        [switch]
        $EnableOfflineFileSyncDebugLogging,

        [string]
        $EventLogSaveLocation = 'c:\OfflineFileStatus',

        [string]
        $EventLogName = "Microsoft-Windows-OfflineFiles/SyncLog",

        [string]
        $EventLogSaveFileName = "OfflineFileStatusLog.csv",

        [string]
        $FailureLogSaveFileName = "FailuresLog.txt",

        [string]
        $Filter = "*",

        [string]
        $FilterXml,

        [string]
        $LoggingDirectory = 'C:\OfflineFileStatus',

        [string]
        $LoggingFileName = 'ScriptExecutionLogging.txt',

        [switch]
        $SaveEventLogsToLocation,

        [switch]
        $UseCredentials,

        [string]
        $UserName = "Computer\User"
    )

    begin {
        $parameters = $PSBoundParameters
        [System.Collections.ArrayList]$completedEntries = @()
        [System.Collections.ArrayList]$failureEntries = @()

        if (-NOT( Test-Path -Path $LoggingDirectory )) {
            try {
                $null = New-Item -Path $LoggingDirectory -Type Directory -ErrorAction Stop
                Save-Output "$(Get-TimeStamp) Directory not found. Creating $LoggingDirectory"
            }
            catch {
                Save-Output "$(Get-TimeStamp) ERROR: $_"
                return
            }
        }
        Save-Output "$(Get-TimeStamp) Starting process"
    }

    process {
        try {
            Save-Output "$(Get-TimeStamp) Setting event log to: $($EventLogName)"

            if ($parameters.ContainsKey('DomainComputers')) {
                $computersFound = Get-AdComputer -Filter $Filter
            }
            else {
                if (-NOT $Computers) {
                    Save-Output "$(Get-TimeStamp) ERROR: You did not specify a computer(s) to connect to"
                    return
                }
                else {
                    $computersFound = $Computers
                }
            }

            foreach ($computer in $computersFound) {
                # Checking to see if we passed a manual list or a domain found list
                if ($computer.Name) { $computer = $computer.Name }

                $script:RpcFailure = $false
                if ($parameters.ContainsKey('EnableOfflineFileSyncDebugLogging')) {
                    if ($parameters.ContainsKey('UseCredentials')) {
                        $password = ConvertTo-SecureString "YourAdminPassword" -AsPlainText -Force
                        $credentials = New-Object System.Management.Automation.PSCredential ($UserName, $password)
                        if (Invoke-Command -Computer $computer -Credential $credentials -ScriptBlock { wevtutil sl Microsoft-Windows-OfflineFiles/SyncLog /e:true /q } -ErrorAction SilentlyContinue -ErrorVariable Failed ) {
                            Save-Output "$(Get-TimeStamp) Analytic log enabled on $($computer)"
                            return
                        }
                    }
                }

                if ($parameters.ContainsKey('DisableOfflineFileSyncDebugLogging')) {
                    if ($parameters.ContainsKey('UseCredentials')) {
                        $password = ConvertTo-SecureString "YourAdminPassword" -AsPlainText -Force
                        $credentials = New-Object System.Management.Automation.PSCredential ($UserName, $password)
                        if (Invoke-Command -Computer $computer -Credential $credentials -ScriptBlock { wevtutil sl Microsoft-Windows-OfflineFiles/SyncLog /e:false /q } -ErrorAction SilentlyContinue -ErrorVariable Failed ) {
                            Save-Output "$(Get-TimeStamp) Analytic log disabled on $($computer)"
                            return
                        }
                    }
                }

                if ($parameters.ContainsKey('EnableConsoleOutput')) {
                    Save-Output "$(Get-TimeStamp) Grabbing events from $($computer)"
                }

                # Events in analytical or debug logs are ready from oldest to newest
                if ($parameters.ContainsKey('FilterXml') -and $WinEventQuery) {
                    $query = $WinEventQuery
                }
                else {
                    $query = @'
<QueryList>
<Query Id="0" Path="Microsoft-Windows-OfflineFiles/SyncLog">
<Select Path="Microsoft-Windows-OfflineFiles/SyncLog">*</Select>
</Query>
</QueryList>
'@
                }

                try {
                    # Get-WinEvent is using Windows Event Log remoting so this will not work inside Invoke-Command
                    if ($parameters.ContainsKey('UseCredentials')) {
                        $password = ConvertTo-SecureString "YourAdminPassword" -AsPlainText -Force
                        $credentials = New-Object System.Management.Automation.PSCredential ($UserName, $password)
                        $events = Get-WinEvent -ComputerName $computer -Credential $credentials -FilterXml $query -Oldest -ErrorAction SilentlyContinue -ErrorVariable Failed
                    }
                    else {
                        $events = Get-WinEvent -ComputerName $computer -FilterXml $query -Oldest -ErrorAction Stop
                    }
                }
                catch {
                    # Get-WinEvent uses Windowed Event Log Remoting so we will automatically fail out on a server we can not reach so need this try catch to tuff the exception and continue
                    $failedEntry = [PSCustomObject]@{
                        ComputerName = $computer
                        Time         = (Get-Date)
                        Action       = $_.CategoryInfo.Activity
                        Reason       = $_.CategoryInfo.Reason
                    }
                    $null = $failureEntries.add($failedEntry)
                    $script:RpcFailure = $true
                    continue
                }

                # Save event records for processing
                if ($Failed -and (-not $script:RpcFailure)) {
                    $failedEntry = [PSCustomObject]@{
                        ComputerName = $Failed.OriginInfo.PSComputerName
                        Time         = (Get-Date)
                        Action       = $Failed.CategoryInfo.Activity
                        Reason       = "$Failed.CategoryInfo.Reason"
                    }
                    $null = $failureEntries.add($failedEntry)
                }

                if ($events) {
                    foreach ($event in $events) {
                        $entry = [PSCustomObject]@{
                            ComputerName = $computer
                            Provider     = $event.ProviderName
                            Id           = $event.Id
                            TimeCreated  = $event.TimeCreated
                            Message      = $event.Message
                        }
                        $null = $completedEntries.add($entry)
                    }
                }
                else {
                    $entry = [PSCustomObject]@{
                        ComputerName = $computer
                        TimeCreated  = (Get-Date)
                        Message      = "No events found in the event log"
                    }
                    $null = $completedEntries.add($entry)
                }

                if ($parameters.ContainsKey('SaveEventLogsToLocation')) {
                    if ($SaveLogLocation -eq 'Default') {
                        Save-Output "$(Get-TimeStamp) ERROR: You did not specify a save location. Unable to save search results."
                        return
                    }
                    else {
                        Save-Output "$(Get-TimeStamp) Exporting logs to $(Join-Path -Path $EventLogSaveLocation -ChildPath $EventLogSaveFileName). Please wait!" -InboundObject $completedEntries -SaveFileOutput:$True
                    }
                }
                else {
                    if ($parameters.ContainsKey('DisplayResultsOnConsole')) {
                        $completedEntries | Format-Table
                    }
                }
            }

            if ($failureEntries.count -gt 0) {
                Save-Output "$(Get-TimeStamp) WARNINGS / ERRORS: No logs found on some computers!" -FailureObject $failureEntries -SaveFailureOutput:$True
                Save-Output "$(Get-TimeStamp) Please check $(Join-Path -Path $LoggingDirectory -ChildPath $LoggingFileName) for more information."
            }
        }
        catch {
            Save-Output "$(Get-TimeStamp) ERROR: $_"
            return
        }
    }

    end {
        Save-Output "$(Get-TimeStamp) Finished! "
    }
}