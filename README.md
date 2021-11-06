# Get-OfflineFileStatus

Check for legacy client sync client issues

> EXAMPLE 1: <span style="color:yellow">Get-OfflineFileStatus -DisplayErrors -SaveEventLogsToLocation -Computers Computer1, Computer2</span>

- This will connect to Computer1 and Computer2 to search the event logs for events and display any warnings / errors found

> EXAMPLE 2: <span style="color:yellow">Get-OfflineFileStatus -DomainComputers -SaveEventLogsToLocation</span>

- This will connect to to a domain controller and search for all computers based on filter and save the logs to a local or network share

> EXAMPLE 3: <span style="color:yellow">Get-OfflineFileStatus EnableOfflineFileSyncDebugLogging</span>

- Enable offline sync debug logging on a local or remote machine

> EXAMPLE 4: <span style="color:yellow">Get-OfflineFileStatus DisableOfflineFileSyncDebugLogging</span>

- Disable offline sync debug logging on a local or remote machine

<span style="color:orange">NOTE: </span> All logs will be saved to the following variable -> $EventLogSaveLocation = 'c:\OfflineFileStatus'. This can be a local share or a network share with the correct write permissions