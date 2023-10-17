# Defining the Global Variables
$global:Checks = 0
$global:MeetingAssumptions = 0
$global:NotMeetingAssumptions = 0
$global:ChecksRejected = 0
$global:Percent = 0
$global:Rating
$global:ColorRating

# Determining the error event to termintate the program
$ErrorActionPreference = "Stop"

# Function to add the result of each check into HTML Line
function CisReg( $ReportName, $Chapter, $Location, $Parameter, $RecommendedValue){
    Try{
        # Retreiving the value from the regester
        $DownloadedItem = Get-ItemProperty -Path $Location -Name $Parameter
        $ReadValue = $DownloadedItem.$Parameter

        # Using regex to see if the condition is matching
        $Match = $ReadValue -match $RecommendedValue

        # Setting the variable and the color of the row to red
        $Color = "#D20F39"

        # If the condition is met, we set Color to green and increase the appropriate global variable
        if ($Match){
            $Color = "#40A02B"
            $global:MeetingAssumptions += 1
            }

        else{
            #Else the color remains red and we increase the appropriate global variable
            $global:NotMeetingAssumptions += 1
            }
        }

    Catch [System.Management.Automation.PSArgumentException]{ 
        $Color = "#7287FD"
        $global:ChecksRejected += 1
        } 

    Catch [System.Management.Automation.ItemNotFoundException]{
        $Color = "#7287FD"
        $global:ChecksRejected += 1
        }

    Finally { $ErrorActionPreference = "Continue" }

    # Creating the appropriate HTML Line
    $HTMLRow = "<tr style='background-color:$Color;'><td>$Chapter</td><td>$Location</td><td>$Parameter</td><td>$RecommendedValue</td><td>$ReadValue</td></tr>"

    # Adding the row to the file
    Add-Content $ReportName $HTMLRow

    # Increasing the number of checks performed
    $global:Checks += 1

    # Calculating the percentage ratio and rounding it up
    $global:Percent = [int][Math]::Ceiling(($MeetingAssumptions /($Checks - $ChecksRejected))*100)
  
    # Assessing the system configuration
    if ($Percent -ge 0 -and $Percent -le 50) { $global:Rating= "Insufficient"; $global:ColorRating = "FA1E3C"}
    if ($Percent -ge 51 -and $Percent -lt 75) { $global:Rating= "Sufficient"; $global:ColorRating = "F1C232"}
    if ($Percent -ge 75 -and $Percent -lt 85) { $global:Rating= "Good"; $global:ColorRating = "8FCE00"}
    if ($Percent -ge 85 -and $Percent -le 100) { $global:Rating= "Very Good"; $global:ColorRating = "38761D"}
}

$Data = Get-Date

$FileName = "Report.html"

$System = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ProductName).ProductName
$Version = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion).DisplayVersion 
New-Item $FileName -Force 

# Adding Content - Styles, Computer Name and Data
Set-Content $FileName "
<html>
<style>
    body {
        font-family: arial, sans-serif;
        }

    table {
        border-collapse: collapse;
        width: 80%;
        }
  
    td, th {
        border: 1px solid #000000;
        text-align: center;
        padding: 8px;
        }

    #ComputerParameters {
        font-family: arial, sans-serif;
        color: #006B77;
        font-size: 14px;
        }

    #Data {
        font-family: arial, sans-serif;
        color: #000000;
        font-size: 14px;
        }

    #Title {
        font-family: arial, sans-serif;
        color: #000000;
        font-size: 20px;
        font-weight: 900;
        }

</style>
<p id='Title'>TOOL FOR AUTOMATIC VERIFICATION OF COMPLIANCE OF THE MICROSOFT WINDOWS 10 OPERATING SYSTEM CONFIGURATION WITH CIS BENCHMARK GUIDELINES</p>
Paradox
<p id='ComputerParameters'>Computer Name: <strong>$env:computername</strong></p>
<p id='ComputerParameters'>System: <strong>$System</strong></p>
<p id='ComputerParameters'>Version: <strong>$Version</strong></p>
<p id='Data'>Date and Time of Launch: <strong>$Data</strong></p>
<br><br>
"

# Adding a Table Header
Add-Content $FileName "
<table >
<tr>
<th>Chapter</th><th>Location</th><th>Parameter</th><th>Recommended Setting</th><th>Current Setting</th>
</tr>
"

CisReg $FileName "2.2.35" "HKLM:\SYSTEM\ControlSet001\Services\WdiServiceHost" "ObjectName" "NT AUTHORITY\\LocalService"
CisReg $FileName "2.3.1.4" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LimitBlankPasswordUse" "1"
CisReg $FileName "2.3.2.1" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "SCENoApplyLegacyAuditPolicy" "1"
CisReg $FileName "2.3.2.2" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "CrashOnAuditFail" "0"
CisReg $FileName "2.3.4.2" "HKLM:\SYSTEM\CurrentControlSet\Control\Print\Providers\LanMan Print Services\Servers" "AddPrinterDrivers" "1"
CisReg $FileName "2.3.6.1" "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireSignOrSeal" "1"
CisReg $FileName "2.3.6.2" "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "SealSecureChannel" "1"
CisReg $FileName "2.3.6.3" "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "SignSecureChannel" "1"
CisReg $FileName "2.3.6.4" "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "DisablePasswordChange" "0"
CisReg $FileName "2.3.6.5" "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "MaximumPasswordAge" "^([1-9]|[12][0-9]|30)$" 
CisReg $FileName "2.3.6.6" "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" "RequireStrongKey" "1"
CisReg $FileName "2.3.7.1" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DisableCAD" "0"
CisReg $FileName "2.3.7.2" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "DontDisplayLastUserName" "1"
CisReg $FileName "2.3.7.3" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "MaxDevicePasswordFailedAttempts" "^([1-9]|10)$"
CisReg $FileName "2.3.7.4" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "InactivityTimeoutSecs" "^([1-9]|[1-9][0-9]|[1-8][0-9][0-9]|900)$"
CisReg $FileName "2.3.7.5" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "legalnoticetext" "^$"
CisReg $FileName "2.3.7.6" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "legalnoticecaption" "^$"
CisReg $FileName "2.3.7.7" "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "CachedLogonsCount" "^([1-4])$"
CisReg $FileName "2.3.7.8" "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" "PasswordExpiryWarning" "^[5-9]|[1-9][0-4]$"
CisReg $FileName "2.3.8.1" "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "RequireSecuritySignature" "1"
CisReg $FileName "2.3.8.2" "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnableSecuritySignature" "1"
CisReg $FileName "2.3.8.3" "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" "EnablePlainTextPassword" "0"
CisReg $FileName "2.3.9.1" "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "AutoDisconnect" "^([0-9]|1[1-5]|10)$"
CisReg $FileName "2.3.9.2" "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RequireSecuritySignature" "1"
CisReg $FileName "2.3.9.3" "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "EnableSecuritySignature" "1"
CisReg $FileName "2.3.9.4" "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "EnableForcedLogoff" "1"
CisReg $FileName "2.3.10.2" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymousSAM" "1"
CisReg $FileName "2.3.10.3" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "RestrictAnonymous" "1"
CisReg $FileName "2.3.10.4" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "DisableDomainCreds" "1"
CisReg $FileName "2.3.10.5" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "EveryoneIncludesAnonymous" "0"
CisReg $FileName "2.3.10.9" "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" "RestrictNullSessAccess" "1"
CisReg $FileName "2.3.10.11" "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" "NullSessionShares" "^$"
CisReg $FileName "2.3.11.1" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "UseMachineId" "1"
CisReg $FileName "2.3.11.2" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" "AllowNullSessionFallback" "0"
CisReg $FileName "2.3.11.5" "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "NoLMHash" "1"
CisReg $FileName "2.3.15.1" "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" "ObCaseInsensitive" "1"
CisReg $FileName "2.3.15.2" "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" "ProtectionMode" "1"
CisReg $FileName "2.3.17.1" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "FilterAdministratorToken" "1"
CisReg $FileName "2.3.17.2" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorAdmin" "2"
CisReg $FileName "2.3.17.3" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "ConsentPromptBehaviorUser" "0"
CisReg $FileName "2.3.17.4" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableInstallerDetection" "1"
CisReg $FileName "2.3.17.5" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableSecureUIAPaths" "1"
CisReg $FileName "2.3.17.6" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableLUA" "1"
CisReg $FileName "2.3.17.7" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "PromptOnSecureDesktop" "1"
CisReg $FileName "2.3.17.8" "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" "EnableVirtualization" "1"
CisReg $FileName "5.1" "HKLM:\SYSTEM\CurrentControlSet\Services\BTAGService" "Start" "0"
CisReg $FileName "5.2" "HKLM:\SYSTEM\CurrentControlSet\Services\bthserv" "Start" "0"
CisReg $FileName "5.3" "HKLM:\SYSTEM\CurrentControlSet\Services\MapsBroker" "Start" "0"
CisReg $FileName "5.4" "HKLM:\SYSTEM\CurrentControlSet\Services\bowser" "Start" "0"
CisReg $FileName "5.5" "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc" "Start" "0"
CisReg $FileName "5.6" "HKLM:\SYSTEM\CurrentControlSet\Services\IISADMIN" "Start" "0"
CisReg $FileName "5.7" "HKLM:\SYSTEM\CurrentControlSet\Services\irmon" "Start" "0"
CisReg $FileName "5.8" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess" "Start" "0"
CisReg $FileName "5.9" "HKLM:\SYSTEM\CurrentControlSet\Services\lltdsvc" "Start" "0"
CisReg $FileName "5.10" "HKLM:\SYSTEM\CurrentControlSet\Services\LxssManager" "Start" "0"
CisReg $FileName "5.11" "HKLM:\SYSTEM\CurrentControlSet\Services\FTPSVC" "Start" "0"
CisReg $FileName "5.12" "HKLM:\SYSTEM\CurrentControlSet\Services\MSiSCSI" "Start" "0"
CisReg $FileName "5.13" "HKLM:\SYSTEM\CurrentControlSet\Services\sshd" "Start" "0"
CisReg $FileName "5.14" "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPsvc" "Start" "0"
CisReg $FileName "5.15" "HKLM:\SYSTEM\CurrentControlSet\Services\p2psvc" "Start" "0"
CisReg $FileName "5.16" "HKLM:\SYSTEM\CurrentControlSet\Services\p2pimsvc" "Start" "0"
CisReg $FileName "5.17" "HKLM:\SYSTEM\CurrentControlSet\Services\PNRPAutoReg" "Start" "0"
CisReg $FileName "5.18" "HKLM:\SYSTEM\CurrentControlSet\Services\wercplsupport" "Start" "0"
CisReg $FileName "5.19" "HKLM:\SYSTEM\CurrentControlSet\Services\RasAuto" "Start" "0"
CisReg $FileName "5.20" "HKLM:\SYSTEM\CurrentControlSet\Services\SessionEnv" "Start" "0"
CisReg $FileName "5.21" "HKLM:\SYSTEM\CurrentControlSet\Services\TermService" "Start" "0"
CisReg $FileName "5.22" "HKLM:\SYSTEM\CurrentControlSet\Services\UmRdpService" "Start" "0"
CisReg $FileName "5.23" "HKLM:\SYSTEM\CurrentControlSet\Services\RpcLocator" "Start" "0"
CisReg $FileName "5.24" "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteRegistry" "Start" "0"
CisReg $FileName "5.25" "HKLM:\SYSTEM\CurrentControlSet\Services\RemoteAccess" "Start" "0"
CisReg $FileName "5.26" "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer" "Start" "0"
CisReg $FileName "5.27" "HKLM:\SYSTEM\CurrentControlSet\Services\simptcp" "Start" "0"
CisReg $FileName "5.28" "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP" "Start" "0"
CisReg $FileName "5.29" "HKLM:\SYSTEM\CurrentControlSet\Services\sacsvr" "Start" "0"
CisReg $FileName "5.30" "HKLM:\SYSTEM\CurrentControlSet\Services\SSDPSRV" "Start" "0"
CisReg $FileName "5.31" "HKLM:\SYSTEM\CurrentControlSet\Services\upnphost" "Start" "0"
CisReg $FileName "5.32" "HKLM:\SYSTEM\CurrentControlSet\Services\WMSvc" "Start" "0"
CisReg $FileName "5.33" "HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc" "Start" "0"
CisReg $FileName "5.34" "HKLM:\SYSTEM\CurrentControlSet\Services\Wecsvc" "Start" "0"
CisReg $FileName "5.35" "HKLM:\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc" "Start" "0"
CisReg $FileName "5.36" "HKLM:\SYSTEM\CurrentControlSet\Services\icssvc" "Start" "0"
CisReg $FileName "5.37" "HKLM:\SYSTEM\CurrentControlSet\Services\WpnService" "Start" "0"
CisReg $FileName "5.38" "HKLM:\SYSTEM\CurrentControlSet\Services\PushToInstall" "Start" "0"
CisReg $FileName "5.39" "HKLM:\SYSTEM\CurrentControlSet\Services\WinRM" "Start" "0"
CisReg $FileName "5.40" "HKLM:\SYSTEM\CurrentControlSet\Services\W3SVC" "Start" "0"
CisReg $FileName "5.41" "HKLM:\SYSTEM\CurrentControlSet\Services\XboxGipSvc" "Start" "0"
CisReg $FileName "5.42" "HKLM:\SYSTEM\CurrentControlSet\Services\XblAuthManager" "Start" "0"
CisReg $FileName "5.43" "HKLM:\SYSTEM\CurrentControlSet\Services\XblGameSave" "Start" "0"
CisReg $FileName "5.44" "HKLM:\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc" "Start" "0"
CisReg $FileName "9.1.1" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\DomainProfile" "EnableFirewall" "1"
CisReg $FileName "9.1.5" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\DomainProfile" "DisableNotifications" "0"
CisReg $FileName "9.1.6" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\DomainProfile\Logging" "LogFilePath" "C:\\WINDOWS\\System32\\LogFiles\\Firewall\\domainfw.log"
CisReg $FileName "9.1.7" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\DomainProfile\Logging" "LogFileSize" "^(1638[4-9]|1639[0-9]|16[4-9][0-9]{2}|1[7-9][0-9]{3}|[2-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-6])$"
CisReg $FileName "9.1.8" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging" "LogDroppedPackets" "1"
CisReg $FileName "9.1.9" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\DomainProfile\Logging" "LogSuccessfulConnections" "1"
CisReg $FileName "9.2.1" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "EnableFirewall" "1"
CisReg $FileName "9.2.4" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile" "DisableNotifications" "0"
CisReg $FileName "9.2.5" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogFilePath" "C:\\WINDOWS\\System32\\logfiles\\firewall\\privatefw.log"
CisReg $FileName "9.2.6" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogFileSize" "^(1638[4-9]|1639[0-9]|16[4-9][0-9]{2}|1[7-9][0-9]{3}|[2-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-6])$"
CisReg $FileName "9.2.7" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogDroppedPackets" "1"
CisReg $FileName "9.2.8" "HKLM:\SOFTWARE\Policies\Microsoft\WindowsFirewall\PrivateProfile\Logging" "LogSuccessfulConnections" "1"
CisReg $FileName "9.3.1" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\PublicProfile" "EnableFirewall" "1"
CisReg $FileName "9.3.4" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\PublicProfile" "DisableNotifications" "0"
CisReg $FileName "9.3.7" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\PublicProfile\Logging" "LogFilePath" "C:\\WINDOWS\\System32\\Logfiles\\Firewall\\publicfw.log"
CisReg $FileName "9.3.8" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Defaults\FirewallPolicy\PublicProfile\Logging" "LogFileSize" "^(1638[4-9]|1639[0-9]|16[4-9][0-9]{2}|1[7-9][0-9]{3}|[2-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-6])$"
CisReg $FileName "9.3.9" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging" "LogDroppedPackets" "1"
CisReg $FileName "9.3.10" "HKLM:\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\PublicProfile\Logging" "LogSuccessfulConnections" "1"
CisReg $FileName "18.5.10.2" "HKLM:\SOFTWARE\Policies\Microsoft\Peernet" "Disabled" "1"
CisReg $FileName "18.9.4.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\AppModel\StateManager" "AllowSharedLocalAppData" "0"
CisReg $FileName "18.9.83.1" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR" "AllowGameDVR" "0"
CisReg $FileName "18.9.96.2" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" "EnableTranscripting" "0"
CisReg $FileName "18.9.103.4" "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" "NoAutoRebootWithLoggedOnUsers" "0"


# Adding the remaining HTML Contents
Add-Content Report.html "
</table>
<br><br>
Checks Made: <b>$global:Checks</b><br>
Checks that meet the Guideline: <b>$global:MeetingAssumptions</b><br>
Checks that don't meet the Guideline: <b>$global:NotMeetingAssumptions</b><br>
Checks Rejected: <b>$global:ChecksRejected</b><br>
Percentage Score: <b>$global:Percent%</b><br>
The Computer Configuration is <b style='color:$ColorRating;'<b>$global:Rating</b></span>
</html>
"

$Shell = New-Object -ComObject "WScript.Shell"
$Button = $Shell.Popup("Press OK to continue", 0, "The Script Completed Successfully", 0)