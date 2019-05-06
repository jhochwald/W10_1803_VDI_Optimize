#requires -Version 3.0
#requires -RunAsAdministrator
#requires -Modules Appx, Dism, NetAdapter, ScheduledTasks

<#
      .SYNOPSIS
      Microsoft Windows 1803  VDI Cleanup Script

      .DESCRIPTION
      Microsoft Windows 1803  VDI Cleanup Script
      based on white paper: "Optimizing Windows 10, Build 1803, for a Virtual Desktop Infrastructure (VDI) role"

      .EXAMPLE
      PS C:\> .\1803_VDI_Configuration.ps1

      .NOTES
      - TITLE:          Microsoft Windows 1803  VDI Cleanup Script
      - AUTHORED BY:    Robert M. Smith, and Tim Muessig
      - CONTRIBUTORS:   Joerg Hochwald (JHO)
      - AUTHORED DATE:  01/10/2019
      - LAST EDIT DATE: 05/06/2019
      - CONTRIBUTIONS:  Do some Refactoring (JHO)
                        Apply some tweaks (JHO)
                        Embed some stuff to get rid off the external text files (JHO)

      - DEPENDENCIES:   1. LGPO.EXE (available at https://www.microsoft.com/en-us/download/details.aspx?id=55319)
                        2. Previously saved local group policy settings, available on the GitHub site where this script is located
                        3. This PowerShell script

      Categories of cleanup items:
      - Appx package cleanup                 - Complete
      - Scheduled tasks                      - Complete
      - Automatic Windows traces             - Complete
      - OneDrive cleanup                     - Complete
      - Local group policy                   - Complete
      - System services                      - Complete
      - Disk cleanup                         - Complete
      - Default User Profile Customization   - Complete

      This script is dependant on three elements:
      LGPO Settings folder, applied with the LGPO.exe Microsoft app

      the following is the list of almost all the UWP application packages that can be removed with PowerShell, interactively.
      The Store and a few others, such as Wallet, were left off intentionally.  Though it is possible to remove the Store app,
      it is nearly impossible to get it back.  Please review the lists below and comment out or remove references to packages that you do not want to remove.

      .LINK https://social.technet.microsoft.com/wiki/contents/articles/7703.powershell-running-executables.aspx

      .LINK Remove-Item

      .LINK https://blogs.technet.microsoft.com/secguide/2016/01/21/lgpo-exe-local-group-policy-object-utility-v1-0/

      .LINK Set-Service

      .LINK https://msdn.microsoft.com/en-us/library/cc422938.aspx
#>
[CmdletBinding(ConfirmImpact = 'Medium')]
param ()

#region Begin Clean APPX Packages
$null = (Set-Location -Path $PSScriptRoot)

$AppxPackage = @(
   'Microsoft.BingWeather'
   'Microsoft.GetHelp'
   'Microsoft.Getstarted'
   'Microsoft.Messaging'
   'Microsoft.Microsoft3Dviewer'
   'Microsoft.MicrosoftOfficeHub'
   'Microsoft.MicrosoftSolitaireCollection'
   'Microsoft.MicrosoftStickyNotes'
   'Microsoft.MSPaint'
   'Microsoft.OneConnect'
   'Microsoft.People'
   'Microsoft.Print3D'
   'Microsoft.SkypeApp'
   'Microsoft.Windows.Photos'
   'Microsoft.WindowsAlarms'
   'Microsoft.WindowsCamera'
   'Microsoft.windowscommunicationsapps'
   'Microsoft.WindowsFeedbackHub'
   'Microsoft.WindowsSoundRecorder'
   'Microsoft.Xbox.TCUI'
   'Microsoft.XboxApp'
   'Microsoft.XboxGameOverlay'
   'Microsoft.XboxGamingOverlay'
   'Microsoft.XboxIdentityProvider'
   'Microsoft.XboxSpeechToTextOverlay'
   'Microsoft.WindowsMaps'
   'Microsoft.ZuneMusic'
   'Microsoft.ZuneVideo'
)

if ($AppxPackage.Count -gt 0)
{
   foreach ($Item in $AppxPackage)
   {
      $Package = "*$Item*"

      try
      {
         $null = (Get-AppxPackage | Where-Object -FilterScript {
               $_.PackageFullName -like $Package
         } | Remove-AppxPackage -ErrorAction Stop)
      }
      catch
      {
         # get error record
         [Management.Automation.ErrorRecord]$e = $_

         # retrieve information about runtime error
         $info = [PSCustomObject]@{
            Exception = $e.Exception.Message
            Reason    = $e.CategoryInfo.Reason
            Target    = $e.CategoryInfo.TargetName
            Script    = $e.InvocationInfo.ScriptName
            Line      = $e.InvocationInfo.ScriptLineNumber
            Column    = $e.InvocationInfo.OffsetInLine
         }

         # output information. Post-process collected info, and log info (optional)
         $info | Out-String | Write-Verbose

         Write-Warning -Message $e.Exception.Message -ErrorAction Continue
      }

      try
      {
         $null = (Get-AppxPackage -AllUsers | Where-Object -FilterScript {
               $_.PackageFullName -like $Package
         } | Remove-AppxPackage -AllUsers -ErrorAction Stop)
      }
      catch
      {
         # get error record
         [Management.Automation.ErrorRecord]$e = $_

         # retrieve information about runtime error
         $info = [PSCustomObject]@{
            Exception = $e.Exception.Message
            Reason    = $e.CategoryInfo.Reason
            Target    = $e.CategoryInfo.TargetName
            Script    = $e.InvocationInfo.ScriptName
            Line      = $e.InvocationInfo.ScriptLineNumber
            Column    = $e.InvocationInfo.OffsetInLine
         }

         # output information. Post-process collected info, and log info (optional)
         $info | Out-String | Write-Verbose

         Write-Warning -Message $e.Exception.Message -ErrorAction Continue
      }

      try
      {
         $null = (Get-AppxProvisionedPackage -Online | Where-Object -FilterScript {
               $_.PackageName -like $Package
         } | Remove-AppxProvisionedPackage -Online -ErrorAction Stop)
      }
      catch
      {
         # get error record
         [Management.Automation.ErrorRecord]$e = $_

         # retrieve information about runtime error
         $info = [PSCustomObject]@{
            Exception = $e.Exception.Message
            Reason    = $e.CategoryInfo.Reason
            Target    = $e.CategoryInfo.TargetName
            Script    = $e.InvocationInfo.ScriptName
            Line      = $e.InvocationInfo.ScriptLineNumber
            Column    = $e.InvocationInfo.OffsetInLine
         }

         # output information. Post-process collected info, and log info (optional)
         $info | Out-String | Write-Verbose

         Write-Warning -Message $e.Exception.Message -ErrorAction Continue
      }
   }
}
#endregion

#region Disable Scheduled Tasks

# This section is for disabling scheduled tasks.  If you find a task that should not be disabled comment or delete from the "SchTaskList.txt" file.
$SchTasksList = @(
   'OneDrive Standalone Update Task v2'
   'Microsoft Compatibility Appraiser'
   'ProgramDataUpdater'
   'StartupAppTask'
   'CleanupTemporaryState'
   'Proxy'
   'UninstallDeviceTask'
   'ProactiveScan'
   'Consolidator'
   'UsbCeip'
   'Data Integrity Scan'
   'Data Integrity Scan for Crash Recovery'
   'ScheduledDefrag'
   'SilentCleanup'
   'Microsoft-Windows-DiskDiagnosticDataCollector'
   'Diagnostics'
   'StorageSense'
   'DmClient'
   'DmClientOnScenarioDownload'
   'File History (maintenance mode)'
   'ScanForUpdates'
   'ScanForUpdatesAsUser'
   'SmartRetry'
   'Notifications'
   'WindowsActionDialog'
   'WinSAT'
   'Cellular'
   'MapsToastTask'
   'ProcessMemoryDiagnosticEvents'
   'RunFullMemoryDiagnostic'
   'MNO Metadata '
   'LPRemove'
   'GatherNetworkInfo'
   'WiFiTask'
   'Sqm-Tasks'
   'AnalyzeSystem'
   'MobilityManager'
   'VerifyWinRE'
   'RegIdleBackup'
   'FamilySafetyMonitor'
   'FamilySafetyRefreshTask'
   'IndexerAutomaticMaintenance'
   'SpaceAgentTask'
   'SpaceManagerTask'
   'HeadsetButtonPress'
   'SpeechModelDownloadTask'
   'ResPriStaticDbSync'
   'WsSwapAssessmentTask'
   'SR'
   'SynchronizeTimeZone'
   'Usb-Notifications'
   'QueueReporting'
   'UpdateLibrary'
   'Scheduled Start'
   'sih'
   'XblGameSaveTask'
)

if ($SchTasksList.count -gt 0)
{
   foreach ($Item in $SchTasksList)
   {
      try
      {
         $null = (Get-ScheduledTask | Where-Object -FilterScript {
               $_.TaskName -like "$($Item.trim())"
         } | Disable-ScheduledTask -ErrorAction Stop)
      }
      catch
      {
         # get error record
         [Management.Automation.ErrorRecord]$e = $_

         # retrieve information about runtime error
         $info = [PSCustomObject]@{
            Exception = $e.Exception.Message
            Reason    = $e.CategoryInfo.Reason
            Target    = $e.CategoryInfo.TargetName
            Script    = $e.InvocationInfo.ScriptName
            Line      = $e.InvocationInfo.ScriptLineNumber
            Column    = $e.InvocationInfo.OffsetInLine
         }

         # output information. Post-process collected info, and log info (optional)
         $info | Out-String | Write-Verbose

         Write-Warning -Message $e.Exception.Message -ErrorAction Continue
      }
   }
}
#endregion

#region Customize Default User Profile

# End the OneDrive.exe and Explorer.exe processes, then uninstall OneDrive.exe
# Then remove leftover OneDrive .lnk files
$null = (Get-Process -Name OneDrive | Stop-Process -Force)
$null = (Get-Process -Name explorer | Stop-Process -Force)

if (Test-Path -Path "$env:windir\System32\OneDriveSetup.exe" -ErrorAction SilentlyContinue)
{
   $null = (Start-Process -FilePath "$env:windir\System32\OneDriveSetup.exe" -ArgumentList '/uninstall' -Wait)
}

if (Test-Path -Path "$env:windir\SysWOW64\OneDriveSetup.exe" -ErrorAction SilentlyContinue)
{
   $null = (Start-Process -FilePath "$env:windir\SysWOW64\OneDriveSetup.exe" -ArgumentList '/uninstall' -Wait)
}

Remove-Item -Path "$env:windir\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force -ErrorAction Continue
Remove-Item -Path "$env:windir\ServiceProfiles\NetworkService\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\OneDrive.lnk" -Force -ErrorAction Continue

# Remove the automatic start item for OneDrive from the default user profile registry hive and while NTUSER.DAT is open, apply appearance customizations, then close hive file
$DefaultUserSettings = @(
   'Load HKLM\Temp C:\Users\Default\NTUSER.'
   'Delete HKLM\Temp\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v OneDriveSetup /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People /v PeopleBand /t REG_DWORD /d 0 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v TaskbarAnimations /t REG_DWORD /d 0 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\DWM /v EnableAeroPeek /t REG_DWORD /d 0 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowInfoTip /t REG_DWORD /d 0 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v HideIcons /t REG_DWORD /d 0 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ListViewShadow /t REG_DWORD /d 0 /f'
   'add ""HKLM\Temp\Control Panel\Desktop"" /v DragFullWindows /t REG_SZ /d 0 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ListviewAlphaSelect /t REG_DWORD /d 0 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v AutoCheckSelect /t REG_DWORD /d 0 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\AnimateMinMax /v DefaultApplied /t REG_DWORD /d 1 /'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ComboBoxAnimation /v DefaultApplied /t REG_DWORD /d 1 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ControlAnimations /v DefaultApplied /t REG_DWORD /d 1 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\CursorShadow /v DefaultApplied /t REG_DWORD /d 1 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DragFullWindows /v DefaultApplied /t REG_DWORD /d 1 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DropShadow /v DefaultApplied /t REG_DWORD /d 1 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMAeroPeekEnabled /v DefaultApplied /t REG_DWORD /d 1 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMEnabled /v DefaultApplied /t REG_DWORD /d 1 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\DWMSaveThumbnailEnabled /v DefaultApplied /t REG_DWORD /d 1 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\FontSmoothing /v DefaultApplied /t REG_DWORD /d 1 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListBoxSmoothScrolling /v DefaultApplied /t REG_DWORD /d 1 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewAlphaSelect /v DefaultApplied /t REG_DWORD /d 1 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ListviewShadow /v DefaultApplied /t REG_DWORD /d 1 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\MenuAnimation /v DefaultApplied /t REG_DWORD /d 1 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\SelectionFade /v DefaultApplied /t REG_DWORD /d 1 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TaskbarAnimations /v DefaultApplied /t REG_DWORD /d 1 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\Themes /v DefaultApplied /t REG_DWORD /d 1 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\ThumbnailsOrIcon /v DefaultApplied /t REG_DWORD /d 1 /f'
   'add HKLM\Temp\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects\TooltipAnimation /v DefaultApplied /t REG_DWORD /d 1 /f'
   'Unload HKLM\Temp'
)

if ($DefaultUserSettings.count -gt 0)
{
   foreach ($Item in $DefaultUserSettings)
   {
      $null = (Start-Process -FilePath "$env:windir\System32\Reg.exe" -ArgumentList "$Item" -Wait)
   }
}

# Restart the previously closed Explorer.exe process
$null = (Start-Process -FilePath "$env:windir\Explorer.exe" -Wait)
#endregion

#region Disable Windows Traces
$DisableAutologgers = @(
   'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\AppModel\'
   'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\CloudExperienceHostOOBE\'
   'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\DiagLog\'
   'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\NtfsLog\'
   'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\TileStore\'
   'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\UBPM\'
   'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiDriverIHVSession\'
   'HKLM:\SYSTEM\CurrentControlSet\Control\WMI\Autologger\WiFiSession\'
)

if ($DisableAutologgers.count -gt 0)
{
   foreach ($Item in $DisableAutologgers)
   {
      Write-Verbose -Message ('Processing {0}' -f $Item)

      try
      {
         $null = (New-ItemProperty -Path $Item -Name 'Start' -PropertyType 'DWORD' -Value '0' -Force -ErrorAction SilentlyContinue)
      }
      catch
      {
         # get error record
         [Management.Automation.ErrorRecord]$e = $_

         # retrieve information about runtime error
         $info = [PSCustomObject]@{
            Exception = $e.Exception.Message
            Reason    = $e.CategoryInfo.Reason
            Target    = $e.CategoryInfo.TargetName
            Script    = $e.InvocationInfo.ScriptName
            Line      = $e.InvocationInfo.ScriptLineNumber
            Column    = $e.InvocationInfo.OffsetInLine
         }

         # output information. Post-process collected info, and log info (optional)
         $info | Out-String | Write-Verbose

         Write-Warning -Message $e.Exception.Message -ErrorAction Continue
      }
   }
}
#endregion

#region Local Group Policy Settings
# - This code does not:
#   * set a lock screen image.
#   * change the "Root Certificates Update" policy.
#   * change the "Enable Windows NTP Client" setting.
#   * set the "Select when Quality Updates are received" policy
if (Test-Path -Path (Join-Path -Path $PSScriptRoot -ChildPath 'LGPO\LGPO.exe'))
{
   $null = (Start-Process -FilePath (Join-Path -Path $PSScriptRoot -ChildPath 'LGPO\LGPO.exe') -ArgumentList "/g $((Join-Path -Path $PSScriptRoot -ChildPath 'LGPO\VDI_OptimalSettings'))" -Wait)
}
#endregion

#region Disable Services
#################### BEGIN: DISABLE SERVICES section ###########################
$ServicesToDisable = @(
   'HKLM:\SYSTEM\CurrentControlSet\Services\CDPSvc\'
   'HKLM:\SYSTEM\CurrentControlSet\Services\CDPUserSvc\'
   'HKLM:\SYSTEM\CurrentControlSet\Services\OneSyncSvc\'
   'HKLM:\SYSTEM\CurrentControlSet\Services\DusmSvc\'
   'HKLM:\SYSTEM\CurrentControlSet\Services\PimIndexMaintenanceSvc\'
   'HKLM:\SYSTEM\CurrentControlSet\Services\DiagTrack\'
   'HKLM:\SYSTEM\CurrentControlSet\Services\DPS\'
   'HKLM:\SYSTEM\CurrentControlSet\Services\MapsBroker\'
   'HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\'
   'HKLM:\SYSTEM\CurrentControlSet\Services\BcastDVRUserService\'
   'HKLM:\SYSTEM\CurrentControlSet\Services\MessagingService\'
   'HKLM:\SYSTEM\CurrentControlSet\Services\defragsvc\'
   'HKLM:\SYSTEM\CurrentControlSet\Services\SysMain\'
   'HKLM:\SYSTEM\CurrentControlSet\Services\TabletInputService\'
   'HKLM:\SYSTEM\CurrentControlSet\Services\WerSvc\'
   'HKLM:\SYSTEM\CurrentControlSet\Services\WMPNetworkSvc\'
   'HKLM:\SYSTEM\CurrentControlSet\Services\icssvc\'
   'HKLM:\SYSTEM\CurrentControlSet\Services\WSearch\'
   'HKLM:\SYSTEM\CurrentControlSet\Services\VSS\'
   'HKLM:\SYSTEM\CurrentControlSet\Services\XboxGipSvc\'
   'HKLM:\SYSTEM\CurrentControlSet\Services\xbgm\'
   'HKLM:\SYSTEM\CurrentControlSet\Services\XblAuthManager\'
   'HKLM:\SYSTEM\CurrentControlSet\Services\XblGameSave\'
   'HKLM:\SYSTEM\CurrentControlSet\Services\XboxNetApiSvc\'
)

if ($ServicesToDisable.count -gt 0)
{
   foreach ($Item in $ServicesToDisable)
   {
      Write-Verbose -Message ('Processing {0}' -f $Item)

      try
      {
         $null = (New-ItemProperty -Path $Item -Name 'Start' -PropertyType 'DWORD' -Value '4' -Force -ErrorAction Stop)
      }
      catch
      {
         # get error record
         [Management.Automation.ErrorRecord]$e = $_

         # retrieve information about runtime error
         $info = [PSCustomObject]@{
            Exception = $e.Exception.Message
            Reason    = $e.CategoryInfo.Reason
            Target    = $e.CategoryInfo.TargetName
            Script    = $e.InvocationInfo.ScriptName
            Line      = $e.InvocationInfo.ScriptLineNumber
            Column    = $e.InvocationInfo.OffsetInLine
         }

         # output information. Post-process collected info, and log info (optional)
         $info | Out-String | Write-Verbose

         Write-Warning -Message $e.Exception.Message -ErrorAction Continue
      }
   }
}
#endregion

#region Disk Cleanup
#################### BEGIN: DISK CLEANUP section ###########################
# Delete not in-use *.tmp files
$FilesToRemove = (Get-ChildItem -Path "$env:HOMEDRIVE\" -Include *.tmp, *.etl -Recurse -ErrorAction SilentlyContinue)
$null = ($FilesToRemove | Remove-Item -Force -Confirm:$false -ErrorAction SilentlyContinue)

# Delete not in-use anything in your %temp% folder
$null = (Remove-Item -Path $env:TEMP\*.* -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue)

# Delete not in-use anything in the C:\Windows\Temp folder
$null = (Remove-Item -Path $env:windir\Temp\*.* -Recurse -Force -Confirm:$false -ErrorAction SilentlyContinue)

# Disk Cleanup Wizard automation (Cleanmgr.exe /SAGESET:11)
$DiskCleanupSettings = @(
   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Active Setup Temp Folders\'
   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\BranchCache\'
   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\D3D Shader Cache\'
   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Diagnostic Data Viewer database files\'
   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Downloaded Program Files\'
   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Old ChkDsk Files\'
   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Previous Installations\'
   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Recycle Bin\'
   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\RetailDemo Offline Content\'
   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Service Pack Cleanup\'
   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Setup Log Files\'
   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error memory dump files\'
   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\System error minidump files\'
   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Files\'
   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Temporary Setup Files\'
   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Thumbnail Cache\'
   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Update Cleanup\'
   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Upgrade Discarded Files\'
   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\User file versions\'
   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Defender\'
   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Error Reporting Files\'
   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows ESD installation files\'
   'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches\Windows Upgrade Log Files\'
)

if ($DiskCleanupSettings.count -gt 0)
{
   foreach ($Item in $DiskCleanupSettings)
   {
      Write-Verbose -Message ('Processing {0}' -f $Item)

      try
      {
         $null = (New-ItemProperty -Path $Item -Name 'StateFlags0011' -PropertyType 'DWORD' -Value '2' -Force -ErrorAction Stop)
      }
      catch
      {
         # get error record
         [Management.Automation.ErrorRecord]$e = $_

         # retrieve information about runtime error
         $info = [PSCustomObject]@{
            Exception = $e.Exception.Message
            Reason    = $e.CategoryInfo.Reason
            Target    = $e.CategoryInfo.TargetName
            Script    = $e.InvocationInfo.ScriptName
            Line      = $e.InvocationInfo.ScriptLineNumber
            Column    = $e.InvocationInfo.OffsetInLine
         }

         # output information. Post-process collected info, and log info (optional)
         $info | Out-String | Write-Verbose

         Write-Warning -Message $e.Exception.Message -ErrorAction Continue
      }
   }
}

$null = (Start-Process -FilePath "$env:windir\System32\Cleanmgr.exe" -ArgumentList 'SAGERUN:11' -Wait)
#endregion

#region Network Optimization
# LanManWorkstation optimizations
$null = (New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\' -Name 'DisableBandwidthThrottling' -PropertyType 'DWORD' -Value '1' -Force -ErrorAction SilentlyContinue)
$null = (New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\' -Name 'FileInfoCacheEntriesMax' -PropertyType 'DWORD' -Value '1024' -Force -ErrorAction SilentlyContinue)
$null = (New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\' -Name 'DirectoryCacheEntriesMax' -PropertyType 'DWORD' -Value '1024' -Force -ErrorAction SilentlyContinue)
$null = (New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\' -Name 'FileNotFoundCacheEntriesMax' -PropertyType 'DWORD' -Value '1024' -Force -ErrorAction SilentlyContinue)
$null = (New-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Services\LanmanWorkstation\Parameters\' -Name 'DormantFileLimit' -PropertyType 'DWORD' -Value '256' -Force -ErrorAction SilentlyContinue)

# NIC Advanced Properties performance settings for network biased environments
$null = (Set-NetAdapterAdvancedProperty -DisplayName 'Send Buffer Size' -DisplayValue 4MB -ErrorAction SilentlyContinue)

<# Note that the above setting is for a Microsoft Hyper-V VM.  You can adjust these values in your environment...
      by querying in PowerShell using Get-NetAdapterAdvancedProperty, and then adjusting values using the...
      Set-NetAdapterAdvancedProperty command.
#>
#endregion
