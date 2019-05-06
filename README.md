# Introduction 

**Microsoft Windows 1803  VDI Tweak and Cleanup Script**

Automatically apply setting referenced in white paper: "*Optimizing Windows 10, Build 1803, for a Virtual Desktop Infrastructure (VDI) role*"
URL: https://docs.microsoft.com/en-us/windows-server/remote/remote-desktop-services/rds-vdi-recommendations-1803 

## RUN

```powershell
.\1803_VDI_Configuration.ps1
```

Please execute as admin, within an elevated Shell.

## DEPENDENCIES

1. LGPO.EXE (available at https://www.microsoft.com/en-us/download/details.aspx?id=55319)
2. Previously saved local group policy settings, available on the GitHub site where this script is located
3. This PowerShell script

## REFERENCES

- https://social.technet.microsoft.com/wiki/contents/articles/7703.powershell-running-executables.aspx
- https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/remove-item?view=powershell-6
- https://blogs.technet.microsoft.com/secguide/2016/01/21/lgpo-exe-local-group-policy-object-utility-v1-0/
- https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/set-service?view=powershell-6
- https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/remove-item?view=powershell-6
- https://msdn.microsoft.com/en-us/library/cc422938.aspx

## FEATURES

- [x] Appx package cleanup
- [x] Scheduled tasks
- [x] Automatic Windows traces
- [x] OneDrive cleanup
- [x]Local group policy
- [x] System services
- [x] Disk cleanup
- [x] Default User Profile Customization

## NOTES

This script is dependant on three elements:
- LGPO Settings folder, applied with the LGPO.exe Microsoft app
