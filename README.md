# Windows 10 Privacy Guide - Spring Creators Update
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/nutella_1803.jpg)

## Introduction
Windows 10 has raised several concerns about privacy due to the fact that it has a lot of telemetry and online features. In response to these concerns, Microsoft released [a document explaining exactly what data they collect](https://technet.microsoft.com/itpro/windows/configure/windows-diagnostic-data), and now Windows 10 even has a [Diagnostic Data Viewer](https://www.microsoft.com/en-us/store/p/diagnostic-data-viewer/9n8wtrrsq8f7). Most of it seems pretty legit stuff when telemetry is set to basic, but still, if you don't trust them, here's how to prevent Windows 10 from sending your data to Microsoft.  
Please note that not all of these changes can be reverted. If you mess up, you'll have to reinstall Windows.  
Last update: March 20, 2018

## Do not use the default settings
At the end of the setup process, create a local account, don't use Cortana and turn off everything in the privacy settings.
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/setup1703_1.jpg)
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/setup1703_2.jpg)
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/setup1703_3.jpg)
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/setup1703_4.jpg)
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/setup1803_coll.jpg)
If you already installed Windows with the default settings, go to Start > Settings > Privacy to turn them off. You should also go to Account and disconnect your Microsoft account because this guide will prevent it from working properly.

## Let it download all the updates
Once you get to the desktop, go to Settings > Updates and security, and let it download all the updates. Reboot and repeat until no more updates are available.  
This is important because Windows Update may interfere with our activities.
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/updates1803_1.jpg)
Now open the Store app, and let it download updates too.  
Again, this is important because updates would interfere with our activities.  
This may take some time, and it may even get stuck. If it happens, reboot and try again.
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/updates1803_2.jpg)
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/updates1803_3.jpg)
Make sure you check for updates several times, because we absolutely don't want it to try and download stuff while we're removing it.

Now that the system is fully updated, make sure Windows is activated with your license (or KMSPico).

## Remove everything you can
Open the start menu and remove all the applications. Some of them, such as Microsoft Edge, will not have an uninstall option; we'll remove them later.  
What's important now is to remove all the OEM software and the shitty games like Candy Crush and Minecraft.

## Tools
* You will need __Install_Wim_Tweak__. Download [this archive](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/install_wim_tweak.zip) and extract it to C:\Windows\System32
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/iwt_extr.jpg)  
This is a very handy tool that allows us to remove Windows components with a single command. You can delete it from System32 when you're finished with this guide.  
* We need a command prompt, so click start, type ``cmd`` and run it as administrator
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/cmd_1.jpg)
* We will also need PowerShell, so click start, type ``PowerShell`` and run it as administrator
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/ps_1.jpg)

## Removing Windows Defender
In the command prompt, type the following commands:
```
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer" /v SmartScreenEnabled /t REG_SZ /d "Off" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Storage\microsoft.microsoftedge_8wekyb3d8bbwe\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d "0" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v DisableAntiSpyware /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DontReportInfectionInformation /t REG_DWORD /d 1 /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\Sense" /f
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\SecurityHealthService" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontOfferThroughWUAU" /t REG_DWORD /d 1 /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /v "SecurityHealth" /f
reg delete "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "SecurityHealth" /f
install_wim_tweak /o /c Windows-Defender /r
pushd "C:\Windows\SystemApps"
takeown /f Microsoft.Windows.SecHealthUI_cw5n1h2txyewy /r /d y
icacls Microsoft.Windows.SecHealthUI_cw5n1h2txyewy /reset /T
icacls Microsoft.Windows.SecHealthUI_cw5n1h2txyewy /grant Everyone:(F) /t /c /q
rmdir /s /q Microsoft.Windows.SecHealthUI_cw5n1h2txyewy
```
This will take 1-2 minutes.  
Now, go to Start and right click Windows Defender Security Center, select More > App settings, and click Reset. This will remove the icon from the start menu.
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/wdend1803_2.jpg)
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/wdend1803_3.jpg)

After a while, Windows will remind us that the system is unprotected. When it does, click Start, type Control Panel, open it, go to System and Security > Security and Maintenance, and turn off messages about virus protection.
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/wdend1703_1.jpg)

## Removing features
We will now remove almost all UWP features in Windows. The only UWP app you'll have left will be the settings app.  
If you manually install UWP apps later (like cracked UWP games) they may not work properly.

__Note:__ if some of the apps reappear after a few minutes, it's because you didn't wait for the updates to finish. You can simply remove them again using the same commands.

### Windows Store
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *store* | Remove-AppxPackage
```
You can ignore any error that pops up.  
In the command prompt, type:
```
install_wim_tweak /o /c Microsoft-Windows-ContentDeliveryManager /r
install_wim_tweak /o /c Microsoft-Windows-Store /r
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v RemoveWindowsStore /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v DisableStoreApps /t REG_DWORD /d 1 /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\PushToInstall" /v DisablePushToInstall /t REG_DWORD /d 1 /f
sc delete PushToInstall
```

### Music, TV, ...
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *zune* | Remove-AppxPackage
```
Additionally, you should remove Windows Media Player: go to Start > Settings > Apps > Manage optional features, and remove Windows Media Player.

__Alternatives__: [MPC-HC](https://mpc-hc.org/), [VLC](https://www.videolan.org/vlc/), [MPV](https://mpv.srsfckn.biz/)

### Xbox and Game DVR
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *xbox* | Remove-AppxPackage
```
You can ignore any error that pops up.  
In the command prompt, type:
```
sc delete XblAuthManager
sc delete XblGameSave
sc delete XboxNetApiSvc
sc delete XboxGipSvc
reg delete "HKLM\SYSTEM\CurrentControlSet\Services\xbgm" /f
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /disable
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTaskLogon" /disable
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR" /v AllowGameDVR /t REG_DWORD /d 0 /f
```
Additionally, go to Start > Settings > Gaming and turn off everything.

### Sticky Notes
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *sticky* | Remove-AppxPackage
```
__Alternatives__: [Notebot](http://notebot.fdossena.com/)

### Maps
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *maps* | Remove-AppxPackage
```
In the command prompt, type:
```
sc delete MapsBroker
sc delete lfsvc
schtasks /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /disable
```

### Alarms and Clock
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *alarms* | Remove-AppxPackage
Get-AppxPackage -AllUsers *people* | Remove-AppxPackage
```
You can ignore any error that pops up.

### Mail, Calendar, ...
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *comm* | Remove-AppxPackage
Get-AppxPackage -AllUsers *mess* | Remove-AppxPackage
```
You can ignore any error that pops up.

__Alternatives__: [Thunderbird](https://www.mozilla.org/thunderbird/)

### OneNote
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *onenote* | Remove-AppxPackage
```

### Photos
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *photo* | Remove-AppxPackage
```
__Alternatives__: [JPEGView](https://sourceforge.net/projects/jpegview/), or the old Windows Photo Viewer

### Camera
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *camera* | Remove-AppxPackage
```
Ignore any error that pops up

### Weather, News, ...
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *bing* | Remove-AppxPackage
```

### Calculator
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *calc* | Remove-AppxPackage
```
__Alternatives__: [SpeedCrunch](http://www.speedcrunch.org/)

### Sound Recorder
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *soundrec* | Remove-AppxPackage
```
__Alternatives__: [Audacity](http://www.audacityteam.org/)

### Paint 3D and VR features
In the command prompt, type:
```
install_wim_tweak /o /c Microsoft-Windows-Holographic /r
```
Reboot (__important__) and reopen our command prompt and PowerShell.  
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *holo* | Remove-AppxPackage
Get-AppxPackage -AllUsers *3db* | Remove-AppxPackage
Get-AppxPackage -AllUsers *3dv* | Remove-AppxPackage
Get-AppxPackage -AllUsers *paint* | Remove-AppxPackage
```
In the command prompt, type:
```
for /f "tokens=1* delims=" %I in ('reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Edit" ^| find /i "3D Edit"') do (reg delete "%I" /f )
for /f "tokens=1* delims=" %I in ('reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Print" ^| find /i "3D Print"') do (reg delete "%I" /f )
pushd "C:\Program Files"
takeown /f WindowsApps /r /d y
icacls WindowsApps /reset /T
icacls WindowsApps /grant Everyone:(F) /t /c /q
cd WindowsApps
for /f %f in ('dir /b Microsoft.MSPaint*') do takeown /f %f /r /d y && rmdir /s /q %f
```
__Important__: if takeown complains about "y" not being a valid option, replace it with whatever is short for yes in your language. This is only a problem if you're not using Windows in English.

### Microsoft Edge
In the command prompt, type:
```
install_wim_tweak /o /c Microsoft-Windows-Internet-Browser /r
install_wim_tweak /o /c Adobe-Flash /r
```
Additionally, you should remove IE11: Go to Start > Settings > Apps > Manage optional features, and remove Internet Explorer 11.

__Alternatives__: [Firefox](http://www.firefox.com/"), [Chromium](http://chromium.woolyss.com/), [Iridium Browser](https://iridiumbrowser.de)

### Contact Support, Get Help
In the command prompt, type:
```
install_wim_tweak /o /c Microsoft-Windows-ContactSupport /r
```
In the PowerShell, type:
```
Get-AppxPackage *GetHelp* | Remove-AppxPackage
```
Additionally, Go to Start > Settings > Apps > Manage optional features, and remove Contact Support (if present).

### Microsoft Quick Assist
Go to Start > Settings > Apps > Manage optional features, and remove Microsoft Quick Assist

### Connect
In the command prompt, type:
```
install_wim_tweak /o /c Microsoft-PPIProjection-Package /r
```

### Reboot!
Reboot the system and you're now free of UWP garbage.

## Disabling Cortana
With the Anniversary Update, Microsoft hid the option to disable Cortana.  
__Warning__: Do not attempt to remove the Cortana package using install_wim_tweak or the PowerShell, as it will break Windows Search and you will have to reinstall Windows!

Open our command prompt again and use this command:
```
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"  /v "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" /t REG_SZ /d  "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search  and Cortana  application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" /f
```
Reboot again and Cortana is gone. The icon is still there, but it will open the regular search instead.

## More tweaking
Open the command prompt again.
### Turn off Windows Error reporting
In the command prompt, type:
```
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
```
We will remove the service later, but in case an update reinstalls it, this will at least keep it turned off.

### No more forced updates
This will notify when updates are available, and you decide when to install them.  
In the command prompt, type:
```
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v NoAutoUpdate /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v AUOptions /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallDay /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v ScheduledInstallTime /t REG_DWORD /d 3 /f
```

### No license checking
By default, Windows will check your license every time you turn on your PC, this will prevent it.  
In the command prompt, type:
```
reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v NoGenTicket /t REG_DWORD /d 1 /f
```

### Disable sync
It doesn't really affect you if you're not using a Microsoft Account, but it will at least disable the Sync settings from the Settings app.  
In the command prompt, type:
```
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSyncUserOverride /t REG_DWORD /d 1 /f
```

### No Windows Tips
In the command prompt, type:
```
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f
```

### Reboot!
Reboot the system and reopen our command prompt for the next step.

## Removing OneDrive
If you don't use OneDrive (and you shouldn't), you can remove it from your system with these commands, entered in the command prompt:
```
taskkill /F /IM onedrive.exe
```
If you're on 32-bit Windows, type
```
"%SYSTEMROOT%\System32\OneDriveSetup.exe" /uninstall
```
If you're on 64-bit Windows, type
```
"%SYSTEMROOT%\SysWOW64\OneDriveSetup.exe" /uninstall
```
Now reboot, and reopen the command prompt and type:
```
rd "%USERPROFILE%\OneDrive" /Q /S
rd "C:\OneDriveTemp" /Q /S
rd "%LOCALAPPDATA%\Microsoft\OneDrive" /Q /S
rd "%PROGRAMDATA%\Microsoft OneDrive" /Q /S
reg delete "HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
reg delete "HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f
del /Q /F "%localappdata%\Microsoft\OneDrive\OneDriveStandaloneUpdater.exe" 
```
Don't worry if some of these commands fail, it is normal if you never used OneDrive.  
Reboot once again, and reopen the command prompt for the next step.

## Removing Telemetry and other unnecessary services
In the command prompt type the following commands:
```
sc delete DiagTrack
sc delete dmwappushservice
sc delete WerSvc
sc delete CDPUserSvc
sc delete OneSyncSvc
sc delete MessagingService
sc delete wercplsupport
sc delete PcaSvc
sc delete InstallService
sc delete wlidsvc
sc delete wisvc
sc delete RetailDemo
sc delete diagsvc
sc delete shpamsvc 
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "CDPUserSvc" ^| find /i "CDPUserSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "OneSyncSvc" ^| find /i "OneSyncSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "MessagingService" ^| find /i "MessagingService"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "PimIndexMaintenanceSvc" ^| find /i "PimIndexMaintenanceSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UserDataSvc" ^| find /i "UserDataSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UnistoreSvc" ^| find /i "UnistoreSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "CDPSvc" ^| find /i "CDPSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "BcastDVRUserService" ^| find /i "BcastDVRUserService"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "Sgrmbroker" ^| find /i "Sgrmbroker"') do (reg delete %I /f)
sc delete diagnosticshub.standardcollector.service
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v AITEnable /t REG_DWORD /d 0 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableInventory /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisablePCA /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AppCompat" /v DisableUAR /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\MicrosoftEdge\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "EnableSmartScreen" /t REG_DWORD /d 0 /f
reg add "HKCU\Software\Microsoft\Internet Explorer\PhishingFilter" /v "EnabledV9" /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
```
Press Win+R, type regedit, press enter, and navigate to HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services.  
Here we need to locate the key following keys:
* DPS
* WdiServiceHost
* WdiSystemHost
  
These keys have messed up permissions. To delete them, we must fix them, here's a video showing how to do it:  
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/delkey.gif)  
Right click the key and select Permissions, then click Advanced, change the Owner to your username, check "Replace owner on subcontainers and objects" and "Replace all child object permission entries with inheritable permission entries from this object", if inheritance is enabled, disable it and convert to explicit permissions, apply, remove all the permission entries and add one for your username with Full control, confirm everything and delete the key.  
Repeat for the 3 keys and you're done.

## Scheduled tasks
Windows 10 has a huge amount of scheduled tasks that may report some data. Type these commands in the command prompt to remove them:
```
schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /disable
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /disable
schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable
schtasks /Change /TN "Microsoft\Windows\DiskDiagnostic\Microsoft-Windows-DiskDiagnosticDataCollector" /disable
schtasks /Change /TN "Microsoft\Windows\DiskFootprint\Diagnostics" /disable
schtasks /Change /TN "Microsoft\Windows\FileHistory\File History (maintenance mode)" /disable
schtasks /Change /TN "Microsoft\Windows\Maintenance\WinSAT" /disable
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /disable
schtasks /Change /TN "Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /disable
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /disable
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /disable
schtasks /Change /TN "Microsoft\Windows\License Manager\TempSignedLicenseExchange" /disable
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /disable
schtasks /Change /TN "Microsoft\Windows\Clip\License Validation" /disable
schtasks /Change /TN "\Microsoft\Windows\ApplicationData\DsSvcCleanup" /disable
schtasks /Change /TN "\Microsoft\Windows\Power Efficiency Diagnostics\AnalyzeSystem" /disable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\LoginCheck" /disable
schtasks /Change /TN "\Microsoft\Windows\PushToInstall\Registration" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /disable
schtasks /Change /TN "\Microsoft\Windows\Subscription\EnableLicenseAcquisition" /disable
schtasks /Change /TN "\Microsoft\Windows\Subscription\LicenseAcquisition" /disable
del /F /Q "C:\Windows\System32\Tasks\Microsoft\Windows\SettingSync\*" 
```
Some of these may not exist, it's fine.

## Last touches
We must disable Windows Spotlight, and other "Suggestions" (literal ads).

Go to Start > Settings > Personalization: 
* Under Lock screen and set the background to Picture
* Under Start set Show suggestions occasionally in Start to off (They're literally ads)

Go back to Settings and go to System > Notifications and actions:
* Set Get tips, tricks, and suggestions as you use Windows to off
* Set Show me the Windows welcome... to off
 
Go back to Settings and go to Privacy:
* Under General, turn off everything
* Under Activity history, turn off everything
* Under App diagnostics, set Let apps access diagnostic information to off

Go back to Settings and go to Search:
* Under Permissions & History, turn off everything

On the taskbar:
* Right click the people icon and uncheck "Show People button"

## Recommended: use a firewall!
For some applications (such as the settings app), the only way to prevent them from reporting data is to block them with a firewall. This is why you should use a firewall to block all traffic except the applications you explicitly allow, like your web browser.
Personally, I allow Windows Update, Network discovery and sharing, DHCP, DNS, my web browser and nothing more.
### Option 1: TinyWall
[TinyWall](http://tinywall.pados.hu/) is my favorite, but the installer no longer works on Windows 10 1803 because of an issue with digital signatures. I'm sure the author will fix this soon, but in the meanwhile, I made a [modified installer](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/TinyWall-2.1-1803.exe) without the problematic signature.  
Setting up the firewall may take some time, but you'll be as safe as you could possibly be when using Windows. Tinywall's autolearn feature is very useful when you install a new application: it will learn its patterns and allow them through the firewall.  
A big limitation of Tinywall, if you decide to use it, is that you cannot allow/block individual UWP apps (for instance, allow Facebook but not Candy Crush). Blocking C:\Windows\System32\WWAHost.exe (recommended) will block all of them, while allowing it will allow all of them to go through.  
Microsoft Edge is the only exception and has its own exe files. The same thing happens if you use the UNIX subsystem, there is no way to block specific applications.

### Option 2: SimpleWall
[SimpleWall](https://www.henrypp.org/product/simplewall) works pretty much in the same way that TinyWall does but the UI is a bit more basic, it doesn't have the autolearn feature of TinyWall, and exe files must be added one by one for apps like Steam or git that have many executables.  
Unlike TinyWall however, this firewall can block individual UWP apps, which is a nice feature. 

## Congratulations! Your copy of Windows is now Debotnetted!
Things will change in the future, and I'll do what I can to keep this guide updated.
As of March 2018, this guide works on Windows 10 Pro.

## Can Windows revert these changes?
There are a few things that can revert the changes we made here:
* __Major updates__:  when a major update is installed it's like reinstalling Windows. It keeps your programs and settings but the system is reinstalled, and all the botnet with it. Major updates usually come out every 8-12 months. I will keep the guide updated every time a new major update comes out.
* __Using ``dism /Online /Cleanup-Image /RestoreHealth``__:  if you run this command, it will revert almost all changes
* __Using System Restore__:  if you go back to before the changes were made, it will revert changes
