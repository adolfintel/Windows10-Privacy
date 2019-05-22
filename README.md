# Windows 10 Privacy Guide - 1903 Update
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/nutella_1903.jpg)

## Introduction
Windows 10 has raised several concerns about privacy due to the fact that it has a lot of telemetry and online features. In response to these concerns, Microsoft released [a document explaining exactly what data they collect](https://technet.microsoft.com/itpro/windows/configure/windows-diagnostic-data), and now Windows 10 even has a [Diagnostic Data Viewer](https://www.microsoft.com/en-us/store/p/diagnostic-data-viewer/9n8wtrrsq8f7). Most of it seems pretty legit stuff when telemetry is set to basic, but still, if you don't trust them, here's how to prevent Windows 10 from sending your data to Microsoft.  
Last update: May 22, 2019

__Important:__ This procedure cannot be reverted without reinstalling Windows. Do not follow this guide if:
* You are not an experienced user
* You need to use a Microsoft Account for any reason (outside of your web browser)
* You need to download anything from the Windows Store (including distros for the Linux subsystem if you want to use it)
* You need to add/remove user accounts to your PC (new accounts will not work properly)

You're doing this at your own risk, I am not responsible for any data loss or damage that may occur.

Let's start.

## Do not use the default settings
At the end of the setup process, create a local account, don't use Cortana and turn off everything in the privacy settings.
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/setup1809_1.jpg)
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/setup1809_2.jpg)
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/setup1809_3.jpg)
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/setup1903_4.jpg)
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/setup1903_5.jpg)
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/setup1809_coll.jpg)
If you already installed Windows with the default settings, go to Start > Settings > Privacy to turn them off. You should also go to Account and disconnect your Microsoft account because this guide will prevent it from working properly.

## Let it download all the updates
Once you get to the desktop, go to Settings > Updates and security, and let it download all the updates. Reboot and repeat until no more updates are available.  
This is important because Windows Update may interfere with our activities.
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/updates1903_1.jpg)  
Now open the Store app, and let it download updates too.  
Again, this is important because updates would interfere with our activities.  
This may take some time. 
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/updates1809_2.jpg)
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/updates1809_3.jpg)  
Make sure you check for updates several times, because we absolutely don't want it to download stuff while we're removing it.

Now that the system is fully updated, make sure Windows is activated with your license (or KMSPico).

## Remove everything you can
Open the start menu and remove all the applications. Some of them, such as Microsoft Edge, will not have an uninstall option; we'll remove them later.  
What's important now is to remove all the OEM software and the shitty games like Candy Crush and Minecraft.

If you used previous versions of Windows 10, you'll notice that this time we can remove more stuff, like Paint 3D, without resorting to tricks.

## Tools
* You will need __Install_Wim_Tweak__. Download [this archive](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/install_wim_tweak.zip), extract it to your Desktop, then move it to C:\Windows\System32
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/iwt1809_extr.jpg)  
This is a very handy tool that allows us to remove Windows components with a single command. You can delete it from System32 when you're finished with this guide.  
* We need a command prompt, so click start, type ``cmd`` and run it as administrator
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/cmd1809_1.jpg)
* We will also need PowerShell, so click start, type ``PowerShell`` and run it as administrator
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/ps1809_1.jpg)

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
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\SecHealthUI.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
install_wim_tweak /o /c Windows-Defender /r
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\Windows.SystemToast.SecurityAndMaintenance" /v "Enabled" /t REG_DWORD /d 0 /f
```
This will take 1-2 minutes.  
Unfortunately, since June 2018, the Windows Security icon in the Start menu can no longer be removed without breaking the system.

If Windows complains about the system being unprotected, right click the notification and hide it.
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/wdend1803_1.jpg)

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
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v SilentInstalledAppsEnabled /t REG_DWORD /d 0 /f
sc delete PushToInstall
```

### Music, TV, ...
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *zune* | Remove-AppxPackage
Get-WindowsPackage -Online | Where PackageName -like *MediaPlayer* | Remove-WindowsPackage -Online -NoRestart
```

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
schtasks /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /disable
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

### Microsoft Edge
Right click the Edge icon on your taskbar and unpin it.

In the command prompt, type:
```
install_wim_tweak /o /c Microsoft-Windows-Internet-Browser /r
install_wim_tweak /o /c Adobe-Flash /r
```  
In the PowerShell, type:
```
Get-WindowsPackage -Online | Where PackageName -like *InternetExplorer* | Remove-WindowsPackage -Online -NoRestart
```  
__Alternatives__: [Firefox](http://www.firefox.com/"), [Chromium](http://chromium.woolyss.com/), [Iridium Browser](https://iridiumbrowser.de), [Pale Moon](https://www.palemoon.org/)

### Contact Support, Get Help
In the command prompt, type:
```
install_wim_tweak /o /c Microsoft-Windows-ContactSupport /r
```
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *GetHelp* | Remove-AppxPackage
```
Additionally, Go to Start > Settings > Apps > Manage optional features, and remove Contact Support (if present).

### Microsoft Quick Assist
In the PowerShell, type:
```
Get-WindowsPackage -Online | Where PackageName -like *QuickAssist* | Remove-WindowsPackage -Online -NoRestart
```

### Connect
In the command prompt, type:
```
install_wim_tweak /o /c Microsoft-PPIProjection-Package /r
```

### Your Phone
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *phone* | Remove-AppxPackage
```

### Hello Face
In the PowerShell, type:
```
Get-WindowsPackage -Online | Where PackageName -like *Hello-Face* | Remove-WindowsPackage -Online -NoRestart
```

In the command prompt, type:
```
schtasks /Change /TN "\Microsoft\Windows\HelloFace\FODCleanupTask" /Disable
```

### Edit with 3D Paint / 3D Print
It is now possible to remove 3D Paint and 3D Print, but they forgot to remove the option in the context menu when you remove them. To remove it, run this in the command prompt:
```
for /f "tokens=1* delims=" %I in (' reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Edit" ^| find /i "3D Edit" ') do (reg delete "%I" /f )
for /f "tokens=1* delims=" %I in (' reg query "HKEY_CLASSES_ROOT\SystemFileAssociations" /s /k /f "3D Print" ^| find /i "3D Print" ') do (reg delete "%I" /f )
```

### System Restore
In the PowerShell, type:
```
Disable-ComputerRestore -Drive "C:\"
vssadmin delete shadows /all /Quiet
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" /v "DisableSR " /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableConfig" /t "REG_DWORD" /d "1" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore" /v "DisableSR " /t "REG_DWORD" /d "1" /f
schtasks /Change /TN "\Microsoft\Windows\SystemRestore\SR" /disable
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
reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f
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

## Removing Telemetry and other unnecessary services
In the command prompt type the following commands:
```
sc delete DiagTrack
sc delete dmwappushservice
sc delete WerSvc
sc delete OneSyncSvc
sc delete MessagingService
sc delete wercplsupport
sc delete PcaSvc
sc config wlidsvc start=demand
sc delete wisvc
sc delete RetailDemo
sc delete diagsvc
sc delete shpamsvc 
sc delete TermService
sc delete UmRdpService
sc delete SessionEnv
sc delete TroubleshootingSvc
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "wscsvc" ^| find /i "wscsvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "OneSyncSvc" ^| find /i "OneSyncSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "MessagingService" ^| find /i "MessagingService"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "PimIndexMaintenanceSvc" ^| find /i "PimIndexMaintenanceSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UserDataSvc" ^| find /i "UserDataSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "UnistoreSvc" ^| find /i "UnistoreSvc"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "BcastDVRUserService" ^| find /i "BcastDVRUserService"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "Sgrmbroker" ^| find /i "Sgrmbroker"') do (reg delete %I /f)
for /f "tokens=1" %I in ('reg query "HKLM\SYSTEM\CurrentControlSet\Services" /k /f "ClipSVC" ^| find /i "ClipSVC"') do (reg delete %I /f)
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
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoRecentDocsHistory" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\CompatTelRunner.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\DeviceCensus.exe" /v Debugger /t REG_SZ /d "%windir%\System32\taskkill.exe" /f
```
Note: since version 1803, the Task View feature depends on CDPUserSvc and its other services. They can no longer be removed without breaking this feature.

Press Win+R, type regedit, press enter, and navigate to HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services.  
Here we need to locate the following keys:
* DPS
* WdiServiceHost
* WdiSystemHost
  
These keys have messed up permissions. To delete them, we must fix them, here's a video showing how to do it:  
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/delkey.gif)  
Right click the key and select Permissions, then click Advanced, change the Owner to your username, check "Replace owner on subcontainers and objects" and "Replace all child object permission entries with inheritable permission entries from this object", if inheritance is enabled, disable it and convert to explicit permissions, apply, remove all the permission entries and add one for your username with Full control, confirm everything and delete the key.  
Repeat for the 3 keys and you're done.

### Scheduled tasks
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
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\RecommendedTroubleshootingScanner" /disable
schtasks /Change /TN "\Microsoft\Windows\Diagnosis\Scheduled" /disable
schtasks /Change /TN "\Microsoft\Windows\NetTrace\GatherNetworkInfo" /disable
del /F /Q "C:\Windows\System32\Tasks\Microsoft\Windows\SettingSync\*" 
```
Some of these may not exist, it's fine.

## Last touches
We must disable Windows Spotlight, and other "Suggestions" (literal ads).

Go to Start > Settings > Personalization > Lock screen: 
* Set the background to Picture
* Set "Get fun facts, tips, tricks and more on your lock screen" to off

Go to Personalization > Start:
* Set Show suggestions occasionally in Start to off (They're literally ads)

Go back to Settings and go to System > Notifications and actions:
* Set "Get tips, tricks, and suggestions as you use Windows" to off
* Set "Show me the Windows welcome..." to off

Go to System > Multitasking:
* Set "Show suggestions occasionally in your timeline" to off
 
Go back to Settings and go to Privacy:
* Under General, turn off everything
* Under Activity history, turn off everything
* Under Speech, turn off everything
* Under Inking, turn off everything
* Under App diagnostics, set Let apps access diagnostic information to off

Go back to Settings and go to Search:
* Under Permissions & History, turn off everything

Later on, you might get a "Suggestions" notification. Right click it and turn it off.

## Use a firewall!
For some applications (such as the settings app), the only way to prevent them from reporting data is to block them with a firewall. This is why you should use a firewall to block all traffic except the applications you explicitly allow, like your web browser.
Personally, I allow Windows Update, Network discovery and sharing, DHCP, DNS, my web browser and nothing more.

[SimpleWall](https://www.henrypp.org/product/simplewall) is the new recommended firewall for this guide. If you used TinyWall before, it no longer works on 1903, so uninstall it.  
SimpleWall can block/unblock individual executables, UWP apps, and services, as well as filter by address, port and protocol.  
Unlike TinyWall unfortunately, it doesn't have an autolearn mode, but it has a very useful notification that pops up when an application is blocked, so you can decide if you want to block it or allow it permanently. This is very useful when installing new software. Get used to seeing a lot of these in the first hours.  
My recommended configuration for SimpleWall is this:
* Under Settings > Mode, use Whitelist. This will block all traffic that you don't explicitly allow
* Under Settings > Settings > General, enable "Load on system startup", "Start minimized", and "Skip User Account Control prompt"
* Under Settings > Settings > Rules, select "Enable boot-time filters"
* Under Settings > Settings > Rules > System Rules, allow smb (inbound and outbound), if you plan to use network file sharing, and also Windows Update
* Under File > Import, you can load my preset: [download](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/simplewall_config.zip). It blocks some Windows features that aren't already blocked by the guide, and allows all apps to access the local network but not the Internet.
* Click on Enable filtering, then select Whitelist

Feel free to experiment with SimpleWall, it is a very powerful tool.  
The only disadvantage at the moment is that it blocks Windows Update even if you explicitly allow it. The developer is aware of this issue and it will probably be fixed in later releases. A temporary workaround is available [here](https://github.com/henrypp/simplewall/issues/206#issuecomment-439830634).

## Congratulations! Your copy of Windows is now Debotnetted!
Things will change in the future, and I'll do what I can to keep this guide updated.
As of May 2018, this guide works on Windows 10 Pro.

## Can Windows revert these changes?
When a major update is installed, almost all changes will be reverted and you'll have to repeat this procedure. Major updates come out about twice a year.
