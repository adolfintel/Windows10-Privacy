# Windows 10 Privacy Guide - Creators Update
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/nutella.jpg)

## Introduction
Windows 10 has raised several concerns about privacy due to the fact that it has a lot of telemetry and online features. In response to these concerns, Microsoft released [a document explaining exactly what data they collect](https://technet.microsoft.com/itpro/windows/configure/windows-diagnostic-data). Most of it seems pretty legit stuff, but still, if you don't trust them, here's how to prevent Windows 10 from sending all your data to Microsoft.  
Please note that not all of these changes can be reverted. If you mess up, you'll have to reinstall Windows.  
Last update: July 25, 2017

## Do not use the default settings
At the end of the setup process, create a local account, don't use Cortana and turn off everything in the privacy settings.
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/setup1703_1.jpg)
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/setup1703_2.jpg)
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/setup1703_3.jpg)
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/setup1703_4.jpg)
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/setup1703_5.jpg)
If you already installed Windows with the default settings, go to Start > Settings > Privacy to turn them off. You should also go to Account and disconnect your Microsoft account because this guide will prevent it from working properly.

## Let it download all the updates
Once you get to the desktop, go to Settings > Updates and security, and let it download all the updates. Reboot and repeat until no more updates are available.  
This is important because Windows Update may interfere with our activities.
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/updates1703_1.jpg)
Now open the Store app, and let it download updates too.  
Again, this is important because it may interfere with our activities.  
This may take some time, and it may even get stuck. If it happens, reboot and try again.
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/updates_2.jpg)
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/updates_3.jpg)
Now that the system is fully updated, make sure Windows is activated with your license (or KMSPico).

## Remove everything you can
Open the start menu and remove all the applications. Some of them, such as Microsoft Edge, will not have an uninstall option; we'll remove them later.  
What's important now is to remove all the OEM software and the shitty games like Candy Crush and Minecraft.

## Power tools
* You will need __Install_Wim_Tweak__. Download [this archive](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/install_wim_tweak.zip) and extract it to C:\Windows\System32
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/iwt_extr.jpg)
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
install_wim_tweak /o /c Windows-Defender /r
```
This will take 1-2 minutes. After that, reboot and reopen our command prompt and PowerShell.  
Windows will keep reminding us that the system is unprotected. Click Start, type Control Panel and open it, go to System and Security > Security and Maintenance, and turn off messages about virus protection.
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/wdend1703_1.jpg)
Unfortunately, the Windows Defender icon is still present in the start menu, although it does nothing. I have yet to find a way to remove it without breaking functionality.

## Removing features
### Windows Store
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *store* | Remove-AppxPackage
```
In the command prompt, type:
```
install_wim_tweak /o /c Microsoft-Windows-ContentDeliveryManager /r
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v RemoveWindowsStore /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\WindowsStore" /v DisableStoreApps /t REG_DWORD /d 1 /f
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
install_wim_tweak /o /c Microsoft-Xbox-GameCallableUI /r
sc delete XblAuthManager
sc delete XblGameSave
sc delete XboxNetApiSvc
sc delete XboxGipSvc
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTask" /disable
schtasks /Change /TN "Microsoft\XblGameSave\XblGameSaveTaskLogon" /disable
```
To remove Game DVR (the Win+G thing that pops up while you're playing), download [this archive](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/Remove_GamePanel.zip), extract it somewhere and run "Remove GamePanel.bat" as administrator.  
__Warning__: Some updates will partially restore Game DVR causing errors to pop up when a game is started. If that happens, simply reapply the fix.  
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
```

### Alarms and Clock
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *alarms* | Remove-AppxPackage
Get-AppxPackage -AllUsers *people* | Remove-AppxPackage
```

### Mail, Calendar, ...
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *comm* | Remove-AppxPackage
Get-AppxPackage -AllUsers *mess* | Remove-AppxPackage
```
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

### Camera (if you don't have a camera)
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

### Calculator (not recommended)
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
Reboot and reopen our command prompt and PowerShell.  
In the PowerShell, type:
```
Get-AppxPackage -AllUsers *holo* | Remove-AppxPackage
Get-AppxPackage -AllUsers *3db* | Remove-AppxPackage
Get-AppxPackage -AllUsers *3dv* | Remove-AppxPackage
Get-AppxPackage -AllUsers *paint* | Remove-AppxPackage
```
In the command prompt, type:
```
pushd "C:\Program Files"
takeown /f WindowsApps /r /d y
icacls WindowsApps /reset /T
icacls WindowsApps /grant Everyone:(F) /t /c /q
cd WindowsApps
for /f %f in ('dir /b Microsoft.MSPaint*') do takeown /f %f /r /d y && rmdir /s /q %f
```
__Important__: if takeown complains about "y" not being a valid option, replace it with whatever is short for yes in your language. This is not a problem if you're not using Windows in English.

### Microsoft Edge (not recommended)
In the command prompt, type:
```
install_wim_tweak /o /c Microsoft-Windows-Internet-Browser /r
install_wim_tweak /o /c Adobe-Flash /r
```
Additionally, you should remove IE11: Go to Start > Settings > Apps > Manage optional features, and remove Internet Explorer 11.

__Alternatives__: [Firefox](http://www.firefox.com/"), [Chromium](http://chromium.woolyss.com/)

### Contact Support, Get Help
In the command prompt, type:
```
install_wim_tweak /o /c Microsoft-Windows-ContactSupport /r
```
Additionally, Go to Start > Settings > Apps > Manage optional features, and remove Contact Support.

### Microsoft Quick Assist
Go to Start > Settings > Apps > Manage optional features, and remove Microsoft Quick Assist

### Connect
In the command prompt, type:
```
install_wim_tweak /o /c Microsoft-PPIProjection-Package /r
```

### Reboot!
Reboot the system. Hopefully everything is still in place.

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
```
Don't worry if some of these commands fail, it is normal if you never used OneDrive.  
Reboot once again, and reopen the command prompt for the next step.

## Removing Telemetry and other unnecessary services
First, click start, type "Services" and open it. You will find a huge list of Windows Services, most of which are fine and safe, but others send data to Microsoft.  
Find a service called Contact Data_xxxxx or CDPUserSvc_xxxxx, where xxxxx are 5 randomly generated characters (yes, Windows is using literal malware techniques to prevent automated removal of this trash).
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/serv1703.jpg)
Write down these 5 characters.

Now type these commands in the command prompt to delete them:
```
sc delete DiagTrack
sc delete dmwappushservice
sc delete WerSvc
sc delete CDPUserSvc
sc delete CDPUserSvc_xxxxx
sc delete OneSyncSvc
sc delete OneSyncSvc_xxxxx
sc delete MessagingService
sc delete MessagingService_xxxxx
sc delete diagnosticshub.standardcollector.service
reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules\" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d 0 /f
reg delete "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /f
reg add "HKLM\SYSTEM\ControlSet001\Control\WMI\AutoLogger\AutoLogger-Diagtrack-Listener" /v Start /t REG_DWORD /d 0 /f
```
Press Win+R, type regedit, press enter, and navigate to HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services.  
Here we need to delete the following keys:
* PimIndexMaintenanceSvc
* PimIndexMaintenanceSvc_xxxxx
* DPS
* UserDataSvc
* UserDataSvc_xxxxx
* UnistoreSvc
* UnistoreSvc_xxxxx
* xbgm (If you removed the Xbox stuff)

Some of those keys are "protected" by messed up permissions. To delete them, you must fix them, here's a video showing how to do it:
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/delkey.gif)
Right click the key and select Permissions, then click Advanced, change the Owner to your username, check "Replace owner on subcontainers and objects" and "Replace all child object permission entries with inheritable permission entries from this object", if inheritance is enabled, disable it and convert to explicit permissions, apply, remove all the permission entries and add one for your username with Full control, confirm everything and delete the key.

Reboot!

Last but not least, we also need to remove Microsoft Compatibility Telemetry. This process does more than spying on you, it's also a resource hog when it's running, especially if you don't have an SSD.  
To remove it, download [this archive](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/Remove_CompatTel.zip), extract it somewhere and run "Remove_CompatTel.bat" as administrator.

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
```
Some of these may not exist, it's fine.

## Last touches
We must disable Windows Spotlight, and other "Suggestions" (literal ads).

Go to Start > Settings > Personalization: 
* Under Lock screen and set the background to Picture
* Under Start set Occasionally show suggestions in Start to off (They're literally ads)

Go back to Settings and go to System > Notifications and actions:
* Set Get tips, tricks, and suggestions as you use Windows to off
* Set Show me the Windows welcome... to off
 
Go back to Settings and go to Privacy:
* Under General, set Let Windows track app launches... to off
* Under App diagnostics, set Let apps access diagnostic information to off

## Protect your wifi network from your friends!
If you give your Wifi password to a friend who has Wifi Sensor turned on (it was turned on by default in the previous versions of Windows 10), it will share your password with his Skype, Outlook, ... contacts, which means your Wifi password will be sent to Microsoft.  
You can disable this by adding _optout to the name of your network.
![](https://raw.githubusercontent.com/adolfintel/Windows10-Privacy/master/data/screen(35).png)

## Optional: use a firewall!
For some applications (such as the settings app), the only way to prevent them from reporting data is to block them with a firewall. This is why you should use a firewall, such as [TinyWall](http://tinywall.pados.hu/) to block all traffic except what you explicitly allow.  
Personally, I allow Windows Update, Network discovery and sharing, DHCP, DNS, my web browser and nothing more. This will limit the traffic of undesired applications to DNS queries, they won't be able to send or receive anything.  
Setting up the firewall may take some time, but you'll be as safe as you could possibly be when using Windows. Tinywall's autolearn feature is very useful when you install a new application: it will learn its patterns and allow them through the firewall.  
A big limitation of Tinywall, if you decide to use it, is that you cannot allow/block individual UWP apps (for instance, allow Facebook but not Candy Crush). Blocking WWAHost.exe (recommended) will block all of them, while allowing it will allow all of them to go through. Microsoft Edge is the only exception and has its own exe files. The same thing happens if you use the UNIX subsystem, there is no way to block specific applications.

## Congratulations! Your copy of Windows is now Debotnetted!
Things will change in the future, and I'll do what I can to keep this guide updated.
As of May 2017, this guide works on Windows 10 Pro.

## Can Windows revert these changes?
There are a few things that can revert the changes we made here:
* __Major updates__:  when a major update is installed it's like reinstalling Windows. It keeps your programs and settings but the system is reinstalled, and all the botnet with it. Major updates usually come out every 8-12 months. I will keep the guide updated every time a new major update comes out.
* __Some minor updates__: some updates will update Game DVR, as well as the Microsoft Compatibility Telemetry, thus reinstalling them if you removed them, so you will have to remove them again. These updates usually come out every 2 months and are the ones that take a long time to download and install. Nothing else will not be restored.
* __Using ``sfc /scannow``__:  this command checks system files for integrity. If you run it, it will reinstall Game DVR and Microsoft Compatibility Telemetry.
* __Using ``dism /Online /Cleanup-Image /RestoreHealth``__:  if you run this command, it will revert almost all changes
* __Using System Restore__:  if you go back to before the changes were made, it will revert changes
