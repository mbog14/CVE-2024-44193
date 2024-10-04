# Hacking Windows through iTunes  - Local Privilege Escalation 0-day

## Introducing CVE-2024–44193
This is a write up on CVE-2024–44193 which is a Local Privilege Escalation exploit in iTunes version 12.13.2.3. 

It was patched September 12, 2024 by Apple.
Link to Apple's Security Advisory: [Apple's Security Advisory](https://support.apple.com/en-us/121328)

iTunes version 12.13.2.3 installs the Apple Device Discovery Service:
`C:\Program Files\Common Files\Apple\Mobile Device Support\AppleMobileDeviceService.exe` which is vulnerable to a Local Privilege Escalation exploit.

## TL;DR
In respect and understanding for those of you who do not care about a yet another poorly written and probably too long write up, here is the short version:

The vulnerability is enabled due to poor management of user permissions in the `C:\ProgramData\Apple\*` path. 
This allows members of the Local Group "Users" to write arbitrary files within that path. When the `AppleMobileDeviceService.exe` service is restarted, which can be triggered by an unprivileged user, an arbitrary folder/file deletion primitive can be armed to gain arbitrary code execution on the system with SYSTEM privileges.

## Tooling:
**Warning!** Mediocre tool explanations incoming.

Skip this section if you are already familiar with the tools.

- Oplock

[SetOpLock](https://github.com/googleprojectzero/symboliclink-testing-tools/tree/main/SetOpLock)

The Oplock tool is a tool to use an “opportunistic lock” in Windows. The tool allows us “halt” a process by locking a file until certain requirements are satisfied, however it can also be used to “halt” a process for malicious purposes such as gaining enough time for our exploit payload to run.

- FolderContentsDeleteToFolderDelete

[FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)

The FolderContentsDeleteToFolderDelete tool works by automatically create a folder with a file within. An oplock is then set on the file to halt the process. When the process is halted, the file is moved out of the folder. The folder is then deleted, and recreated as a NTFS junction to a target destination.
When the oplock is cancelled, and the process continues, the file/folder deletion follows the newly created NTFS junction to the target destination and deletes that file before continuing execution.

- FolderOrFileDeleteToSystem

[FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)

This tool is probably best explained by the Zero Day Initiative so here is a link to an explanation directly from them:

[Abusing Arbitrary File Deletes to Escalate Privileges and other Great Tricks](https://www.zerodayinitiative.com/blog/2022/3/16/abusing-arbitrary-file-deletes-to-escalate-privilege-and-other-great-tricks)

## The actual write up
### Introduction to the vulnerable service `AppleMobileDeviceService.exe`
Once iTunes is installed, it also installs a service: `AppleMobileDeviceService.exe` which runs with SYSTEM privileges.
When I investigated that service using Windows Sysinternals Process Monitor (Procmon) I immediately spotted some concerning behavior.

The service will recursively go through all files within the `C:\ProgramData\Apple\Lockdown\*` path and will delete all folders and files that do not belong there.

For local testing, I used ProcessHacker2 to forcefully restart the service in order to inspect program behavior.
The observed behavior was that the service running as SYSTEM will query the directory and all the sub directories within, and then it will run the `CreateFile` operation with `Delete On Close` option enabled meaning that the SYSTEM service will query the `C:\ProgramData\Apple\Lockdown\*` path and recursively query the sub folders and files within that directory and delete them.

<img title="a title" alt="Alt text" src="/images/recursion.png">

## Problematic user privileges in the path: `C:\ProgramData\Apple\*`
Windows Sysinternals https://learn.microsoft.com/en-us/sysinternals/ accesschk64.exe can be used to check access rights on specific folders. 
Members of the Local Group "Users" have write permissions within the `C:\ProgramData\Apple\Lockdown\` folder which enables low privileged users to write arbitrary files within the folder.

<img title="a title" alt="Alt text" src="/images/badpermissions.png">

## Arbitrary file/folder deletion primitive
Because we can write arbitrary files within the Lockdown path, and the SYSTEM process will delete them when the service is restarted it was possible to create an abitrary file/folder deletion primitive. 
In order to illustrate this I create two sub folders within the Lockdown folder. 
Sub folder a, and sub folder b within sub folder a. 
This will look like this: `C:\ProgramData\Apple\Lockdown\a\b`
 

Within sub folder `a` there is a text file called `aa.txt` and within sub folder `b` there is a text file called `bb.txt`

`C:\ProgramData\Apple\Lockdown\a\aa.txt`

`C:\ProgramData\Apple\Lockdown\a\b\bb.txt`

<img title="a title" alt="Alt text" src="/images/deleteonclose.png">

*As can be seen in the screenshot above, the "CreateFile" Operation is being run with "Delete On Close" Option on aa.txt deleting it.*

When the SYSTEM process runs the operation `CreateFile` on `aa.txt` and `bb.txt` the with the option `Delete On Close` on the files the SYSTEM process `AppleMobileDeviceService.exe` will delete the files. 
Now it is possible for us create arbitrary files within the Lockdown folder, and delete them which leads us to the next neat trick.

### NTFS junctions
In Windows it is possible to use NTFS junctions to direct a folder to someplace else. In a way, this is similar to symlinks in Linux. 
To illustrate this it is possible to create a NTFS junctions (symlink) within the `C:\ProgramData\Apple\Lockdown` folder pointing to a folder on the Desktop. 
You can achieve this yourself using using PowerShell `New-Item -Type Junction -Path whatever -Target "C:\Users\user\Desktop\AAyes"`, or just use the toolset offered by ZDI: 

[FilesystemEoPs](https://github.com/thezdi/PoC/tree/main/FilesystemEoPs)

Run the following command to point a NTFS junctions within the Lockdown folder to "Target" on the Desktop.
```
.\FolderContentsDeleteToFolderDelete.exe /target "C:\Users\user\Desktop\AAyes" /initial "C:\ProgramData\Apple\Lockdown"
```


When the Service is restarted, the newly created NTFS junction will point to `AAyes` located on the Desktop. 
Because the Service runs the `CreateFile` operation with `Delete On Close` option as SYSTEM the file will be deleted. 
Because the operation is run with SYSTEM privileges we have an arbitrary folder or file deletion primitive which means that we can get code execution on the host as SYSTEM.

<img title="a title" alt="Alt text" src="/images/aayes_delete.png">

**NOTE:**

It was necessary to make certain source code edits in the FolderContentsDeleteToFolderDelete project due to file name / folder name restrictions. The file names / folder names had to be very short for the deletion to take place. The reason behind this is unknown and it has not been investigated as short names solved the issue in a reliable way.

#### FolderContentsDeleteToFolderDelete source code edits:
```
const wchar_t folder2path[] = L"C:\\d";
const wchar_t exploitFileName[] = L"e.txt";

// It was required to shorten the two consstants: “folder2path” and “exploitFileName”
// They where changed to: L"C:\\d" and L"e.txt" because it seemed that file and folder name length had a meaningful impact on exploit functionality.

[...]

// We also needed to edit the “folder1path” value to L”c” in order to shorten it.
folder1path += L"c";

```

### Exploitation thesis
Because the service will recursively follow any junctions (symlinks) the thesis was that it would be possible to arbitrarily delete files on the system as SYSTEM using the vulnerable Apple service which will follow the NTFS junction. Since the vulnerable service conveniently allows unprivileged users to restart the service using the ("Apps -> Installed apps -> Apple Mobile Device Support -> Modify -> Repair) trick using the Windows GUI it is possible to trigger the exploit at will. Once the service is restarted it will follow the NTFS junction and the determined program behavior dictates that the service will delete the files or folders that the user chooses to point to.

In other words, it is the user that decides which files or folders the service will delete. 
Because it runs as SYSTEM, we can delete *almost* any file on the system (not files requiring TrustedInstaller privileges).

This means that we can carefully craft a chain of events that will do the following:
1. Prepare oplock to halt the process at a convenient time for us to prepare exploitation steps
2. Restart service, oplock is triggered and the process is halted
3. Prepare our MSI rollback trick using FolderOrFileDeleteToSystem.exe
4. Prepare our NTFS junction to point file deletion primitive to Config.MSI prepared by the MSI rollback trick step using FolderContentsDeleteToFolderDelete.exe
5. Release the oplock

## Proof Of Concept
The Proof of Concept consists of 5 steps.

1. Set Oplock on C:\ProgramData\Apple\Lockdown\
```
.\SetOpLock.exe C:\ProgramData\Apple\Lockdown\
```
<img title="a title" alt="Alt text" src="/images/setoplock.png">

2. Trigger service restart
 Apps -> Installed apps -> Apple Mobile Device Support -> Modify -> Repair

3. Prepare MSI rollback trick
```
.\FolderOrFileDeleteToSystem.exe
```

4. Prepare Windows Junction (symlink) step to point the service arbitrary folder/file deletion primitive to the MSI installer
```
.\FolderContentsDeleteToFolderDelete.exe /target 'C:\Config.Msi' /initial "C:\ProgramData\Apple\Lockdown"
```

5. Release Oplock

When the Oplock is released in step five, we monitor FolderContentsDeleteToFolderDelete process to verify that the NTFS junciton was followed and that the Config.MSI located in C:\ was correctly deleted. Then we monitor the FolderOrFileDeletionToSystem.exe process to verify that we win the race condition and that the "malicious" Config.MSI folder with the modified rollback script is written. If everything goes right, we can CTRL+ALT+DELETE, open the Accessibility menu in the lower right hand corner and open the On-screen Keyboard. Because we have overwritten the HID.DLL in C:\Program Files\Common Files\microsoft shared\ink\HID.DLL using the malicious rollback script a CMD shell will pop as SYSTEM finishing our exploit.
<img title="a title" alt="Alt text" src="/images/foldercontentsdeletetofolderdelete.png">

Executing and monitoring FolderContentsDeleteToFolderDelete.exe

<img title="a title" alt="Alt text" src="/images/folderorfiledeletetosystem.png">

Executing and monitoring FolderOrFileDeleteToSystem.exe

<img title="a title" alt="Alt text" src="/images/shell.png">

**Popping a SYSTEM shell**
