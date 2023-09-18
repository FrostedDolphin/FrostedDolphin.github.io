---
title: Going in Blind - Evidence of Execution
author: austin
date: 2023-09-17
categories: [Forensics, Evidence of Execution]
tags: [Forensics]
---

## Introduction

You get a call from your parents one day saying they think their laptop or computer was hacked. Immediately you might being sighing or rolling your eyes as you get dried out being the only free tech support person in your friends/family circle. With how uncommon these types of events are (yeah, right?), you may be thinking this was probably some sort of tech scammer or other type of unauthorized remote access event. You could conduct a "user interview" which would give more context into the situation, like what they were doing before they called or if they saw any pop-ups etc, but that involves extending the conversation even further, risking your sanity.. The hero you are cuts them short and tells them you'll handle it. 

Where does your investigation begin? Even if you had an EDR/AV solution on that host, there might not be any detections to go off of, you're completely on your own and feel overwhelmed. One might even say, "Lost in the sauce". This is where taking a forensics perspective would come in handy. Introducing the category of forensic artifacts called **evidence of execution**. 

## What is evidence of execution?

Evidence of execution is exactly what it's name suggests. It gives us solid proof that cannot be disputed that a binary was in fact run on a host along with a timeline of when it was run on the host and how many times (up to a certain amount but this will be covered shortly) it was run. 

### Prefetch: Introduction
Usually one of the first places I look when starting a blind investigation is in the Windows prefetch folder, this gives a list of all executable names that were run on the host. But what exactly is a prefetch file and why is it useful? 

Windows prefetch is a process where the operating system loads data and code from disk to memory before its needed, this speeds up the application load time. The cache manager will monitor information about what running in each application and use it when that application starts up again. (think of an application crashing on you and when it restarts, you pick up where you left off before the crash). Some of these cache files are in the form of a prefetch file with a .pf extension. If configured correctly in Windows, there will be a cache file for every application you run (just one of the many ways Windows tracks your every move). Prefetch files are also known as a shell item, this means that there is enough information stored in this artifact to give us more than just a birds eye view of what is being run on a host. Shell items record not only timestamps and executable names, but also the file size and Master File Table (MFT) information on the original file and folder in the path if it was renamed or moved.

 There are some things to keep in mind about prefetch as you're sifting through the data. 
- Windows 7 Pefetch files only stores 1 run time 
- Windows 8+ Prefetch files will store the last 8 run times (plus the file creation time of the prefetch file itself, this would be give us the last 9 times the binary was run)
- Timestamp of the .pf file's date created is within 10 seconds of when the application executing 
- There will be multiple entries for files like dllhost, svchost, rundll32, and backgroundtask host due to the many different commandline arguments that get passed with each instance of these
- These track applications that are both GUI and commandline based (huge win)
- Windows workstation has prefetching turned on by default 
- Windows server does not have this turned on by default 
- Windows 7 and before is limited to 128 files inside of the prefetch folder 
- Windows 8+ is limited to 1024 files inside of the prefetch folder


Location: 
`C:\Windows\Prefetch`

Enabling prefetch

Registry Key: `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters`

Value: `EnablePrefetcher`

Type: `REG_WORD`

Value: `1`

### Prefetch: Analysis

The meta data inside of these files are information about the volume, files and directories used, and up to the last 8 execution times. To parse this data out, use PSCmd.exe, a popular tool from Eric Zimmerman. This tool can be used to parse out a single prefetch file, or a whole directory of them. 

> If all that's needed is a check to see the most recently executed applications, file created and file modified dates seen within the folder of prefetch files would do just fine. 
{: .prompt-tip }

An example of usage for PECmd.exe:
```
> PECmd.exe -f CALCULATOR.EXE-DD323BEE.pf 
> PECmd.exe -d C:\Windows\Prefetch --csv C:\temp\casefiles -q 
```

This is what running PECmd on a single prefetch file would look like, notice the file and directories referenced section, this is everything that this exe touched within the first ten second of it running (remember when it was mentioned above that prefetch files don't get created until after 10 seconds of the file being run). From a malware analysis perspective, you might be able to use these sections to find some other IOCs to aid in your search. 

```
PECmd version 1.5.0.0

Author: Eric Zimmerman (saericzimmerman@gmail.com)
https://github.com/EricZimmerman/PECmd

Command line: -f .\SETUP.EXE-BC6B5435.pf

Keywords: temp, tmp

Processing .\SETUP.EXE-BC6B5435.pf

Created on: 2022-08-13 17:31:26
Modified on: 2022-08-13 17:31:36
Last accessed on: 2023-09-18 04:01:00

Executable name: SETUP.EXE
Hash: BC6B5435
File size (bytes): 29,846
Version: Windows 10 or Windows 11

Run count: 3
Last run: 2022-08-13 17:31:26
Other run times: 2022-08-13 17:31:26, 2022-08-13 17:31:26

Volume information:

#0: Name: \VOLUME{01d8559f7371205e-b0737add} Serial: B0737ADD Created: 2022-04-21 16:47:13 Directories: 10 File references: 40

Directories referenced: 10

00: \VOLUME{01d8559f7371205e-b0737add}\PROGRAM FILES (X86)
01: \VOLUME{01d8559f7371205e-b0737add}\PROGRAM FILES (X86)\MICROSOFT
02: \VOLUME{01d8559f7371205e-b0737add}\PROGRAM FILES (X86)\MICROSOFT\EDGE
...
09: \VOLUME{01d8559f7371205e-b0737add}\WINDOWS\SYSTEM32

Files referenced: 43

00: \VOLUME{01d8559f7371205e-b0737add}\WINDOWS\SYSTEM32\NTDLL.DLL
01: \VOLUME{01d8559f7371205e-b0737add}\PROGRAM FILES (X86)\MICROSOFT\EDGE\APPLICATION\104.0.1293.54\INSTALLER\SETUP.EXE (Executable: True)
02: \VOLUME{01d8559f7371205e-b0737add}\WINDOWS\SYSTEM32\KERNEL32.DLL
03: \VOLUME{01d8559f7371205e-b0737add}\WINDOWS\SYSTEM32\KERNELBASE.DLL
...
```


Below we can see the csv output when you run PECmd against an entire directory of prefetch files. There are two files that get created, the on labeled timeline is most interesting because we can not only see the prefetch file that were most interested in, but also all the other binaries that were run in proximity. This can give us clues to other lolbins (Live Off the Land Binaries) that are harder to detect malice from but easy to abuse. For example we might see a malicious setup file being run and be able to point out when it was run from its prefetch file, but until we pull this timeline, we might not know it had the capability of running wmic commands, or establishing persistence with reg.exe. This isn't the best picture of a timeline to showcase for malice but it gives an example of what you would expect to see. 

![PECmd for a single prefetch file](/assets/img/PFdir.png) 
_Output of PECmd.exe on a directory_ 


Say you do come across a piece of malware that was run on the host, but it was deleted either due to user getting rid of it, the malware was self deleting, or it was scrubbed away with antivirus, it would be preferred to sandbox the malware and do additional research on it to help see what the binary does and be able to find more artifacts to aid in your response, or even to just make sure the device is clean of any other residue it may have left behind. Checking the recycle bin or AV quarantine location is a safe bet, but that's boring. What's more exciting is looking at the registry of course! 

### Application Compatibility - ShimCache + AmCache: Introduction

Generally speaking, application compatibility in Windows checks each executable and helps load other properties from a previous version of Windows for the application to run correctly. We're not interested in if a file is able to run correctly on a current version of Windows or not, what is interesting here is Windows having the audacity to scan every file in a directory whether if its being run or not with absolutely no consent. This is a prime example of Windows not only invading your privacy, but your files and folders privacy as well. This artifact will do a couple things for an examiner:

1. If the malware was in a directory of other tools, those other tools maybe also be scanned and placed in the database here for us to view. 
2. Each executable comes with a SHA1 hash ;) 

### Application Compatibility - ShimCache + AmCache: Analysis

Here's how to extract this juicy information. First, (make sure the rest of Eric Zimmermans tools are on the machine being investigated) run this command on the live host:

```
> AppCompatCacheParser.exe --csv C:\temp 
```

Next, open the file that was just created and filter on any files or folders of interest. Example: if a piece of malware was dropped in a temp directory or in an interestingly named folder, filter on that folder name and you'll be getting some nice information about other tools that might not have been run. 

![AppCompatCacheParser on a live machine](/assets/img/AppCompatParser.png)
_Output of AppCompatCacheParser_

Again, nothing too exciting here to showcase since these are legitimate files, but could just as easily be stealthy malware, just use your imagination here and pretend C:\Windows\Temp is a directory filled with bad. 

Next, run amcacheparser which will parse the amcache hive and place the results in multiple folders. The files with the information needed to get the file hashes are `Amcache_UnassociatedEntries`, `Amcache_DriveBinaries`, and `Amcache_ProgramEntries`. The parser here will categorize the files based on its attributes, therefore the binary(ies) you're interested in may be in any one of these csv files. Just have to open them up and look :)

```
> amcacheparser.exe -i -f C:\Windows\AppCompat\Programs\Amcache.hve --csv C:\temp
```

Now check the above mentioned files for your artifacts and collect your iocs! 

![AMCache on a live machine](/assets/img/AMCache.png)
_Output of AmCacheParser_

All that's left is finding a database to search for your sample's hash, download it, and now it's yours to sandbox! My favorite are VirusTotal and VirusShare.

Thanks for reading, here's some resources and references:

## Refences & Resources

> [**forensafe - AmCache**](https://forensafe.com/blogs/AmCache.html)

> [**andreafortuna - AmCache / ShimCache**](https://forensafe.com/blogs/AmCache.html)

> [**Magnet - Prefetch**](https://forensafe.com/blogs/AmCache.html)