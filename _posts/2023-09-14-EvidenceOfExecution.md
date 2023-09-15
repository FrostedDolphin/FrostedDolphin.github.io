---
title: Going in Blind - Evidence of Execution
author: austin
date: 2023-09-15
categories: [Forensics, Evidence of Execution]
tags: [Forensics]
---

## Introduction

You get a call from your parents one day saying they think their laptop or computer was hacked into. Immediately you might being sighing or rolling your eyes as you get dried out being the only free tech support person in your friends/family circle. With how uncommon these types of events are (yeah, right?), you may be thinking this was probably some sort of tech scammer or other type of unauthorized remote access event. You could conduct a "user interview" which would give more context into the situation, like what they were doing before they called or if they saw any pop-ups etc, but that involves extending the conversation even further, risking your sanity.. The hero you are cuts them short and tells them you'll handle it. 

Where does your investigation begin? Even if you had an EDR/AV solution on that host, there might not be any detections to go off of, you're completely on your own and feel overwhelmed. One might even say, "Lost in the sauce". This is where taking a forensics perspective would come in handy. Introducing the category of forensic artifacts called **evidence of execution**. 

## What is evidence of execution?

Evidence of execution does exactly what's said in the name. It gives us solid proof that cannot be disputed that a binary was in fact run on a host along with a timeline of when it was run on the host and how many times (up to a certain amount but this will be covered shortly) it was run. 

### Prefetch: Introduction
Usually one of the first places I look when starting a blind investigation is in the Windows prefetch folder, this gives a list of all executable names that were run on the host. But what exactly is a prefetch file and why is it useful? 

Windows prefetch is a process where the operating system loads data and code from disk to memory before its needed, this speeds up the application load time. The cache manager will monitor information about what running in each application and use it when that application starts up again. (think of an application crashing on you and when it restarts, you pick up where you left off before the crash). Some of these cache files are in the form of a prefetch file with a .pf extension. If configured correctly in Windows, there will be a cache file for every application you run (just one of the many ways Windows tracks your every move). Prefetch files are also known as a shell item, this means that there is enough information stored in this artifact to give us more than just a birds eye view of what being run on a host. Shell items record not only timestamps and executable name, but also the file size and Master File Table (MFT) information on the original file and folder in the path if it was renamed or moved.

 There are some things to keep in mind about prefetch as you're sifting through the data. 
- Windows 7 Pefetch files only stores 1 run time 
- Windows 8+ Prefetch files will store the last 8 run times (plus the file creation time of the prefetch file itself, this would be give us the last 9 times the binary was run)
- There will be multiple entries for files like dllhost, svchost, rundll32, and backgroundtask host due to the many different commandline arguments that get passed with each instance of these
- These track applications that are both GUI and commandline based (huge win)
- Windows workstation has prefetching turned on by default 
- Windows server does not have this turned on by default 
- Windows 7 and before is limited to 128 files inside of the prefetch folder 
- Windows 8+ is limited to 1024 files inside of the prefetch folder

```
Location: 
C:\Windows\Prefetch

Enabling prefetch: 
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters
Value: EnablePrefetcher 
Type: REG_WORD 
Value: 1
```

### Prefetch: Analysis

