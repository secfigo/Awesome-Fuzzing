Welcome to Awesome Fuzzing [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)
===================

A list of fuzzing resources ( Books, courses - free and paid, videos, tools, tutorials,and vulnerable applications to practice on ) for learning Fuzzing and initial phases of Exploit Development like root cause analysis.

### Table of Contents
- [Books](#books)
- [Courses](#courses)
   + [Free](#free)
   + [Paid](#paid)
- [Videos](#videos)
  + [NYU Poly Course videos](#nyu-poly-videos)
  + [Conference talks/tutorials on Fuzzing](#conf-talks-tutorials)
- [Tutorials](#tutorials)
- [Tools](#tools)
  + [File Format Fuzzers](#file-format-fuzzers)
  + [Network Protocol Fuzzers](#network-protocol-fuzzers)
  + [Taint Analysis](#taint-analysis)
  + [Symbolic Execution + SAT/SMT Solvers](#smt-solvers)
  + [Essential Tools (generic)](#essential-tools)
- [Vulnerable Applications](#vuln-apps)


Awesome Fuzzing Resources
-------------

<a name="books" />
### Books

Fuzzing: Brute Force Vulnerability Discovery  - https://www.amazon.com/Fuzzing-Brute-Force-Vulnerability-Discovery/dp/0321446119 

Fuzzing for Software Security Testing and Quality Assurance - https://www.amazon.com/Fuzzing-Software-Security-Assurance-Information/dp/1596932147

Open Source Fuzzing Tools - https://www.amazon.com/Open-Source-Fuzzing-Tools-Rathaus/dp/1597491950 

Gray Hat Python - https://www.amazon.com/Gray-Hat-Python-Programming-Engineers/dp/1593271921 


> **Note:** Chapter(s) in the following books are dedicated to fuzzing

> - The Shellcoder's Handbook: Discovering and Exploiting Security Holes ( Chapter 15 ) - https://www.amazon.com/Shellcoders-Handbook-Discovering-Exploiting-Security/

> - iOS Hacker's Handbook - Chapter 1 - https://www.amazon.com/iOS-Hackers-Handbook-Charlie-Miller/dp/1118204123/ 

IDA Pro - The IDA Pro Book: The Unofficial Guide to the World's Most Popular Disassembler



<a name="courses" />
### </i> Courses

<a name="free" />
#### Free 
NYU Poly - https://vimeo.com/5236104 ( see videos for more )

Samclass.info ( check projects section and chapter 17 ) - https://samsclass.info/127/127_F15.shtml

Modern Binary Exploitation ( RIPESEC ) - Chapter 15 - https://github.com/RPISEC/MBE 

<a name="paid" />
#### Paid ( $$$ ) 
Offensive Security, Cracking The Perimeter ( CTP ) and Advanced Windows Exploitation ( AWE ) -  https://www.offensive-security.com/information-security-training/

SANS 660/760 Advanced Exploit Development for Penetration Testers - https://www.sans.org/course/advance-exploit-development-pentetration-testers


<a name="videos" />
### Videos
<a name="nyu-poly-videos" />
#### NYU Poly Course videos (from Dan Guido)
Mike Zusman - Fuzzing 101 (Part 1) - https://vimeo.com/5236104

Mike Zusman - Fuzzing 101 (Part 2) - https://vimeo.com/5237484

Mike Zusman - Fuzzing 101 (2009)  - https://vimeo.com/7574602 

<a name="conf-talks-tutorials" />
#### Conference talks/tutorials on Fuzzing
Youtube Playlist of various fuzzing talks and presentations - https://www.youtube.com/playlist?list=PLtPrYlwXDImiO_hzK7npBi4eKQQBgygLD
Consider watching talks from Charlie Miller, 

<a name="tutorials" />
### <i class="icon-file"></i> Tutorials
> **Note:** Folks at fuzzing.info has done a great job of collecting some awesome links, i'm not going to duplicate their work. I will add papers from 2015 and 2016 soon here.

Fuzzing Papers- https://fuzzing.info/papers/ 

Fuzzing Blogs  - https://fuzzing.info/resources/ 

https://www.corelan.be/index.php/2013/02/26/root-cause-analysis-memory-corruption-vulnerabilities/ 
https://www.corelan.be/index.php/2013/07/02/root-cause-analysis-integer-overflows/ 

Spike
http://null-byte.wonderhowto.com/how-to/hack-like-pro-build-your-own-exploits-part-3-fuzzing-with-spike-find-overflows-0162789/ 

<a name="tools" />
### Tools
<a name="file-format-fuzzers" />
#### File Format Fuzzers

MiniFuzz  - https://www.microsoft.com/en-sg/download/details.aspx?id=21769 

BFF from cert - https://www.cert.org/vulnerability-analysis/tools/bff.cfm?

AFL Fuzzer (Linux only) - http://lcamtuf.coredump.cx/afl/ 

Peach Fuzzer - https://peachfuzz.sourceforge.net/ 

Failure Observation Engine (FOE) - www.cert.org/vulnerability-analysis/tools/foe.cfm 

rmadair - http://rmadair.github.io/fuzzer/

<a name="network-protocol-fuzzers" />
#### Network Protocol Fuzzers
Sulley - https://github.com/OpenRCE/sulley

Spike  - http://www.immunitysec.com/downloads/SPIKE2.9.tgz 

Peach Fuzzer - https://peachfuzz.sourceforge.net/ 

Metasploit - https://www.rapid7.com/products/metasploit/download.jsp 

<a name="taint-analysis" />
#### Taint Analysis ( How user input affects the execution)
PANDA ( Platform for Architecture-Neutral Dynamic Analysis ) - https://github.com/moyix/panda - 

QIRA (QEMU Interactive Runtime Analyser) - http://qira.me/ 

<a name="smt-solvers" />
#### Symbolic Execution + SAT/SMT Solvers
Z3 - https://github.com/Z3Prover/z3 

SMT-LIB - http://smtlib.cs.uiowa.edu/ 

#### References

I haven't included some of the legends like AxMan, please refer the following link for more information.
https://www.ee.oulu.fi/research/ouspg/Fuzzers 

<a name="essential-tools" />
#### Essential Tools (generic)

<a name="debuggers" />
##### Debuggers 


Windbg - https://msdn.microsoft.com/en-in/library/windows/hardware/ff551063(v=vs.85).aspx 

Immunity Debugger - http://debugger.immunityinc.com

OllyDbg - http://www.ollydbg.de/

Mona.py ( Plugin for windbg and Immunity dbg )  - https://github.com/corelan/mona/

X64dbg - https://github.com/x64dbg/


Evan's Debugger (EDB) - http://codef00.com/projects#debugger

GDB - http://www.sourceware.org/gdb/ 

PEDA - https://github.com/longld/peda 

Radare2 - http://www.radare.org/r/ 


<a name="dissembers" />
##### Dissemblers and some more


IDA Pro  - https://www.hex-rays.com/products/ida/index.shtml

binnavi - https://github.com/google/binnavi

Capstone - https://github.com/aquynh/capstone

<a name="others" />
##### Others

ltrace - http://ltrace.org/

strace - http://sourceforge.net/projects/strace/


<a name="vuln-apps"/>
### Vulnerable Applications
Exploit-DB - https://www.exploit-db.com
(search and pick the exploits, which have respective apps available for download, reproduce the exploit by using fuzzer of your choice)




