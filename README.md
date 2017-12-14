Welcome to Awesome Fuzzing [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)
===================

A curated list of fuzzing resources ( Books, courses - free and paid, videos, tools, tutorials and vulnerable applications to practice on ) for learning Fuzzing and initial phases of Exploit Development like root cause analysis.

### Table of Contents
- [Books](#books)
- [Courses](#courses)
   + [Free](#free)
   + [Paid](#paid)
- [Videos](#videos)
  + [NYU Poly Course videos](#nyu-poly-course-videos)
  + [Conference talks and tutorials](#conference-talks-and-tutorials)
- [Tutorials and Blogs](#tutorials-and-blogs)
- [Tools](#tools)
  + [File Format Fuzzers](#file-format-fuzzers)
  + [Network Protocol Fuzzers](#network-protocol-fuzzers)
  + [Taint Analysis](#taint-analysis)
  + [Symbolic Execution SAT and SMT Solvers](#symbolic-execution-sat-and-smt-solvers)
  + [Essential Tools](#essential-tools)
- [Vulnerable Applications](#vulnerable-applications)
- [Anti-Fuzzing](#anti-fuzzing)
- [Contributing](#contributing)


# Awesome Fuzzing Resources

## Books

*Books on fuzzing*
- [Fuzzing: Brute Force Vulnerability Discovery](https://www.amazon.com/Fuzzing-Brute-Force-Vulnerability-Discovery/dp/0321446119) by Michael Sutton, Adam Greene, Pedram Amini.

- [Fuzzing for Software Security Testing and Quality Assurance ](https://www.amazon.com/Fuzzing-Software-Security-Assurance-Information/dp/1596932147) by Ari Takanen, Charles Miller, and Jared D Demott.

- [Open Source Fuzzing Tools](https://www.amazon.com/Open-Source-Fuzzing-Tools-Rathaus/dp/1597491950) by by Gadi Evron and Noam Rathaus.

- [Gray Hat Python](https://www.amazon.com/Gray-Hat-Python-Programming-Engineers/dp/1593271921) by Justin Seitz.


> **Note:** Chapter(s) in the following books are dedicated to fuzzing.

> - [The Shellcoder's Handbook: Discovering and Exploiting Security Holes ( Chapter 15 )](https://www.amazon.com/Shellcoders-Handbook-Discovering-Exploiting-Security/) by Chris Anley, Dave Aitel, David Litchfield and others.

> - [iOS Hacker's Handbook - Chapter 1](https://www.amazon.com/iOS-Hackers-Handbook-Charlie-Miller/dp/1118204123/) Charles Miller, Dino DaiZovi, Dion Blazakis, Ralf-Philip Weinmann, and Stefan Esser.

> - [IDA Pro - The IDA Pro Book: The Unofficial Guide to the World's Most Popular Disassembler](https://www.amazon.com/IDA-Pro-Book-Unofficial-Disassembler-ebook/dp/B005EI84TM)


## Courses

*Courses/Training videos on fuzzing*


### Free  

[NYU Poly ( see videos for more )](https://vimeo.com/5236104 ) - Made available freely by Dan Guido.

[Samclass.info ( check projects section and chapter 17 ) ](https://samsclass.info/127/127_F15.shtml) - by Sam.

[Modern Binary Exploitation ( RPISEC ) - Chapter 15 ](https://github.com/RPISEC/MBE) - by RPISEC.

[Offensive Computer Security - Week 6](http://www.cs.fsu.edu/~redwood/OffensiveComputerSecurity/lectures.html) - by W. Owen Redwood and Prof. Xiuwen Liu. 

### Paid

[Offensive Security, Cracking The Perimeter ( CTP ) and Advanced Windows Exploitation ( AWE )](https://www.offensive-security.com/information-security-training/)

[SANS 660/760 Advanced Exploit Development for Penetration Testers](https://www.sans.org/course/advance-exploit-development-pentetration-testers)

[Exodus Intelligence - Vulnerability development master class](https://blog.exodusintel.com/2016/05/18/exodus-intelligence-2016-training-course/)


## Videos

*Videos talking about fuzzing techniques, tools and best practices*


### NYU Poly Course videos
[Fuzzing 101 (Part 1)](https://vimeo.com/5236104) - by Mike Zusman.

[Fuzzing 101 (Part 2)](https://vimeo.com/5237484) - by Mike Zusman.

[Fuzzing 101 (2009)](https://vimeo.com/7574602) - by Mike Zusman.

[Fuzzing - Software Security Course on Coursera](https://www.coursera.org/learn/software-security/lecture/VgyOn/fuzzing) - by University of Maryland.

### Conference talks and tutorials
[Youtube Playlist of various fuzzing talks and presentations ](https://www.youtube.com/playlist?list=PLtPrYlwXDImiO_hzK7npBi4eKQQBgygLD) - Lots of good content in these videos. 

[Browser bug hunting - Memoirs of a last man standing](https://vimeo.com/109380793) - by Atte Kettunen

[Coverage-based Greybox Fuzzing as Markov Chain](https://www.comp.nus.edu.sg/~mboehme/paper/CCS16.pdf)

[DerbyCon 2016: Fuzzing basics...or how to break software](http://www.securitytube.net/video/16939)


## Tutorials and Blogs

*Tutorials and blogs which explain methodology, techniques and best practices of fuzzing*

[Effective File Format Fuzzing](http://j00ru.vexillium.org/slides/2016/blackhat.pdf) - Mateusz “j00ru” Jurczyk @ Black Hat Europe 2016, London

[A year of Windows kernel font fuzzing Part-1 the results](http://googleprojectzero.blogspot.in/2016/06/a-year-of-windows-kernel-font-fuzzing-1_27.html) - Amazing article by Google's Project Zero, describing what it takes to do fuzzing and create fuzzers.

[A year of Windows kernel font fuzzing Part-2 the techniques](http://googleprojectzero.blogspot.in/2016/07/a-year-of-windows-kernel-font-fuzzing-2.html) - Amazing article by Google's Project Zero, describing what it takes to do fuzzing and create fuzzers.

[Interesting bugs and resources at fuzzing project](https://blog.fuzzing-project.org/) - by fuzzing-project.org.

[Fuzzing workflows; a fuzz job from start to finish](https://foxglovesecurity.com/2016/03/15/fuzzing-workflows-a-fuzz-job-from-start-to-finish/) - by @BrandonPrry.

[A gentle introduction to fuzzing C++ code with AFL and libFuzzer](http://jefftrull.github.io/c++/clang/llvm/fuzzing/sanitizer/2015/11/27/fuzzing-with-sanitizers.html) - by Jeff Trull.

[A 15 minute introduction to fuzzing](https://www.mwrinfosecurity.com/our-thinking/15-minute-guide-to-fuzzing/) - by folks at MWR Security.

> **Note:** Folks at fuzzing.info has done a great job of collecting some awesome links, I'm not going to duplicate their work. I will add papers missed by them and from 2015 and 2016.
[Fuzzing Papers](https://fuzzing.info/papers) - by fuzzing.info

[Fuzzing Blogs](https://fuzzing.info/resources/) - by fuzzing.info 

[Root Cause Analysis of the Crash during Fuzzing](
https://www.corelan.be/index.php/2013/02/26/root-cause-analysis-memory-corruption-vulnerabilities/) - by Corelan Team. 
[Root cause analysis of integer flow](https://www.corelan.be/index.php/2013/07/02/root-cause-analysis-integer-overflows/) - by Corelan Team.

[Creating custom peach fuzzer publishers](http://blog.opensecurityresearch.com/2014/01/creating-custom-peach-fuzzer-publishers.html) - by Open Security Research

[7 Things to Consider Before Fuzzing a Large Open Source Project](https://www.linux.com/blog/7-things-consider-fuzzing-large-open-source-project) - by Emily Ratliff.


##### From Fuzzing to Exploit:
[From fuzzing to 0-day](https://blog.techorganic.com/2014/05/14/from-fuzzing-to-0-day/) - by Harold Rodriguez(@superkojiman).

[From crash to exploit](https://www.corelan.be/index.php/2013/02/26/root-cause-analysis-memory-corruption-vulnerabilities/) - by Corelan Team. 

##### Peach Fuzzer related tutorials

[Getting Started with Peach](http://community.peachfuzzer.com/v2/PeachQuickstart.html)

[Fuzzing with Peach Part 1](http://www.flinkd.org/fuzzing-with-peach-part-1/) - by Jason Kratzer of corelan team


[Fuzzing with Peach Part 2](http://www.flinkd.org/fuzzing-with-peach-part-2-fixups-2/) - by Jason Kratzer of corelan team.

[Auto generation of Peach pit files/fuzzers](http://doc.netzob.org/en/latest/tutorials/peach.html) - by Frédéric Guihéry, Georges Bossert.

##### AFL Fuzzer related tutorials
[Fuzzing workflows; a fuzz job from start to finish](https://foxglovesecurity.com/2016/03/15/fuzzing-workflows-a-fuzz-job-from-start-to-finish/) - by @BrandonPrry.

[Fuzzing capstone using AFL persistent mode](https://toastedcornflakes.github.io/articles/fuzzing_capstone_with_afl.html) - by @toasted_flakes

[RAM disks and saving your SSD from AFL Fuzzing](http://cipherdyne.org/blog/2014/12/ram-disks-and-saving-your-ssd-from-afl-fuzzing.html)

[Bug Hunting with American Fuzzy Lop](https://josephg.com/blog/bug-hunting-with-american-fuzzy-lop/)

[Advanced usage of American Fuzzy Lop with real world examples](http://volatileminds.net/2015/07/01/advanced-afl-usage.html)

[Segfaulting Python with afl-fuzz](http://tomforb.es/segfaulting-python-with-afl-fuzz)

[Fuzzing Perl: A Tale of Two American Fuzzy Lops](http://www.geeknik.net/71nvhf1fp)

[Fuzzing With AFL-Fuzz, a Practical Example ( AFL vs Binutils )](https://www.evilsocket.net/2015/04/30/fuzzing-with-afl-fuzz-a-practical-example-afl-vs-binutils/)

[The Importance of Fuzzing...Emulators?](https://mgba.io/2016/09/13/fuzzing-emulators/)

[How Heartbleed could've been found](https://blog.hboeck.de/archives/868-How-Heartbleed-couldve-been-found.html)

[Filesystem Fuzzing with American Fuzzy lop](http://events.linuxfoundation.org/sites/events/files/slides/AFL%20filesystem%20fuzzing%2C%20Vault%202016_0.pdf)

[Fuzzing Perl/XS modules with AFL](https://medium.com/@dgryski/fuzzing-perl-xs-modules-with-afl-4bfc2335dd90)

[How to fuzz a server with American Fuzzy Lop](https://www.fastly.com/blog/how-fuzz-server-american-fuzzy-lop/) - by Jonathan Foote

[Fuzzing with AFL Workshop - a set of challenges on real vulnerabilities](https://github.com/ThalesIgnite/afl-training)

##### libFuzzer Fuzzer related tutorials

[libFuzzer Tutorial](http://tutorial.libfuzzer.info)

[libFuzzer Workshop: "Modern fuzzing of C/C++ Projects"](https://github.com/Dor1s/libfuzzer-workshop)


##### Spike Fuzzer related tutorials

[Fuzzing with Spike to find overflows](http://null-byte.wonderhowto.com/how-to/hack-like-pro-build-your-own-exploits-part-3-fuzzing-with-spike-find-overflows-0162789/)

[Fuzzing with Spike](https://samsclass.info/127/proj/p18-spike.htm) - by samclass.info


##### FOE Fuzzer related tutorials

[Fuzzing with FOE](https://samsclass.info/127/proj/p16-fuzz.htm) - by Samclass.info


##### SMT/SAT solver tutorials

[Z3 - A guide](http://rise4fun.com/z3/tutorial/guide) - Getting Started with Z3: A Guide


## Tools

*Tools which helps in fuzzing applications*


### File Format Fuzzers

*Fuzzers which helps in fuzzing file formats like pdf, mp3, swf etc.,*

[MiniFuzz - Wayback Machine link](https://web.archive.org/web/20140512203517/http://download.microsoft.com/download/D/6/E/D6EDC908-A1D7-4790-AB0B-66A8B35CD931/MiniFuzzSetup.msi) - Basic file format fuzzing tool by Microsoft. (No longer available on Microsoft website).

[BFF from CERT](https://www.cert.org/vulnerability-analysis/tools/bff.cfm?) - Basic Fuzzing Framework for file formats.

[AFL Fuzzer (Linux only)]( http://lcamtuf.coredump.cx/afl/) - American Fuzzy Lop Fuzzer by Michal Zalewski aka lcamtuf

[Win AFL](https://github.com/ivanfratric/winafl) - A fork of AFL for fuzzing Windows binaries by Ivan Fratic

[Shellphish Fuzzer](https://github.com/shellphish/fuzzer) - A Python interface to AFL, allowing for easy injection of testcases and other functionality.

[TriforceAFL](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2016/june/project-triforce-run-afl-on-everything/) - A modified version of AFL that supports fuzzing for applications whose source code not available.

[Peach Fuzzer](https://peachfuzz.sourceforge.net/) - Framework which helps to create custom dumb and smart fuzzers.

[MozPeach](https://github.com/MozillaSecurity/peach) - A fork of peach 2.7 by Mozilla Security.

[Failure Observation Engine (FOE)](www.cert.org/vulnerability-analysis/tools/foe.cfm) - mutational file-based fuzz testing tool for windows applications.

[rmadair](http://rmadair.github.io/fuzzer/) - mutation based file fuzzer that uses PyDBG to monitor for signals of interest.

[honggfuzz](https://github.com/google/honggfuzz) - A general-purpose, easy-to-use fuzzer with interesting analysis options. Supports feedback-driven fuzzing based on code coverage. Supports GNU/Linux, FreeBSD, Mac OSX and Android.

[zzuf](https://github.com/samhocevar/zzuf) - A transparent application input fuzzer. It works by intercepting file operations and changing random bits in the program's input.

[radamsa](https://github.com/aoh/radamsa) - A general purpose fuzzer and test case generator.

[binspector](https://github.com/binspector/binspector) - A binary format analysis and fuzzing tool

[grammarinator](https://github.com/renatahodovan/grammarinator) - Fuzzing tool for file formats based on ANTLR v4 grammars (lots of grammars already available from the ANTLR project).

### Network Protocol Fuzzers

*Fuzzers which helps in fuzzing applications which use network based protocals like HTTP, SSH, SMTP etc.,*

[Peach Fuzzer](https://peachfuzz.sourceforge.net/) - Framework which helps to create custom dumb and smart fuzzers.

[Sulley](https://github.com/OpenRCE/sulley) -  A fuzzer development and fuzz testing framework consisting of multiple extensible components by Pedram Amini.

[boofuzz](https://github.com/jtpereyda/boofuzz) -  A fork and successor of Sulley framework.

[Spike](http://www.immunitysec.com/downloads/SPIKE2.9.tgz) - A fuzzer development framework like sulley, a predecessor of sulley. 

[Metasploit Framework](https://www.rapid7.com/products/metasploit/download.jsp) - A framework which contains some fuzzing capabilities via Auxiliary modules. 

[Nightmare](https://github.com/joxeankoret/nightmare) - A distributed fuzzing testing suite with web administration, supports fuzzing using network protocols.

[rage_fuzzer](https://github.com/deanjerkovich/rage_fuzzer) - A dumb protocol-unaware packet fuzzer/replayer.


### Misc 
*Other notable fuzzers like Kernel Fuzzers, general purpose fuzzer etc.,*


[KernelFuzzer](https://github.com/mwrlabs/KernelFuzzer) - Cross Platform Kernel Fuzzer Framework.

[honggfuzz](http://google.github.io/honggfuzz/) - A general-purpose, easy-to-use fuzzer with interesting analysis options.

[Hodor Fuzzer](https://github.com/nccgroup/hodor) - Yet Another general purpose fuzzer.

[libFuzzer](http://libfuzzer.info) - In-process, coverage-guided, evolutionary fuzzing engine for targets written in C/C++.

[syzkaller](https://github.com/google/syzkaller) - Distributed, unsupervised, coverage-guided Linux syscall fuzzer.

[ansvif](https://oxagast.github.io/ansvif/) - An advanced cross platform fuzzing framework designed to find vulnerabilities in C/C++ code.

### Taint Analysis
*How user input affects the execution*

[PANDA ( Platform for Architecture-Neutral Dynamic Analysis )](https://github.com/moyix/panda)

[QIRA (QEMU Interactive Runtime Analyser)](http://qira.me/)

[kfetch-toolkit](https://github.com/j00ru/kfetch-toolkit) - Tool to perform advanced logging of memory references performed by operating systems’ kernels

### Symbolic Execution SAT and SMT Solvers

[Z3](https://github.com/Z3Prover/z3) - A theorem prover from Microsoft Research.

[SMT-LIB](http://smtlib.cs.uiowa.edu/) - An international initiative aimed at facilitating research and development in Satisfiability Modulo Theories (SMT)


### References

I haven't included some of the legends like AxMan, please refer the following link for more information.
https://www.ee.oulu.fi/research/ouspg/Fuzzers 


### Essential Tools

*Tools of the trade for exploit developers, reverse engineers*


#### Debuggers 


[Windbg](https://msdn.microsoft.com/en-in/library/windows/hardware/ff551063(v=vs.85).aspxi) - The preferred debugger by exploit writers.

[Immunity Debugger](http://debugger.immunityinc.com) - Immunity Debugger by Immunity Sec.

[OllyDbg ](http://www.ollydbg.de/) - The debugger of choice by reverse engineers and exploit writers alike.

[Mona.py ( Plugin for windbg and Immunity dbg )](https://github.com/corelan/mona/) - Awesome tools that makes life easy for exploit developers.

[x64dbg](https://github.com/x64dbg/) - An open-source x64/x32 debugger for windows.

[Evan's Debugger (EDB)](http://codef00.com/projects#debugger) - Front end for gdb.

[GDB - Gnu Debugger](http://www.sourceware.org/gdb/) - The favorite linux debugger.

[PEDA](https://github.com/longld/peda) - Python Exploit Development Assistance for GDB.

[Radare2](http://www.radare.org/r/) - Framework for reverse-engineering and analyzing binaries.


#### Disassemblers and some more

*Dissemblers, disassembly frameworks etc.,*


[IDA Pro](https://www.hex-rays.com/products/ida/index.shtml) - The best disassembler

[binnavi](https://github.com/google/binnavi) - Binary analysis IDE, annotates control flow graphs and call graphs of disassembled code.

[Capstone](https://github.com/aquynh/capstone) - Capstone is a lightweight multi-platform, multi-architecture disassembly framework.


#### Others

[ltrace](http://ltrace.org/) - Intercepts library calls 

[strace](http://sourceforge.net/projects/strace/) - Intercepts system calls


## Vulnerable Applications

Exploit-DB - https://www.exploit-db.com
(search and pick the exploits, which have respective apps available for download, reproduce the exploit by using fuzzer of your choice)

PacketStorm - https://packetstormsecurity.com/files/tags/exploit/

[Fuzzgoat](https://github.com/fuzzstati0n/fuzzgoat) - Vulnerable C program for testing fuzzers.


##### Samples files for seeding during fuzzing:

https://files.fuzzing-project.org/

[PDF Test Corpus from Mozilla](https://github.com/mozilla/pdf.js/tree/master/test/pdfs)

[MS Office file format documentation](https://www.microsoft.com/en-us/download/details.aspx?id=14565)

[Fuzzer Test Suite](https://github.com/google/fuzzer-test-suite) - Set of tests for fuzzing engines. Includes different well-known bugs such as Heartbleed, c-ares $100K bug and others.


## Anti Fuzzing

[Introduction to Anti-Fuzzing: A Defence In-Depth Aid](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2014/january/introduction-to-anti-fuzzing-a-defence-in-depth-aid/)


## Contributing

[Please refer the guidelines at contributing.md for details](Contributing.md).

Thanks to the following folks who made contributions to this project. 
+ [Tim Strazzere](https://twitter.com/timstrazz)
+ [jksecurity](https://github.com/jksecurity)
+ [and these awesome people](https://github.com/secfigo/Awesome-Fuzzing/graphs/contributors)
