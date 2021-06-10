Fuzzing 大合集 [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome)
===================

这是一个在学习 fuzzing 的最初阶段最好的有关 fuzzing 的资源合集（书籍、课程、视频、教程等等）

### Table of Contents
- [书籍](#书籍)
- [课程](#课程)
   + [免费](#免费)
   + [付费](#付费)
- [视频](#videos)
  + [NYU Poly Course videos](#nyu-poly-videos)
  + [Conference talks/tutorials on Fuzzing](#conf-talks-tutorials)
- [教程](#教程)
- [工具](#工具)
  + [云 Fuzzer](#cloud-fuzzers)
  + [文件格式 Fuzzer](#文件格式Fuzzer)
  + [网络协议 Fuzzer](#网络协议Fuzzer)
  + [浏览器 Fuzzer](#浏览器Fuzzer)
  + [污点分析](#taint-analysis)
  + [符号执行 + SAT/SMT求解器](#符号执行)
  + [基本工具（通用）](#基本工具（通用）)
- [存在漏洞的应用程序](#存在漏洞的应用程序)
- [反Fuzzing](#反Fuzzing)
- [导向性Fuzzing](#导向性Fuzzing)
- [贡献](#贡献)

Awesome Fuzzing Resources
-------------
<a name="books" />

## 书籍

*关于 fuzzing 的书籍*

+ [Fuzzing: Brute Force Vulnerability Discovery](https://www.amazon.com/Fuzzing-Brute-Force-Vulnerability-Discovery/dp/0321446119) 作者： Michael Sutton, Adam Greene, Pedram Amini

+ [Fuzzing for Software Security Testing and Quality Assurance ](https://www.amazon.com/Fuzzing-Software-Security-Assurance-Information/dp/1596932147) 作者： Ari Takanen, Charles Miller, Jared D Demott

+ [Open Source Fuzzing Tools](https://www.amazon.com/Open-Source-Fuzzing-Tools-Rathaus/dp/1597491950) 作者： Gadi Evron, Noam Rathaus

+ [Gray Hat Python](https://www.amazon.com/Gray-Hat-Python-Programming-Engineers/dp/1593271921) 作者： Justin Seitz

+ [The Fuzzing Book](https://www.fuzzingbook.org/) 作者： Andreas Zeller, Rahul Gopinath, Marcel Böhme, Gordon Fraser, Christian Holler.


> **Note:** 下列书籍中的部分章节也描述了 fuzzing

> - [The Shellcoder's Handbook: Discovering and Exploiting Security Holes ( Chapter 15 )](https://www.amazon.com/Shellcoders-Handbook-Discovering-Exploiting-Security/dp/047008023X) 作者 Chris Anley, Dave Aitel, David Litchfield 等

> - [iOS Hacker's Handbook - Chapter 1](https://www.amazon.com/iOS-Hackers-Handbook-Charlie-Miller/dp/1118204123) 作者： Charles Miller, Dino DaiZovi, Dion Blazakis, Ralf-Philip Weinmann, and Stefan Esser

> - [IDA Pro - The IDA Pro Book: 世界上最流行的反汇编工具的非官方指导书](https://www.amazon.com/IDA-Pro-Book-2nd-ebook/dp/B005EI84TM)

<a name="courses" />

## 课程

*与 fuzzing 有关的课程/培训*

<a name="free" />

### 免费

[NYU Poly ( see videos for more )](https://vimeo.com/5236104 ) - Dan Guido 出品的免费指导

[Samclass.info ( check projects section and chapter 17 ) ](https://samsclass.info/127/127_F15.shtml) - Sam 出品

[Modern Binary Exploitation ( RPISEC ) - Chapter 15 ](https://github.com/RPISEC/MBE) - RPISEC 出品

[Offensive Computer Security - Week 6](http://www.cs.fsu.edu/~redwood/OffensiveComputerSecurity/lectures.html) - W. Owen Redwood 和 Prof. Xiuwen Liu 出品

<a name="paid" />

### 付费

[Offensive Security, Cracking The Perimeter ( CTP ) and Advanced Windows Exploitation ( AWE )](https://www.offensive-security.com/information-security-training/)

[SANS 660/760 Advanced Exploit Development for Penetration Testers](https://www.sans.org/course/advanced-exploit-development-penetration-testers)

[Exodus Intelligence - 漏洞挖掘大师级课程](https://blog.exodusintel.com/2016/05/18/exodus-intelligence-2016-training-course/)

<a name="videos" />

## 视频

*讨论 fuzzing 技术、工具、最佳实践的视频*
<a name="nyu-poly-videos" />

### NYU Poly Course videos (from Dan Guido)

[Fuzzing 101 (Part 1)](https://vimeo.com/5236104) - Mike Zusman 出品

[Fuzzing 101 (Part 2)](https://vimeo.com/5237484) - Mike Zusman 出品

[Fuzzing 101 (2009)](https://vimeo.com/7574602) - Mike Zusman 出品

[Fuzzing - Software Security Course on Coursera](https://www.coursera.org/lecture/software-security/fuzzing-VgyOn) - 马里兰大学出品

<a name="conf-talks-tutorials" />

### 关于 Fuzzing 的会议讨论/教程

[攻击反病毒软件的内核驱动](https://github.com/bee13oy/AV_Kernel_Vulns/tree/master/Zer0Con2017)

[Fuzzing Windows 内核 - OffensiveCon 2020](https://github.com/yoava333/presentations/blob/master/Fuzzing%20the%20Windows%20Kernel%20-%20OffensiveCon%202020.pdf)

[Youtube 上关于 Fuzzing 演讲的内容](https://www.youtube.com/playlist?list=PLtPrYlwXDImiO_hzK7npBi4eKQQBgygLD) - 列表内有许多优质内容

[浏览器漏洞狩猎](https://vimeo.com/109380793) - Atte Kettunen 出品

[应用马尔科夫链、基于覆盖度的灰盒 Fuzzing](https://www.comp.nus.edu.sg/~mboehme/paper/CCS16.pdf)

[DerbyCon 2016: Fuzzing 如何击溃软件](http://www.irongeek.com/i.php?page=videos/derbycon6/411-fuzzing-basicshow-to-break-software-grid-aka-scott-m)

[Fuzz Theory](https://www.youtube.com/watch?v=5rE8xEg5tXk&list=PLSkhUfcCXvqG6FRTCCxIfoMK6rw3NZvb6)

<a name="tutorials" />

## 教程与博客

*解释 fuzzing 方法、技术与最佳实践的教程与博客*

[Fuzzing Closed Source PDF Viewers](https://www.gosecure.net/blog/2019/07/30/fuzzing-closed-source-pdf-viewers/)

[Effective File Format Fuzzing](https://j00ru.vexillium.org/slides/2016/blackhat.pdf) - Mateusz “j00ru” Jurczyk @ Black Hat Europe 2016, London

[A year of Windows kernel font fuzzing Part-1 the results](https://googleprojectzero.blogspot.com/2016/06/a-year-of-windows-kernel-font-fuzzing-1_27.html) - Google Zero 项目的最佳论文，描述了如何进行 fuzzing 以及如何构建一个 fuzzer

[A year of Windows kernel font fuzzing Part-2 the techniques](https://googleprojectzero.blogspot.com/2016/07/a-year-of-windows-kernel-font-fuzzing-2.html) - Google Zero 项目的最佳论文，描述了如何进行 fuzzing 以及如何构建一个 fuzzer

[Interesting bugs and resources at fuzzing project](https://blog.fuzzing-project.org/) - fuzzing-project.org 出品

[Fuzzing workflows; a fuzz job from start to finish](https://foxglovesecurity.com/2016/03/15/fuzzing-workflows-a-fuzz-job-from-start-to-finish/) - @BrandonPrry 出品

[A gentle introduction to fuzzing C++ code with AFL and libFuzzer](http://jefftrull.github.io/c++/clang/llvm/fuzzing/sanitizers/2015/11/27/fuzzing-with-sanitizers.html) - Jeff Trull 出品

[15 分钟介绍 fuzzing](https://www.mwrinfosecurity.com/our-thinking/15-minute-guide-to-fuzzing/) - MWR Security 出品

> **Note:** Folks at fuzzing.info 收集了很多非常有用的链接，我没有重复他们的工作，我只是整理了 2015 年到 2016 年间他们没有收录的文章
[Fuzzing Papers](https://fuzzing.info/papers/) - fuzzing.info 出品

[Fuzzing 博客](https://fuzzing.info/resources/) - fuzzing.info 出品 

[Root Cause Analysis of the Crash during Fuzzing](https://www.corelan.be/index.php/2013/02/26/root-cause-analysis-memory-corruption-vulnerabilities/) - Corelan Team 出品
[Root cause analysis of integer flow](https://www.corelan.be/index.php/2013/07/02/root-cause-analysis-integer-overflows/) - Corelan Team 出品

[Creating custom peach fuzzer publishers](http://blog.opensecurityresearch.com/2014/01/creating-custom-peach-fuzzer-publishers.html) - Open Security Research 出品

[在 Fuzzing 大型开源项目前要考虑的 7 件事](https://www.linuxfoundation.org/blog/2016/02/7-things-to-consider-before-fuzzing-a-large-open-source-project/) - Emily Ratliff 

##### 从 Fuzzing 到 Exploit

[从 fuzzing 到 0-day](https://blog.techorganic.com/2014/05/14/from-fuzzing-to-0-day/) - Harold Rodriguez(@superkojiman) 出品

[从 crash 到 exploit](https://www.corelan.be/index.php/2013/02/26/root-cause-analysis-memory-corruption-vulnerabilities/) - Corelan Team 出品

##### Peach Fuzzer 相关教程

[Peach 上手指南](http://community.peachfuzzer.com/v2/PeachQuickstart.html)
[使用 Peach 进行 Fuzzing Part 1](http://www.flinkd.org/2011/07/fuzzing-with-peach-part-1/) - Jason Kratzer of corelan team 出品
[使用 Peach 进行 Fuzzing Part 2](http://www.flinkd.org/2011/11/fuzzing-with-peach-part-2-fixups-2/) - Jason Kratzer of corelan team 出品 
[Peach pit 文件的自动生成](http://doc.netzob.org/en/latest/tutorials/peach.html) - Frédéric Guihéry, Georges Bossert 出品

##### AFL Fuzzer 相关教程

[Creating a fuzzing harness for FoxitReader 9.7 ConvertToPDF Function](https://christopher-vella.com/2020/02/28/creating-a-fuzzing-harness-for-foxitreader-9-7-converttopdf-function/)

[通过 Fuzzing Adobe Reader 在 50 天获得 50 个 CVE](https://research.checkpoint.com/2018/50-adobe-cves-in-50-days/)

[Fuzzing sockets 第一部分：FTP servers](https://securitylab.github.com/research/fuzzing-sockets-FTP)

[Fuzzing software 第一部分：常见挑战与解决方案](https://securitylab.github.com/research/fuzzing-challenges-solutions-1)

[Fuzzing software 第二部分：高级技巧](https://securitylab.github.com/research/fuzzing-software-2)

[Fuzzing 工作流程，包含 fuzz 的始末](https://foxglovesecurity.com/2016/03/15/fuzzing-workflows-a-fuzz-job-from-start-to-finish/) - @BrandonPrry 出品

[使用 AFL persistent 模式对 capstone 进行 Fuzzing](https://toastedcornflakes.github.io/articles/fuzzing_capstone_with_afl.html) - @toasted_flakes 出品

[RAM disks and saving your SSD from AFL Fuzzing](http://cipherdyne.org/blog/2014/12/ram-disks-and-saving-your-ssd-from-afl-fuzzing.html)

[使用 AFL 进行 Bug 挖掘](https://josephg.com/blog/bug-hunting-with-american-fuzzy-lop/)

[AFL 在真实示例中的高级用法](https://volatileminds.net/2015/07/01/advanced-afl-usage.html)

[Segfaulting Python with afl-fuzz](https://tomforb.es/segfaulting-python-with-afl-fuzz)

[使用 AFL-Fuzz 进行 Fuzzing 的实例( AFL vs Binutils )](https://www.evilsocket.net/2015/04/30/fuzzing-with-afl-fuzz-a-practical-example-afl-vs-binutils/)

[Fuzzing 模拟器的重要性](https://mgba.io/2016/09/13/fuzzing-emulators/)

[心脏滴血漏洞是如何被发现的](https://blog.hboeck.de/archives/868-How-Heartbleed-couldve-been-found.html)

[用 AFL 进行文件系统 Fuzzing](https://events.static.linuxfound.org/sites/events/files/slides/AFL%20filesystem%20fuzzing%2C%20Vault%202016_0.pdf)

[使用 AFL 对 Perl/XS 进行模糊测试](https://medium.com/@dgryski/fuzzing-perl-xs-modules-with-afl-4bfc2335dd90)

[如何使用 AFL 对服务器进行模糊测试](https://www.fastly.com/blog/how-fuzz-server-american-fuzzy-lop) - by Jonathan Foote

[一系列真实漏洞的挑战：使用 AFL 完成模糊测试](https://github.com/ThalesIgnite/afl-training)

[Fuzzing 101 - PHDays](https://github.com/RootUp/PHDays9)

##### libFuzzer 相关教程

[libFuzzer 教程](https://github.com/google/fuzzer-test-suite/blob/master/tutorial/libFuzzerTutorial.md)

[狩猎 VirtualBox 的漏洞](http://blog.paulch.ru/2020-07-26-hunting-for-bugs-in-virtualbox-first-take.html)

[如何使用 libFuzzer 对现代 C/C++ 项目进行模糊测试](https://github.com/Dor1s/libfuzzer-workshop)

##### honggfuzz 相关教程

[如何使用 honggfuzz 发现 VLC 中的 Double-Free RCE 漏洞](https://www.pentestpartners.com/security-blog/double-free-rce-in-vlc-a-honggfuzz-how-to/)

##### Spike Fuzzer 相关教程

[使用 Spike 发现溢出漏洞](https://null-byte.wonderhowto.com/how-to/hack-like-pro-build-your-own-exploits-part-3-fuzzing-with-spike-find-overflows-0162789/)

[使用 Spike 进行模糊测试](https://samsclass.info/127/proj/p18-spike.htm) - Samclass.info 出品

##### FOE Fuzzer 相关教程

[Fuzzing with FOE](https://samsclass.info/127/proj/p16-fuzz.htm) - Samclass.info 出品


##### SMT/SAT 求解器教程

[Z3 - A guide](https://rise4fun.com/z3/tutorial/guide) - Z3 快速上手指南

##### 构建一个反馈驱动的 Fuzzer

[如何构建一个反馈驱动的 Fuzzer](https://blog.fadyothman.com/tag/myfuzzer/) - by @fady_othman

<a name="tools" />

## 工具

*那些在 fuzzing 中能帮上忙的工具*
<a name="file-format-fuzzers" />

### 云 Fuzzer

*可以在云环境中进行模糊测试的模糊测试工具*

[Cloudfuzzer](https://github.com/ouspg/cloudfuzzer) - 在云环境中自动、便易地进行云 Fuzzing 的框架

[Fuzzit](https://fuzzit.dev) - Fuzzit 是一个 Fuzzing 即服务的平台，被 systemd, radare2 等多个开源\闭源项目使用，想加入请联系 oss@fuzzit.dev

### 文件格式 Fuzzer

*那些帮助对像 pdf, mp3, swf 等文件格式进行 fuzzing 的 Fuzzers*

[Rehepapp](https://github.com/FoxHex0ne/Rehepapp)

[Newer version of Rehepapp](https://github.com/FoxHex0ne/Rehepapp)

[针对 PE 文件进行静态二进制插桩辅助、结合 WinAFL 的 Fuzzer](https://github.com/wmliang/pe-afl)

[MiniFuzz](https://www.microsoft.com/en-sg/download/details.aspx?id=21769) - Microsoft 出品的基础文件格式 fuzzing 工具

[BFF from CERT](https://resources.sei.cmu.edu/library/asset-view.cfm?assetID=507974) - 基础文件格式 fuzzing 框架

[AFL Fuzzer (Linux only)]( http://lcamtuf.coredump.cx/afl/) - Michal Zalewski aka lcamtuf 开发的 Fuzzer

[Win AFL](https://github.com/ivanfratric/winafl) - Ivan Fratic 开发的针对 Windows 二进制程序 fuzzing 的 AFL 分支版本

[Shellphish Fuzzer](https://github.com/shellphish/fuzzer) - 一个操纵 AFL 的 Python 接口，可以简单的写入测试用例与其他功能

[TriforceAFL](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2016/june/project-triforce-run-afl-on-everything/) - 一个 AFL 的修正版，支持应用源码无法获得情况下的 fuzzing

[AFLGo](https://github.com/aflgo/aflgo) - 基于 AFL 构建的导向性灰盒 Fuzzing，针对程序特定位置进行模糊测试

[Peach Fuzzer](https://sourceforge.net/projects/peachfuzz/) - 帮助创建传统 dumb 以及小型 fuzzer 的框架

[MozPeach](https://github.com/MozillaSecurity/peac://github.com/MozillaSecurity/peach) - 由 Mozilla Security 开发基于 peach 2.7 版本的分支版本

[Failure Observation Engine (FOE)](https://vuls.cert.org/confluence/display/tools/CERT+FOE+-+Failure+Observation+Engine) - 基于畸形文件的 Windows 程序 Fuzzing 工具

[rmadair](http://rmadair.github.io/fuzzer/) - 基于畸形文件的 fuzzer，使用 PyDBG 来监视感兴趣的信号

[honggfuzz](http://honggfuzz.com/) - 支持反馈驱动、基于代码覆盖率的通用、易用型 Fuzzer

[zzuf](https://github.com/samhocevar/zzuf) - 一个透明应用输入 fuzzer，可以拦截文件操作、改变程序输入的随机位

[radamsa](https://github.com/aoh/radamsa) - 通用的 fuzzer，测试用例生成器

[binspector](https://github.com/binspector/binspector) - 二进制格式分析与模糊测试工具

[grammarinator](https://github.com/renatahodovan/grammarinator) - 基于 ANTLR v4 语法的文件格式模糊测试工具（ANTLR 项目已有大量的语法）

<a name="network-protocol-fuzzers" />

### 网络协议 Fuzzer

*那些帮助对像 HTTP, SSH, SMTP 等网络协议进行 fuzzing 的 Fuzzer*

[Peach Fuzzer](https://sourceforge.net/projects/peachfuzz/) - 帮助创建传统 dumb 以及小型 fuzzer 的框架

[Sulley](https://github.com/OpenRCE/sulley) -  Michael Sutton 开发，包含多个可扩展组件的 Fuzzer 开发与 Fuzzing 测试框架

[boofuzz](https://github.com/jtpereyda/boofuzz) -  Sulley 框架的继任者

[Spike](http://www.immunitysec.com/downloads/SPIKE2.9.tgz) - 像 sulley 的 fuzzer 开发框架，是 sulley 的前身

[Metasploit Framework](https://github.com/rapid7/metasploit-framework) - 通过 Auxiliary 模块使其具有了 fuzzing 能力的框架

[Nightmare](https://github.com/joxeankoret/nightmare) - 一个带有 Web 管理界面的分布式 fuzzing 测试套件，支持对网络协议进行 fuzzing

[rage_fuzzer](https://github.com/deanjerkovich/rage_fuzzer) - 未知协议包 fuzzer

[Fuzzotron](https://github.com/denandz/fuzzotron) - 支持 TCP、UDP 的简单多进程网络 Fuzzer

[Mutiny](https://github.com/Cisco-Talos/mutiny-fuzzer) - 通过重放畸变的 PCAP 数据包来对网络进行 Fuzzer

[Fuzzing For Worms](https://github.com/dobin/ffw) - 用于网络服务的 Fuzzing 框架

[AFL (w/ networking patch)](https://github.com/jdbirdwell/afl) - 用于网络 Fuzzing 的非官方版 AFL

[AFLNet](https://github.com/aflnet/aflnet) - 用于网络协议的灰盒 Fuzzer（AFL 的扩展）

### 浏览器Fuzzer

[BFuzz](https://github.com/RootUp/BFuzz) - An input based, browser fuzzing framework.

<a name="Misc" />

### 杂项，内核 Fuzzer，通用 Fuzzer

[Choronzon](https://github.com/CENSUS/choronzon) - 基于遗传知识的 Fuzzer

[QuickFuzz](https://github.com/CIFASIS/QuickFuzz) - Haskell 写的针对第三方软件使用常见文件格式进行测试的工具，利用现成的、知名的 Fuzzer

[gramfuzz](https://github.com/d0c-s4vage/gramfuzz) - 可定义复杂语法来建模文档与二进制数据格式的基于语法的 Fuzzer

[KernelFuzzer](https://github.com/mwrlabs/KernelFuzzer) - 跨平台内核 Fuzzer 框架

[honggfuzz](http://honggfuzz.com/) - 带有分析选项的通用、易用型 fuzzer

[Hodor Fuzzer](https://github.com/nccgroup/hodor) - 曾经是另一个通用的 fuzzer

[libFuzzer](http://llvm.org/docs/LibFuzzer.html) - 面向 C/C++ 程序、基于覆盖度的进化模糊测试工具

[syzkaller](https://github.com/google/syzkaller) - 分布式、无监督、基于覆盖度的 Linux 系统调用模糊测试工具

[ansvif](https://oxagast.github.io/ansvif/) - 用于在 C/C++ 程序中查找漏洞的高级跨平台模糊测试框架

[Tribble](https://github.com/SatelliteApplicationsCatapult/tribble) - 易用、覆盖度指导的 JVM 模糊测试框架

[go-fuzz](https://github.com/dvyukov/go-fuzz) - 覆盖度指导的 go 包模糊测试

<a name="taint-analysis" />

### 流分析（用户输入如何影响执行）

[PANDA ( Platform for Architecture-Neutral Dynamic Analysis )](https://github.com/moyix/panda)

[QIRA (QEMU Interactive Runtime Analyser)](http://qira.me/)

[kfetch-toolkit](https://github.com/j00ru/kfetch-toolkit) - 用于记录操作系统内核执行的内存引用的高级日志工具

[moflow](https://github.com/vrtadmin/moflow) - 软件安全框架，包括漏洞的挖掘和修补

<a name="smt-solvers" />

### 符号执行 + SAT/SMT 求解器

[Z3](https://github.com/Z3Prover/z3)

[SMT-LIB](http://smtlib.cs.uiowa.edu/) 

### 参考

我没有把全部的东西都纳进来，比如 AxMan，请参考以下链接获取更多信息
https://www.ee.oulu.fi/research/ouspg/Fuzzers

<a name="essential-tools" />

### 基本工具（通用）

*漏洞利用工具开发者、逆向工程师常用的工具*
<a name="debuggers" />

#### 调试工具

[Windbg](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools) - 漏洞利用者常用的调试器

[Immunity Debugger](http://debugger.immunityinc.com) - Immunity Sec 出品的调试器

[OllyDbg](http://www.ollydbg.de/) - 逆向工程师的常见选择

[Mona.py ( Plugin for windbg and Immunity dbg )](https://github.com/corelan/mona/) - 漏洞利用开发者的绝佳工具

[x64dbg](https://github.com/x64dbg/) - 开源 Windows x64/x32 调试器

[Evan's Debugger (EDB)](http://codef00.com/projects#debugger) - Front end for gdb.

[GDB - Gnu Debugger](http://www.sourceware.org/gdb/) - 最好的 Linux 调试器

[PEDA](https://github.com/longld/peda) - Python 开发的 GDB 辅助程序

[Radare2](http://www.radare.org/r/) - 逆向工程与程序分析的框架

<a name="dissembers" />

#### 反汇编工具

*反汇编工具、反汇编框架等*

[IDA Pro](https://www.hex-rays.com/products/ida/index.shtml) - 最好的反汇编工具

[binnavi](https://github.com/google/binnavi) - 二进制程序分析 IDE，注释反汇编代码的控制流图与调用图

[Capstone](https://github.com/aquynh/capstone) - Capstone 是一个轻量、跨平台、多架构支持的反汇编框架

<a name="others" />

#### 其他

[ltrace](http://ltrace.org/) - 库调用拦截

[strace](https://sourceforge.net/projects/strace/) - 系统调用拦截


<a name="vuln-apps"/>

## 存在漏洞的应用程序

[Exploit-DB](https://www.exploit-db.com)
 搜索、选取漏洞，有些提供了程序下载，可以通过你选择试用的 fuzzer 对利用进行复现

[PacketStorm](https://packetstormsecurity.com/files/tags/exploit/)

[Fuzzgoat](https://github.com/fuzzstati0n/fuzzgoat) - 对有漏洞的 C 程序模糊测试的工具

[vulnserver](https://github.com/stephenbradshaw/vulnserver) - 用来测试 Fuzzer 的存在漏洞的服务器

##### fuzzing 期间种子样本文件

https://files.fuzzing-project.org/

[PDF Test Corpus from Mozilla](https://github.com/mozilla/pdf.js/tree/master/test/pdfs)

[MS Office file format documentation](https://www.microsoft.com/en-us/download/details.aspx?id=14565)

[Fuzzer Test Suite](https://github.com/google/fuzzer-test-suite) - 模糊测试引擎的测试集，包括许多知名的 Bug，如 Heartbleed、c-ares $100K bug 等

[Fuzzing Corpus](https://github.com/strongcourage/fuzzing-corpus) - 包含多种文件格式、用于 Fuzzing 的语料库

<a name="antifuzz"/>

## 反Fuzzing

[Anti-Fuzzing 的介绍：纵深防御的辅助](https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2014/january/introduction-to-anti-fuzzing-a-defence-in-depth-aid/)

[Fuzzification: 反 Fuzzing 技术](https://www.usenix.org/conference/usenixsecurity19/presentation/jung)

[AntiFuzz: 阻止对二进制可执行文件的 Fuzzing](https://www.usenix.org/conference/usenixsecurity19/presentation/guler)

## 导向性Fuzzing

[Awesome Directed Fuzzing](https://github.com/strongcourage/awesome-directed-fuzzing): 导向性 Fuzzing 研究论文的列表

<a name="contribution"/>

## 贡献

[请查看 contributing.md 中关于细节的介绍](Contributing.md).

感谢下列人员对这个项目的贡献：
+ [Tim Strazzere](https://twitter.com/timstrazz)
+ [jksecurity](https://github.com/jksecurity)
+ [and these awesome people](https://github.com/secfigo/Awesome-Fuzzing/graphs/contributors)
