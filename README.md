# Clang Control Flow Integrity (CFI) Bypass Techniques
In the following we demonstrate three exploitation techniques to bypass Clang's CFI implementation [0] when applied to Chromium [1]. Clang implements fine-grained CFI, hence, unlike Microsoft's/Intel's CFI implementation CFGuard/CET, it cannot be bypassed using COOP [3]. The first two proof-of-concept exploits do not attack the CFI implementation itself but exploit the absence of other mitigation, i.e., JIT region protection and return address protection. Both techniques are well known, and we include them for completeness. Our third attack exploits a weakness in Clang's CFI that exists because the compiler tries to optimize the CFI run-time check. We implement our proof-of-concept exploits for an older version of the Chromium browser, which is vulnerable to cve-2017-5121 [4]. 

## Setup
We used our server for compilation and a VM for testing, hence, two different versions. We provide the binaries for easier testing.

### Compilation
System: Ubuntu 14.04.5 LTS  
Follow Google's instructions [2] and check out / compile a vulnerable version
```
fetch --nohooks chromium
cd src/
git fetch --tags
git checkout -b cve-2017-5121 61.0.3163.100
gclient sync --with_branch_heads
./build/install-build-deps.sh 
gclient runhooks
# enable "turbo_escape" by setting it to" "true" in v8/src/flag-definitions.h
gn gen out/cfi '--args=is_debug=false is_cfi=true use_cfi_cast=true use_thin_lto=true' --check
ninja -C out/cfi chrome 
```

### Execution
System: Ubuntu 16.04.3 LTS  
Binaries: https://drive.google.com/file/d/1Ik8q_nOdq-pdRqTgEfVVT7rO-e9V2vs2/ (150mb)  
Run it with `./chrome --no-sandbox --single-process --disable-gpu <path to exploit>`. For our proof-of-concept exploits we focus on hijacking the instruction pointer (= bypassing CFI), hence, their effectiveness can only be observed with an attached debugger.

## Proof-of-concept Exploits
cve-2017-5121 is a bug in the escape analysis of Chrome's JIT engine. The vulnerability allows to disclose memory, as well as, corrupt arbitrary data. Details can be found in the corresponding blog post by Microsoft [5]. We exploit this vulnerability to gain arbitrary read-write to the render process.

### PoC-1: [code injection into JIT region](cve-2017-5121-code-injection.html)
Chromium/V8 keeps its JIT region mapped as RWX. Hence, by disclosing its address the attacker can inject a malicious payload, and invoke the payload by calling the corresponding JavaScript function. This is the most common attack technique to achieve arbitrary code execution in Chromium. This techniques is also described by Microsoft [5], and explains why Chrome does not include CFI by default despite its very low impact on the overall performance.

### PoC-2: [corrupting return address](cve-2017-5121-ret-addr-corruption.html)
Assuming that the JIT region is no longer writable, e.g., by adapting a similar strategy as Chakra [6], the attacker needs to leverage traditional code-reuse attack techniques like Return-oriented Programming (ROP). Since Clang-CFI focuses on protecting forward branches, the attacker can hijack the control flow by corrupting a return address. Therefore, the attacker first discloses a stack address, e.g., the `isolate` struct which contains stack addresses (e.g., `isolate->thread_local_top_->c_entry_fp_`), and then leverages the arbitrary read/write primitive to overwrite a return address of an active stackframe.

### PoC-3: [corrupting stack-spilled registers](cve-2017-5121-spilled-register.html)
The previous two attacks do not directly bypass Clang-CFI but exploit the absence of the strict enforcement of w^x memory and return address protection. However, both are feasible in practice [6, 7]. Hence, for our third attack we assume that these mitigations are in place.

Due to how Clang-CFI is implemented, the compiler generates code that in some cases spills registers, which contain CFI-related values, temporarily to writable memory (stack). This is a problem because these CFI-values are supposed to be immutable as they are used to determine whether a call/jump destination address is valid or not. Hence, the attacker can modify the enforced CFI policy by corrupting these spilled registers.

An analysis of the Chrome binary yields a surprisingly large number of instances where this happens. However, it is unlikely that all of these cases are exploitable, because this technique requires the attacker to reliably corrupt stack values without a stack-based memory-corruption vulnerability. In a browser setting this can be achieved either by spawning separate threads, or JavaScript callback functions. We refer to our previously published paper [8] for more details.

For our PoC we use JavaScript callbacks: first, we trigger the execution of native code, which is subject to CFI run-time checks, by invoking a function member function of a JavaScript object. If defined, this code will trigger the execution of a JavaScript callback function, hence, switching the execution back to JavaScript. As a consequence, the stackframe of the native code can be reliably manipulated while executing JavaScript. We leverage our read/write primitive within the callback function (see `xhr_delay()`) to then corrupt the spilled register.

We trigger the execution of the native code/callback by creating a `XMLHttpRequest` (line 310) JavaScript object and setting `onreadystatechange` to `xhr_delay()` (line 362). Calling the `open()` function of the `XMLHttpRequest` object will invoke the native `blink::EventTarget::FireEventListeners()` function.
```
.text:00000000068E3970 ; _QWORD __cdecl blink::EventTarget::FireEventListeners(blink::EventTarget *__hidden this, blink::Event *)
.text:00000000068E3970
.text:00000000068E3970 var_40          = qword ptr -40h
.text:00000000068E3970 var_38          = qword ptr -38h
.text:00000000068E3970
.text:00000000068E3970                 push    rbp
.text:00000000068E3971                 push    r15
.text:00000000068E3973                 push    r14
.text:00000000068E3975                 push    r13
.text:00000000068E3977                 push    r12
.text:00000000068E3979                 push    rbx
.text:00000000068E397A                 sub     rsp, 18h
.text:00000000068E397E                 mov     r14, rsi
.text:00000000068E3981                 mov     r13, rdi
.text:00000000068E3984                 mov     rax, [r13+0]
.text:00000000068E3988                 lea     r15, __typeid__ZTSN5blink4NodeE_global_addr ; <---- should stay read-only
.text:00000000068E398F                 mov     rcx, rax
.text:00000000068E3992                 sub     rcx, r15
.text:00000000068E3995                 ror     rcx, 3
.text:00000000068E3999                 cmp     rcx, 41418h
.text:00000000068E39A0                 ja      loc_68E3C1B
.text:00000000068E39A6                 lea     rdx, __typeid__ZTSN5blink11EventTargetE_byte_array
.text:00000000068E39AD                 test    byte ptr [rcx+rdx], 80h
.text:00000000068E39B1                 jz      loc_68E3C1B
.text:00000000068E39B7                 mov     rdi, r13
.text:00000000068E39BA                 call    qword ptr [rax+0C8h]
[...]
.text:00000000068E3A9E                 mov     rdi, r13
.text:00000000068E3AA1                 mov     rsi, r14
.text:00000000068E3AA4                 mov     rdx, rbx
.text:00000000068E3AA7                 mov     rcx, r12
.text:00000000068E3AAA                 call    blink::EventTarget::FireEventListeners(blink::Event *,blink::EventTargetData *,blink::HeapVector<blink::RegisteredEventListener,1ul> &)
.text:00000000068E3AAF                 test    al, al
```
This snippet is taken from the function prologue. Later the another `FireEventListeners()` (different arguments) which eventually will change the context to execute the JavaScript callback function:
```
.text:00000000068E3DA0 blink::EventTarget::FireEventListeners(blink::Event *, blink::EventTargetData *, blink::HeapVector<blink::RegisteredEventListener, 1ul> &) proc near
; [...]
.text:00000000068E3DA0                 push    rbp
.text:00000000068E3DA1                 push    r15  ; <---- not so read-only anymore
.text:00000000068E3DA3                 push    r14
.text:00000000068E3DA5                 push    r13  
.text:00000000068E3DA7                 push    r12
; [...]
; Switch to JavaScript execution, in our case xhr_delay() is executed.
; Note, r13 and r15 are temporarily spilled on the stack.
; [...]
.text:00000000068E486D                 add     rsp, 1D8h
.text:00000000068E4874                 pop     rbx
.text:00000000068E4875                 pop     r12
.text:00000000068E4877                 pop     r13  
.text:00000000068E4879                 pop     r14
.text:00000000068E487B                 pop     r15  ; <---- loaded from writable memory
.text:00000000068E487D                 pop     rbp
.text:00000000068E487E                 retn
```
 After returning from `FireEventListeners()`, the execution continues with the following code:
```
.text:00000000068E3AAA                 call    blink::EventTarget::FireEventListeners(blink::Event *,blink::EventTargetData *,blink::HeapVector<blink::RegisteredEventListener,1ul> &)
.text:00000000068E3AAF                 test    al, al
.text:00000000068E3AB1                 jnz     loc_68E3B5D
.text:00000000068E3AB7                 jmp     loc_68E3BDF
[...]
.text:00000000068E3B5D loc_68E3B5D:
;
; Not vulnerable CFI check, because rdx is freshly loaded
;
.text:00000000068E3B5D                 mov     rax, [r14]
.text:00000000068E3B60                 lea     rdx, __typeid__ZTSN5blink5EventE_global_addr
.text:00000000068E3B67                 mov     rcx, rax
.text:00000000068E3B6A                 sub     rcx, rdx
.text:00000000068E3B6D                 ror     rcx, 7
.text:00000000068E3B71                 cmp     rcx, 0BCh
.text:00000000068E3B78                 lea     rbx, __typeid__ZTSN5blink11EventTargetE_byte_array
.text:00000000068E3B7F                 ja      loc_68E3C1B
.text:00000000068E3B85                 lea     rdx, __typeid__ZTSN5blink5EventE_byte_array
.text:00000000068E3B8C                 test    byte ptr [rcx+rdx], 40h
.text:00000000068E3B90                 jz      loc_68E3C1B
.text:00000000068E3B96                 mov     rdi, r14
.text:00000000068E3B99                 call    qword ptr [rax+40h]
;
; Vulnerable CFI check:
;
; r13 and r15 are loaded at the beginning of the function and then pushed/popped
; to/from the stack during nested function calls. Note, that the following CFI check
; is similar to the one in the beginning of the function. This is probably the reasons the
; compiler decided to load the values once and keep them in a callee-save register.
;
.text:00000000068E3B9C                 mov     rax, [r13+0]
.text:00000000068E3BA0                 mov     rcx, rax
.text:00000000068E3BA3                 sub     rcx, r15 ; <----  r15 is corrupted
.text:00000000068E3BA6                 ror     rcx, 3
.text:00000000068E3BAA                 cmp     rcx, 41418h ; <---- will pass
.text:00000000068E3BB1                 ja      short loc_68E3C1B  
.text:00000000068E3BB3                 test    byte ptr [rcx+rbx], 80h ; <---- will pass
.text:00000000068E3BB7                 jz      short loc_68E3C1B
.text:00000000068E3BB9                 mov     rdi, r13
.text:00000000068E3BBC                 call    qword ptr [rax+48h]  ; <---- set RIP to arbitrary address
```



## References
[0] https://clang.llvm.org/docs/ControlFlowIntegrity.html  
[1] https://www.chromium.org/developers/testing/control-flow-integrity  
[2] https://chromium.googlesource.com/chromium/src/+/master/docs/linux_build_instructions.md  
[3] http://syssec.rub.de/media/emma/veroeffentlichungen/2015/03/28/COOP-Oakland15.pdf  
[4] https://bugs.chromium.org/p/chromium/issues/detail?id=765433  
[5] https://cloudblogs.microsoft.com/microsoftsecure/2017/10/18/browser-security-beyond-sandboxing  
[6] https://blogs.windows.com/msedgedev/2017/02/23/mitigating-arbitrary-native-code-execution  
[7] https://software.intel.com/sites/default/files/managed/4d/2a/control-flow-enforcement-technology-preview.pdf  
[8] https://www.informatik.tu-darmstadt.de/fileadmin/user_upload/Group_TRUST/PubsPDF/ccs15.stackdefiler.pdf  