.386
.model flat, stdcall
option casemap:none

include \masm32\include\windows.inc


;COMPILE WITH SUBSYSTEM:WINDOWS :)
    
.code

start:
   
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;Algo for protector:
;    1)search apis, using delta-offset
;    2)GetFileAttributes and compare with those installed
;    3)GetModuleFileNameA and compare with installed one
;    4)Checksum and compare with one installed   
;    5) If everythings fine, JMP to original entry point
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

call delta                                              ;compute delta and OEP
delta:
    pop ebp

    mov eax, ebp
    sub eax, 5
    
    sub ebp,offset delta ;delta

    sub eax, [ebp + offset protect_section_RVA]
    add eax, [ebp + offset OEP_RVA]
    mov [ebp + offset old_entry_point], eax             ; OEP
    


    ;;;;;;;;;;;;;;;;;;
    ;;;;;;;;;get kernel base
    ;;;;;;;;;;;;;;;;;;;;;;


    mov esi, [esp]    
    call GetBase 
    mov [ebp + offset kern_base], eax      ;saving address of kernel32 base
    ;;;;;;;;;;
    mov ebx, eax                        ; address in ebx to call procedure
    mov eax, offset NameGetProcAddr     ; making delta to GetProcAddress name constant
    add eax, ebp
    push eax
    call GetGetProcAddress
    mov  [ebp + offset addrof_get_proc_addr], eax          ;saving address of GetProcAddress

    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;;;;;;get GetFileAttributes address
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;

    lea eax, [ebp + offset NameGetFileAttributes]
    push eax                                                ; 2nd parameter of GetProcAddr
    mov eax, [ebp + offset kern_base]
    push eax                                                ; 1st parameter of GetProcAddr
    mov eax, [ebp + offset addrof_get_proc_addr]
    call eax                                                ;call GetProcAddr, result in eax
    mov [ebp + offset addrof_get_file_attr], eax            ;save address

    ;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;;;;;;get ExitProcess address
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;

    lea eax, [ebp + offset NameExitProcess]
    push eax
    mov eax, [ebp + offset kern_base]
    push eax                                                ; 1st parameter of GetProcAddr
    mov eax, [ebp + offset addrof_get_proc_addr]
    call eax                                                ;call GetProcAddr, result in eax
    mov [ebp + offset addrof_exitprocess], eax              ;save address
    
    ;;;;;;;;;;;;;;;;;;;;;;;;;
    ;;;;;;;GetModuleFileNameA address
    ;;;;;;;;;;;;;;;;;;;;;;;;;

    lea eax, [ebp + offset NameGetModuleFileNameA]
    push eax
    mov eax, [ebp + offset kern_base]
    push eax
    mov eax, [ebp + offset addrof_get_proc_addr] 
    call eax
    mov [ebp + offset addrof_getmodulefilename], eax
    
    ;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;;;;;LoadLibrary address
    ;;;;;;;;;;;;;;;;;;;;;;;;;;
    
    lea eax, [ebp + offset NameLoadLibraryA]
    push eax
    mov eax, [ebp + offset kern_base]
    push eax
    mov eax, [ebp + offset addrof_get_proc_addr]
    call eax
    mov [ebp + offset addrof_loadlibrarya], eax
    
    ;;;;;;;;;;;;;;;;;;;;;;;;;
    ;;;;;Load user32.dll 
    ;;;;;;;;;;;;;;;;;;;;;;;;;;
    
    lea eax, [ebp + offset NameUser32DLL]
    push eax
    mov eax, [ebp + addrof_loadlibrarya]
    call eax
    mov [ebp + offset user32_base], eax


    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;;;;;Load ImageHlp.dll
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    
    lea eax, [ebp + offset NameImageHlpDLL]
    push eax
    mov eax, [ebp + addrof_loadlibrarya]
    call eax
    mov [ebp + offset imagehlp_base], eax

    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;;;;;CheckSumMappedFile address
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;
    
    lea eax, [ebp + offset NameCheckSumMappedFile]
    push eax
    mov eax, [ebp + offset imagehlp_base]
    push eax
    mov eax, [ebp + offset addrof_get_proc_addr] 
    call eax
    mov [ebp + offset addrof_checksum], eax

    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;;;;;CreateFileA address
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;

    lea eax, [ebp + offset NameCreateFileA]
    push eax
    mov eax, [ebp + offset kern_base]
    push eax
    mov eax, [ebp + offset addrof_get_proc_addr] 
    call eax
    mov [ebp + offset addrof_createfilea], eax


    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;;;;;CreateFileMappingA address
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    
    lea eax, [ebp + offset NameCreateFileMappingA]
    push eax
    mov eax, [ebp + offset kern_base]
    push eax
    mov eax, [ebp + offset addrof_get_proc_addr] 
    call eax
    mov [ebp + offset addrof_createfilemappinga], eax
    
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;;;;;MapViewOfFile address
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    
    lea eax, [ebp + offset NameMapViewOfFile]
    push eax
    mov eax, [ebp + offset kern_base]
    push eax
    mov eax, [ebp + offset addrof_get_proc_addr] 
    call eax
    mov [ebp + offset addrof_mapviewoffile], eax


    ;;;;;;;;;;;;;;;;;;;;;;;;;
    ;;;;MessageBoxA address (in user32.dll)
    ;;;;;;;;;;;;;;;;;;;;;;;;;;


    lea eax, [ebp + offset NameMessageBoxA]
    push eax
    mov eax, [ebp + offset user32_base]
    push eax
    mov eax, [ebp + offset addrof_get_proc_addr] 
    call eax
    mov [ebp + offset addrof_messageboxa], eax



    ;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;;;;;;;;;;Check if file environment is the same
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;

    ;;;;;;;;;;;get file path
    
    push 260                                                ; restrict file path len to 255 bytes
    lea eax, [ebp + offset cur_file_path]
    push eax
    push 0
    call [ebp + offset addrof_getmodulefilename]            ;cur_file_path holds the file path
    
    ;;;;;;;compare file paths
    cld
    lea esi, [ebp + offset cur_file_path]
    lea edi, [ebp + offset inst_file_path] 
    mov ecx, 260
    repe cmpsb
    cmp ecx, 0
    jnz ERROR_PATH                                        ;not equal ?   exit process
    
    ;;;;;;;;;;;;;;;get file attrs

    lea ebx, [ebp + offset cur_file_path]
    push ebx
    call [ebp + offset addrof_get_file_attr]
    
    ;;;;;;;;;;;;;;compare curr attrs with prev
    
    mov ebx, [ebp + offset file_attributes]
    cmp eax, ebx
    jnz ERROR_ATTR                                        ;not equal? then exitprocess


    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;;;;;;;;;;;;;;;;;;CHECK FILE INTEGRITY
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

    ;create file 

    push 0
    mov eax, [ebp + offset image_map_size]
    push eax
    push OPEN_EXISTING
    push 0
    push FILE_SHARE_READ
    push GENERIC_READ
    lea eax, [ebp + offset cur_file_path]
    push eax
    call [ebp + offset addrof_createfilea]  

    ; handle is in eax

    ;create file mapping

    push 0
    mov esi, [ebp + offset image_map_size]
    push esi
    push 0
    push PAGE_READONLY
    push 0
    push eax
    call [ebp + offset addrof_createfilemappinga]

    ;mapview of file

    mov esi, [ebp + offset image_map_size]
    push esi
    push 0
    push 0
    push FILE_MAP_READ
    push eax
    call [ebp + offset addrof_mapviewoffile]

    ;checksum
    
    lea esi, [ebp + offset new_checksum]
    push esi
    push edi
    mov esi, [ebp + offset image_map_size]
    push esi
    push eax
    call [ebp + offset addrof_checksum]

    ;compare checksum and finish
    
    mov eax, [ebp + offset old_checksum]
    mov esi, [ebp + offset new_checksum]
    
    cmp eax, esi
    jnz ERROR_CHECKSUM

    ;;checks passed, run program
    
    jmp JMP_NO_ERROR




    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;;;;;;;;;;;;;;EXITS
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    
    ERROR_PATH:
    push MB_OK
    lea eax, [ebp + offset NameErrorCaption]
    push eax
    lea eax, [ebp + offset NameErrorPath]
    push eax
    push 0
    mov eax, [ebp + offset addrof_messageboxa]
    call eax
    jmp EXIT_PROCESS

    ERROR_ATTR:
    push MB_OK
    lea eax, [ebp + offset NameErrorCaption]
    push eax
    lea eax, [ebp + offset NameErrorAttr]
    push eax
    push 0
    mov eax, [ebp + offset addrof_messageboxa]
    call eax
    jmp EXIT_PROCESS    

    ERROR_CHECKSUM:
    push MB_OK
    lea eax, [ebp + offset NameErrorCaption]
    push eax
    lea eax, [ebp + offset NameErrorChecksum]
    push eax
    push 0
    mov eax, [ebp + offset addrof_messageboxa]
    call eax
    jmp EXIT_PROCESS    

    
    JMP_NO_ERROR:
    jmp [ebp + offset old_entry_point]
    
    EXIT_PROCESS:
    push 0
    call [ebp + addrof_exitprocess]

    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;;;;;;;;INSTALLED PARAMETERS
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

    image_map_size dd 0badceedh
    OEP_RVA dd 1badceedh
    file_attributes dd 2badceedh
    old_checksum dd 3badceedh
    protect_section_RVA dd 4badceedh


    inst_file_path db 260 dup(0)

    ;;;;;;;;;;;;;;;;;;;;;;;;
    ;;;;;;;;;;;CONSTANTS
    ;;;;;;;;;;;;;;;;;;;;;;;;
    
    NameGetProcAddr db 'GetProcAddress', 0
    NameGetFileAttributes db 'GetFileAttributesA', 0
    NameGetModuleFileNameA db 'GetModuleFileNameA', 0
    NameExitProcess db 'ExitProcess', 0
    NameLoadLibraryA db 'LoadLibraryA', 0    
    NameMessageBoxA db 'MessageBoxA', 0
    NameCheckSumMappedFile db 'CheckSumMappedFile', 0
    NameMapViewOfFile db 'MapViewOfFile', 0
    NameCreateFileA db 'CreateFileA', 0
    NameCreateFileMappingA db 'CreateFileMappingA', 0
   

    NameUser32DLL db 'User32.dll', 0
    NameImageHlpDLL db 'Imagehlp.dll', 0
    
    NameErrorCaption db 'Exe corrupted', 0
    NameErrorPath db 'File path changed', 0
    NameErrorAttr db 'File attributes changed', 0
    NameErrorChecksum db 'File checksum changed', 0

    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    ;;;;;;;;;;TEMPORARY VARIABLES
    ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    
    kern_base dd -1
    user32_base dd -1
    imagehlp_base dd -1
    
    addrof_get_proc_addr dd -1
    addrof_get_file_attr dd -1 
    addrof_getmodulefilename dd -1
    addrof_exitprocess dd -1
    addrof_loadlibrarya dd -1
    addrof_messageboxa dd -1
    addrof_checksum dd -1
    addrof_createfilemappinga dd -1
    addrof_createfilea dd -1
    addrof_mapviewoffile dd -1

    cur_file_path db 260 dup(0)
    new_checksum dd -1
    old_entry_point dd -1

    





;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;PROCEDURES TO GET APIS
;got from TPOC lab
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;


;#########################################################################
;Процедура ValidPE
;Проверка правильности PE-файла
;Вход: В esi - адрес файла в памяти
;Выход: если файл правильный, то eax=1, иначе eax=0
;Заметки: обычно процедура используется с проецируемыми файлами в память
;#########################################################################
ValidPE proc
	push esi;сохраняем все регистры
	pushf;сохраняем регистр флагов
	.IF WORD ptr [esi]=="ZM"
		assume esi:ptr IMAGE_DOS_HEADER;указание компилятору, что в esi указатель на IMAGE_DOS_HEADER
		add esi,[esi].e_lfanew;переход к PE заголовку
		.IF WORD PTR [esi]=="EP"
			popf;восстанавливаем значения флагов
			pop esi;восстанавливаем значения регистров
			mov eax,TRUE
			ret
		.ENDIF
	.ENDIF
	popf;восстанавливаем значения флагов
	pop esi;восстанавливаем значения регистров	
	mov eax,FALSE
	ret
ValidPE endp
;#########################################################################
;Конец процедуры ValidPE
;#########################################################################

;#########################################################################
;Процедура GetBase							
;Поиск базы исполняемого файла, если есть адрес где-то внутри него
;Вход: В esi - адрес внутри файла в памяти
;Выход:В eax - база PE-файла
;Заметки:обычно процедура используется с спроецируемыми файлами в память
;#########################################################################
GetBase proc
LOCAL Base:DWORD;чтобы не изменять контекст по договоренности
	push esi;сохраняем все регистры, которые используются
	push ecx

	pushf;сохраняем регистр флагов
	and esi,0FFFF0000H;гранулярность выделения памяти
	mov ecx,6;счетчик страниц

NextPage:;проверка очередной страницы
	call ValidPE
	.IF eax==1
		mov Base,esi
		popf
		pop ecx
		pop esi
		mov eax,Base
		ret
	.ENDIF
	sub esi,10000H
	loop NextPage

	popf;восстанавливаем значения флагов
	pop ecx
	pop esi;восстанавливаем значения регистров
	mov eax,FALSE;не нашли базу :(
	ret
GetBase endp
;#########################################################################
;Конец процедуры GetBase
;#########################################################################




;Процедура GetGetProcAddress
;Поиск адреса внутри kernel32.dll
;Вход: в стек кладется смещение имени "GetProcAddress"
;	ebx - база kernel32.dll
;Выход:В eax - адрес функции GetProcAddress
;#########################################################################
GetGetProcAddress proc NameFunc:DWORD
	pushad;сохраняем регистры
	mov esi,ebx
	assume esi:ptr IMAGE_DOS_HEADER
	add esi,[esi].e_lfanew;в esi - заголовок PE

	assume esi:ptr IMAGE_NT_HEADERS
	lea esi,[esi].OptionalHeader;в esi - адрес опционального заголовка

	assume esi:ptr IMAGE_OPTIONAL_HEADER
	lea esi,[esi].DataDirectory;в esi - адрес DataDirectory
	mov esi,dword ptr [esi]
	add esi,ebx;в esi - структура IMAGE_EXPORT_DIRECTORY
	push esi
	assume esi:ptr IMAGE_EXPORT_DIRECTORY
	mov esi,[esi].AddressOfNames
	add esi,ebx;в esi - массив имен функций
	xor edx,edx;в edx - храним индекс

	mov eax,esi
	mov esi,dword ptr [esi]
NextName:;поиск следующего имени функции
	add esi,ebx
	mov edi,NameFunc
	mov ecx,14;количество байт в "GetProcAddress"
	cld
	repe cmpsb
	.IF ecx==0;нашли имя
		jmp GetAddr
	.ENDIF
	inc edx
	add eax,4
	mov esi,dword ptr [eax]
	jmp NextName
GetAddr:;если нашли "GetProcAddress"
	pop esi
	mov edi,esi
	mov esi,[esi].AddressOfNameOrdinals
	add esi,ebx;в esi - массив слов с индесками
	mov dx,word ptr [esi][edx*2]
	assume edi:ptr IMAGE_EXPORT_DIRECTORY
	sub edx,[edi].nBase;вычитаем начальный ординал
	inc edx;т.к. начальный ординал начинается с 1
	mov esi,[edi].AddressOfFunctions
	add esi,ebx;в esi - массив адресов функций
	mov eax,dword ptr [esi][edx*4]
	add eax,ebx;в eax - адрес функции GetProcAddress
	mov NameFunc,eax
	popad;восстанавливаем регистры
	mov eax,NameFunc
	ret
GetGetProcAddress endp	
;#########################################################################
;Конец процедуры GetGetProcAddress
;#########################################################################



end start
