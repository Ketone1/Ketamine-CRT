.code
GetProcessEnvironment proc
	mov rax, gs:[60h] 
    ret
GetProcessEnvironment endp
end