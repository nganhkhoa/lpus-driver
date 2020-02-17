PUBLIC FindKdVersionBlock
.code _text


FindKdVersionBlock PROC PUBLIC
mov rax, gs:[108h]
ret
FindKdVersionBlock ENDP


END
