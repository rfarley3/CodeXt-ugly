; whatever B to hold original value to be good for exec
; still symbolic so taint is propogated

; do XOR on one of the bytes a = X XOR Y, A XOR Y
; x = buf[3]
; buf[3] = x xor y
; mark y symb
; buf[3] = buf[3] xor y
; now buf[3] should be original value, but marked as symb <- 1st req
; now try to exec buf (so buf[3] is forced to be concretized) <- 2nd req


; also need to trace taint propogation
; buf[4] =^ buf[3]
; buf[4] =^ buf[3]
; now buf[4] is original value, but marked as symbolic (bc of buf[3] bc of y)

; now need to trace multiple taint propogations
; mark buf[5] as symbolic
; buf[6] =^ buf[5]
