package mlkem

/*
#cgo CFLAGS: -I ../../libs
#cgo LDFLAGS: -Wl,-rpath,${SRCDIR} -L../../libs -lopengm_pqc_aarch64-apple-darwin

#include "bindings.h"
*/
import "C"

func Mlkem768KeyGen() ([]byte, []byte) {
	ek := make([]byte, 384*3+32)
	dk := make([]byte, 2400)

	C.mlkem768_keygen((*C.uint8_t)(&ek[0]), (*C.uint8_t)(&dk[0]))

	return ek, dk
}
