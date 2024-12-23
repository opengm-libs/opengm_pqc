package mlkem_test

import (
	"fmt"
	"testing"

	"github.com/opengm-libs/opengm_pqc/goapi/mlkem"
)

func TestMlkem768(t *testing.T) {
	ek, dk := mlkem.Mlkem768KeyGen()
	fmt.Println(ek)
	fmt.Println()
	fmt.Println(dk)
}
