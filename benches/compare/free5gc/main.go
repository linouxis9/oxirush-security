// The MILENAGE and the NAS security of free5GC, as compare.sh runs them:
//
//	free5gc-security <case> <iterations>
//
// The cases are those of the Rust program: av, an authentication vector of
// MILENAGE, and nea1 to nia3, the ciphering or the MAC of a message of 1500
// octets. It prints the nanoseconds, the allocations and the octets
// allocated per operation, and the peak memory of the program in KiB.
package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/free5gc/nas/security"
	"github.com/free5gc/util/milenage"
)

// The inputs of the Rust program.
var (
	key       = [16]byte{0xd3, 0xc5, 0xd5, 0x92, 0x32, 0x7f, 0xb1, 0x1c, 0x40, 0x35, 0xc6, 0x68, 0x0a, 0xf8, 0xc6, 0xd1}
	count     = uint32(0x398a59b4)
	bearer    = uint8(0x15)
	direction = uint8(1)
	opc       = []byte{0xcd, 0x63, 0xcb, 0x71, 0x95, 0x4a, 0x9f, 0x4e, 0x48, 0xa5, 0x99, 0x4e, 0x37, 0xa0, 0x2b, 0xaf}
	k         = []byte{0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f, 0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6, 0xbc}
	rand      = []byte{0x23, 0x55, 0x3c, 0xbe, 0x96, 0x37, 0xa8, 0x9d, 0x21, 0x8a, 0xe6, 0x4d, 0xae, 0x47, 0xbf, 0x35}
	sqn       = []byte{0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07}
	amf       = []byte{0xb9, 0xb9}
)

func peakMemory() int64 {
	var usage syscall.Rusage
	syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
	return usage.Maxrss
}

func main() {
	usage := "free5gc-security <case> <iterations>"
	if len(os.Args) != 3 {
		panic(usage)
	}
	iterations, err := strconv.Atoi(os.Args[2])
	if err != nil {
		panic(usage)
	}
	data := make([]byte, 1500)
	for i := range data {
		data[i] = 0x5a
	}
	cipher := func(algorithm uint8) func() {
		return func() {
			if err := security.NASEncrypt(algorithm, key, count, bearer, direction, data); err != nil {
				panic(err)
			}
		}
	}
	mac := func(algorithm uint8) func() {
		return func() {
			if _, err := security.NASMacCalculate(algorithm, key, count, bearer, direction, data); err != nil {
				panic(err)
			}
		}
	}
	operations := map[string]func(){
		"av": func() {
			if _, _, _, _, err := milenage.GenerateAKAParameters(opc, k, rand, sqn, amf); err != nil {
				panic(err)
			}
		},
		"nea1": cipher(security.AlgCiphering128NEA1),
		"nea2": cipher(security.AlgCiphering128NEA2),
		"nea3": cipher(security.AlgCiphering128NEA3),
		"nia1": mac(security.AlgIntegrity128NIA1),
		"nia2": mac(security.AlgIntegrity128NIA2),
		"nia3": mac(security.AlgIntegrity128NIA3),
	}
	operation, ok := operations[os.Args[1]]
	if !ok {
		panic(usage)
	}
	operation()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	for i := 0; i < iterations; i++ {
		operation()
	}
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	n := float64(iterations)
	fmt.Printf("%.1f %.2f %.0f %d\n", float64(elapsed.Nanoseconds())/n,
		float64(after.Mallocs-before.Mallocs)/n, float64(after.TotalAlloc-before.TotalAlloc)/n,
		peakMemory())
}
