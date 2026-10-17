// The MILENAGE of free5GC (github.com/free5gc/util/milenage), for the
// comparison of differential/: one line of inputs on the standard input,
// one line of outputs on the standard output, in hexadecimal digits.
//
// Inputs:  K OP RAND SQN AMF SQNMS BIT
// Outputs: OPc AUTN XRES CK IK SQN AK CK IK RES AUTS SQNMS AUTN-REFUSED AUTS-REFUSED
//
// The second CK, IK and RES are those of the USIM, from the AUTN that the
// vector has; AUTN-REFUSED and AUTS-REFUSED say whether that AUTN and the
// AUTS, with bit BIT changed, are refused.
package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/free5gc/util/milenage"
)

func main() {
	in := bufio.NewScanner(os.Stdin)
	out := bufio.NewWriter(os.Stdout)
	defer out.Flush()
	for in.Scan() {
		if err := line(out, strings.Fields(in.Text())); err != nil {
			fmt.Fprintln(out, "error", err)
		}
		// The other program waits for the line
		out.Flush()
	}
}

func line(out *bufio.Writer, fields []string) error {
	if len(fields) != 7 {
		return fmt.Errorf("%d fields", len(fields))
	}
	var b [6][]byte
	for i := range b {
		var err error
		if b[i], err = hex.DecodeString(fields[i]); err != nil {
			return err
		}
	}
	k, op, rand, sqn, amf, sqnms := b[0], b[1], b[2], b[3], b[4], b[5]
	bit, err := strconv.Atoi(fields[6])
	if err != nil {
		return err
	}
	opc, err := milenage.GenerateOPc(k, op)
	if err != nil {
		return err
	}
	ik, ck, xres, autn, err := milenage.GenerateAKAParameters(opc, k, rand, sqn, amf)
	if err != nil {
		return err
	}
	sqnhe, ak, ueIk, ueCk, res, err := milenage.GenerateKeysWithAUTN(opc, k, rand, autn)
	if err != nil {
		return err
	}
	auts, err := milenage.GenerateAUTS(opc, k, rand, sqnms)
	if err != nil {
		return err
	}
	back, err := milenage.ValidateAUTS(opc, k, rand, auts)
	if err != nil {
		return err
	}
	changed := append([]byte{}, autn...)
	changed[bit%128/8] ^= 0x80 >> (bit % 8)
	_, _, _, _, _, autnErr := milenage.GenerateKeysWithAUTN(opc, k, rand, changed)
	changed = append([]byte{}, auts...)
	changed[bit%112/8] ^= 0x80 >> (bit % 8)
	_, autsErr := milenage.ValidateAUTS(opc, k, rand, changed)
	h := hex.EncodeToString
	fmt.Fprintln(out, h(opc), h(autn), h(xres), h(ck), h(ik), h(sqnhe), h(ak), h(ueCk), h(ueIk),
		h(res), h(auts), h(back), autnErr != nil, autsErr != nil)
	return nil
}
