// swifftx.go
package swifftx

/*
#cgo CFLAGS: -I.  // Ensure it includes the current directory
#cgo LDFLAGS: -L. -lSWIFFTX
#include "SHA3.h"
#include <stdlib.h>

void InitHashState(hashState* state, int hashbitlen) {
    Init(state, hashbitlen);
}

void UpdateHashState(hashState* state, const unsigned char* data, uint64_t databitlen) {
    Update(state, data, databitlen);
}

void FinalHashState(hashState* state, unsigned char* hashval) {
    Final(state, hashval);
}

void HashFunction(int hashbitlen, const unsigned char* data, uint64_t databitlen, unsigned char* hashval) {
    Hash(hashbitlen, data, databitlen, hashval);
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

type SWIFFTX struct {
	state C.hashState
}

// New initializes a new SWIFFTX instance with the specified hash length.
func New(hashbitlen int) (*SWIFFTX, error) {
	if hashbitlen != 224 && hashbitlen != 256 && hashbitlen != 384 && hashbitlen != 512 {
		return nil, errors.New("unsupported hash length")
	}
	s := &SWIFFTX{}
	C.InitHashState(&s.state, C.int(hashbitlen))
	return s, nil
}

// Update processes the input data.
func (s *SWIFFTX) Update(data []byte) {
	C.UpdateHashState(&s.state, (*C.uchar)(unsafe.Pointer(&data[0])), C.uint64_t(len(data)*8))
}

// Final computes the final hash value.
func (s *SWIFFTX) Final() ([]byte, error) {
	hashval := make([]byte, C.SWIFFTX_OUTPUT_BLOCK_SIZE)
	C.FinalHashState(&s.state, (*C.uchar)(unsafe.Pointer(&hashval[0])))
	return hashval, nil
}

// Hash computes the hash value for the input data all at once.
func Hash(hashbitlen int, data []byte) ([]byte, error) {
	if hashbitlen != 224 && hashbitlen != 256 && hashbitlen != 384 && hashbitlen != 512 {
		return nil, errors.New("unsupported hash length")
	}
	hashval := make([]byte, C.SWIFFTX_OUTPUT_BLOCK_SIZE)
	C.HashFunction(C.int(hashbitlen), (*C.uchar)(unsafe.Pointer(&data[0])), C.uint64_t(len(data)*8), (*C.uchar)(unsafe.Pointer(&hashval[0])))
	return hashval, nil
}
