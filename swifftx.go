package swifftx

/*
#cgo CFLAGS: -I.
#cgo LDFLAGS: -L. -lSWIFFTX
#include "SHA3.h"
#include <stdint.h>
*/
import "C"
import (
	"errors"
	"fmt"
	"unsafe"
)

type SWIFFTX struct {
	state C.hashState
}

// Assuming BitSequence is defined as a byte
type BitSequence byte

// Assuming DataLength is defined as uint64_t
type DataLength uint64

// Assuming HashReturn is defined as an int or another appropriate type
type HashReturn int

// Set to the output size for 256-bit hash
const SWIFFTX_OUTPUT_BLOCK_SIZE = 32

// New initializes a new SWIFFTX instance with the specified hash length.
func New(hashbitlen int) (*SWIFFTX, error) {
	if hashbitlen != 224 && hashbitlen != 256 && hashbitlen != 384 && hashbitlen != 512 {
		return nil, errors.New("unsupported hash length")
	}
	s := &SWIFFTX{}
	C.Init(&s.state, C.int(hashbitlen))
	return s, nil
}

// Update processes the input data.
func (s *SWIFFTX) Update(data []byte) {
	C.Update(&s.state, (*C.uchar)(unsafe.Pointer(&data[0])), C.uint64_t(len(data)*8))
}

// Final computes the final hash value.
func (s *SWIFFTX) Final() ([]byte, error) {
	hashval := make([]byte, SWIFFTX_OUTPUT_BLOCK_SIZE) // Use defined constant
	C.Final(&s.state, (*C.uchar)(unsafe.Pointer(&hashval[0])))
	return hashval, nil
}

// Hash computes the hash value for the input data all at once.
func Hash(hashbitlen int, data []byte) (HashReturn, []byte, error) {
	if hashbitlen != 224 && hashbitlen != 256 && hashbitlen != 384 && hashbitlen != 512 {
		return 0, nil, errors.New("unsupported hash length")
	}

	// Prepare output hash value slice
	hashval := make([]byte, C.SWIFFTX_OUTPUT_BLOCK_SIZE)

	// Call the C function
	result := C.Hash(C.int(hashbitlen), (*C.BitSequence)(unsafe.Pointer(&data[0])),
		C.DataLength(len(data)*8), (*C.BitSequence)(unsafe.Pointer(&hashval[0])))

	// Return the result and the computed hash value
	return HashReturn(result), hashval, nil
}

func main() {
	// Example usage of the SWIFFTX hashing
	hashLength := 256
	data := []byte("Hello, SWIFFTX!")

	// Create a new SWIFFTX instance
	swifftx, err := New(hashLength)
	if err != nil {
		fmt.Println("Error initializing SWIFFTX:", err)
		return
	}

	// Update the hashing state with data
	swifftx.Update(data)

	// Finalize the hash computation
	hashValue, err := swifftx.Final()
	if err != nil {
		fmt.Println("Error finalizing hash:", err)
		return
	}

	// Print the hash value
	fmt.Printf("Hash value: %x\n", hashValue)
}
