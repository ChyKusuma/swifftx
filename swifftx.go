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
	"os"
	"unsafe"
)

type SWIFFTX struct {
	state C.hashState
}

type BitSequence byte
type DataLength uint64
type HashReturn int

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
	hashval := make([]byte, SWIFFTX_OUTPUT_BLOCK_SIZE)
	C.Final(&s.state, (*C.uchar)(unsafe.Pointer(&hashval[0])))
	return hashval, nil
}

// Hash computes the hash value for the input data all at once.
func Hash(hashbitlen int, data []byte) (HashReturn, []byte, error) {
	if hashbitlen != 224 && hashbitlen != 256 && hashbitlen != 384 && hashbitlen != 512 {
		return 0, nil, errors.New("unsupported hash length")
	}

	hashval := make([]byte, C.SWIFFTX_OUTPUT_BLOCK_SIZE)
	result := C.Hash(C.int(hashbitlen), (*C.BitSequence)(unsafe.Pointer(&data[0])),
		C.DataLength(len(data)*8), (*C.BitSequence)(unsafe.Pointer(&hashval[0])))
	return HashReturn(result), hashval, nil
}

func main() {
	// Set permissions for the library
	libPath := "/Users/kusuma/Desktop/bc-go-v1/crypto/Swifftx/libSWIFFTX.dylib"
	err := os.Chmod(libPath, 0755) // or use 0644 depending on your needs
	if err != nil {
		fmt.Println("Error setting permissions:", err)
		return
	}

	// Example usage of the SWIFFTX hashing
	hashLength := 256
	data := []byte("Hello, SWIFFTX!")

	// Print the original data message
	fmt.Println("Data message:", string(data))

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
