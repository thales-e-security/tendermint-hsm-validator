// Copyright 2017 Thales e-Security
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
// IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
// CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
// TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
// OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

package module

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"

	"github.com/pkg/errors"
)

const (
	seeJobResponse_OK              = iota
	seeJobResponse_Error           = iota
	seeJobResponse_ProcessingError = iota
	WordSize                       = 4
)

// marshallAll marshalls all items and returns a buffer. Supported
// types are []byte, int, int32, uint8 and string. All integer types
// are treated as 32-bit values.
func marshallAll(items ...interface{}) (io.Reader, error) {
	buffer := new(bytes.Buffer)
	var err error

	for _, item := range items {
		switch i := item.(type) {
		case []byte:
			err = marshallBytes(i, buffer)
		case int32:
			err = marshallInt(i, buffer)
		case int:
			err = marshallInt(int32(i), buffer)
		case uint8:
			err = marshallInt(int32(i), buffer)
		case int64:
			err = marshallInt64(i, buffer)
		case string:
			err = marshallString(i, buffer)
		default:
			err = errors.Errorf("Unknown type: %s", reflect.TypeOf(item))
		}

		if err != nil {
			break
		}
	}

	return buffer, err
}

// unmarshallAll will consume data from reader and unmarshall into the supplied
// objects.
func unmarshallAll(reader io.Reader, destinations ...interface{}) error {
	var err error

	for _, dest := range destinations {

		if dp, ok := dest.(*[]byte); ok {
			*dp, err = unmarshallBytes(reader)
		} else if dp, ok := dest.(*int32); ok {
			*dp, err = unmarshallInt(reader)
		} else if dp, ok := dest.(*string); ok {
			*dp, err = unmarshallString(reader)
		}

		if err != nil {
			break
		}
	}

	return err
}

// unmarshallInt reads an int32 from the input data.
func unmarshallInt(in io.Reader) (int32, error) {
	var result int32
	err := binary.Read(in, binary.LittleEndian, &result)
	return result, err
}

// marshallInt writes an int32 to the output buffer.
func marshallInt(i int32, out io.Writer) error {
	return binary.Write(out, binary.LittleEndian, i)
}

// marshallInt64 writes an int64 to the output buffer.
func marshallInt64(i int64, out io.Writer) error {
	return binary.Write(out, binary.LittleEndian, i)
}

// marshallString writes a string to the output buffer.
func marshallString(s string, out io.Writer) error {
	return marshallBytes(append([]byte(s), 0), out)
}

// unmarshallString reads a string from the input data.
func unmarshallString(in io.Reader) (string, error) {
	s, err := unmarshallBytes(in)
	return string(s[:len(s)-1]), err
}

// marshallBytes writes a slice to the output buffer.
func marshallBytes(b []byte, out io.Writer) error {
	err := marshallInt(int32(len(b)), out)
	if err != nil {
		return err
	}

	_, err = out.Write(b)
	if err != nil {
		return err
	}

	numPadBytesNeeded := getPaddingForLength(len(b))
	if numPadBytesNeeded > 0 {
		padding := make([]byte, numPadBytesNeeded)
		_, err = out.Write(padding)
	}

	return err
}

// getPaddingForLength calculates the amount of padding required
// to align with the word boundary.
func getPaddingForLength(length int) int {
	return (WordSize - (length % WordSize)) % WordSize
}

// unmarshallBytes reads a slice from the input data.
func unmarshallBytes(in io.Reader) ([]byte, error) {
	length, err := unmarshallInt(in)
	if err != nil {
		return nil, err
	}

	result := make([]byte, length)

	n, err := io.ReadFull(in, result)
	if err != nil {
		return result, errors.Wrap(err, fmt.Sprintf("Tried to read %d bytes, found %d", length, n))
	}

	paddingToDiscard := getPaddingForLength(int(length))
	_, err = io.CopyN(ioutil.Discard, in, int64(paddingToDiscard))
	return result, errors.Wrap(err, fmt.Sprintf("Failed to discard %d padding bytes", paddingToDiscard))
}

// unmarshallModuleReponse unpicks the response from a module. If the response
// indicates an error then an appropriate error string is returned. Otherwise
// the job response data is returned.
func unmarshallModuleReponse(in io.Reader) ([]byte, error) {

	// Skip the first four bytes, since they contain a redundant
	// length indicator
	_, err := io.CopyN(ioutil.Discard, in, 4)
	if err != nil {
		return nil, err
	}

	responseCode, err := unmarshallInt(in)
	if err != nil {
		return nil, err
	}

	switch responseCode {
	case seeJobResponse_OK:
		return unmarshallBytes(in)
	case seeJobResponse_Error:
		errorString, err := unmarshallString(in)
		if err != nil {
			return nil, errors.WithMessage(err, "Failed to unmarshal error string")
		}
		return nil, errors.New("Error from module: " + errorString)

	case seeJobResponse_ProcessingError:
		errorString, err := unmarshallString(in)
		if err != nil {
			return nil, errors.WithMessage(err, "Failed to unmarshal error string")
		}
		errorCode, err := unmarshallInt(in)
		if err != nil {
			return nil, errors.WithMessage(err, "Failed to unmarshal error code")
		}
		return nil, errors.New(fmt.Sprintf("Error from module (code=%d): %s", errorCode, errorString))
	default:
		return nil, errors.Errorf("Unknown response code: %d", responseCode)
	}
}
