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
	"fmt"
	"io"
	"net"
)

// sendJobToModule sends job data to the module. If the module responds with an error message, this is returned
// in `error`, otherwise the job response is returned as a byte slice. Generally this response requires further
/// unmarshalling (e.g. if it contains binary data)
func sendJobToModule(jobNumber int32, marshalledData io.Reader, ipAddress string, portnumber int) ([]byte, error) {

	buffer := new(bytes.Buffer)
	err := marshallInt(jobNumber, buffer)
	if err != nil {
		return nil, err
	}

	_, err = buffer.ReadFrom(marshalledData)
	if err != nil {
		return nil, err
	}

	// Note: this is not aligned to four bytes, as a marshalled byte array would be
	bufferWithLength := new(bytes.Buffer)
	err = marshallInt(int32(buffer.Len()), bufferWithLength)
	if err != nil {
		return nil, err
	}

	_, err = buffer.WriteTo(bufferWithLength)
	if err != nil {
		return nil, err
	}

	address := fmt.Sprintf("%s:%d", ipAddress, portnumber)

	conn, err := net.Dial("tcp", address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	_, err = bufferWithLength.WriteTo(conn)
	if err != nil {
		return nil, err
	}

	result := new(bytes.Buffer)
	_, err = result.ReadFrom(conn)
	if err != nil {
		return nil, err
	}

	return unmarshallModuleReponse(result)
}
