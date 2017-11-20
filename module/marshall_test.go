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
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestMarshallInt(t *testing.T) {
	doTestInt(42, t)
	doTestInt(-1, t)
}

func doTestInt(i int32, t *testing.T) {
	buffer := new(bytes.Buffer)

	err := MarshallInt(i, buffer)
	require.Nil(t, err, err)

	result, err := UnmarshallInt(buffer)
	require.Nil(t, err, err)
	require.Equal(t, i, result)
}

func TestMarshallBytes(t *testing.T) {
	someBytes := []byte("Hello, World!")
	buffer := new(bytes.Buffer)

	err := MarshallBytes(someBytes, buffer)
	require.Nil(t, err, err)
	require.True(t, math.Mod(float64(buffer.Len()), 4) == 0, "Not a multiple of 4 bytes")

	result, err := UnmarshallBytes(buffer)
	require.Nil(t, err, err)
	require.Equal(t, someBytes, result)
}

func TestMarshallBytesPadding(t *testing.T) {
	threeBytes := []byte{1, 2, 3}
	buffer := new(bytes.Buffer)

	err := MarshallBytes(threeBytes, buffer)
	require.Nil(t, err, err)
	require.Equal(t, 2*WordSize, buffer.Len())

	fourBytes := []byte{1, 2, 3, 4}
	buffer.Reset()

	err = MarshallBytes(fourBytes, buffer)
	require.Nil(t, err, err)
	require.Equal(t, 2*WordSize, buffer.Len())
}

func TestMarshallString(t *testing.T) {
	someString := "Hello, World!"
	buffer := new(bytes.Buffer)

	err := MarshallString(someString, buffer)
	require.Nil(t, err, err)

	result, err := UnmarshallString(buffer)
	require.Nil(t, err, err)
	require.Equal(t, someString, result)
}

func TestMarshallAll(t *testing.T) {
	b := []byte{1, 2, 3}
	i := int32(42)
	s := "Hello, World!"

	buffer, err := MarshallAll(b, i, s)
	require.Nil(t, err)

	b2, err := UnmarshallBytes(buffer)
	require.Nil(t, err)

	i2, err := UnmarshallInt(buffer)
	require.Nil(t, err)

	s2, err := UnmarshallString(buffer)
	require.Nil(t, err)

	require.Equal(t, b, b2)
	require.Equal(t, i, i2)
	require.Equal(t, s, s2)
}

func TestMarshallUnmarshallAll(t *testing.T) {
	b := []byte{1, 2, 3}
	i := int32(42)
	s := "Hello, World!"

	buffer, err := MarshallAll(b, i, s)
	require.Nil(t, err)

	var b2 []byte
	var i2 int32
	var s2 string

	err = UnmarshallAll(buffer, &b2, &i2, &s2)
	require.Nil(t, err)

	require.Equal(t, b, b2)
	require.Equal(t, i, i2)
	require.Equal(t, s, s2)
}
