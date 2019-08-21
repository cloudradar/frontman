package datacounters

import (
	"io"
	"sync/atomic"
)

// ReaderCounter is counter for io.Reader
type ReadCloserCounter struct {
	// count is loaded atomically, so we need to ensure 64-bit alignment on 32-bit platforms:
	// https://golang.org/pkg/sync/atomic/#pkg-note-BUG
	count uint64
	io.ReadCloser
	readCloser io.ReadCloser
}

// NewReaderCounter function for create new ReaderCounter
func NewReadCloserCounter(r io.ReadCloser) *ReadCloserCounter {
	return &ReadCloserCounter{
		readCloser: r,
	}
}

func (counter *ReadCloserCounter) Read(buf []byte) (int, error) {
	n, err := counter.readCloser.Read(buf)
	atomic.AddUint64(&counter.count, uint64(n))
	return n, err
}

func (counter *ReadCloserCounter) Close() error {
	return counter.readCloser.Close()
}

// Count function return counted bytes
func (counter *ReadCloserCounter) Count() uint64 {
	return atomic.LoadUint64(&counter.count)
}
