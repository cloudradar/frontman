package gzipreader

import (
	"io"
	"compress/gzip"
)

// GzipReader wraps a ReadCloser
// call gzip.NewReader on the first call to Read
type GzipReader struct {
	Reader  io.ReadCloser
	zreader *gzip.Reader
	zerr    error
}

func (gz *GzipReader) Read(p []byte) (n int, err error) {
	if gz.zreader == nil {
		if gz.zerr == nil {
			gz.zreader, gz.zerr = gzip.NewReader(gz.Reader)
		}
		if gz.zerr != nil {
			return 0, gz.zerr
		}
	}

	if err != nil {
		return 0, err
	}
	return gz.zreader.Read(p)
}

func (gz *GzipReader) Close() error {
	return gz.Reader.Close()
}
