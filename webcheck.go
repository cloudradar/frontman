package frontman

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"

	"github.com/cloudradar-monitoring/frontman/pkg/utils/datacounters"
	"github.com/cloudradar-monitoring/frontman/pkg/utils/gzipreader"
	"golang.org/x/net/html"
)

func getTextFromHTML(r io.Reader) (text string) {
	dom := html.NewTokenizer(r)
	startToken := dom.Token()

loopDom:
	for {
		tt := dom.Next()
		switch {
		case tt == html.ErrorToken:
			break loopDom // End of the document,  done
		case tt == html.StartTagToken:
			startToken = dom.Token()
		case tt == html.TextToken:

			if startToken.Data == "script" {
				continue
			}

			if startToken.Data == "style" {
				continue
			}

			TxtContent := html.UnescapeString(string(dom.Text()))
			if len(TxtContent) > 0 {
				text += TxtContent
			}
		}
	}
	return
}

func (fm *Frontman) initHttpTransport() {
	fm.httpTransport = &http.Transport{
		DisableKeepAlives: true,
		Proxy:             http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   15 * time.Second,
			KeepAlive: 0,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          1,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	if fm.IgnoreSSLErrors {
		fm.httpTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, RootCAs: fm.rootCAs}
	}
}

func isBodyReaderMatchesPattern(reader io.Reader, pattern string, extractTextFromHTML bool) error {
	var text []byte

	var whereSuffix string
	if extractTextFromHTML {
		text = []byte(getTextFromHTML(reader))
		whereSuffix = "in the raw HTML"
	} else {
		var err error
		// read and search in raw file
		text, err = ioutil.ReadAll(reader)
		if err != nil {
			return fmt.Errorf("got error while reading response body: %s", err.Error())
		}
		whereSuffix = "in the extracted text"
	}

	if !bytes.Contains(text, []byte(pattern)) {
		return fmt.Errorf("pattern '%s' not found %s", pattern, whereSuffix)
	}

	return nil
}

func (fm *Frontman) runWebCheck(data WebCheckData) (map[string]interface{}, error) {
	prefix := fmt.Sprintf("http.%s.", data.Method)
	m := make(map[string]interface{})
	m[prefix+"success"] = 0

	httpClientWithMaxRedirection := fm.newHTTPClientWithCustomMaxRedirectionsLimit(fm.HTTPCheckMaxRedirects)
	timeout := fm.HTTPCheckTimeout

	if data.Timeout < timeout {
		timeout = fm.HTTPCheckTimeout
	}

	data.Method = strings.ToUpper(data.Method)
	req, err := http.NewRequest(data.Method, data.URL, nil)
	if err != nil {
		return m, err
	}

	startedConnectonAt := time.Now()
	defer func() {
		m[prefix+"totalTimeSpent_s"] = time.Since(startedConnectonAt).Seconds()
	}()
	var wroteRequestAt time.Time

	trace := &httptrace.ClientTrace{
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			wroteRequestAt = time.Now()
		},
	}

	ctx, _ := context.WithTimeout(req.Context(), secToDuration(timeout))
	req = req.WithContext(httptrace.WithClientTrace(ctx, trace))
	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("User-Agent", fm.userAgent())

	if data.Method == "POST" && data.PostData != "" {
		req.Body = ioutil.NopCloser(strings.NewReader(data.PostData))
		// close noop closer to bypass lint warnings
		_ = req.Body.Close()
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := httpClientWithMaxRedirection.Do(req)
	if httpClientWithMaxRedirection.Err != nil {
		// we exceed max redirection number
		return m, httpClientWithMaxRedirection.Err
	} else if ctx.Err() == context.DeadlineExceeded {
		return m, fmt.Errorf("got timeout while performing request")
	} else if err != nil {
		return m, fmt.Errorf("got error while performing request: %s", err.Error())
	}

	if data.ExpectedHTTPStatus > 0 && resp.StatusCode != data.ExpectedHTTPStatus {
		return m, fmt.Errorf("bad status code. Expected %d, got %d", data.ExpectedHTTPStatus, resp.StatusCode)
	}

	// wrap body reader with the ReadCloserCounter
	bodyReaderWithCounter := datacounters.NewReadCloserCounter(resp.Body)
	resp.Body = bodyReaderWithCounter

	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		// wrap body reader with gzip reader
		resp.Body = &gzipreader.GzipReader{Reader: resp.Body}
	}
	defer func() {
		// don't care about body close error
		// because it doesn't affects any kind of checks we have
		_ = resp.Body.Close()
	}()

	if data.ExpectedPattern != "" {
		err = isBodyReaderMatchesPattern(resp.Body, data.ExpectedPattern, !data.SearchHTMLSource)
	} else {
		// we don't need the content itself
		// just read the reader, so bodyReaderWithCounter will be able to count bytes
		_, err = ioutil.ReadAll(resp.Body)
	}

	bytesReceived := bodyReaderWithCounter.Count()
	m[prefix+"bytesReceived"] = bytesReceived

	secondsSinceRequestWasSent := time.Since(wroteRequestAt).Seconds()
	if secondsSinceRequestWasSent > 0 {
		m[prefix+"downloadPerformance_bps"] = int64(float64(bytesReceived) / secondsSinceRequestWasSent) // Measure download speed since the request sent
	}

	if ctx.Err() == context.DeadlineExceeded {
		return m, fmt.Errorf("got timeout while reading response body")
	} else if err != nil {
		return m, err
	}

	m[prefix+"success"] = 1
	return m, nil
}

type httpClientAndError struct {
	*http.Client
	Err error
}

func (fm *Frontman) newHTTPClientWithCustomMaxRedirectionsLimit(maxRedirects int) *httpClientAndError {
	if fm.httpTransport == nil {
		fm.initHttpTransport()
	}

	client := &httpClientAndError{&http.Client{Transport: fm.httpTransport}, nil}
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if maxRedirects <= 0 {
			return http.ErrUseLastResponse
		} else if fm.HTTPCheckMaxRedirects > 0 {
			if len(via) > fm.HTTPCheckMaxRedirects {
				client.Err = fmt.Errorf("too many(>%d) redirects", fm.HTTPCheckMaxRedirects)
				return http.ErrUseLastResponse
			}
		}
		return nil
	}
	return client
}
