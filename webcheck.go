package frontman

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"golang.org/x/net/html"
	"github.com/cloudradar-monitoring/frontman/pkg/utils/datacounters"
	"github.com/cloudradar-monitoring/frontman/pkg/utils/gzipreader"
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

func (fm *Frontman) runWebCheck(data WebCheckData) (m map[string]interface{}, err error) {
	prefix := fmt.Sprintf("http.%s.", data.Method)
	m = make(map[string]interface{})
	m[prefix+"success"] = 0

	if fm.httpTransport == nil {
		fm.initHttpTransport()
	}

	httpClient := &http.Client{Transport: fm.httpTransport}
	timeout := fm.HTTPCheckTimeout

	if data.Timeout < timeout {
		timeout = fm.HTTPCheckTimeout
	}

	var tooManyRedirects error
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if data.DontFollowRedirects {
			return http.ErrUseLastResponse
		} else if fm.HTTPCheckMaxRedirects > 0 {
			if len(via) > fm.HTTPCheckMaxRedirects {
				tooManyRedirects = fmt.Errorf("too many(>%d) redirects", fm.HTTPCheckMaxRedirects)
				return http.ErrUseLastResponse
			}
		}
		return nil
	}

	data.Method = strings.ToUpper(data.Method)
	req, err := http.NewRequest(data.Method, data.URL, nil)

	if err != nil {
		return
	}

	startedConnectonAt := time.Now()
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
		req.Body.Close()
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	resp, err := httpClient.Do(req)

	if resp != nil {
		m[prefix+"httpStatusCode"] = resp.StatusCode
	}

	if tooManyRedirects != nil {
		err = tooManyRedirects
		return
	} else if err != nil {
		if ctx.Err() != nil && ctx.Err() == context.DeadlineExceeded {
			err = fmt.Errorf("got timeout while performing request")
		} else {
			err = fmt.Errorf("got error while performing request: %s", err.Error())
		}
		return
	}
	defer resp.Body.Close()

	// wrap ReadCloser with the ReadCloserCounter
	bodyReaderWithCounter := datacounters.NewReadCloserCounter(resp.Body)
	resp.Body = bodyReaderWithCounter

	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip"){
		resp.Body = &gzipreader.GzipReader{Reader: resp.Body}
	}
	if data.ExpectedHTTPStatus > 0 && resp.StatusCode != data.ExpectedHTTPStatus {
		m[prefix+"totalTimeSpent_s"] = time.Since(startedConnectonAt).Seconds()
		return m, fmt.Errorf("bad status code. Expected %d, got %d", data.ExpectedHTTPStatus, resp.StatusCode)
	}

	m[prefix+"success"] = 1

	if data.ExpectedPattern != "" {
		if !data.SearchHTMLSource {
			text := getTextFromHTML(resp.Body)
			if !strings.Contains(text, data.ExpectedPattern) {
				m[prefix+"success"] = 0
			}
		} else {
			// read and search in raw file
			text, readErr := ioutil.ReadAll(resp.Body)
			if readErr != nil {
				err = fmt.Errorf("got error while reading response body: %s", readErr.Error())
				m[prefix+"success"] = 0
			} else if !bytes.Contains(text, []byte(data.ExpectedPattern)) {
				m[prefix+"success"] = 0
			}
		}

		if m[prefix+"success"] == 0 {
			where := "in the text"
			if data.SearchHTMLSource {
				where = "in the raw HTML"
			}
			if ctx.Err() != nil {
				if ctx.Err() == context.DeadlineExceeded {
					err = fmt.Errorf("got timeout while reading response body")
				} else {
					err = fmt.Errorf("got error while reading response body: %s", ctx.Err().Error())
				}
			} else {
				err = fmt.Errorf("pattern '%s' not found %s", data.ExpectedPattern, where)
			}
		}

	} else {
		_, err = ioutil.ReadAll(resp.Body)
		if err != nil {
			err = fmt.Errorf("got error while reading response body: %s", err.Error())
		}
	}

	bytesReceived := bodyReaderWithCounter.Count()

	m[prefix+"bytesReceived"] = bytesReceived
	m[prefix+"totalTimeSpent_s"] = time.Since(startedConnectonAt).Seconds()
	seconds := time.Since(wroteRequestAt).Seconds()
	if seconds > 0 {
		m[prefix+"downloadPerformance_bps"] = int64(float64(bytesReceived) / seconds) // Measure download speed since the request sent
	}

	return
}
