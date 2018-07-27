package frontman

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"

	"golang.org/x/net/html"

	"bytes"
	"context"
	"fmt"
	"io/ioutil"

	"github.com/miolini/datacounter"
)

var UserAgent = "Frontman"

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
		fm.httpTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
}

func (fm *Frontman) runWebCheck(data WebCheckData) (m *MeasurementWebcheck, res int, err error) {
	if fm.httpTransport == nil {
		fm.initHttpTransport()
	}

	httpClient := &http.Client{Transport: fm.httpTransport}
	timeout := data.Timeout

	if fm.HTTPCheckTimeout > 0 && fm.HTTPCheckTimeout < timeout {
		timeout = fm.HTTPCheckTimeout
	}

	var tooManyRedirects error
	httpClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if data.DontFollowRedirects {
			return http.ErrUseLastResponse
		} else if fm.HTTPCheckMaxRedirects > 0 {
			if len(via) > fm.HTTPCheckMaxRedirects {
				tooManyRedirects = fmt.Errorf("Too many(>%d) redirects", fm.HTTPCheckMaxRedirects)
				return http.ErrUseLastResponse
			}
		}
		return nil
	}

	req, err := http.NewRequest(strings.ToUpper(data.Method), data.URL, nil)

	if err != nil {
		return nil, 0, err
	}

	var startedConnectonAt time.Time
	var wroteRequestAt time.Time

	trace := &httptrace.ClientTrace{
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			wroteRequestAt = time.Now()
		},
	}

	ctx, _ := context.WithTimeout(req.Context(), secToDuration(timeout))
	req = req.WithContext(httptrace.WithClientTrace(ctx, trace))
	req.Header.Add("Accept-Encoding", "deflate") // gzip disabled to simplify download speed measurement
	req.Header.Add("User-Agent", UserAgent)
	resp, err := httpClient.Do(req)

	if tooManyRedirects != nil {
		return nil, 0, tooManyRedirects
	} else if err != nil {
		if ctx.Err() != nil && ctx.Err() == context.DeadlineExceeded {
			err = fmt.Errorf("Got timeout while performing request")
		} else {
			err = fmt.Errorf("Got error while performing request: %s", err.Error())
		}
		return nil, 0, err
	}
	defer resp.Body.Close()

	if data.ExpectedHTTPStatus > 0 && resp.StatusCode != data.ExpectedHTTPStatus {
		return m, 0, fmt.Errorf("Bad status code. Expected %d, got %d", data.ExpectedHTTPStatus, resp.StatusCode)
	}

	var totalBytes int

	if data.ExpectedPattern != "" {
		if !data.SearchHTMLSource {
			bodyReaderWithCounter := datacounter.NewReaderCounter(resp.Body)
			text := getTextFromHTML(bodyReaderWithCounter)
			totalBytes = int(bodyReaderWithCounter.Count())

			if strings.Contains(text, data.ExpectedPattern) {
				res = 1
			}
		} else {
			text, _ := ioutil.ReadAll(resp.Body)
			totalBytes = len(text)

			if bytes.Contains(text, []byte(data.ExpectedPattern)) {
				res = 1
			}
		}

		if res == 0 {
			where := "in the text"
			if data.SearchHTMLSource {
				where = "in the raw HTML"
			}
			if ctx.Err() != nil {
				if ctx.Err() == context.DeadlineExceeded {
					err = fmt.Errorf("Got timeout while reading response body")
				} else {
					err = fmt.Errorf("Got error while reading response body: %s", ctx.Err().Error())
				}
			} else {
				err = fmt.Errorf("Pattern '%s' not found %s", data.ExpectedPattern, where)
			}
		}

	} else {
		b := make([]byte, 512)
		for true {
			n, err := resp.Body.Read(b)
			totalBytes += n
			if err != nil {
				break
			}
		}

	}

	m = &MeasurementWebcheck{}
	m.BytesReceived = ValueIntInUnit{int64(totalBytes), "bytes"}
	m.HTTPStatusCode.Value = resp.StatusCode
	m.TotalTimeSpent = ValueInUnit{time.Since(startedConnectonAt).Seconds(), "s"}
	m.DownloadPerformance = ValueIntInUnit{int64(float64(totalBytes) / time.Since(wroteRequestAt).Seconds()), "bps"} // Measure download speed since the request sent

	return
}