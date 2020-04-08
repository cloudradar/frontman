package frontman

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
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

func (fm *Frontman) newHTTPTransport(ignoreSSLErrors bool) *http.Transport {
	t := &http.Transport{
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
		TLSClientConfig:       &tls.Config{},
	}

	if ignoreSSLErrors { // TODO: honor fm.Config.IgnoreSSLErrors value
		t.TLSClientConfig.InsecureSkipVerify = true
		t.TLSClientConfig.RootCAs = fm.rootCAs
	}

	return t
}

func checkBodyReaderMatchesPattern(reader io.Reader, pattern string, extractTextFromHTML bool) error {
	var text []byte

	var whereSuffix string
	if extractTextFromHTML {
		text = []byte(getTextFromHTML(reader))
		whereSuffix = "in the extracted text"
	} else {
		var err error
		text, err = ioutil.ReadAll(reader)
		if err != nil {
			return fmt.Errorf("got error while reading response body: %s", err.Error())
		}
		whereSuffix = "in the raw HTML"
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

	// In case the webcheck disables redirect following we set maxRedirects to 0
	maxRedirects := 0
	if !data.DontFollowRedirects {
		maxRedirects = fm.Config.HTTPCheckMaxRedirects
	}
	var httpTransport = fm.newHTTPTransport(data.IgnoreSSLErrors)
	httpClient := fm.newClientWithOptions(httpTransport, maxRedirects)

	timeout := fm.Config.HTTPCheckTimeout

	// set individual timeout in case it is less than in this check
	if data.Timeout > 0 && data.Timeout < timeout {
		timeout = data.Timeout
	}

	data.Method = strings.ToUpper(data.Method)

	ctx, cancel := context.WithTimeout(context.Background(), secToDuration(timeout))
	defer cancel()

	req, err := http.NewRequest(data.Method, data.URL, nil)
	if err != nil {
		return m, err
	}

	startedConnectionAt := time.Now()
	defer func() {
		m[prefix+"totalTimeSpent_s"] = time.Since(startedConnectionAt).Seconds()
	}()

	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("User-Agent", fm.userAgent())

	var hostHeader string
	for key, val := range data.Headers {
		req.Header.Set(key, val)
		if hostHeader == "" && strings.ToLower(key) == "host" {
			hostHeader = val
		}
	}
	if hostHeader != "" && hostHeader != req.URL.Host {
		// most probably we should enable SNI handshake
		httpTransport.TLSClientConfig.ServerName = hostHeader
		req.Host = hostHeader
	}

	if data.Method == "POST" && data.PostData != "" {
		req.Body = ioutil.NopCloser(strings.NewReader(data.PostData))
		// close noop closer to bypass lint warnings
		_ = req.Body.Close()
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	var wroteRequestAt time.Time
	trace := &httptrace.ClientTrace{
		GotFirstResponseByte: func() {
			m[prefix+"timeToFirstByte_s"] = time.Since(wroteRequestAt).Seconds()
		},
	}

	wroteRequestAt = time.Now()
	resp, err := httpClient.Do(req.WithContext(httptrace.WithClientTrace(ctx, trace)))
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return m, fmt.Errorf("timeout exceeded")
		}
		return m, err
	}
	defer resp.Body.Close()

	// Set the httpStatusCode in case we got a response
	m[prefix+"httpStatusCode"] = resp.StatusCode

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

	if data.ExpectedPattern != "" {
		err = checkBodyReaderMatchesPattern(resp.Body, data.ExpectedPattern, !data.SearchHTMLSource)
	} else {
		// we don't need the content itself because we don't need to check any pattern
		// just read the reader, so bodyReaderWithCounter will be able to count bytes
		_, err = ioutil.ReadAll(resp.Body)
	}

	bytesReceived := bodyReaderWithCounter.Count()
	m[prefix+"bytesReceived"] = bytesReceived

	secondsSinceRequestWasSent := time.Since(wroteRequestAt).Seconds()
	if secondsSinceRequestWasSent > 0 {
		// Measure download speed since the request sent
		m[prefix+"downloadPerformance_bps"] = int64(float64(bytesReceived) / secondsSinceRequestWasSent)
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return m, fmt.Errorf("timeout exceeded")
		}
		return m, err
	}

	m[prefix+"success"] = 1
	return m, nil
}

func (fm *Frontman) newClientWithOptions(transport *http.Transport, maxRedirects int) *http.Client {
	client := &http.Client{Transport: transport}

	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		// copies headers from previous request (go strips Authorization header on redirects)
		lastRequest := via[len(via)-1]
		for attr, val := range lastRequest.Header {
			if _, ok := req.Header[attr]; !ok {
				req.Header[attr] = val
			}
		}

		if maxRedirects <= 0 {
			logrus.Println("redirects are not allowed")
			return http.ErrUseLastResponse
		} else if len(via) > maxRedirects {
			logrus.Printf("too many(>%d) redirects", maxRedirects)
			return http.ErrUseLastResponse
		}
		return nil
	}

	return client
}

func runWebChecks(fm *Frontman, wg *sync.WaitGroup, resultsChan chan<- Result, checkList []WebCheck) int {
	succeed := 0
	for _, check := range checkList {
		wg.Add(1)
		go func(check WebCheck) {
			defer wg.Done()

			if check.UUID == "" {
				// in case checkUuid is missing we can ignore this item
				logrus.Errorf("webCheck: missing checkUuid key")
				return
			}

			res := Result{
				Node:      fm.Config.NodeName,
				CheckType: "webCheck",
				CheckUUID: check.UUID,
				Timestamp: time.Now().Unix(),
			}

			res.Check = check.Check

			switch {
			case check.Check.Method == "":
				logrus.Errorf("webCheck: missing check.method key")
				res.Message = "Missing check.method key"
			case check.Check.URL == "":
				logrus.Errorf("webCheck: missing check.url key")
				res.Message = "Missing check.url key"
			default:
				var err error
				res.Measurements, err = fm.runWebCheck(check.Check)
				if err != nil {
					recovered := false
					if fm.Config.FailureConfirmation > 0 {
						logrus.Debugf("webCheck failed, retrying up to %d times: %s: %s", fm.Config.FailureConfirmation, check.UUID, err.Error())

						for i := 1; i <= fm.Config.FailureConfirmation; i++ {
							time.Sleep(time.Duration(fm.Config.FailureConfirmationDelay*1000) * time.Millisecond)
							logrus.Debugf("Retry %d for failed check %s", i, check.UUID)
							res.Measurements, err = fm.runWebCheck(check.Check)
							if err == nil {
								recovered = true
								break
							}
						}
					}
					if !recovered {
						res.Message = err.Error()
					}
					if !recovered && len(fm.Config.Nodes) > 0 {
						checkRequest := &Input{
							WebChecks: []WebCheck{check},
						}
						data, _ := json.Marshal(checkRequest)
						fm.askNodes(data, &res)
					}
					if !recovered {
						logrus.Debugf("webCheck: %s: %s", check.UUID, err.Error())
					}
				}
			}

			if res.Message == "" {
				succeed++
			}

			resultsChan <- res
		}(check)
	}
	return succeed
}
