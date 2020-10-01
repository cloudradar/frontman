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
	"net/url"
	"strings"
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

func (fm *Frontman) newHTTPTransport(ignoreSSLErrors *bool) *http.Transport {
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

	valueProvided := ignoreSSLErrors != nil
	if (valueProvided && *ignoreSSLErrors) ||
		(!valueProvided && fm.Config.IgnoreSSLErrors) {
		t.TLSClientConfig.InsecureSkipVerify = true
		t.TLSClientConfig.RootCAs = fm.rootCAs
	}

	return t
}

func checkBodyReaderMatchesPattern(reader io.Reader, pattern string, expectedPresence string, extractTextFromHTML bool) error {
	var text []byte

	expectedPresence = strings.ToLower(expectedPresence)
	if expectedPresence != "absent" {
		expectedPresence = "present"
	}

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

	if expectedPresence == "present" && !bytes.Contains(text, []byte(pattern)) {
		return fmt.Errorf("pattern expected to be present '%s' not found %s", pattern, whereSuffix)
	}
	if expectedPresence == "absent" && bytes.Contains(text, []byte(pattern)) {
		return fmt.Errorf("pattern expected to be absent '%s' found %s", pattern, whereSuffix)
	}

	return nil
}

func (check WebCheck) uniqueID() string {
	return check.UUID
}

func (check WebCheck) run(fm *Frontman) (*Result, error) {
	if check.UUID == "" {
		return nil, fmt.Errorf("missing checkUuid key")
	}
	if check.Check.Method == "" {
		return nil, fmt.Errorf("missing check.method key")
	}
	if check.Check.URL == "" {
		return nil, fmt.Errorf("missing check.url key")
	}

	res := Result{
		Node:      fm.Config.NodeName,
		CheckType: "webCheck",
		CheckUUID: check.UUID,
		Check:     check.Check,
		Timestamp: time.Now().Unix(),
	}

	prefix := fmt.Sprintf("http.%s.", check.Check.Method)
	m := make(map[string]interface{})
	m[prefix+"success"] = 0

	// In case the webcheck disables redirect following we set maxRedirects to 0
	maxRedirects := 0
	if !check.Check.DontFollowRedirects {
		maxRedirects = fm.Config.HTTPCheckMaxRedirects
	}
	var httpTransport = fm.newHTTPTransport(check.Check.IgnoreSSLErrors)
	httpClient := fm.newClientWithOptions(httpTransport, maxRedirects)

	timeout := fm.Config.HTTPCheckTimeout

	// set individual timeout in case it is less than in this check
	if check.Check.Timeout > 0 && check.Check.Timeout < timeout {
		timeout = check.Check.Timeout
	}

	check.Check.Method = strings.ToUpper(check.Check.Method)

	ctx, cancel := context.WithTimeout(context.Background(), secToDuration(timeout))
	defer cancel()

	url, err := normalizeURLPort(check.Check.URL)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequest(check.Check.Method, url, nil)
	if err != nil {
		return nil, err
	}

	startedConnectionAt := time.Now()
	defer func() {
		m[prefix+"totalTimeSpent_s"] = time.Since(startedConnectionAt).Seconds()
	}()

	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("User-Agent", fm.userAgent())

	var hostHeader string
	for key, val := range check.Check.Headers {
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

	if check.Check.Method == "POST" && check.Check.PostData != "" {
		req.Body = ioutil.NopCloser(strings.NewReader(check.Check.PostData))
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
			return nil, fmt.Errorf("timeout exceeded")
		}
		return nil, err
	}
	defer resp.Body.Close()

	// Set the httpStatusCode in case we got a response
	m[prefix+"httpStatusCode"] = resp.StatusCode

	if check.Check.ExpectedHTTPStatus > 0 && resp.StatusCode != check.Check.ExpectedHTTPStatus {
		return nil, fmt.Errorf("bad status code. Expected %d, got %d", check.Check.ExpectedHTTPStatus, resp.StatusCode)
	}

	// wrap body reader with the ReadCloserCounter
	bodyReaderWithCounter := datacounters.NewReadCloserCounter(resp.Body)
	resp.Body = bodyReaderWithCounter

	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		// wrap body reader with gzip reader
		resp.Body = &gzipreader.GzipReader{Reader: resp.Body}
	}

	if check.Check.ExpectedPattern != "" {
		err = checkBodyReaderMatchesPattern(resp.Body, check.Check.ExpectedPattern, check.Check.ExpectedPatternPresence, !check.Check.SearchHTMLSource)
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
			return nil, fmt.Errorf("timeout exceeded")
		}
		return nil, err
	}

	m[prefix+"success"] = 1
	res.Measurements = m
	return &res, nil
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

/*
func runWebChecks(fm *Frontman, wg *sync.WaitGroup, local bool, resultsChan *chan Result, checkList []WebCheck) int {
	succeed := 0
	for _, check := range checkList {
		wg.Add(1)
		go func(wg *sync.WaitGroup, check WebCheck, resultsChan *chan Result) {
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
				res.Measurements, err = check.Run(fm)
				if err != nil {
					recovered := false
					if fm.Config.FailureConfirmation > 0 {
						logrus.Debugf("webCheck failed, retrying up to %d times: %s: %s", fm.Config.FailureConfirmation, check.UUID, err.Error())

						for i := 1; i <= fm.Config.FailureConfirmation; i++ {
							time.Sleep(time.Duration(fm.Config.FailureConfirmationDelay*1000) * time.Millisecond)
							logrus.Debugf("Retry %d for failed check %s", i, check.UUID)
							res.Measurements, err = check.Run(fm)
							if err == nil {
								recovered = true
								break
							}
						}
					}
					if !recovered {
						res.Message = err.Error()
					}
					if !recovered && len(fm.Config.Nodes) > 0 && local {
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

			*resultsChan <- res
		}(wg, check, resultsChan)
	}
	return succeed
}
*/

// removes ports from URL if it is the default port for given scheme
func normalizeURLPort(u string) (string, error) {
	url, err := url.Parse(u)
	if err != nil {
		return u, err
	}

	portSeparator := strings.Index(url.Host, ":")
	if portSeparator != -1 {
		port := url.Host[portSeparator+1:]
		if (url.Scheme == "http" && port == "80") || (url.Scheme == "https" && port == "443") {
			url.Host = url.Host[0:portSeparator]
		}
	}

	return url.String(), nil
}
