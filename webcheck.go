package frontman

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/net/html"

	"github.com/cloudradar-monitoring/frontman/pkg/utils/gzipreader"
)

const maxBodySize = 1 * 1024 * 1024

func getTextFromHTML(data []byte) (text string) {
	r := bytes.NewReader(data)
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

func checkBodyReaderMatchesPattern(data []byte, pattern string, expectedPresence string, extractTextFromHTML bool) error {
	expectedPresence = strings.ToLower(expectedPresence)
	if expectedPresence != "absent" {
		expectedPresence = "present"
	}

	var whereSuffix string
	if extractTextFromHTML {
		data = []byte(getTextFromHTML(data))
		whereSuffix = "in the extracted text"
	} else {
		whereSuffix = "in the raw HTML"
	}

	if expectedPresence == "present" && !bytes.Contains(data, []byte(pattern)) {
		return fmt.Errorf("pattern expected to be present '%s' not found %s", pattern, whereSuffix)
	}
	if expectedPresence == "absent" && bytes.Contains(data, []byte(pattern)) {
		return fmt.Errorf("pattern expected to be absent '%s' found %s", pattern, whereSuffix)
	}

	return nil
}

func (check WebCheck) uniqueID() string {
	return check.UUID
}

func (check WebCheck) run(fm *Frontman) (*Result, error) {

	res := &Result{
		Node:         fm.Config.NodeName,
		CheckType:    "webCheck",
		CheckUUID:    check.UUID,
		Check:        check.Check,
		Timestamp:    time.Now().Unix(),
		Measurements: make(map[string]interface{}),
	}

	if check.UUID == "" {
		return res, fmt.Errorf("missing checkUuid key")
	}
	if check.Check.Method == "" {
		return res, fmt.Errorf("missing check.method key")
	}
	if check.Check.URL == "" {
		return res, fmt.Errorf("missing check.url key")
	}

	prefix := fmt.Sprintf("http.%s.", check.Check.Method)
	res.Measurements[prefix+"success"] = 0

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
		return res, err
	}

	req, err := http.NewRequest(check.Check.Method, url, nil)
	if err != nil {
		return res, err
	}

	startedConnectionAt := time.Now()
	defer func() {
		res.Measurements[prefix+"totalTimeSpent_s"] = time.Since(startedConnectionAt).Seconds()
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
			res.Measurements[prefix+"timeToFirstByte_s"] = time.Since(wroteRequestAt).Seconds()
		},
	}

	wroteRequestAt = time.Now()
	resp, err := httpClient.Do(req.WithContext(httptrace.WithClientTrace(ctx, trace)))
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return res, fmt.Errorf("timeout exceeded")
		}
		return res, err
	}
	defer resp.Body.Close()

	// Set the httpStatusCode in case we got a response
	res.Measurements[prefix+"httpStatusCode"] = resp.StatusCode

	if check.Check.ExpectedHTTPStatus > 0 && resp.StatusCode != check.Check.ExpectedHTTPStatus {
		return res, fmt.Errorf("bad status code. Expected %d, got %d", check.Check.ExpectedHTTPStatus, resp.StatusCode)
	}

	if check.Check.Method != "HEAD" {
		if contentLength := resp.Header.Get("Content-Length"); contentLength != "" {
			length, err := strconv.ParseInt(contentLength, 10, 64)
			if err == nil && length > maxBodySize {
				res.Message = fmt.Sprintf("Content-Length too large for checking (%d)", length)
				return res, nil
			}
		}

		contentType := resp.Header.Get("Content-Type")

		ct := strings.Split(contentType, "/")
		if len(ct) >= 2 && ct[0] != "text" {

			switch ct[0] {
			case "audio", "video", "image", "font":
				res.Message = fmt.Sprintf("Content-Type is not readable as text (%s)", contentType)
				return res, nil
			}

			switch contentType {
			case "application/octet-stream", "application/ogg", "application/pdf", "application/x-shockwave-flash", "application/zip":
				res.Message = fmt.Sprintf("Content-Type is not readable as text (%s)", contentType)
				return res, nil
			}
		}
	}

	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		// wrap body reader with gzip reader
		resp.Body = &gzipreader.GzipReader{Reader: resp.Body}
	}

	limitedReader := http.MaxBytesReader(nil, resp.Body, maxBodySize)
	data, err := ioutil.ReadAll(limitedReader)
	if err != nil {
		if err.Error() == "http: request body too large" {
			res.Message = fmt.Sprintf("got error while reading full response body: http: request body exceeds the maximum of %dMB", maxBodySize/1024/1024)
		} else {
			res.Message = fmt.Sprintf("got error while reading response body: %s", err.Error())
		}
	}

	if check.Check.ExpectedPattern != "" {
		err = checkBodyReaderMatchesPattern(data, check.Check.ExpectedPattern, check.Check.ExpectedPatternPresence, !check.Check.SearchHTMLSource)
		if err != nil {
			res.Message = err.Error()
		}
	}

	bytesReceived := len(data)
	res.Measurements[prefix+"bytesReceived"] = bytesReceived

	secondsSinceRequestWasSent := time.Since(wroteRequestAt).Seconds()
	if secondsSinceRequestWasSent > 0 {
		// Measure download speed since the request sent
		res.Measurements[prefix+"downloadPerformance_bps"] = int64(float64(bytesReceived) / secondsSinceRequestWasSent)
	}

	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return res, fmt.Errorf("timeout exceeded")
		}
		return res, nil
	}

	res.Measurements[prefix+"success"] = 1
	return res, nil
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
