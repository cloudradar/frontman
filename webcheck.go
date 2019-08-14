package frontman

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cloudradar-monitoring/frontman/pkg/utils/datacounters"
	"github.com/cloudradar-monitoring/frontman/pkg/utils/gzipreader"
	"github.com/sirupsen/logrus"
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

func defaultHTTPTransport() *http.Transport {
	return &http.Transport{
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
}

func (fm *Frontman) initHTTPTransport() {
	fm.httpTransport = defaultHTTPTransport()

	if fm.Config.IgnoreSSLErrors {
		fm.httpTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true, RootCAs: fm.rootCAs}
	}
}

// transportWithInsecureSSL creates a default http.Transport,
// sets the option to skip verification of insecure TLS.
func transportWithInsecureSSL(rootCAs *x509.CertPool) *http.Transport {
	transport := defaultHTTPTransport()
	transport.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
		RootCAs:            rootCAs,
	}
	return transport
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

	var httpTransport *http.Transport
	if data.IgnoreSSLErrors {
		httpTransport = transportWithInsecureSSL(fm.rootCAs)
	} else {
		httpTransport = fm.httpTransport
	}

	// In case the webcheck disables redirect following we set maxRedirects to 0
	maxRedirects := 0
	if !data.DontFollowRedirects {
		maxRedirects = fm.Config.HTTPCheckMaxRedirects
	}
	httpClient := fm.newClientWithOptions(httpTransport, maxRedirects)

	timeout := fm.Config.HTTPCheckTimeout

	// set individual timeout in case it is less than in this check
	if data.Timeout > 0 && data.Timeout < timeout {
		timeout = data.Timeout
	}

	data.Method = strings.ToUpper(data.Method)

	logrus.Debug("web request w timeout ", timeout)

	ctx, cancel := context.WithTimeout(context.Background(), secToDuration(timeout))
	defer cancel()

	req, err := http.NewRequest(data.Method, data.URL, nil)
	if err != nil {
		return m, err
	}

	startedConnectonAt := time.Now()
	defer func() {
		m[prefix+"totalTimeSpent_s"] = time.Since(startedConnectonAt).Seconds()
	}()

	req.Header.Set("Accept-Encoding", "gzip")
	req.Header.Set("User-Agent", fm.userAgent())

	for key, val := range data.Headers {
		req.Header.Set(key, val)
	}

	if data.Method == "POST" && data.PostData != "" {
		req.Body = ioutil.NopCloser(strings.NewReader(data.PostData))
		// close noop closer to bypass lint warnings
		_ = req.Body.Close()
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}

	wroteRequestAt := time.Now()
	resp, err := httpClient.Do(req.WithContext(ctx))
	if err != nil {
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
