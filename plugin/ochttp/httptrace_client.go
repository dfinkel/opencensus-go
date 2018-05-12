// Copyright 2018, OpenCensus Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ochttp

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptrace"

	"go.opencensus.io/trace"
)

// httpTraceAnnotator adds annotations to its span based on the events in the
// net/http/httptrace.ClientTrace struct.
type httpTraceAnnotator struct {
	span *trace.Span
}

func (h *httpTraceAnnotator) GetConn(hostPort string) {
	h.span.Annotatef(nil, "Getting connection for %q", hostPort)
}

func (h *httpTraceAnnotator) GotConn(connInfo httptrace.GotConnInfo) {
	if connInfo.Reused {
		var idleInfo string
		if connInfo.WasIdle {
			idleInfo = fmt.Sprintf(" (connection was idle for %s)", connInfo.IdleTime)

		}
		h.span.Annotatef(nil, "Got connection from pool.%s local: %q, remote: %q", idleInfo,
			connInfo.Conn.LocalAddr(), connInfo.Conn.RemoteAddr())
		return
	}
	h.span.Annotatef(nil, "New connection created. local: %q, remote: %q",
		connInfo.Conn.LocalAddr(), connInfo.Conn.RemoteAddr())

}

func (h *httpTraceAnnotator) GotFirstResponseByte() {
	h.span.Annotate(nil, "Received first byte")
}

func (h *httpTraceAnnotator) Got100Continue() {
	h.span.Annotate(nil, "Received 100 (Continue)")
}

func (h *httpTraceAnnotator) DNSStart(startInfo httptrace.DNSStartInfo) {
	h.span.Annotatef(nil, "Starting DNS lookup for %q", startInfo.Host)
}

func (h *httpTraceAnnotator) DNSDone(doneInfo httptrace.DNSDoneInfo) {
	if doneInfo.Err != nil {
		if len(doneInfo.Addrs) > 0 {
			h.span.Annotatef(nil, "Partial DNS lookup failure (received %d addrs): %s",
				len(doneInfo.Addrs), doneInfo.Err)
			return
		}
		h.span.Annotatef(nil, "DNS lookup failure: %s", doneInfo.Err)
		return
	}
	h.span.Annotatef(nil, "Completed DNS lookup (coalesced %t)", doneInfo.Coalesced)
}

func (h *httpTraceAnnotator) ConnectStart(network, addr string) {
	h.span.Annotatef(nil, "Starting connection over %s to %q", network, addr)
}

func (h *httpTraceAnnotator) ConnectDone(network, addr string, err error) {
	if err != nil {
		h.span.Annotatef(nil, "Unsuccessful connection attempt over %s to %q: %s",
			network, addr, err)
		return
	}
	h.span.Annotatef(nil, "Connected over %s to %q", network, addr)
}
func (h *httpTraceAnnotator) TLSHandshakeStart() {
	h.span.Annotate(nil, "Starting TLS Handshake")
}
func (h *httpTraceAnnotator) TLSHandshakeDone(tlsState tls.ConnectionState, err error) {
	if err != nil {
		h.span.Annotatef(nil, "TLS Handshake Failed: ", err)
		return
	}
	h.span.Annotatef(nil, "Completed TLS Handshake. With ciphersuite %s and protocol %s (resumed: %t)",
		tlsState.CipherSuite, tlsState.NegotiatedProtocol, tlsState.DidResume)
}
func (h *httpTraceAnnotator) WroteHeaders() {
	h.span.Annotate(nil, "Wrote Request Headers")
}
func (h *httpTraceAnnotator) Wait100Continue() {
	h.span.Annotate(nil, "Awaiting response with 100 (Continue)")
}
func (h *httpTraceAnnotator) WroteRequest(w httptrace.WroteRequestInfo) {
	if w.Err != nil {
		h.span.Annotatef(nil, "Failed to write request: %s", w.Err)
		return
	}
	h.span.Annotate(nil, "Wrote Request")
}

// WithHTTPTrace returns a shallow-copied http.Request with a new context that
// has an http.ClientTrace implementation installed.
// If there is no trace span in the context, this method returns req argument.
func WithHTTPTrace(req *http.Request) *http.Request {
	ctx := req.Context()
	span := trace.FromContext(ctx)
	if span == nil {
		return req
	}

	h := &httpTraceAnnotator{span: span}

	clientTrace := httptrace.ClientTrace{
		GetConn: h.GetConn,
		GotConn: h.GotConn,
		// PutIdleConn is likely to happen after request completion.
		PutIdleConn:          nil,
		GotFirstResponseByte: h.GotFirstResponseByte,
		Got100Continue:       h.Got100Continue,
		DNSStart:             h.DNSStart,
		DNSDone:              h.DNSDone,
		ConnectStart:         h.ConnectStart,
		ConnectDone:          h.ConnectDone,
		TLSHandshakeStart:    h.TLSHandshakeStart,
		TLSHandshakeDone:     h.TLSHandshakeDone,
		WroteHeaders:         h.WroteHeaders,
		Wait100Continue:      h.Wait100Continue,
		WroteRequest:         h.WroteRequest,
	}
	return req.WithContext(httptrace.WithClientTrace(ctx, &clientTrace))
}

// HTTPTraceTransport is a transport that exposes
// net/http/httptrace.ClientTrace events as annotations on the trace for an
// HTTP request.
type HTTPTraceTransport struct {
	Base http.RoundTripper
}

// RoundTrip implements the net/http.RoundTripper interface
func (h *HTTPTraceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	return h.Base.RoundTrip(WithHTTPTrace(req))
}
