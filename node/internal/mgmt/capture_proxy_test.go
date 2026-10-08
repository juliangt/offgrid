package mgmt

// capture_proxy.go (test-only) — a raw TCP recording proxy: it accepts one
// connection at a time, forwards every byte to the real target, and appends
// both directions to the caller's capture buffer. This is what makes the
// §4 passive-capture assertion honest: the bytes recorded are exactly the
// bytes a radio/PHY would carry.

import (
	"net"
	"sync"
	"time"
)

type recordingProxy struct {
	ln net.Listener
	wg sync.WaitGroup
}

func (p *recordingProxy) Addr() net.Addr { return p.ln.Addr() }
func (p *recordingProxy) Close() error   { return p.ln.Close() }

// listenRecordingProxy starts the proxy; every byte flowing in either
// direction is appended to *captured under *mu.
func listenRecordingProxy(captured *[]byte, mu *sync.Mutex, targetAddr string) (*recordingProxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &recordingProxy{ln: ln}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			p.wg.Add(1)
			go func(c net.Conn) {
				defer p.wg.Done()
				p.serveOne(c, captured, mu, targetAddr)
			}(conn)
		}
	}()
	return p, nil
}

func (p *recordingProxy) serveOne(client net.Conn, captured *[]byte, mu *sync.Mutex, targetAddr string) {
	defer client.Close()
	var d net.Dialer
	upstream, err := d.Dial("tcp", targetAddr)
	if err != nil {
		return
	}
	defer upstream.Close()
	var once sync.Once
	pump := func(dst net.Conn, src net.Conn) {
		buf := make([]byte, 16<<10)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				mu.Lock()
				*captured = append(*captured, buf[:n]...)
				mu.Unlock()
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		once.Do(func() {
			_ = client.SetReadDeadline(time.Now().Add(time.Second))
			_ = upstream.SetReadDeadline(time.Now().Add(time.Second))
		})
	}
	done := make(chan struct{}, 2)
	go func() { pump(upstream, client); done <- struct{}{} }()
	go func() { pump(client, upstream); done <- struct{}{} }()
	<-done
	<-done
}
