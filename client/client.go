package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	// "net/http"
	"path/filepath"
)

func handleError(err error) {
	if err != nil {
		log.Fatal("Fatal", err)
	}
}

func main() {
	absPathClientCrt, err := filepath.Abs("../clientCerts/client.crt")
	handleError(err)
	absPathClientKey, err := filepath.Abs("../clientCerts/client.key")
	handleError(err)
	absPathServerCrt, err := filepath.Abs("../serverCerts/server.crt")
	handleError(err)

	cert, err := tls.LoadX509KeyPair(absPathClientCrt, absPathClientKey)
	if err != nil {
		log.Fatalln("Unable to load cert", err)
	}

	roots := x509.NewCertPool()

	// We're going to load the server cert and add all the intermediates and CA from that.
	// Alternatively if we have the CA directly we could call AppendCertificate method
	fakeCA, err := ioutil.ReadFile(absPathServerCrt)
	if err != nil {
		log.Println(err)
		return
	}

	ok := roots.AppendCertsFromPEM([]byte(fakeCA))
	if !ok {
		panic("failed to parse root certificate")
	}

	tlsConf := &tls.Config{
		Certificates:       []tls.Certificate{cert},
		RootCAs:            roots,
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS13,
	}
	// tr := &http.Transport{TLSClientConfig: tlsConf}
	// client := &http.Client{Transport: tr}

	// resp, err := client.Get("https://localhost:8443")
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }

	// fmt.Println(resp.Status)

	// defer resp.Body.Close()
	// body, err := ioutil.ReadAll(resp.Body)
	// if err != nil {
	// 	log.Println(err)
	// 	return
	// }

	// fmt.Println(string(body))
	conn, err := tls.Dial("tcp", "localhost:8443", tlsConf)
	if err != nil {
		log.Fatalf("TLS connection failed: %s", err)
	}

	err2 := conn.Handshake()
	if err2 != nil {
		log.Fatalf("TLS connection failed: %s", err)
	}

	_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: localhost:8443 \r\n\r\n"))
	if err != nil {
		log.Fatalf("failed to write to TLS connection: %s", err)
	}

	// Read response from server
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatalf("failed to read from TLS connection: %s", err)
	}
	fmt.Printf("Server says: %s\n", string(buf[:n]))

	defer conn.Close()
}
