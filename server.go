package main

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/caddyserver/certmagic"
)

func fallback(w http.ResponseWriter, r *http.Request, reason string) {
	location := os.Getenv("FALLBACK_URL")
	if location == "" {
		location = "http://redirect.name/"
	}
	if reason != "" {
		location = fmt.Sprintf("%s#reason=%s", location, url.QueryEscape(reason))
	}
	http.Redirect(w, r, location, 302)
}

func getRedirect(txt []string, url string) (*Redirect, error) {
	var catchAlls []*Config
	for _, record := range txt {
		config := Parse(record)
		if config.From == "" {
			catchAlls = append(catchAlls, config)
			continue
		}
		redirect := Translate(url, config)
		if redirect != nil {
			return redirect, nil
		}
	}

	var config *Config
	for _, config = range catchAlls {
		redirect := Translate(url, config)
		if redirect != nil {
			return redirect, nil
		}
	}

	return nil, errors.New("No paths matched")
}

func handler(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(r.Host, ":")
	host := parts[0]

	hostname := fmt.Sprintf("_redirect.%s", host)
	txt, err := net.LookupTXT(hostname)
	if err != nil {
		fallback(w, r, fmt.Sprintf("Could not resolve hostname (%v)", err))
		return
	}

	redirect, err := getRedirect(txt, r.URL.String())
	if err != nil {
		fallback(w, r, err.Error())
	} else {
		http.Redirect(w, r, redirect.Location, redirect.Status)
	}
}

func getCacheDir() string {
	// set by systemd
	cacheDir := os.Getenv("CACHE_DIRECTORY")
	if cacheDir == "" {
		cacheDir = os.Getenv("STATE_DIRECTORY")
	}
	if cacheDir == "" {
		cacheDir = os.Getenv("XDG_CACHE_HOME")
	}
	if cacheDir == "" {
		cacheDir = os.Getenv("XDG_STATE_HOME")
	}
	if cacheDir == "" {
		cacheDir = "/var/cache/redirectname"
	}
	// test if cacheDir exists
	if _, err := os.Stat(cacheDir); os.IsNotExist(err) {
		err = os.MkdirAll(cacheDir, 0700)
		if err != nil {
			log.Fatalf("Could not create cache directory: %v", err)
		}
	}
	log.Printf("Using cache directory: %s", cacheDir)
	return cacheDir
}

func main() {
	cmCfg := certmagic.NewDefault()
	cacheDir := getCacheDir()
	cmCfg.Storage = &certmagic.FileStorage{
		Path: cacheDir,
	}
	cmCfg.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: PreCheck,
	}
	acmeCfg := certmagic.NewACMEIssuer(
		cmCfg,
		certmagic.DefaultACME,
	)
	acmeCfg.Agreed = true
	acmeCfg.CA = certmagic.LetsEncryptProductionCA
	h := http.HandlerFunc(handler)

	// Start HTTP server
	httpSrv := &http.Server{
		Handler:      acmeCfg.HTTPChallengeHandler(h),
		Addr:         ":80",
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	}
	go func() {
		log.Printf("Listening on http://0.0.0.0")
		log.Fatal(httpSrv.ListenAndServe())
	}()

	// Start HTTPS server
	tlsCfg := cmCfg.TLSConfig()
	tlsCfg.NextProtos = append(
		[]string{"h2", "http/1.1"},
		tlsCfg.NextProtos...,
	)
	httpsSrv := &http.Server{
		Handler:   h,
		Addr:      ":443",
		TLSConfig: tlsCfg,
		// slower because we might need to get a cert
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
	}
	log.Printf("Listening on https://0.0.0.0")
	log.Fatal(httpsSrv.ListenAndServeTLS("", ""))
}
