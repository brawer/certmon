// SPDX-FileCopyrightText: 2021 Sascha Brawer <sascha@brawer.ch>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"flag"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	var portFlag = flag.Int("port", 0, "port for serving HTTP requests")
	var domainsFlag = flag.String("hosts", "codesearch.wmcloud.org,query.wikidata.org,toolforge.org,wmcloud.org", "comma-separated list of internet domains whose TLS certificate expiration dates we monitor")
	flag.Parse()

	port := *portFlag
	if port == 0 {
		port, _ = strconv.Atoi(os.Getenv("PORT"))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	certmon := NewCertMon(strings.Split(*domainsFlag, ","), ctx)
	prometheus.MustRegister(certExpirations)
	http.HandleFunc("/", certmon.HandleStatus)
	http.Handle("/metrics", promhttp.Handler())
	http.ListenAndServe(":"+strconv.Itoa(port), nil)
}
