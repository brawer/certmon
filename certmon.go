// SPDX-FileCopyrightText: 2021 Sascha Brawer <sascha@brawer.ch>
// SPDX-License-Identifier: MIT

package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"math/rand"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

type CertMon struct {
	mutex       sync.Mutex
	expirations map[string]time.Time
	ctx         context.Context
}

var certExpirations = prometheus.NewGaugeVec(
	prometheus.GaugeOpts{
		Subsystem: "certmon",
		Name:      "tls_certificate_expiration_timestamp",
		Help:      "TLS certificate expiration dates, in seconds since 1970-01-01 midnight UTC, by domain name.",
	},
	[]string{
		"domain",
	},
)

func NewCertMon(domains []string, ctx context.Context) *CertMon {
	cm := &CertMon{
		expirations: make(map[string]time.Time, len(domains)),
		ctx:         ctx,
	}
	for _, domain := range domains {
		cm.expirations[domain] = time.Time{}
		ticker := time.NewTicker(10 * time.Second)
		go func(dom string) {
			for {
				select {
				case <-cm.ctx.Done():
					return
				case <-ticker.C:
					// Sleep up to 5000 milliseconds, for jitter so we don't create a flood of concurrent connections.
					sleepTime := time.Duration(rand.Intn(5000)) * time.Millisecond
					time.Sleep(sleepTime)
					exp, _ := FindExpirationTime(dom)
					certExpirations.WithLabelValues(dom).Set(float64(exp.Unix()))
					cm.mutex.Lock()
					cm.expirations[dom] = exp
					cm.mutex.Unlock()
				}
			}
		}(domain)
	}
	return cm
}

// Find the earliest expiration time in the TLS certificate chain for host.
func FindExpirationTime(host string) (time.Time, error) {
	conn, err := tls.Dial("tcp", host+":443", nil)
	if err != nil {
		return time.Time{}, err
	}

	if err = conn.VerifyHostname(host); err != nil {
		return time.Time{}, err
	}

	exp := conn.ConnectionState().PeerCertificates[0].NotAfter
	for _, cert := range conn.ConnectionState().PeerCertificates[1:] {
		if cert.NotAfter.Before(exp) {
			exp = cert.NotAfter
		}
	}

	return exp, nil
}

// Serves a web page with the current status of this server.
func (cm *CertMon) HandleStatus(w http.ResponseWriter, r *http.Request) {
	cm.mutex.Lock()
	defer cm.mutex.Unlock()

	domains := make([]string, 0, len(cm.expirations))
	for dom, _ := range cm.expirations {
		domains = append(domains, dom)
	}

	// Sort by expiration date; if equal, use domain name as secondary key.
	sort.Slice(domains, func(i, j int) bool {
		exp_i := cm.expirations[domains[i]]
		exp_j := cm.expirations[domains[j]]
		if exp_i != exp_j {
			return exp_i.Before(exp_j)
		} else {
			return domains[i] < domains[j]
		}
	})

	fmt.Fprintf(w, "%s",
		`<html>
<head>
<link href='https://tools-static.wmflabs.org/fontcdn/css?family=Roboto+Slab:400,700' rel='stylesheet' type='text/css'/>
<style>
* {
  font-family: 'Roboto Slab', serif;
}
h1 {
  color: #0066ff;
  margin-left: 1em;
  margin-top: 1em;
}
p {
  margin-left: 5em;
}
th {
  text-align: left;
}
</style>
</head>
<body><h1>CertMon: Monitoring TLS Certificates</h1>
<p>Every 30 seconds, this job checks the expiration dates of TLS certificates.
It exposes these dates as <a href="/metrics">metrics</a> for monitoring with <a href="https://prometheus.io/">Prometheus</a>.</p>

<p>Source code: <a href="https://github.com/brawer/certmon">https://github.com/brawer/certmon</a></p>

<p><table>
<tr><th>Domain</th><th>Certificate expires</th></tr>
`)
	for _, domain := range domains {
		exp := cm.expirations[domain]
		fmt.Fprintf(w, "<tr><td>%s</td><td>%s</td></tr>\n",
			domain, exp.Format(time.RFC3339))
	}

	fmt.Fprintf(w, "%s", "</table></p></body></html>\n")
}
