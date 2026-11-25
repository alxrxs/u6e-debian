#!/bin/sh
# Makes the mutual-TLS test certificates in this directory, the shape of a
# site's AD CS chain: a P-521 root and issuing CA signing with SHA-512, P-384
# leaves for server and client auth. Each <leaf>.pem is the leaf then the
# issuing CA (what a host presents), each key PKCS#8; chain.pem is the CA
# bundle peers are verified against. Run once; the tests only read them.
set -eu
cd "$(dirname "$0")"
days=36500

key() { openssl genpkey -algorithm EC -pkeyopt "ec_paramgen_curve:$1" -out "$2.key"; }

ca() { # name curve subject [issuer]
	key "$2" "$1"
	if [ $# -eq 3 ]; then
		openssl req -x509 -new -key "$1.key" -sha512 -days $days -subj "/CN=$3" \
			-addext basicConstraints=critical,CA:TRUE \
			-addext keyUsage=critical,keyCertSign,cRLSign -out "$1.pem"
	else
		openssl req -new -key "$1.key" -subj "/CN=$3" -out "$1.csr"
		openssl x509 -req -in "$1.csr" -CA "$4.pem" -CAkey "$4.key" -sha512 -days $days \
			-set_serial "0x$(openssl rand -hex 8)" -out "$1.pem" -extfile /dev/stdin <<-EOF
				basicConstraints=critical,CA:TRUE,pathlen:0
				keyUsage=critical,keyCertSign,cRLSign
			EOF
		rm "$1.csr"
	fi
}

leaf() { # name issuer sans
	key P-384 "$1"
	openssl req -new -key "$1.key" -subj "/CN=$1" -out "$1.csr"
	openssl x509 -req -in "$1.csr" -CA "$2.pem" -CAkey "$2.key" -sha512 -days $days \
		-set_serial "0x$(openssl rand -hex 8)" -out "$1.leaf" -extfile /dev/stdin <<-EOF
			basicConstraints=critical,CA:FALSE
			keyUsage=critical,digitalSignature
			extendedKeyUsage=serverAuth,clientAuth
			subjectAltName=$3
		EOF
	cat "$1.leaf" "$2.pem" >"$1.pem"
	rm "$1.leaf" "$1.csr"
}

ca root P-521 "u6e test root CA"
ca issuer P-521 "u6e test issuing CA" root
cat issuer.pem root.pem >chain.pem
# The controller, and its renewal: a new key under the same name.
leaf controller issuer DNS:controller.example.org
leaf controller-renewed issuer DNS:controller.example.org
# A scraper the controller admits, and one it does not.
leaf scraper issuer DNS:status1.example.org
leaf stranger issuer DNS:other.example.org
# Two servers the controller dials, by address or by name.
leaf server1 issuer IP:127.0.0.1,DNS:localhost
leaf server2 issuer IP:127.0.0.2
# Another CA's leaf, naming what the others name.
ca foreign-ca P-384 "u6e test foreign CA"
leaf foreign foreign-ca IP:127.0.0.1,DNS:status1.example.org,DNS:controller.example.org
rm -f root.key issuer.key foreign-ca.key
