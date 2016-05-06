# README

According to RFC 5415, "the CAPWAP protocol, a standard, interoperable protocol that enables an Access Controller (AC) to manage a collection of Wireless Termination Points (WTPs)". Although the CAPWAP standard is not tied to any particular access technology, in many real-world deployments, WTPs are typically Wi-Fi access points implementing RFC 5416.

The [Travelping](http://travelping.com) smartcapwap fork implements a CAPWAP WTP and AC, compliant with [RFC 5415](https://datatracker.ietf.org/doc/rfc5415/) and [RFC 5416](https://datatracker.ietf.org/doc/rfc5416/).

## STATUS

NOTE: WTP has been ported to libev. AC has not and is therefore broken for the moment.

### WTP Tested and Working Features

* IEEE 802.11b/g/a/n
* WMM/WME (mostly)
* Local MAC
* single radio, single WLAN mode


### Devices Tested

Only cards with cfg80211 netlink API are supported. The following devices
have been tested:

* Atheros AR9280 (Compex WLE200NX)
* Mediatek MT7602E, MT7612E (ZBT WG2626, ALL-WR1200AC_WRT)

### Planned WTP Features

* encryption (WPA2)
* Hybrid-MAC ([RFC-7494](https://tools.ietf.org/html/rfc7494))

## INSTALLATION

### Requirements

NOTE: To run the smartcapwap WTP you must have a wireless card that has a Linux driver based on the Generic IEEE 802.11 Networking Stack (mac80211).
* Linux 4.4 or newer
* automake 1.9 or newer
* autoconf
* libconfig-dev
* libjson0-dev
* libnl-dev
* libev-dev
* libtool
* libxml2-dev
* wolfssl 3.8 or newer


### Build

WolfSSL:

    ./configure --enable-dtls --enable-ipv6 --enable-aesgcm \
                --enable-aesccm --enable-aesni --enable-poly1305 \
                --enable-ecc --enable-ecc25519 --enable-chacha \
                --enable-supportedcurves --enable-dh --enable-psk \
                --disable-des3 --disable-arc4 --prefix=/usr/
    make
    make install

SmartCAPWAP:

    autoreconf -f -i
    ./configure --disable-ac
    make
    make install
