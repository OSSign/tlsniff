# TLSniff
Display certificate information for remote hosts or local files.

## Example
```bash
tls@tls:~$ tlsniff google.com

Reading from host: google.com 443
╭─ Certificate Information
│  ├─ Version: 3
│  ├─ Subject: CN=*.google.com
│  ├─ Serial Number: 61273374499769446057878895876432914017
│  ╰─ Is CA: false
├─ Issuer
│  ├─ Issuer: CN=WE2,O=Google Trust Services,C=US
│  ├─ Issuing Certificate URL: [http://i.pki.goog/we2.crt]
│  ├─ OCSP Server: [http://o.pki.goog/we2]
│  ├─ CRL Distribution Points: [http://c.pki.goog/we2/xuzt3PU9F_w.crl]
│  ╰─ Issuer Certificate
│     ├─ Subject: CN=WE2,O=Google Trust Services,C=US
│     ├─ Issuer: CN=GlobalSign,OU=GlobalSign ECC Root CA - R4,O=GlobalSign
│     ├─ Not Before: 2023-12-13 09:00:00 +0000 UTC
│     ├─ Not After: 2029-02-20 14:00:00 +0000 UTC
│     ├─ Is CA: true
│     ╰─ Issuer Certificate
│        ├─ Subject: CN=GlobalSign,OU=GlobalSign ECC Root CA - R4,O=GlobalSign
│        ├─ Issuer: CN=GlobalSign,OU=GlobalSign ECC Root CA - R4,O=GlobalSign
│        ├─ Not Before: 2012-11-13 00:00:00 +0000 UTC
│        ├─ Not After: 2038-01-19 03:14:07 +0000 UTC
│        ╰─ Is CA: true
├─ Validity
│  ├─ Not Before: 2025-09-22 08:40:47 +0000 UTC
│  ╰─ Not After: 2025-12-15 08:40:46 +0000 UTC
├─ Algorithms
│  ├─ Signature Algorithm: ECDSA-SHA256
│  ╰─ Public Key Algorithm: ECDSA
├─ SANs
│  ├─ DNS Names
│  │  ├─ *.google.com
│  │  ├─ *.appengine.google.com
│  │  ├─ *.bdn.dev
│  │  ├─ *.origin-test.bdn.dev
│  │  ├─ *.cloud.google.com
│  │  ├─ *.crowdsource.google.com
│  │  ├─ *.datacompute.google.com
│  │  ├─ *.google.ca
│  │  ├─ *.google.cl
│  │  ├─ *.google.co.in
│  │  ├─ *.google.co.jp
│  │  ├─ *.google.co.uk
│  │  ├─ *.google.com.ar
│  │  ├─ *.google.com.au
│  │  ├─ *.google.com.br
│  │  ├─ *.google.com.co
│  │  ├─ *.google.com.mx
│  │  ├─ *.google.com.tr
│  │  ├─ *.google.com.vn
│  │  ├─ *.google.de
│  │  ├─ *.google.es
│  │  ├─ *.google.fr
│  │  ├─ *.google.hu
│  │  ├─ *.google.it
│  │  ├─ *.google.nl
│  │  ├─ *.google.pl
│  │  ├─ *.google.pt
│  │  ├─ *.googleapis.cn
│  │  ├─ *.googlevideo.com
│  │  ├─ *.gstatic.cn
│  │  ├─ *.gstatic-cn.com
│  │  ├─ googlecnapps.cn
│  │  ├─ *.googlecnapps.cn
│  │  ├─ googleapps-cn.com
│  │  ├─ *.googleapps-cn.com
│  │  ├─ gkecnapps.cn
│  │  ├─ *.gkecnapps.cn
│  │  ├─ googledownloads.cn
│  │  ├─ *.googledownloads.cn
│  │  ├─ recaptcha.net.cn
│  │  ├─ *.recaptcha.net.cn
│  │  ├─ recaptcha-cn.net
│  │  ├─ *.recaptcha-cn.net
│  │  ├─ widevine.cn
│  │  ├─ *.widevine.cn
│  │  ├─ ampproject.org.cn
│  │  ├─ *.ampproject.org.cn
│  │  ├─ ampproject.net.cn
│  │  ├─ *.ampproject.net.cn
│  │  ├─ google-analytics-cn.com
│  │  ├─ *.google-analytics-cn.com
│  │  ├─ googleadservices-cn.com
│  │  ├─ *.googleadservices-cn.com
│  │  ├─ googlevads-cn.com
│  │  ├─ *.googlevads-cn.com
│  │  ├─ googleapis-cn.com
│  │  ├─ *.googleapis-cn.com
│  │  ├─ googleoptimize-cn.com
│  │  ├─ *.googleoptimize-cn.com
│  │  ├─ doubleclick-cn.net
│  │  ├─ *.doubleclick-cn.net
│  │  ├─ *.fls.doubleclick-cn.net
│  │  ├─ *.g.doubleclick-cn.net
│  │  ├─ doubleclick.cn
│  │  ├─ *.doubleclick.cn
│  │  ├─ *.fls.doubleclick.cn
│  │  ├─ *.g.doubleclick.cn
│  │  ├─ dartsearch-cn.net
│  │  ├─ *.dartsearch-cn.net
│  │  ├─ googletraveladservices-cn.com
│  │  ├─ *.googletraveladservices-cn.com
│  │  ├─ googletagservices-cn.com
│  │  ├─ *.googletagservices-cn.com
│  │  ├─ googletagmanager-cn.com
│  │  ├─ *.googletagmanager-cn.com
│  │  ├─ googlesyndication-cn.com
│  │  ├─ *.googlesyndication-cn.com
│  │  ├─ *.safeframe.googlesyndication-cn.com
│  │  ├─ app-measurement-cn.com
│  │  ├─ *.app-measurement-cn.com
│  │  ├─ gvt1-cn.com
│  │  ├─ *.gvt1-cn.com
│  │  ├─ gvt2-cn.com
│  │  ├─ *.gvt2-cn.com
│  │  ├─ 2mdn-cn.net
│  │  ├─ *.2mdn-cn.net
│  │  ├─ googleflights-cn.net
│  │  ├─ *.googleflights-cn.net
│  │  ├─ admob-cn.com
│  │  ├─ *.admob-cn.com
│  │  ├─ *.gemini.cloud.google.com
│  │  ├─ googlesandbox-cn.com
│  │  ├─ *.googlesandbox-cn.com
│  │  ├─ *.safenup.googlesandbox-cn.com
│  │  ├─ *.gstatic.com
│  │  ├─ *.metric.gstatic.com
│  │  ├─ *.gvt1.com
│  │  ├─ *.gcpcdn.gvt1.com
│  │  ├─ *.gvt2.com
│  │  ├─ *.gcp.gvt2.com
│  │  ├─ *.url.google.com
│  │  ├─ *.youtube-nocookie.com
│  │  ├─ *.ytimg.com
│  │  ├─ ai.android
│  │  ├─ android.com
│  │  ├─ *.android.com
│  │  ├─ *.flash.android.com
│  │  ├─ g.cn
│  │  ├─ *.g.cn
│  │  ├─ g.co
│  │  ├─ *.g.co
│  │  ├─ goo.gl
│  │  ├─ www.goo.gl
│  │  ├─ google-analytics.com
│  │  ├─ *.google-analytics.com
│  │  ├─ google.com
│  │  ├─ googlecommerce.com
│  │  ├─ *.googlecommerce.com
│  │  ├─ ggpht.cn
│  │  ├─ *.ggpht.cn
│  │  ├─ urchin.com
│  │  ├─ *.urchin.com
│  │  ├─ youtu.be
│  │  ├─ youtube.com
│  │  ├─ *.youtube.com
│  │  ├─ music.youtube.com
│  │  ├─ *.music.youtube.com
│  │  ├─ youtubeeducation.com
│  │  ├─ *.youtubeeducation.com
│  │  ├─ youtubekids.com
│  │  ├─ *.youtubekids.com
│  │  ├─ yt.be
│  │  ├─ *.yt.be
│  │  ├─ android.clients.google.com
│  │  ├─ *.android.google.cn
│  │  ├─ *.chrome.google.cn
│  │  ├─ *.developers.google.cn
│  │  ╰─ *.aistudio.google.com
│  ├─ Email Addresses
│  ├─ IP Addresses
│  ╰─ URIs
╰─ Other Extensions
   ├─ Permitted DNS Domains: []
   ╰─ Policy Identifiers: [2.23.140.1.2.1]
```
