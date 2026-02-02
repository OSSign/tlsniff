# TLSniff
Display certificate information for remote hosts or local files.

## Usage
```bash
Get information about a certificate from an URL, file path or stdin

Usage:
  tlsniff --[path or url] [path or url] [flags]

Examples:
tlsniff --url https://example.com
tlsniff example.com
tlsniff --host example.com:443
tlsniff --path /path/to/cert.pem
cat /path/to/cert.pem | tlsniff -

Flags:
  -c, --chain         Print the full chain of trust (if available) instead of just the names
  -h, --help          help for tlsniff
  -H, --host          Specify that the argument is a hostname (with optional port) (default) (default true)
  -P, --pass string   Password for decrypting PKCS#12 or encrypted PEM files
  -p, --path          Specify that the argument is a file path
```

## Examples
### Microsoft (Basic Chain)
```bash
tls@tls:~$ tlsniff microsoft.com

Reading from host: microsoft.com 443
╭─ Certificate Information
│  ├─ Version: 3
│  ├─ Subject: CN=microsoft.com,O=Microsoft Corporation,L=Redmond,ST=WA,C=US
│  ├─ Serial Number: 1137545254554039778717926461496486019823897892
│  ╰─ Is CA: false
├─ Validity
│  ├─ Currently Valid
│  ├─ Not Before: 2025-10-01 05:17:14 +0000 UTC
│  ╰─ Not After: 2026-03-30 05:17:14 +0000 UTC
├─ Algorithms
│  ├─ Signature Algorithm: SHA384-RSA
│  ╰─ Public Key Algorithm: RSA
├─ SANs
│  ╰─ DNS Names
│     ├─ microsoft.com, s.microsoft.com, ga.microsoft.com, aep.microsoft.com, aer.microsoft.com, grv.microsoft.com, hup.microsoft.com, mac.microsoft.com
│     ├─ mkb.microsoft.com, pme.microsoft.com, pmi.microsoft.com, rss.microsoft.com, sar.microsoft.com, tco.microsoft.com, fuse.microsoft.com, ieak.microsoft.com
│     ├─ mac2.microsoft.com, mcsp.microsoft.com, open.microsoft.com, shop.microsoft.com, spur.microsoft.com, itpro.microsoft.com, mango.microsoft.com
│     ├─ music.microsoft.com, pymes.microsoft.com, store.microsoft.com, aether.microsoft.com, alerts.microsoft.com, design.microsoft.com, garage.microsoft.com
│     ├─ gigjam.microsoft.com, msctec.microsoft.com, online.microsoft.com, stream.microsoft.com, afflink.microsoft.com, connect.microsoft.com
│     ├─ develop.microsoft.com, domains.microsoft.com, example.microsoft.com, madeira.microsoft.com, msdnisv.microsoft.com, mspress.microsoft.com
│     ├─ www.aep.microsoft.com, www.aer.microsoft.com, wwwbeta.microsoft.com, business.microsoft.com, empresas.microsoft.com, learning.microsoft.com
│     ├─ msdnwiki.microsoft.com, openness.microsoft.com, pinpoint.microsoft.com, snackbox.microsoft.com, sponsors.microsoft.com, stationq.microsoft.com
│     ├─ aistories.microsoft.com, community.microsoft.com, crawlmsdn.microsoft.com, iotschool.microsoft.com, messenger.microsoft.com, minecraft.microsoft.com
│     ├─ backoffice.microsoft.com, enterprise.microsoft.com, iotcentral.microsoft.com, pinunblock.microsoft.com, reroute443.microsoft.com
│     ├─ communities.microsoft.com, explore-smb.microsoft.com, expressions.microsoft.com, ondernemers.microsoft.com, techacademy.microsoft.com
│     ├─ terraserver.microsoft.com, communities2.microsoft.com, connectevent.microsoft.com, dataplatform.microsoft.com, entrepreneur.microsoft.com
│     ├─ hxd.research.microsoft.com, mspartnerira.microsoft.com, mydatahealth.microsoft.com, oemcommunity.microsoft.com, real-stories.microsoft.com
│     ├─ www.formspro.microsoft.com, futuredecoded.microsoft.com, upgradecenter.microsoft.com, learnanalytics.microsoft.com, onlinelearning.microsoft.com
│     ├─ businesscentral.microsoft.com, cloud-immersion.microsoft.com, studentpartners.microsoft.com, analyticspartner.microsoft.com
│     ├─ businessplatform.microsoft.com, explore-security.microsoft.com, kleinunternehmen.microsoft.com, partnercommunity.microsoft.com
│     ├─ explore-marketing.microsoft.com, innovationcontest.microsoft.com, partnerincentives.microsoft.com, phoenixcataloguat.microsoft.com
│     ├─ szkolyprzyszlosci.microsoft.com, www.powerautomate.microsoft.com, successionplanning.microsoft.com, lumiaconversationsuk.microsoft.com
│     ├─ successionplanninguat.microsoft.com, businessmobilitycenter.microsoft.com, skypeandteams.fasttrack.microsoft.com
│     ├─ www.microsoftdlapartnerow.microsoft.com, commercialappcertification.microsoft.com, www.skypeandteams.fasttrack.microsoft.com
│     ├─ ceoconnections.event.microsoft.com, biz4afrika.microsoft.com, cashback.microsoft.com, www.cashback.microsoft.com, visio.microsoft.com
│     ├─ insidemsr.microsoft.com, developervelocityassessment.com, www.developervelocityassessment.com, gears5.com, www.gears5.com, www.gearstactics.com
│     ├─ gearstactics.com, m12.microsoft.com, seeingai.com, yourchoice.microsoft.com, mvtd.events.microsoft.com, imagine.microsoft.com, microsoft.com.au
│     ├─ www.microsoft.com.au, dynamics.microsoft.com, powerplatform.microsoft.com, powerapps.microsoft.com, powerautomate.microsoft.com
│     ├─ powervirtualagents.microsoft.com, powerpages.microsoft.com, test.ideas.fabric.microsoft.com, sds.microsoft.com, ppe.sds.microsoft.com
│     ├─ www.microsoft365copilot.com, www.jclarity.com, techinnovatorsspotlight.com, www.techinnovatorsspotlight.com, copilot.ai, getlicensingready.com
│     ├─ www.getlicensingready.com, jpn.delve.office.com, aus.delve.office.com, ind.delve.office.com, kor.delve.office.com, cobra.me.microsoft.com
│     ├─ www.businesscentral.com, businesscentral.com, msaidatastudio.officeppe.net, ideas.fabric.microsoft.com, www.cpt.link, cpt.link, yarp.dot.net
│     ╰─ microsoftstream.com, www.microsoftstream.com, web.microsoftstream.com, discover.copilot.ai, copilot.com, www.copilot.com, discover.copilot.com
├─ Misc
│  ├─ CRL Distribution Points
│  │  ╰─ http://www.microsoft.com/pkiops/crl/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2008.crl
│  ├─ OCSP Servers
│  │  ╰─ http://oneocsp.microsoft.com/ocsp
│  ╰─ Policy Identifiers
│     ├─ 1.3.6.1.4.1.311.76.509.1.1
│     ╰─ 2.23.140.1.2.2
╰─ Issuer
   ├─ Issuer: CN=Microsoft Azure RSA TLS Issuing CA 08,O=Microsoft Corporation,C=US
   ├─ Issuing Certificate URL: [http://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2008%20-%20xsign.crt]
   ├─ To fetch the full chain, use the --chain flag
   ╰─ Issuer Certificate
      ├─ Trusted by system root CAs
      ├─ Subject: CN=Microsoft Azure RSA TLS Issuing CA 08,O=Microsoft Corporation,C=US
      ╰─ Issuer Certificate
         ├─ Trusted by system root CAs
         ├─ Subject: CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US
         ╰─ Trusted Root CA
```

### Microsoft (Full Chain)
```bash
tls@tls:~$ tlsniff microsoft.com --chain


Reading from host: microsoft.com 443
╭─ Certificate Information
│  ├─ Version: 3
│  ├─ Subject: CN=microsoft.com,O=Microsoft Corporation,L=Redmond,ST=WA,C=US
│  ├─ Serial Number: 1137545254554039778717926461496486019823897892
│  ╰─ Is CA: false
├─ Validity
│  ├─ Currently Valid
│  ├─ Not Before: 2025-10-01 05:17:14 +0000 UTC
│  ╰─ Not After: 2026-03-30 05:17:14 +0000 UTC
├─ Algorithms
│  ├─ Signature Algorithm: SHA384-RSA
│  ╰─ Public Key Algorithm: RSA
├─ SANs
│  ╰─ DNS Names
│     ├─ microsoft.com, s.microsoft.com, ga.microsoft.com, aep.microsoft.com, aer.microsoft.com, grv.microsoft.com, hup.microsoft.com, mac.microsoft.com
│     ├─ mkb.microsoft.com, pme.microsoft.com, pmi.microsoft.com, rss.microsoft.com, sar.microsoft.com, tco.microsoft.com, fuse.microsoft.com, ieak.microsoft.com
│     ├─ mac2.microsoft.com, mcsp.microsoft.com, open.microsoft.com, shop.microsoft.com, spur.microsoft.com, itpro.microsoft.com, mango.microsoft.com
│     ├─ music.microsoft.com, pymes.microsoft.com, store.microsoft.com, aether.microsoft.com, alerts.microsoft.com, design.microsoft.com, garage.microsoft.com
│     ├─ gigjam.microsoft.com, msctec.microsoft.com, online.microsoft.com, stream.microsoft.com, afflink.microsoft.com, connect.microsoft.com
│     ├─ develop.microsoft.com, domains.microsoft.com, example.microsoft.com, madeira.microsoft.com, msdnisv.microsoft.com, mspress.microsoft.com
│     ├─ www.aep.microsoft.com, www.aer.microsoft.com, wwwbeta.microsoft.com, business.microsoft.com, empresas.microsoft.com, learning.microsoft.com
│     ├─ msdnwiki.microsoft.com, openness.microsoft.com, pinpoint.microsoft.com, snackbox.microsoft.com, sponsors.microsoft.com, stationq.microsoft.com
│     ├─ aistories.microsoft.com, community.microsoft.com, crawlmsdn.microsoft.com, iotschool.microsoft.com, messenger.microsoft.com, minecraft.microsoft.com
│     ├─ backoffice.microsoft.com, enterprise.microsoft.com, iotcentral.microsoft.com, pinunblock.microsoft.com, reroute443.microsoft.com
│     ├─ communities.microsoft.com, explore-smb.microsoft.com, expressions.microsoft.com, ondernemers.microsoft.com, techacademy.microsoft.com
│     ├─ terraserver.microsoft.com, communities2.microsoft.com, connectevent.microsoft.com, dataplatform.microsoft.com, entrepreneur.microsoft.com
│     ├─ hxd.research.microsoft.com, mspartnerira.microsoft.com, mydatahealth.microsoft.com, oemcommunity.microsoft.com, real-stories.microsoft.com
│     ├─ www.formspro.microsoft.com, futuredecoded.microsoft.com, upgradecenter.microsoft.com, learnanalytics.microsoft.com, onlinelearning.microsoft.com
│     ├─ businesscentral.microsoft.com, cloud-immersion.microsoft.com, studentpartners.microsoft.com, analyticspartner.microsoft.com
│     ├─ businessplatform.microsoft.com, explore-security.microsoft.com, kleinunternehmen.microsoft.com, partnercommunity.microsoft.com
│     ├─ explore-marketing.microsoft.com, innovationcontest.microsoft.com, partnerincentives.microsoft.com, phoenixcataloguat.microsoft.com
│     ├─ szkolyprzyszlosci.microsoft.com, www.powerautomate.microsoft.com, successionplanning.microsoft.com, lumiaconversationsuk.microsoft.com
│     ├─ successionplanninguat.microsoft.com, businessmobilitycenter.microsoft.com, skypeandteams.fasttrack.microsoft.com
│     ├─ www.microsoftdlapartnerow.microsoft.com, commercialappcertification.microsoft.com, www.skypeandteams.fasttrack.microsoft.com
│     ├─ ceoconnections.event.microsoft.com, biz4afrika.microsoft.com, cashback.microsoft.com, www.cashback.microsoft.com, visio.microsoft.com
│     ├─ insidemsr.microsoft.com, developervelocityassessment.com, www.developervelocityassessment.com, gears5.com, www.gears5.com, www.gearstactics.com
│     ├─ gearstactics.com, m12.microsoft.com, seeingai.com, yourchoice.microsoft.com, mvtd.events.microsoft.com, imagine.microsoft.com, microsoft.com.au
│     ├─ www.microsoft.com.au, dynamics.microsoft.com, powerplatform.microsoft.com, powerapps.microsoft.com, powerautomate.microsoft.com
│     ├─ powervirtualagents.microsoft.com, powerpages.microsoft.com, test.ideas.fabric.microsoft.com, sds.microsoft.com, ppe.sds.microsoft.com
│     ├─ www.microsoft365copilot.com, www.jclarity.com, techinnovatorsspotlight.com, www.techinnovatorsspotlight.com, copilot.ai, getlicensingready.com
│     ├─ www.getlicensingready.com, jpn.delve.office.com, aus.delve.office.com, ind.delve.office.com, kor.delve.office.com, cobra.me.microsoft.com
│     ├─ www.businesscentral.com, businesscentral.com, msaidatastudio.officeppe.net, ideas.fabric.microsoft.com, www.cpt.link, cpt.link, yarp.dot.net
│     ╰─ microsoftstream.com, www.microsoftstream.com, web.microsoftstream.com, discover.copilot.ai, copilot.com, www.copilot.com, discover.copilot.com
├─ Misc
│  ├─ CRL Distribution Points
│  │  ╰─ http://www.microsoft.com/pkiops/crl/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2008.crl
│  ├─ OCSP Servers
│  │  ╰─ http://oneocsp.microsoft.com/ocsp
│  ╰─ Policy Identifiers
│     ├─ 1.3.6.1.4.1.311.76.509.1.1
│     ╰─ 2.23.140.1.2.2
╰─ Issuer
   ├─ Issuer: CN=Microsoft Azure RSA TLS Issuing CA 08,O=Microsoft Corporation,C=US
   ├─ Issuing Certificate URL: [http://www.microsoft.com/pkiops/certs/Microsoft%20Azure%20RSA%20TLS%20Issuing%20CA%2008%20-%20xsign.crt]
   ╰─ Issuer Certificate
      ├─ Certificate Information
      │  ├─ Trusted by system root CAs
      │  ├─ Version: 3
      │  ├─ Subject: CN=Microsoft Azure RSA TLS Issuing CA 08,O=Microsoft Corporation,C=US
      │  ├─ Serial Number: 19915020730521552240994289177714326432
      │  ╰─ Is CA: true
      ├─ Validity
      │  ├─ Currently Valid
      │  ├─ Not Before: 2023-06-08 00:00:00 +0000 UTC
      │  ╰─ Not After: 2026-08-25 23:59:59 +0000 UTC
      ├─ Algorithms
      │  ├─ Signature Algorithm: SHA384-RSA
      │  ╰─ Public Key Algorithm: RSA
      ├─ SANs
      │  ╰─ No Subject Alternate Names present
      ├─ Misc
      │  ├─ CRL Distribution Points
      │  │  ╰─ http://crl3.digicert.com/DigiCertGlobalRootG2.crl
      │  ├─ OCSP Servers
      │  │  ╰─ http://ocsp.digicert.com
      │  ╰─ Policy Identifiers
      │     ├─ 2.23.140.1.2.1
      │     ╰─ 2.23.140.1.2.2
      ╰─ Issuer
         ├─ Issuer: CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US
         ├─ Issuing Certificate URL: [http://cacerts.digicert.com/DigiCertGlobalRootG2.crt]
         ╰─ Issuer Certificate
            ├─ Certificate Information
            │  ├─ Trusted by system root CAs
            │  ├─ Version: 3
            │  ├─ Subject: CN=DigiCert Global Root G2,OU=www.digicert.com,O=DigiCert Inc,C=US
            │  ├─ Serial Number: 4293743540046975378534879503202253541
            │  ╰─ Is CA: true
            ├─ Validity
            │  ├─ Currently Valid
            │  ├─ Not Before: 2013-08-01 12:00:00 +0000 UTC
            │  ╰─ Not After: 2038-01-15 12:00:00 +0000 UTC
            ├─ Algorithms
            │  ├─ Signature Algorithm: SHA256-RSA
            │  ╰─ Public Key Algorithm: RSA
            ├─ SANs
            │  ╰─ No Subject Alternate Names present
            ╰─ Misc
               ╰─ Trusted Root CA