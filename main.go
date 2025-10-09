package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/url"
	"os"
	"strings"

	"github.com/clysec/greq"
	"github.com/spf13/cobra"
	"go.mozilla.org/pkcs7"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/jedib0t/go-pretty/v6/list"
)

var rootCmd = &cobra.Command{
	Use:   "certinfo --[path or url] [path or url]",
	Short: "Get information about a certificate from an URL, file path or stdin",
	Example: `certinfo --url https://example.com
certinfo example.com
certinfo --host example.com:443
certinfo --path /path/to/cert.pem
cat /path/to/cert.pem | certinfo -`,
	Args: cobra.ExactArgs(1),
	Run:  Run,
}

func init() {
	rootCmd.PersistentFlags().BoolP("host", "H", true, "Specify that the argument is a hostname (with optional port) (default)")
	rootCmd.PersistentFlags().BoolP("path", "p", false, "Specify that the argument is a file path")

	rootCmd.PersistentFlags().StringP("pass", "P", "", "Password for decrypting PKCS#12 or encrypted PEM files")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %v", err)
	}
}

func Run(cmd *cobra.Command, args []string) {
	item := args[0]

	var cert *x509.Certificate

	if item == "-" {
		log.Println("Reading from stdin")
		by, err := io.ReadAll(os.Stdin)
		if err != nil {
			log.Fatalf("Error reading from stdin: %v", err)
		}

		pw, _ := cmd.Flags().GetString("pass")
		cert = ParseFile(by, pw)
	} else {
		isPath, _ := cmd.Flags().GetBool("path")
		if isPath {
			log.Println("Reading from path:", item)

			content, err := os.ReadFile(item)
			if err == nil {
				pw, _ := cmd.Flags().GetString("pass")
				cert = ParseFile(content, pw)
			}
		}
	}

	if cert == nil {
		parsed, err := url.Parse(item)
		if err == nil {
			fmt.Println(parsed.Hostname())
			if parsed.Hostname() == "" {
				parsed.Host = parsed.Path
				parsed.Path = ""
			}
			fmt.Println(parsed.Port())

			if parsed.Port() == "" && !strings.Contains(parsed.Host, ":") {
				parsed.Host = parsed.Host + ":443"
			}

			if parsed.Hostname() == "" {
				fmt.Println("Reading from host:", item)
				split := strings.Split(item, ":")
				if len(split) == 0 {
					log.Fatalf("Invalid host format")
				}

				if len(split) == 1 {
					split = append(split, "443")
				}

				cert = ReadHost(split[0], split[1])
			} else {
				fmt.Println("Reading from host:", parsed.Hostname(), parsed.Port())
				cert = ReadHost(parsed.Hostname(), parsed.Port())
			}
		}
	}

	if cert == nil {
		log.Fatalf("Could not determine if input is a path or URL. Please specify --path or --url.")
	}

	PrintCert(cert)
}

func ParseFile(content []byte, pw string) *x509.Certificate {
	block, _ := pem.Decode(content)
	if block != nil {
		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil {
				return cert
			}

			pkcert, err := pkcs7.Parse(block.Bytes)
			if err == nil && len(pkcert.Certificates) > 0 {
				return pkcert.Certificates[0]
			}

			_, pfxcert, _, err := pkcs12.DecodeChain(block.Bytes, pw)
			if err == nil {
				return pfxcert
			}

			log.Fatalf("Failed to parse certificate: %v", err)
		}

		log.Fatalf("Unsupported PEM block type: %s", block.Type)
	}

	x5cert, err := x509.ParseCertificate(content)
	if err == nil {
		return x5cert
	}

	pkcert, err := pkcs7.Parse(content)
	if err == nil && len(pkcert.Certificates) > 0 {
		return pkcert.Certificates[0]
	}

	_, pfxcert, _, err := pkcs12.DecodeChain(content, pw)
	if err == nil {
		return pfxcert
	}

	b64dec := []byte{}
	_, err = base64.StdEncoding.Decode(b64dec, content)
	if err == nil {
		return ParseFile(b64dec, pw)
	}

	log.Fatalf("Failed to parse certificate: %v", err)
	return nil
}

func ReadHost(hostname, port string) *x509.Certificate {
	conf := &tls.Config{
		InsecureSkipVerify: true,
	}

	conn, err := tls.Dial("tcp", hostname+":"+port, conf)
	if err != nil {
		log.Fatalf("Error connecting to %s:%s - %v", hostname, port, err)
		return nil
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) > 0 {
		return certs[0]
	}

	log.Println("No certificates found")
	return nil
}

func PrintCert(cert *x509.Certificate) {
	l := list.NewWriter()
	l.SetStyle(list.StyleConnectedRounded)

	l.AppendItem("Certificate Information")
	l.Indent()
	l.AppendItem(fmt.Sprintf("Version: %d", cert.Version))
	l.AppendItem("Subject: " + cert.Subject.String())
	l.AppendItem("Serial Number: " + cert.SerialNumber.String())
	l.AppendItem(fmt.Sprintf("Is CA: %t", cert.IsCA))
	l.UnIndent()

	l.AppendItem("Issuer")
	l.Indent()
	l.AppendItem("Issuer: " + cert.Issuer.String())
	l.AppendItem(fmt.Sprintf("Issuing Certificate URL: %v", cert.IssuingCertificateURL))
	l.AppendItem(fmt.Sprintf("OCSP Server: %v", cert.OCSPServer))
	l.AppendItem(fmt.Sprintf("CRL Distribution Points: %v", cert.CRLDistributionPoints))
	if len(cert.IssuingCertificateURL) > 0 {
		PrintNextIssuer(cert.IssuingCertificateURL[0], l)
	}
	l.UnIndent()

	l.AppendItem("Validity")
	l.Indent()
	l.AppendItem("Not Before: " + cert.NotBefore.String())
	l.AppendItem("Not After: " + cert.NotAfter.String())
	l.UnIndent()

	l.AppendItem("Algorithms")
	l.Indent()
	l.AppendItem("Signature Algorithm: " + cert.SignatureAlgorithm.String())
	l.AppendItem("Public Key Algorithm: " + cert.PublicKeyAlgorithm.String())
	l.UnIndent()

	l.AppendItem("SANs")
	l.Indent()

	l.AppendItem("DNS Names")
	l.Indent()
	for _, name := range cert.DNSNames {
		l.AppendItem(name)
	}
	l.UnIndent()

	l.AppendItem("Email Addresses")
	l.Indent()
	for _, email := range cert.EmailAddresses {
		l.AppendItem(email)
	}
	l.UnIndent()

	l.AppendItem("IP Addresses")
	l.Indent()
	for _, ip := range cert.IPAddresses {
		l.AppendItem(ip.String())
	}
	l.UnIndent()

	l.AppendItem("URIs")
	l.Indent()
	for _, uri := range cert.URIs {
		l.AppendItem(uri.String())
	}
	l.UnIndent()

	l.UnIndent()

	l.AppendItem("Other Extensions")
	l.Indent()
	l.AppendItem(fmt.Sprintf("Permitted DNS Domains: %v", cert.PermittedDNSDomains))
	l.AppendItem(fmt.Sprintf("Policy Identifiers: %v", cert.PolicyIdentifiers))
	l.UnIndent()

	fmt.Println(l.Render())
}

func PrintNextIssuer(url string, writer list.Writer) {
	if url == "" {
		return
	}

	content, err := greq.GetRequest(url).Execute()
	if err != nil {
		log.Printf("Failed to fetch issuer certificate from %s: %v", url, err)
		return
	}

	if content.StatusCode > 299 {
		log.Printf("Failed to fetch issuer certificate from %s: HTTP %d", url, content.StatusCode)
		return
	}

	contentBytes, err := content.BodyBytes()
	if err != nil {
		log.Printf("Failed to read body from %s: %v", url, err)
		return
	}

	issuerCert := ParseFile(contentBytes, "")
	if issuerCert == nil {
		log.Printf("Failed to parse issuer certificate from %s", url)
		return
	}

	writer.AppendItem("Issuer Certificate")
	writer.Indent()
	writer.AppendItem("Subject: " + issuerCert.Subject.String())
	writer.AppendItem("Issuer: " + issuerCert.Issuer.String())
	writer.AppendItem("Not Before: " + issuerCert.NotBefore.String())
	writer.AppendItem("Not After: " + issuerCert.NotAfter.String())
	writer.AppendItem(fmt.Sprintf("Is CA: %t", issuerCert.IsCA))
	if len(issuerCert.IssuingCertificateURL) > 0 {
		PrintNextIssuer(issuerCert.IssuingCertificateURL[0], writer)
	}

	writer.UnIndent()
}
