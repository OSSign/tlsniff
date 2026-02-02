//go:build !js && !wasm && !wasip1

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
	"time"

	"github.com/clysec/greq"
	"github.com/spf13/cobra"
	"go.mozilla.org/pkcs7"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/jedib0t/go-pretty/v6/list"
	"github.com/jedib0t/go-pretty/v6/text"
)

var rootCmd = &cobra.Command{
	Use:   "tlsniff --[path or url] [path or url]",
	Short: "Get information about a certificate from an URL, file path or stdin",
	Example: `tlsniff --url https://example.com
tlsniff example.com
tlsniff --host example.com:443
tlsniff --path /path/to/cert.pem
cat /path/to/cert.pem | tlsniff -`,
	Run: Run,
}

func init() {
	rootCmd.PersistentFlags().BoolP("host", "H", true, "Specify that the argument is a hostname (with optional port) (default)")
	rootCmd.PersistentFlags().BoolP("path", "p", false, "Specify that the argument is a file path")
	rootCmd.PersistentFlags().BoolP("chain", "c", false, "Print the full chain of trust (if available)")

	rootCmd.PersistentFlags().StringP("pass", "P", "", "Password for decrypting PKCS#12 or encrypted PEM files")
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %v", err)
	}
}

func Run(cmd *cobra.Command, args []string) {
	cargs := args
	if len(cargs) == 0 {
		cargs = append(cargs, "-")
	}

	for _, item := range cargs {
		log.Println("-------------------------------------------------")
		log.Println("Processing item:", item)
		var certs []*x509.Certificate

		if item == "-" {
			os.Stderr.WriteString("Waiting to read from stdin...\n")
			by, err := io.ReadAll(os.Stdin)
			if err != nil {
				log.Fatalf("Error reading from stdin: %v", err)
			}

			pw, _ := cmd.Flags().GetString("pass")
			certs = ParseFile(by, pw)
		} else {
			isPath, _ := cmd.Flags().GetBool("path")
			if isPath {
				log.Println("Reading from path:", item)

				content, err := os.ReadFile(item)
				if err == nil {
					pw, _ := cmd.Flags().GetString("pass")
					certs = ParseFile(content, pw)
				}
			} else {
				isActualPath, err := os.Stat(item)
				if err == nil && !isActualPath.IsDir() {
					log.Println("Reading from path:", item)

					content, err := os.ReadFile(item)
					if err == nil {
						pw, _ := cmd.Flags().GetString("pass")
						certs = ParseFile(content, pw)
					}
				}
			}
		}

		if len(certs) == 0 {
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

					certs = []*x509.Certificate{ReadHost(split[0], split[1])}
				} else {
					fmt.Println("Reading from host:", parsed.Hostname(), parsed.Port())
					certs = []*x509.Certificate{ReadHost(parsed.Hostname(), parsed.Port())}
				}
			}
		}

		if len(certs) == 0 {
			log.Fatalf("Could not determine if input is a path or URwriter. Please specify --path or --urwriter.")
		}

		writer := list.NewWriter()
		writer.SetStyle(list.StyleConnectedRounded)

		chainFlag, err := cmd.Flags().GetBool("chain")
		if err != nil {
			chainFlag = false
		}

		for _, cert := range certs {
			PrintCert(cert, writer, chainFlag, true)
			writer.AppendItem("-------------------------------------------------")
		}

		fmt.Println(writer.Render())
	}
}

func ParseFile(content []byte, pw string) []*x509.Certificate {
	block, rest := pem.Decode(content)
	out := []*x509.Certificate{}

	if block != nil {
		blocks := []*pem.Block{block}
		for len(rest) > 0 {
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			blocks = append(blocks, block)
		}

		for _, block := range blocks {
			if block.Type == "CERTIFICATE" {
				errs := []error{}
				cert, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					out = append(out, cert)
					continue
				}
				errs = append(errs, err)

				pkcert, err := pkcs7.Parse(block.Bytes)
				if err == nil && len(pkcert.Certificates) > 0 {
					out = append(out, pkcert.Certificates...)
					continue
				}

				errs = append(errs, err)

				_, pfxcert, _, err := pkcs12.DecodeChain(block.Bytes, pw)
				if err == nil {
					out = append(out, pfxcert)
					continue
				}

				errs = append(errs, err)

				log.Printf("Err: Failed to parse certificate: %v", errs)
				continue
			}

			log.Printf("Err: Unsupported PEM block type: %s", block.Type)
		}

	}

	x5cert, err := x509.ParseCertificate(content)
	if err == nil {
		out = append(out, x5cert)
	}

	pkcert, err := pkcs7.Parse(content)
	if err == nil && len(pkcert.Certificates) > 0 {
		out = append(out, pkcert.Certificates...)
	}

	_, pfxcert, _, err := pkcs12.DecodeChain(content, pw)
	if err == nil {
		out = append(out, pfxcert)
	}

	b64dec := []byte{}
	_, err = base64.StdEncoding.Decode(b64dec, content)
	if err == nil {
		return ParseFile(b64dec, pw)
	}

	if len(out) > 0 {
		return out
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

func PrintCert(cert *x509.Certificate, writer list.Writer, fullChain bool, first bool) {
	isTrusted := IsTrusted(cert)

	writer.AppendItem("Certificate Information")
	writer.Indent()
	if isTrusted == nil {
		writer.AppendItem(text.FgGreen.Sprint("Trusted by system root CAs"))
	} else if !first {
		writer.AppendItem(text.BgRed.Sprint("Not trusted by system root CAs: " + isTrusted.Error()))
	}
	writer.AppendItem(fmt.Sprintf("Version: %d", cert.Version))
	writer.AppendItem("Subject: " + cert.Subject.String())
	writer.AppendItem("Serial Number: " + cert.SerialNumber.String())

	writer.AppendItem(fmt.Sprintf("Is CA: %t", cert.IsCA))
	writer.UnIndent()

	writer.AppendItem("Validity")
	writer.Indent()

	isValid := cert.NotBefore.Before(time.Now()) && cert.NotAfter.After(time.Now())
	if isValid {
		writer.AppendItem(text.FgGreen.Sprint("Currently Valid"))
	} else if cert.NotBefore.After(time.Now()) {
		writer.AppendItem(text.BgRed.Sprint("Not valid yet. Valid from " + cert.NotBefore.String()))
	} else if cert.NotAfter.Before(time.Now()) {
		writer.AppendItem(text.BgRed.Sprint("Expired on " + cert.NotAfter.String()))
	}

	writer.AppendItem("Not Before: " + cert.NotBefore.String())
	writer.AppendItem("Not After: " + cert.NotAfter.String())
	writer.UnIndent()

	writer.AppendItem("Algorithms")
	writer.Indent()
	writer.AppendItem("Signature Algorithm: " + cert.SignatureAlgorithm.String())
	writer.AppendItem("Public Key Algorithm: " + cert.PublicKeyAlgorithm.String())
	writer.UnIndent()

	writer.AppendItem("SANs")
	writer.Indent()

	if len(cert.DNSNames)+len(cert.EmailAddresses)+len(cert.IPAddresses)+len(cert.URIs) > 0 {

		if len(cert.DNSNames) > 0 {
			writer.AppendItem("DNS Names")
			writer.Indent()
			if len(cert.DNSNames) > 10 {
				line := ""
				maxLen := 150

				for _, name := range cert.DNSNames {
					if len(line)+len(name) > maxLen {
						writer.AppendItem(line)
						line = ""
					}

					if line == "" {
						line = name
					} else {
						line = line + ", " + name
					}
				}
			} else {
				for _, name := range cert.DNSNames {
					writer.AppendItem(name)
				}
			}

			writer.UnIndent()
		}

		if len(cert.EmailAddresses) > 0 {
			writer.AppendItem("Email Addresses")
			writer.Indent()
			for _, email := range cert.EmailAddresses {
				writer.AppendItem(email)
			}
			writer.UnIndent()
		}

		if len(cert.IPAddresses) > 0 {

			writer.AppendItem("IP Addresses")
			writer.Indent()
			for _, ip := range cert.IPAddresses {
				writer.AppendItem(ip.String())
			}
			writer.UnIndent()
		}

		if len(cert.URIs) > 0 {
			writer.AppendItem("URIs")
			writer.Indent()
			for _, uri := range cert.URIs {
				writer.AppendItem(uri.String())
			}
			writer.UnIndent()
		}

	} else {
		writer.AppendItem("No Subject Alternate Names present")
	}

	writer.UnIndent()

	writer.AppendItem("Misc")
	writer.Indent()
	if len(cert.CRLDistributionPoints) > 0 {
		writer.AppendItem("CRL Distribution Points")
		writer.Indent()
		for _, crl := range cert.CRLDistributionPoints {
			if _, err := url.Parse(crl); err == nil {
				writer.AppendItem(crl)
			} else {
				writer.AppendItem(text.FgRed.Sprint("(invalid URL) " + crl))
			}
		}
		writer.UnIndent()
	}

	if len(cert.OCSPServer) > 0 {
		writer.AppendItem("OCSP Servers")
		writer.Indent()
		for _, ocsp := range cert.OCSPServer {
			if _, err := url.Parse(ocsp); err == nil {
				writer.AppendItem(ocsp)
			} else {
				writer.AppendItem(text.FgRed.Sprint("(invalid URL) " + ocsp))
			}
		}
		writer.UnIndent()
	}

	if len(cert.PermittedDNSDomains) > 0 {
		writer.AppendItem("Permitted DNS Domains")
		writer.Indent()
		for _, domain := range cert.PermittedDNSDomains {
			writer.AppendItem("Permitted DNS Domain: " + domain)
		}
		writer.UnIndent()
	}

	if len(cert.PolicyIdentifiers) > 0 {
		writer.AppendItem("Policy Identifiers")
		writer.Indent()
		for _, policy := range cert.PolicyIdentifiers {
			writer.AppendItem(policy.String())
		}
		writer.UnIndent()
	}

	if cert.Issuer.String() == cert.Subject.String() {
		if isTrusted == nil {
			writer.AppendItem(text.FgGreen.Sprint("Trusted Root CA"))
		} else {
			writer.AppendItem(text.BgRed.Sprint("Self-signed certificate"))
		}
		writer.UnIndent()
		return
	}

	writer.UnIndent()

	writer.AppendItem("Issuer")
	writer.Indent()
	writer.AppendItem("Issuer: " + cert.Issuer.String())
	writer.AppendItem(fmt.Sprintf("Issuing Certificate URL: %v", cert.IssuingCertificateURL))
	if !fullChain {
		writer.AppendItem("To fetch the full chain, use the --chain flag")
	}

	if len(cert.IssuingCertificateURL) > 0 {
		PrintNextIssuer(cert.IssuingCertificateURL[0], writer, fullChain)
	}

	writer.UnIndent()
}

func PrintNextIssuer(url string, writer list.Writer, fullChain bool) {
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

	issuerCerts := ParseFile(contentBytes, "")
	if issuerCerts == nil || len(issuerCerts) == 0 {
		log.Printf("Failed to parse issuer certificate from %s", url)
		return
	}

	if len(issuerCerts) > 1 {
		log.Printf("Warning: Multiple certificates found at %s, using the first one", url)
	}

	issuerCert := issuerCerts[0]

	isTrusted := IsTrusted(issuerCert)

	writer.AppendItem("Issuer Certificate")
	writer.Indent()

	if fullChain {
		PrintCert(issuerCert, writer, fullChain, false)
	} else {
		if isTrusted == nil {
			writer.AppendItem(text.FgGreen.Sprint("Trusted by system root CAs"))
		} else {
			writer.AppendItem(text.BgRed.Sprint("Not trusted by system root CAs: " + isTrusted.Error()))
		}
		writer.AppendItem("Subject: " + issuerCert.Subject.String())
		if issuerCert.Subject.String() == issuerCert.Issuer.String() {

			if isTrusted == nil {
				writer.AppendItem(text.FgGreen.Sprint("Trusted Root CA"))
			} else {
				writer.AppendItem(text.BgRed.Sprint("Self-signed certificate"))
			}
			writer.UnIndent()
			return
		}
		if len(issuerCert.IssuingCertificateURL) > 0 {
			PrintNextIssuer(issuerCert.IssuingCertificateURL[0], writer, fullChain)
		}
	}

	writer.UnIndent()
}

func IsTrusted(cert *x509.Certificate) error {
	roots, err := x509.SystemCertPool()
	if err != nil {
		return fmt.Errorf("failed to load system root CAs: %v", err)
	}

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	_, err = cert.Verify(opts)
	return err
}
