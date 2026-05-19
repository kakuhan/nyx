// Package reality 提供 REALITY 模式证书伪装
// 借鉴 Xray REALITY 设计：窃取真实网站的证书外观（Subject/Issuer/SAN），
// 生成匹配的自签名证书，被动观察者看到的是知名网站的证书信息。
package reality

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"time"
)

// FetchCert 从目标域名抓取真实证书，克隆其元数据生成匹配的自签名证书。
// 返回 PEM 证书 + 匹配的 RSA 私钥（LoadX509KeyPair 会通过验证）。
func FetchCert(domain string) ([]byte, []byte, error) {
	realCert, err := fetchCertFromDomain(domain)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch cert for %s: %w", domain, err)
	}

	// 克隆真实证书的 Subject/Issuer/SAN，生成自签名证书（私钥匹配）
	certPEM, keyPEM, err := cloneCert(realCert, domain)
	if err != nil {
		return nil, nil, fmt.Errorf("clone cert: %w", err)
	}
	return certPEM, keyPEM, nil
}

// SaveCert 将证书和密钥写入文件
func SaveCert(certPath, keyPath string, certPEM, keyPEM []byte) error {
	if idx := strings.LastIndex(certPath, "/"); idx >= 0 {
		os.MkdirAll(certPath[:idx], 0755)
	}
	if err := os.WriteFile(certPath, certPEM, 0644); err != nil {
		return fmt.Errorf("write cert: %w", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("write key: %w", err)
	}
	return nil
}

// fetchCertFromDomain 从目标域名:443 抓取真实 TLS 证书
func fetchCertFromDomain(domain string) (*x509.Certificate, error) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp",
		fmt.Sprintf("%s:443", domain), &tls.Config{
			ServerName:         domain,
			InsecureSkipVerify: true,
		})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no certs received from %s", domain)
	}
	return state.PeerCertificates[0], nil
}

// cloneCert 克隆真实证书的 Subject/Issuer/SAN，生成自签名证书（私钥匹配）
func cloneCert(realCert *x509.Certificate, domain string) ([]byte, []byte, error) {
	// 生成新 RSA 密钥
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("generate RSA: %w", err)
	}

	// 合并 DNSNames — 确保 domain 在列表中且不重复
	dnsNames := []string{domain}
	for _, name := range realCert.DNSNames {
		if name != domain {
			dnsNames = append(dnsNames, name)
		}
	}

	// 克隆元数据：Subject、Issuer、SAN、NotBefore/After
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      realCert.Subject,
		Issuer:       realCert.Issuer,
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     dnsNames,
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("create cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM, nil
}

// GenSelfSigned 自签名证书（fallback：无真实证书可克隆时）
func GenSelfSigned(domain string) ([]byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("generate serial: %w", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		DNSNames:     []string{domain},
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM, nil
}
