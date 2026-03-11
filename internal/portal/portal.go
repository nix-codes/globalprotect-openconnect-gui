// Package portal implements the GlobalProtect portal HTTP calls natively,
// allowing seamless reconnect without re-opening the SAML browser flow.
package portal

import (
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

const userAgent = "PAN GlobalProtect/6.3.0-33 (Linux)"

// Gateway is a VPN gateway advertised by the portal.
type Gateway struct {
	Name    string
	Address string
}

// Config holds the portal's response from getconfig.esp.
type Config struct {
	PortalUserauthcookie   string
	PrelogonUserauthcookie string
	Gateways               []Gateway
}

// GetConfig calls POST https://<portal>/global-protect/getconfig.esp.
//
// For fresh auth pass preloginCookie (from SAML) and leave portalUserauthcookie empty.
// For reconnect pass portalUserauthcookie and leave preloginCookie empty.
//
// Returns an error if the server responds with a non-200 status or if the
// portal-userauthcookie field is absent/empty (caller should fall back to
// fresh auth in that case).
func GetConfig(portal, username, preloginCookie, portalUserauthcookie string) (*Config, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "linux"
	}

	form := url.Values{}
	form.Set("user", username)
	form.Set("passwd", "")
	form.Set("prelogin-cookie", preloginCookie)
	form.Set("portal-userauthcookie", portalUserauthcookie)
	form.Set("portal-prelogonuserauthcookie", "")
	form.Set("prot", "https:")
	form.Set("jnlpReady", "jnlpReady")
	form.Set("ok", "Login")
	form.Set("direct", "yes")
	form.Set("ipv6-support", "yes")
	form.Set("clientVer", "4100")
	form.Set("clientos", "Linux")
	form.Set("computer", hostname)
	form.Set("server", portal)
	form.Set("host", portal)

	endpoint := "https://" + portal + "/global-protect/getconfig.esp"
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("getconfig.esp: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("getconfig.esp: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	cfg, err := parseGetConfigResponse(body)
	if err != nil {
		return nil, err
	}
	if cfg.PortalUserauthcookie == "" {
		return nil, fmt.Errorf("getconfig.esp: empty portal-userauthcookie (auth rejected)")
	}
	return cfg, nil
}

// GatewayLogin calls POST https://<gateway>/ssl-vpn/login.esp and returns
// the URL-encoded openconnect cookie token.
func GatewayLogin(gateway, username, portalUserauthcookie, prelogonUserauthcookie string) (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "linux"
	}

	form := url.Values{}
	form.Set("user", username)
	form.Set("passwd", "")
	form.Set("prelogin-cookie", "")
	form.Set("portal-userauthcookie", portalUserauthcookie)
	form.Set("portal-prelogonuserauthcookie", prelogonUserauthcookie)
	form.Set("prot", "https:")
	form.Set("jnlpReady", "jnlpReady")
	form.Set("ok", "Login")
	form.Set("direct", "yes")
	form.Set("ipv6-support", "yes")
	form.Set("clientVer", "4100")
	form.Set("clientos", "Linux")
	form.Set("computer", hostname)
	form.Set("server", gateway)

	endpoint := "https://" + gateway + "/ssl-vpn/login.esp"
	req, err := http.NewRequest(http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", userAgent)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("login.esp: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("login.esp: HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read response: %w", err)
	}

	return parseGatewayLoginResponse(body, hostname)
}

// ---- XML parsers ------------------------------------------------------------

// getConfigXML mirrors the structure of the getconfig.esp XML response.
type getConfigXML struct {
	XMLName              xml.Name `xml:"policy"`
	PortalUserauthcookie string   `xml:"portal-userauthcookie"`
	PrelogonCookie       string   `xml:"portal-prelogonuserauthcookie"`
	Gateways             struct {
		External struct {
			List struct {
				Entries []gatewayEntry `xml:"entry"`
			} `xml:"list"`
		} `xml:"external"`
	} `xml:"gateways"`
}

type gatewayEntry struct {
	Name    string `xml:"name,attr"`
	Address string `xml:"address"`
}

func parseGetConfigResponse(body []byte) (*Config, error) {
	var doc getConfigXML
	if err := xml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("parse getconfig response: %w", err)
	}

	cfg := &Config{
		PortalUserauthcookie:   doc.PortalUserauthcookie,
		PrelogonUserauthcookie: doc.PrelogonCookie,
	}
	for _, e := range doc.Gateways.External.List.Entries {
		addr := e.Address
		if addr == "" {
			addr = e.Name // portal uses name attr as the hostname when no <address> child
		}
		if addr != "" {
			cfg.Gateways = append(cfg.Gateways, Gateway{
				Name:    e.Name,
				Address: addr,
			})
		}
	}
	return cfg, nil
}

// loginXML mirrors the structure of the login.esp XML response.
// The response contains a <jnlp> element with a list of <argument> elements.
type loginXML struct {
	XMLName   xml.Name `xml:"jnlp"`
	Arguments []string `xml:"application-desc>argument"`
}

func parseGatewayLoginResponse(body []byte, hostname string) (string, error) {
	var doc loginXML
	if err := xml.Unmarshal(body, &doc); err != nil {
		return "", fmt.Errorf("parse login response: %w", err)
	}

	args := doc.Arguments
	get := func(i int) string {
		if i < len(args) {
			return args[i]
		}
		return ""
	}

	authcookie := get(1)
	portal := get(3)
	user := get(4)
	domain := get(7)
	preferredIP := get(15)

	if authcookie == "" {
		return "", fmt.Errorf("login.esp: empty authcookie in response")
	}

	token := url.Values{}
	token.Set("authcookie", authcookie)
	token.Set("portal", portal)
	token.Set("user", user)
	token.Set("domain", domain)
	token.Set("preferred-ip", preferredIP)
	token.Set("computer", hostname)

	return token.Encode(), nil
}
