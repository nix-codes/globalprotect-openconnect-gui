// Package assets embeds static files bundled with the application.
package assets

import _ "embed"

//go:embed vpn-green.png
var VpnGreenPNG []byte

//go:embed vpn-amber.png
var VpnAmberPNG []byte

//go:embed vpn-grey.png
var VpnGreyPNG []byte
