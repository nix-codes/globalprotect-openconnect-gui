package ui

import (
	"fyne.io/fyne/v2"

	"github.com/nix-codes/gpoc-gui/assets"
)

// vpnConnectedIcon returns the green VPN shield for the connected state.
func vpnConnectedIcon() fyne.Resource {
	return fyne.NewStaticResource("vpn-green.png", assets.VpnGreenPNG)
}

// vpnConnectingIcon returns the amber VPN shield for connecting/disconnecting states.
func vpnConnectingIcon() fyne.Resource {
	return fyne.NewStaticResource("vpn-amber.png", assets.VpnAmberPNG)
}

// vpnDisconnectedIcon returns the grey VPN shield for the disconnected/error states.
func vpnDisconnectedIcon() fyne.Resource {
	return fyne.NewStaticResource("vpn-grey.png", assets.VpnGreyPNG)
}
