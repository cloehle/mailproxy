// main.go - Katzenpost client xmpp proxy binary.
// Copyright (C) 2017  Yawning Angel.
// Copyright (C) 2020  Christian Loehle.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"os/user"
	"path"
	"syscall"

	"github.com/katzenpost/core/utils"
	"github.com/cloehle/xmppproxy"
	"github.com/cloehle/xmppproxy/config"
	"github.com/katzenpost/playground"
	"github.com/katzenpost/registration_client"
	rclient "github.com/katzenpost/registration_client/mailproxy"
)

func main() {
	cfgFile := flag.String("f", "katzenpost.toml", "Path to the server config file.")
	genOnly := flag.Bool("g", false, "Generate the keys and exit immediately.")
	register := flag.Bool("r", false, "Register the account")
	accountName := flag.String("account", "", "account name to register")
	providerName := flag.String("provider", playground.ProviderName, "provider to use")
	providerKey := flag.String("providerKey", playground.ProviderKeyPin, "provider to use")

	authority := flag.String("authority", playground.AuthorityAddr, "address of nonvoting pki")
	onionAuthority := flag.String("onionAuthority", playground.OnionAuthorityAddr, ".onion address of nonvoting pki")
	authorityKey := flag.String("authorityKey", playground.AuthorityPublicKey, "authority public key, base64 or hex")

	registrationAddr := flag.String("registrationAddr", playground.RegistrationAddr, "account registration address")
	onionRegistrationAddr := flag.String("onionRegistrationAddr", playground.OnionRegistrationAddr, "account registration address")
	registerWithoutHttps := flag.Bool("registrationWithoutHttps", false, "register using insecure http (for testing environments)")

	registerWithOnion := flag.Bool("onion", false, "register using the Tor onion service")
	socksNet := flag.String("torSocksNet", "tcp", "tor SOCKS network (e.g. tcp or unix)")
	socksAddr := flag.String("torSocksAddr", "127.0.0.1:9150", "tor SOCKS address (e.g. 127.0.0.1:9050")

	dataDir := flag.String("dataDir", "", "xmppproxy data directory, defaults to ~/.xmppproxy")

	flag.Parse()

	if *register {
		if len(*accountName) == 0 {
			flag.Usage()
			return
		}

		// 1. ensure xmppproxy data dir doesn't already exist
		xmppproxyDir := ""
		if len(*dataDir) == 0 {
			usr, err := user.Current()
			if err != nil {
				panic("failure to retrieve current user information")
			}
			xmppproxyDir = path.Join(usr.HomeDir, ".xmppproxy")
		} else {
			xmppproxyDir = *dataDir
		}
		if _, err := os.Stat(xmppproxyDir); !os.IsNotExist(err) {
			panic(fmt.Sprintf("aborting registration, %s already exists", xmppproxyDir))
		}
		if err := utils.MkDataDir(xmppproxyDir); err != nil {
			panic(err)
		}

		// 2. generate xmppproxy key material and configuration
		linkKey, identityKey, err := rclient.GenerateConfig(*accountName, *providerName, *providerKey, *authority, *onionAuthority, *authorityKey, xmppproxyDir, *socksNet, *socksAddr, *registerWithOnion)
		if err != nil {
			panic(err)
		}

		// 3. perform registration with the mixnet Provider
		var options *client.Options = nil
		if *registerWithOnion {
			registrationAddr = onionRegistrationAddr
			options = &client.Options{
				Scheme:       "http",
				UseSocks:     true,
				SocksNetwork: *socksNet,
				SocksAddress: *socksAddr,
			}
		} else if *registerWithoutHttps {
			options = &client.Options{
				Scheme:       "http",
				UseSocks:     false,
				SocksNetwork: "",
				SocksAddress: "",
			}
		}
		c, err := client.New(*registrationAddr, options)
		if err != nil {
			panic(err)
		}
		err = c.RegisterAccountWithIdentityAndLinkKey(*accountName, linkKey, identityKey)
		if err != nil {
			panic(err)
		}

		fmt.Printf("Successfully registered %s@%s\n", *accountName, *providerName)
		fmt.Printf("xmppproxy -f %s\n", xmppproxyDir+"/xmppproxy.toml")
		return
	}

	// Set the umask to something "paranoid".
	syscall.Umask(0077)

	cfg, err := config.LoadFile(*cfgFile, *genOnly)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config file '%v': %v\n", *cfgFile, err)
		os.Exit(-1)
	}

	// Setup the signal handling.
	ch := make(chan os.Signal)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)

	// Start up the proxy.
	proxy, err := xmppproxy.New(cfg)
	if err != nil {
		if err == xmppproxy.ErrGenerateOnly {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "Failed to spawn server instance: %v\n", err)
		os.Exit(-1)
	}
	defer proxy.Shutdown()

	// Halt the proxy gracefully on SIGINT/SIGTERM, and scan RecipientDir on SIGHUP.
	go func() {
		for {
			switch <-ch {
			case syscall.SIGHUP:
				proxy.ScanRecipientDir()
			default:
				proxy.Shutdown()
				return
			}
		}
	}()

	// Wait for the proxy to explode or be terminated.
	proxy.Wait()
}
