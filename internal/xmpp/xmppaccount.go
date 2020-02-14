// xmppaccount.go - Katzenpost client xmppproxy xmpp interface
// Copyright (C) 2020 Christian Loehle
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

package xmpp

import (
	"encoding/xml"
	"fmt"
	"strings"

	"github.com/cloehle/xmppproxy/xmppserver"

	"sync"
)

// AccountManager deals with understanding the local set of talek logs in use and remote users
type AccountManager struct {
	Online  map[string]chan<- []byte
	OnlineLock    *sync.Mutex
}

// Authenticate is called when local user attempts to authenticate
func (a AccountManager) Authenticate(username, password string) (success bool, err error) {
	success = true
	return
}

// CreateAccount is called when local user attempts to register
func (a AccountManager) CreateAccount(username, password string) (success bool, err error) {
	success = true
	return
}

// OnlineRoster is called periodically by client
func (a AccountManager) OnlineRoster(jid string) (online []string, err error) {
	a.OnlineLock.Lock()
	defer a.OnlineLock.Unlock()

	// For status
	online = append(online, "status")
	for person := range a.Online {
		online = append(online, person)
	}
	return
}

// msg from local user
func (a AccountManager) RouteRoutine(bus <-chan xmppserver.Message) {
	var channel chan<- []byte
	var ok bool

	for {
		message := <-bus
		a.OnlineLock.Lock()

		fmt.Printf("%s -> %s\n", message.To, message.Data)
		if channel, ok = a.Online[message.To]; ok {
			switch message.Data.(type) {
			case []byte:
				channel <- message.Data.([]byte)
			default:
				data, err := xml.Marshal(message.Data)
				if err != nil {
					panic(err)
				}
				channel <- data
			}
		}

		a.OnlineLock.Unlock()
	}
}

// Local user online
func (a AccountManager) ConnectRoutine(bus <-chan xmppserver.Connect) {
	for {
		message := <-bus
		a.OnlineLock.Lock()
		localPart := strings.SplitN(message.Jid, "@", 2)
		fmt.Printf("Adding %s to roster\n", localPart)
		a.Online[localPart[0]] = message.Receiver
		a.OnlineLock.Unlock()
	}
}

// Local user offline
func (a AccountManager) DisconnectRoutine(bus <-chan xmppserver.Disconnect) {
	for {
		message := <-bus
		a.OnlineLock.Lock()
		localPart := strings.SplitN(message.Jid, "@", 2)
		delete(a.Online, localPart[0])
		a.OnlineLock.Unlock()
	}
}

func handleMessagesTo(jid string) chan interface{} {
	iface := make(chan interface{})
	go func() {
		for {
			n := <-iface
			fmt.Printf("Msg To %s: %s\n", jid, n)
		}
	}()
	return iface
}

// RosterManagementExtension watches for messages outbound from client.
type RosterManagementExtension struct {
	Accounts AccountManager
}

// Process takes in messages (presence stanzas) from the xmpp client
// subscribe = contact addition, presence notifications
func (e *RosterManagementExtension) Process(message interface{}, from *xmppserver.Client) {
	parsedPresence, ok := message.(*xmppserver.ClientPresence)
	if ok && parsedPresence.Type != "subscribe" {
		fmt.Printf("Saw client presence: %v\n", parsedPresence)
	    /*from.Send([]byte("<presence from='status@talexmpp'><priority>1</priority></presence>"))
		for person := range e.Accounts.Online {
			from.Send([]byte("<presence from='" + person + "@talexmpp/talek' to='" + from.Jid() + "' />"))
		}*/
	} else if ok {
		fmt.Printf("Subscribing to: %v\n", parsedPresence.To)
		// Initiate Contact addition.
		/*contact, offer := GetOffer("nickname", parsedPresence.To)
		contact.Start(e.Client)
		sender := func(msg []byte) {
			wrapped := fmt.Sprintf("<message from='%s@talexmpp/talek' type='chat'><body>%s</body></message>", parsedPresence.To, msg)
			from.Send([]byte(wrapped))
		}
		fromUser := contact.Channel(&sender)
		e.Accounts.Online[parsedPresence.To] = fromUser
		from.Send([]byte("<message from='status@talexmpp' type='chat'><body>Contact generated. Offer:\n" + string(offer) + "</body></message>"))
        */
	}

	//parsedMessage, ok := message.(*xmppserver.ClientMessage)
}

