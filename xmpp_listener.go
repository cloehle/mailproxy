// xmpp_listener.go - XMPP listener.
// Copyright (C) 2018  Yawning Angel.
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

package xmppproxy

import (
	"net"

	"github.com/katzenpost/core/worker"
	"gopkg.in/op/go-logging.v1"
    "github.com/cloehle/xmppproxy/xmppserver"

    "sync"
	"fmt"
	"encoding/xml"
	"encoding/base64"
	"strings"

	"github.com/cloehle/xmppproxy/internal/account"
    "github.com/cloehle/xmppproxy/internal/imf"
    "github.com/cloehle/xmppproxy/event"
    "github.com/emersion/go-message"
    "time"
    "errors"
)

type xmppListener struct {
	worker.Worker
    server xmppserver.Server

	p   *Proxy
	l   net.Listener
	a	*AccountManager
	log *logging.Logger
	// Jid and Loopreceiver have to be modified accordingly if we want xmppserver
	// to support multiple local clients
	Loopreceiver chan<- []byte
	Accountname string
	Roster []string
	RosterLock *sync.Mutex
	BodyContentOnly bool
}

func (l *xmppListener) Halt() {
	// Close the listener and wait for the worker(s) to return.
	//xmppserver provides no way of closing client connections, so
	// there is no graceful shutdown anyway
	//l.l.Close()
	l.Worker.Halt()
}

func (l *xmppListener) worker() {
	addr := l.l.Addr()
	l.log.Noticef("Listening on: %v", addr)
	defer func() {
		l.log.Noticef("Stopping listening on: %v", addr)
		l.l.Close() // Usually redundant, but harmless.
	}()
	for {
		conn, err := l.l.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				l.log.Errorf("Critical accept failure: %v", err)
				return
			}
			continue
		}

		rAddr := conn.RemoteAddr()
		l.log.Debugf("Accepted new connection: %v", rAddr)
		l.Go(func() { l.server.TCPAnswer(conn) })
	}

	// NOTREACHED
}

func newXMPPListener(p *Proxy, bodyContentOnly bool) (*xmppListener, error) {
	l := new(xmppListener)
	l.p = p
	l.log = p.logBackend.GetLogger("listener/xmpp")

	var err error
	l.l, err = net.Listen("tcp", p.cfg.Proxy.XMPPAddress)
	if err != nil {
		return nil, err
	}

	var messagebus = make(chan xmppserver.Message)
	var connectbus = make(chan xmppserver.Connect)
	var disconnectbus = make(chan xmppserver.Disconnect)

	l.BodyContentOnly = bodyContentOnly

	// TODO: restore from saved contact state

	//TODO: If multiple accounts can be used, modify accordingly
	//but this is a big IF for the future, I dont think this feature
	// is or ever was useful/advisable
	accountnames := p.accounts.ListIDs()
	if len(accountnames) != 1 {
		l.log.Errorf("Accountstore has not exactly one account")
		return nil, err
	}
	l.log.Debugf("starting xmpp listener as account %s", l.Accountname)
	l.Accountname = accountnames[0]
	l.Roster = []string{accountnames[0]}
	l.RosterLock = &sync.Mutex{}

	l.a = &AccountManager{Proxy: p,
	 log: p.logBackend.GetLogger("listener/AccountManager")}

	l.server = xmppserver.Server{
		Accounts:   l.a,
		ConnectBus: connectbus,
		Extensions: []xmppserver.Extension{
			&xmppserver.NormalMessageExtension{MessageBus: messagebus},
			&xmppserver.DebugExtension{},
			&xmppserver.RosterExtension{Accounts: l.a},
			&GlueExtension{},
			&RosterManagementExtension{Accounts: l.a},
		},
		DisconnectBus: disconnectbus,
		Domain:        "localhost",
		SkipTLS:     true,
		Log:	l.log,
	}

	go l.a.RouteRoutine(messagebus)
	go l.a.ConnectRoutine(connectbus)
	go l.a.DisconnectRoutine(disconnectbus)

	l.Go(l.worker)
	return l, nil
}

//Start smtp part

type enqueueLater struct {
	replyID      string
	accID        string
	rID          string
	payload      *[]byte
	entity       *message.Entity
	isUnreliable bool
	expire       time.Time
}

func (e *enqueueLater) sendIMFFailure(account *account.Account, err error) {
	failed := make(map[string]error)
	failed[e.rID] = err
	report, err := imf.NewEnqueueFailure(e.accID, nil, failed, e.entity.Header)
	if err == nil {
		account.StoreReport(report)
	}
}

type eventListener struct {
	worker.Worker

	p   *Proxy
	log *logging.Logger

	enqueueLaterCh chan *enqueueLater
	sendLater      map[string]*enqueueLater
}

func (l *eventListener) onKaetzchenReply(e *event.KaetzchenReplyEvent) {
	id := string(e.MessageID)
	r, ok := l.sendLater[id]
	if !ok {
		l.log.Errorf("Cannot match Kaetzchen Reply %v", e)
		return
	}
	delete(l.sendLater, id)
	acc, _, err := l.p.getAccount(r.accID)
	if err != nil {
		l.log.Warningf("getAccount() failed for %v", r.accID)
		return
	}
	defer acc.Deref()
	rcpt, err := l.p.toAccountRecipient(r.rID)
	if err != nil {
		l.log.Warningf("toAccountRecipient() failed for %v", r.rID)
		return
	}
	if e.Err != nil {
		l.log.Warningf("KaetzchenReplyEvent received with error: %v", e.Err)
		return
	}
	user, pubKey, err := l.p.ParseKeyQueryResponse(e.Payload)
	if err != nil {
		l.log.Warningf("ParseKeyQueryResponse returned %v", err)
		return
	}
	if user != rcpt.User {
		l.log.Warningf("ParseKeyQueryResponse returned WRONG USER, wanted %v got %v", rcpt.User, user)
		return
	}
	l.log.Noticef("Discovered key for %v: %v", r.rID, pubKey)
	l.p.SetRecipient(r.rID, pubKey)
	rcpt, err = l.p.toAccountRecipient(r.rID)
	if err != nil {
		l.log.Warningf("Failed to lookup freshly discovered account: %v", err)
		return
	}
	if l.p.xmppListener.BodyContentOnly {
		// If we only send actual content messages, there is no good way or use
		// to notify recipient that we queried their key
		return
	}
	//subscription will always trigger kaetzchen keyserver loopup @ recipient => subscription too, right?
	request := fmt.Sprintf("<presence from='%s' id='%x' to='%s' type='subscribe' xmlns='jabber:client'/>", l.p.xmppListener.Accountname, xmppserver.CreateCookie(), rcpt.ID)

	if _, err := acc.EnqueueMessage(rcpt, []byte(request), false); err != nil {
		l.log.Errorf("Failed to enqueue for '%v': %v", rcpt, err)
	}

}

func setSenderMessage(xmlmessage []byte, sender string) ([]byte, error) {
	var parsed xmppserver.ClientMessage
	err := xml.Unmarshal(xmlmessage, &parsed)
	if err != nil {
		return xmlmessage, err
	}
	parsed.From = sender
	return xml.Marshal(parsed)
}

func getMessageBodyContent(xmlmessage []byte) (string, error) {
	var parsed xmppserver.ClientMessage
	err := xml.Unmarshal(xmlmessage, &parsed)
	if err != nil {
		return "", err
	}
	return parsed.Body, nil
}

func (l *eventListener) onMessageReceived(e *event.MessageReceivedEvent) {
	// e contains the msg id
	// theoretically we would like the message belonging to that id
	// but api only provides ReceivePop, which always returns
	// eldest message
	// Although it seems counter-intuitive to not request that
	// specific message that fired the event, it should still work as intended
	// (or even better, as we ideally want the eldest message anyway)
	message, err := l.p.ReceivePop(e.AccountID)
	l.log.Debugf("ReceivePop returned message from %v", message.SenderID)
	if err != nil {
		l.log.Warningf("ReceivePop() failed for %v", e.AccountID)
		return
	}
	if l.p.xmppListener.BodyContentOnly {
		wrapped := fmt.Sprintf("<message from='%s' type='chat'><body>%s</body></message>", message.SenderID, message.Payload)
		l.p.xmppListener.Loopreceiver <- []byte(wrapped)
		return
	}
	// Now we need to check if it is a subscription or a message
	if strings.HasPrefix(string(message.Payload), "<presence") {
		var parsed xmppserver.ClientPresence
		err := xml.Unmarshal(message.Payload, &parsed)
		if err != nil {
			l.log.Errorf("Error Unmarshalling XML", err)
			return
		}
		parsed.From = message.SenderID
		data, err := xml.Marshal(parsed)
		if err != nil {
			l.log.Errorf("Error Marshalling XML", err)
			return
		}
		l.p.xmppListener.Loopreceiver <- []byte(data)
		// If it is a subscription request, we send an additional message with
		// the senders key, so that client can add/deny based on the key
		if parsed.Type == "subscribe" {
			sender, err := l.p.GetRecipient(message.SenderID)
			if err != nil {
				l.log.Warningf("Invalid Subscribe argument", err);
				return
			}
			request := fmt.Sprintf("<message from='%s' type='chat'><body>I would like to add you to my contacts, my key is:%s</body></message>", message.SenderID, base64.StdEncoding.EncodeToString(sender.Bytes()))
			l.p.xmppListener.Loopreceiver <- []byte(request)
		}
	} else if strings.HasPrefix(string(message.Payload), "<message") {
		data, err := setSenderMessage(message.Payload, message.SenderID)
		if err != nil {
			l.log.Errorf("Error marshalling XML", err)
			return
		}
		l.p.xmppListener.Loopreceiver <- []byte(data)

	} else {
			l.log.Errorf("Received unsupported XMPP, neither presence nor message: %s", string(message.Payload))
	}
}

func (l *eventListener) prune(t time.Time) {
	toDel := make([]string, 0)
	for k, r := range l.sendLater {
		if t.After(r.expire) {
			if acc, _, err := l.p.getAccount(r.accID); err != nil {
				toDel = append(toDel, k)
				r.sendIMFFailure(acc, errors.New("Unable to discover key for recipient"))
				acc.Deref()
			}
		}
	}
	for _, d := range toDel {
		delete(l.sendLater, d)
	}
}

func (l *eventListener) worker() {
	l.log.Debugf("Listening for events now")
	// set up state for queuing messages to send later
	l.sendLater = make(map[string]*enqueueLater)
	wakeup := func() <-chan time.Time {
		return time.After(1 * time.Minute)
	}

	for {
		select {
		case <-l.HaltCh():
			l.log.Debugf("Shutting down eventListener.")
			close(l.enqueueLaterCh)
			return
		case t := <-wakeup():
			l.log.Debugf("Waking up eventListener to prune messages")
			l.prune(t)
		case msg := <-l.enqueueLaterCh:
			l.sendLater[msg.replyID] = msg
		case evt := <-l.p.EventSink:
			switch e := evt.(type) {
			case *event.KaetzchenReplyEvent:
				l.onKaetzchenReply(e)
			case *event.MessageReceivedEvent:
				l.onMessageReceived(e)
			default: //TODO: else what?
			}
		}
	}
}

func newEventListener(p *Proxy) *eventListener {
	l := new(eventListener)
	l.p = p
	l.log = p.logBackend.GetLogger("listener/EventSink")
	l.enqueueLaterCh = make(chan *enqueueLater)
	l.Go(l.worker)
	return l
}


// AccountManager deals with understanding the local set of talek logs in use and remote users
type AccountManager struct {
	Proxy *Proxy
	log *logging.Logger
}

// Authenticate is called when local user attempts to authenticate
func (a AccountManager) Authenticate(username, password string) (success bool, err error) {
	success = true
	return
}

// CreateAccount is called when local user attempts to register
func (a AccountManager) CreateAccount(username, password string) (success bool, err error) {
	success = true
	//TODO: XMPPProxy generate and register account @ provider
	return
}

// OnlineRoster is called periodically by client
func (a AccountManager) OnlineRoster(jid string) (online []string, err error) {
	a.Proxy.xmppListener.RosterLock.Lock()
	defer a.Proxy.xmppListener.RosterLock.Unlock()

	for _,person := range a.Proxy.xmppListener.Roster {
		online = append(online, person)
	}
	online = a.Proxy.xmppListener.Roster
	return
}

// msg from local user
// enqueue message here
func (a AccountManager) RouteRoutine(bus <-chan xmppserver.Message) {
	for {
		message := <-bus
		var messagedata []byte
		var err error

		switch message.Data.(type) {
		case []byte:
			messagedata = message.Data.([]byte)
		case string:
			messagedata = []byte(message.Data.(string))
		default:
			messagedata, err = xml.Marshal(message.Data)
			if err != nil {
				panic(err)
			}
		}
		bodyContent, err := getMessageBodyContent(messagedata)
		if err != nil {
			a.log.Error("Could not parse XML from client", err)
			panic(err)
		}
		if bodyContent == "" {
			a.log.Debugf("Received message with empty body from XMPP client, not routing it")
			continue
		}
		if a.Proxy.xmppListener.BodyContentOnly {
			a.log.Infof("Routing Content Message: %s -> %s", message.To, message.Data)
			messagedata = []byte(bodyContent)
		} else {
			a.log.Infof("Routing XMPP Message: %s -> %s", message.To, message.Data)
		}

		account, accountID, err := a.Proxy.getAccount(a.Proxy.xmppListener.Accountname)
		if err != nil {
			a.log.Errorf("No account matching %s", a.Proxy.xmppListener.Accountname)
			panic("No matching account to send from")
		}
		recipient, err := a.Proxy.toAccountRecipient(message.To)
		if err != nil {
			a.log.Errorf("No recipient found for %s using accountID %v", message.To, accountID)
			panic("No matching recipient")
		}
		if _, err := account.EnqueueMessage(recipient, []byte(messagedata), false); err != nil {
			a.log.Errorf("Failed to enqueue for '%v': %v", recipient, err)
		}
	}
}

// Local user online
// xmppserver is written in a way that this is run for every user
// but we should only ever have that for loop run once
// TODO: add all recipients in keystore to online roster
func (a AccountManager) ConnectRoutine(bus <-chan xmppserver.Connect) {
	for {
		message := <-bus
		a.Proxy.xmppListener.Loopreceiver = message.Receiver
	}
}

// Local user offline
func (a AccountManager) DisconnectRoutine(bus <-chan xmppserver.Disconnect) {
	for {
		message := <-bus
		a.log.Infof("Disconnect: %s", message)
	}
}

// RosterManagementExtension watches for messages outbound from client.
type RosterManagementExtension struct {
	Accounts *AccountManager
}

// Process takes in messages (presence stanzas) from the xmpp client
// subscribe = contact addition, presence notifications
func (e *RosterManagementExtension) Process(message interface{}, from *xmppserver.Client) {
	parsedPresence, ok := message.(*xmppserver.ClientPresence)
	if ok && parsedPresence.Type != "subscribe" {
		e.Accounts.log.Debugf("Presence request received")
	    // I would ignore status anyway, so simply drop any presence stanzas
		// TODO: Proper way to handle this?
		for _,person := range e.Accounts.Proxy.xmppListener.Roster {
			from.Send([]byte("<presence from='" + person + "' to='" + from.Jid() + "' />"))
		}
	} else if ok {
		e.Accounts.log.Infof("Subscribing to: %v\n", parsedPresence.To)
		recipient, err := e.Accounts.Proxy.toAccountRecipient(parsedPresence.To)
		if err != nil {
			e.Accounts.log.Warningf("Invalid Subscribe argument", err);
			return
		}
		account, accountID, err := e.Accounts.Proxy.getAccount(e.Accounts.Proxy.xmppListener.Accountname)
		if err != nil {
			e.Accounts.log.Errorf("Could not find matching account for %s", e.Accounts.Proxy.xmppListener.Accountname, err);
			return
		}
		if recipient.PublicKey == nil && !account.InsecureKeyDiscovery {
			e.Accounts.log.Errorf("Recipient ('%v') is not known and Insecure Key Discovery is disabled, Subscription dropped")
			return
		}
		if recipient.PublicKey == nil {
			msgID, err := e.Accounts.Proxy.QueryKeyFromProvider(accountID, recipient.ID)
			if err != nil {
				e.Accounts.log.Warningf("Failed to query key for '%v': ", recipient.ID, err)
			}
			e.Accounts.log.Infof("Key Query sent with message id %v", msgID)
			e.Accounts.log.Infof("We should send from account %v now", account)
			// defer this message to be sent later
			// This is only relevant if we want actual subscription
			// TODO: Sent subscription request with own key as subscription message
			// Always set subcription=both, as this guarantees clients will display it in roster
			expire := time.Now().Add(time.Duration(e.Accounts.Proxy.cfg.Debug.UrgentQueueLifetime) * time.Second)
			// nil here was entity, this needs adaption to xmpp instead of imf anyway
			e.Accounts.Proxy.eventListener.enqueueLaterCh <- &enqueueLater{string(msgID), accountID, recipient.ID, nil, nil, false, expire}
		} else {
			request := fmt.Sprintf("<presence from='%s' id='%x' to='%s' type='subscribe' xmlns='jabber:client'/>", e.Accounts.Proxy.xmppListener.Accountname, xmppserver.CreateCookie(), recipient.ID)
			if _, err := account.EnqueueMessage(recipient, []byte(request), false); err != nil {
				e.Accounts.log.Errorf("Failed to enqueue for '%v': %v", recipient, err)
			}
			e.Accounts.log.Infof("Skipped Kaetzchen Request as %s is already known", parsedPresence.To)
		}
		e.Accounts.log.Infof("Adding %s to Roster", parsedPresence.To)
		e.Accounts.Proxy.xmppListener.RosterLock.Lock()
		e.Accounts.Proxy.xmppListener.Roster = append(e.Accounts.Proxy.xmppListener.Roster, parsedPresence.To)
		e.Accounts.Proxy.xmppListener.RosterLock.Unlock()

		// After a subscription the server needs to set the new roster to all
		// resources
		roster, _ := e.Accounts.OnlineRoster(from.Jid())
		msg := fmt.Sprintf("<iq id='%x' to='%s type='set'><query xmlns='jabber:iq:roster' ver='ver7'>", xmppserver.CreateCookie(), from.Jid())
		for _, v := range roster {
			msg = msg + "<item jid='" + v + "'/>"
		}
		msg = msg + "</query></iq>"
		e.Accounts.log.Infof("Sending back roster")
		from.Send([]byte(msg))
	}
}
