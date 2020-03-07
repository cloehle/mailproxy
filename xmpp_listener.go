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
	"strings"
    //SMTP:
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
	a	AccountManager
	log *logging.Logger
}

func (l *xmppListener) Halt() {
	// Close the listener and wait for the worker(s) to return.
	l.l.Close()
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

func newXMPPListener(p *Proxy) (*xmppListener, error) {
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

	// restore from saved contact state

	l.a = AccountManager{Online: []string{}, OnlineLock: &sync.Mutex{}, Proxy: p}

	l.server = xmppserver.Server{
		Accounts:   l.a,
		ConnectBus: connectbus,
		Extensions: []xmppserver.Extension{
			&xmppserver.NormalMessageExtension{MessageBus: messagebus},
			&xmppserver.RosterExtension{Accounts: l.a},
			&GlueExtension{},
			&RosterManagementExtension{Accounts: l.a},
		},
		DisconnectBus: disconnectbus,
		Domain:        "localhost",
		SkipTLS:     true,
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
		r.sendIMFFailure(acc, e.Err)
		return
	}
	user, pubKey, err := l.p.ParseKeyQueryResponse(e.Payload)
	if err != nil {
		l.log.Warningf("ParseKeyQueryResponse returned %v", err)
		r.sendIMFFailure(acc, err)
		return
	}
	if user != rcpt.User {
		l.log.Warningf("ParseKeyQueryResponse returned WRONG USER, wanted %v got %v", rcpt.User, user)
		r.sendIMFFailure(acc, errors.New("Keyserver returned PublicKey for WRONG USER!"))
		return
	}
	l.log.Noticef("Discovered key for %v: %v", r.rID, pubKey)
	l.p.SetRecipient(r.rID, pubKey)
	report, err := imf.KeyLookupSuccess(r.accID, r.rID, pubKey)
	if err != nil {
		l.log.Warningf("Failed to produce KeyLookupSuccess report: %v", err)
		return
	}
	acc.StoreReport(report)
	rcpt, err = l.p.toAccountRecipient(r.rID)
	if err != nil {
		l.log.Warningf("Failed to lookup freshly discovered account: %v", err)
		return
	}
	_, err = acc.EnqueueMessage(rcpt, *r.payload, r.isUnreliable)
	if err != nil {
		r.sendIMFFailure(acc, err)
	}
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
	if err != nil {
		l.log.Warningf("ReceivePop() failed for %v", e.AccountID)
		return
	}
	wrapped := fmt.Sprintf("<message from='%s@katzenpost/xmpp' type='chat'><body>%s</body></message>", message.SenderID, message.Payload)
	l.p.xmppListener.a.Loopreceiver <- []byte(wrapped)
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
				l.onMessageReceived(e) //TODO: give this to xmpp channel
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
	Online []string
	OnlineLock    *sync.Mutex
	// Jid and Loopreceiver have to be modified accordingly if we want xmppserver
	// to support multiple local clients
	Jid string
	Loopreceiver chan<- []byte
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
	a.OnlineLock.Lock()
	defer a.OnlineLock.Unlock()

	// For status
	/*online = append(online, "status")
	for person := range a.Online {
		online = append(online, person)
	}*/
	//Is this bad because xmppserver modifies it?
	online = a.Online
	return
}

// msg from local user
// enqueue message here
func (a AccountManager) RouteRoutine(bus <-chan xmppserver.Message) {
	for {
		message := <-bus
		var data []byte
		a.OnlineLock.Lock()

		fmt.Printf("%s -> %s\n", message.To, message.Data)
		//if ok = a.Online[message.To]; ok {
			switch message.Data.(type) {
			case []byte:
				data = message.Data.([]byte)
			default:
				var err error
				data, err = xml.Marshal(message.Data)
				if err != nil {
					panic(err)
				}
			}
			account, accountID, err := a.Proxy.getAccount(a.Jid)
			if err != nil {
				a.log.Errorf("No account matching %s", a.Jid)
				panic("No matching account to send from")
			}
			recipient, err := a.Proxy.toAccountRecipient(message.To)
			if err != nil {
				a.log.Errorf("No recipient found for %s using accountID %v", message.To, accountID)
				panic("No matching recipient")
			}
			if _, err := account.EnqueueMessage(recipient, data, false); err != nil {
				//TODO: false was isUnreliable, check for problems later on
				a.log.Errorf("Failed to enqueue for '%v': %v", recipient, err)
			}
		a.OnlineLock.Unlock()
	}
}

// Local user online
// xmppserver is written in a way that this is run for every user
// but we should only ever have that for loop run once
// TODO: add all recipients in keystore to online roster
func (a AccountManager) ConnectRoutine(bus <-chan xmppserver.Connect) {
	for {
		message := <-bus
		a.OnlineLock.Lock()
		if a.Jid != "" && a.Jid != message.Jid {
			panic("Multiple JIDs not supported")
		}
		a.Jid = message.Jid
		localPart := strings.SplitN(message.Jid, "@", 2)
		fmt.Printf("Adding %s to roster\n", localPart)
		a.Loopreceiver = message.Receiver
		a.OnlineLock.Unlock()
	}
}

// Local user offline
func (a AccountManager) DisconnectRoutine(bus <-chan xmppserver.Disconnect) {
	for {
		message := <-bus
		a.log.Infof("Disconnect: %s", message)
		//a.OnlineLock.Lock()
		//localPart := strings.SplitN(message.Jid, "@", 2)
		//delete(a.Online, localPart[0]) //TODO: Why would this be useful anyway?
		//a.OnlineLock.Unlock()
		//a.AlreadyOnline = false
	}
}

/*
//What is this even? not called anywere?
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
*/

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
	    // I would ignore status anyway, so simply drop any presence stanzas
		/*from.Send([]byte("<presence from='status@katzenpost'><priority>1</priority></presence>"))
		for person := range e.Accounts.Online {
			from.Send([]byte("<presence from='" + person + "@katzenpost/xmpp' to='" + from.Jid() + "' />"))
		}*/
	} else if ok {
		fmt.Printf("Subscribing to: %v\n", parsedPresence.To)
		recipient, err := e.Accounts.Proxy.toAccountRecipient(parsedPresence.To)
		if err != nil {
			e.Accounts.log.Warningf("Invalid Subscribe argument");
			return
		}
		// TODO:
		/*if rcpt.PublicKey == nil && !e.Accounts.Proxy.getAccount(parsedPresence.From).InsecureKeyDiscovery {
			e.Accounts.log.Warningf("Recipient ('%v') is not known and Insecure Key Discovery is disabled")
			return
		}*/

		account, accountID, err := e.Accounts.Proxy.getAccount(e.Accounts.Jid)
		if recipient.PublicKey == nil {
			msgID, err := e.Accounts.Proxy.QueryKeyFromProvider(accountID, recipient.ID)
			if err != nil {
				e.Accounts.log.Warningf("Failed to query key for '%v': ", recipient.ID, err)
			}
			e.Accounts.log.Infof("Key Query sent with message id %v", msgID)
			e.Accounts.log.Infof("We should send from account %v now", account)
			// defer this message to be sent later
			// This is only relevant if we want actual subscription
			//expire := time.Now().Add(time.Duration(e.Accounts.Proxy.cfg.Debug.UrgentQueueLifetime) * time.Second)
			// nil here was entity, this needs adaption to xmpp instead of imf anyway
			//e.Accounts.Proxy.eventListener.enqueueLaterCh <- &enqueueLater{string(msgID), accountID, recipient.ID, &payload, nil, false, expire}
		} else {
			// TODO: some sort of actual subscription mechanism?
			/*if _, err = account.EnqueueMessage(recipient, payload, false); err != nil {
				e.Accounts.log.Errorf("Failed to enqueue for '%v': %v", recipient, err)
			}*/
		}
		e.Accounts.OnlineLock.Lock()
		e.Accounts.Online = append(e.Accounts.Online, parsedPresence.To)
		e.Accounts.OnlineLock.Unlock()
		/*
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

/*
func newSMTPListener(p *Proxy) (*smtpListener, error) {
	l := new(smtpListener)
	l.p = p
	l.log = p.logBackend.GetLogger("listener/SMTP")

	var err error
	l.l, err = net.Listen("tcp", p.cfg.Proxy.SMTPAddress)
	if err != nil {
		return nil, err
	}

	l.Go(l.worker)
	return l, nil
}

type smtpSession struct {
	l *smtpListener

	log *logging.Logger

	nConn net.Conn
	sConn *smtpd.Conn
	id    uint64
}

func (s *smtpSession) worker() {
	defer s.nConn.Close()

	env := &smtpEnvelope{}
	defer env.Reset() // This holds an account.Account, which is refcounted.

	var viaESMTP bool
evLoop:
	for {
		ev := s.sConn.Next()
		switch ev.What {
		case smtpd.DONE, smtpd.ABORT:
			break evLoop
		case smtpd.COMMAND:
			// Check for cancelation.  This assumes the peer is going
			// to be sending commands in a timely manner, which seems
			// reasonable in the context of a local mail proxy.
			select {
			case <-s.l.HaltCh():
				s.sConn.RejectMsg("Server shutting down")
				break evLoop
			default:
			}

			// Conn.Next() will enforce command ordering, so this
			// can just accumulate based on the command, resetting
			// as appropriate.
			switch ev.Cmd {
			case smtpd.HELO:
				viaESMTP = false
				env.Reset()
			case smtpd.EHLO:
				viaESMTP = true
				env.Reset()
			case smtpd.RSET:
				env.Reset()
			case smtpd.MAILFROM:
				acc, accID, err := s.l.p.getAccount(ev.Arg)
				if err != nil {
					s.log.Warningf("Invalid MAIL FROM argument '%v': %v", ev.Arg, err)
					s.sConn.Reject()
					break
				}
				s.log.Debugf("Set account: '%v'", accID)
				env.SetAccount(accID, acc) // Takes ownership of the acc ref count.
			case smtpd.RCPTTO:
				rcpt, err := s.l.p.toAccountRecipient(ev.Arg)
				if err != nil {
					s.log.Warningf("Invalid RCPT TO argument '%v': %v", ev.Arg, err)
					s.sConn.Reject()
					break
				}
				// If automatic key discovery is enabled for this account, continue.
				if rcpt.PublicKey == nil && !env.account.InsecureKeyDiscovery {
					s.log.Warningf("RCPT TO ('%v') does not specify a known recipient.", rcpt.ID)
					s.sConn.Reject()
					break
				}
				s.log.Debugf("Added recipient: '%v'", rcpt.ID)
				env.AddRecipient(rcpt)
			case smtpd.DATA:
			default:
				s.log.Errorf("Invalid command: %v", ev.Cmd)
				s.sConn.Reject()
				break evLoop
			}
		case smtpd.GOTDATA:
			if err := s.onGotData(env, []byte(ev.Arg), viaESMTP); err != nil {
				s.log.Errorf("Failed to handle received message: %v", err)
				s.sConn.Reject()
			}
		default:
			s.log.Errorf("Invalid event: %v", ev)
			break evLoop
		}
	}

	s.log.Debugf("Connection terminated.")
}

func (s *smtpSession) onGotData(env *smtpEnvelope, b []byte, viaESMTP bool) error {
	defer env.Reset()

	// De-duplicate the recipients.
	env.DedupRecipients()
	if len(env.recipients) == 0 {
		return nil
	}

	// Validate and pre-process the outgoing message body.
	payload, entity, isUnreliable, err := s.l.p.preprocessOutgoing(b, viaESMTP)
	if err != nil {
		return err
	}

	// TODO: It is probably worth grouping all recipients of a given message
	// into a single send queue entry instead of creating a queue entry for
	// each recipient, but this is a far more simple approach, and unlike
	// traditional MTAs, xmppproxy is only going to be servicing a single
	// user with a comparatively low volume of mail anyway.
	failed := make(map[string]error)
	var enqueued []string

	for _, recipient := range env.recipients {
		if recipient.PublicKey == nil {
			msgID, err := s.l.p.QueryKeyFromProvider(env.accountID, recipient.ID)
			if err != nil {
				s.log.Warningf("Failed to query key for '%v': ", recipient.ID, err)
				failed[recipient.ID] = err
				continue
			}
			// defer this message to be sent later
			expire := time.Now().Add(time.Duration(s.l.p.cfg.Debug.UrgentQueueLifetime) * time.Second)
			s.l.p.eventListener.enqueueLaterCh <- &enqueueLater{string(msgID), env.accountID, recipient.ID, &payload, entity, isUnreliable, expire}
		} else {
			if _, err = env.account.EnqueueMessage(recipient, payload, isUnreliable); err != nil {
				s.log.Errorf("Failed to enqueue for '%v': %v", recipient, err)
				failed[recipient.ID] = err
				continue
			} else {
				enqueued = append(enqueued, recipient.ID)
			}
		}
	}

	switch len(failed) {
	case 0:
		return nil
	case len(env.recipients):
		// Technically I think I'm supposed to create a bounce message,
		// but that's silly when I can just reject the SMTP transaction.
		//
		// LMTP fully supports rejecting at send time on a per-recipient
		// basis, but we need to use SMTP, unfortunately.
		return errEnqueueAllFailed
	default:
	}

	// Generate a multipart/report indicating which recipients failed.
	report, err := imf.NewEnqueueFailure(env.accountID, enqueued, failed, entity.Header)
	if err != nil {
		return err
	}
	return env.account.StoreReport(report)
}

func (s *smtpSession) Write(p []byte) (n int, err error) {
	// This is used to adapt the smtpd package's idea of logging to our
	// leveled logging interface.

	if len(p) == 0 {
		return 0, nil
	}

	logType := p[0]
	if logType == 'r' || logType == 'w' {
		// Keep the prefix for network read/write debug logs.
		s.log.Debug(string(p))
		return len(p), nil
	}

	logMsg := string(bytes.TrimSpace(p[1:]))
	if len(logMsg) == 0 {
		return len(p), nil
	}
	switch logType {
	case '#':
		s.log.Notice(logMsg)
	case '!':
		s.log.Error(logMsg)
	default:
		// Should never happen, according to the package docs.
		s.log.Debugf("Unknown log type '%v': %v", logType, logMsg)
	}

	return len(p), nil
}

type smtpEnvelope struct {
	account    *account.Account
	recipients []*account.Recipient
	accountID  string
}

func (e *smtpEnvelope) SetAccount(id string, a *account.Account) {
	if e.account != nil {
		e.account.Deref()
	}
	e.account = a
	e.accountID = id
}

func (e *smtpEnvelope) AddRecipient(r *account.Recipient) {
	e.recipients = append(e.recipients, r)
}

func (e *smtpEnvelope) DedupRecipients() {
	newR := make([]*account.Recipient, 0, len(e.recipients))

	dedupMap := make(map[string]bool)
	for _, v := range e.recipients {
		if !dedupMap[v.ID] {
			dedupMap[v.ID] = true
			newR = append(newR, v)
		}
	}
	e.recipients = newR
}

func (e *smtpEnvelope) Reset() {
	e.SetAccount("", nil)
	e.recipients = nil
}
*/
