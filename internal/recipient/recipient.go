// recipient.go - Recipient public key store.
// Copyright (C) 2018  Yawning Angel.
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

// Package recipient implements the recipient public key store.
package recipient

import (
	"errors"
	"fmt"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/thwack"
	"github.com/katzenpost/mailproxy/config"
	"golang.org/x/net/idna"
	"golang.org/x/text/secure/precis"
)

var (
	errMissingAt        = errors.New("recipient: address is missing '@'")
	errOversizedLocal   = errors.New("recipient: address has oversized local-part")
	errInvalidPublicKey = errors.New("recipient: invalid public key")
	errNoSuchRecipient  = errors.New("recipient: no such recipient")
)

// Store is the recipient store.
type Store struct {
	sync.Mutex

	recipients   map[string]*ecdh.PublicKey
	recipientDir string

	caseSensitiveUsers bool
}

// Normalize normalizes the provided recipient according to the rules specified
// at the Store construction time, along with performing some basic sanity
// checking, and returns the normalized address, local part and domain.  The
// Store is not queried for recipient presence.
func (s *Store) Normalize(r string) (string, string, string, error) {
	addr, err := mail.ParseAddress(r)
	if err != nil {
		return "", "", "", err
	}

	splitA := strings.SplitN(addr.Address, "@", 2)
	if len(splitA) != 2 {
		// Should never happen, mail.ParseAddress() appears to validate this.
		return "", "", "", errMissingAt
	}

	// XXX: Per RFC 5322 A.5 basically anything can have comments inserted in
	// between tokens.  This should strip them out.  But anyone that does
	// something like `foo(comment)@(bar.comment)example.org` deserves
	// to have failures.
	local, domain := splitA[0], splitA[1]
	if !s.caseSensitiveUsers {
		local, err = precis.UsernameCaseMapped.String(local)
	} else {
		local, err = precis.UsernameCasePreserved.String(local)
	}
	if err != nil {
		return "", "", "", err
	}
	if len(local) > constants.RecipientIDLength {
		return "", "", "", errOversizedLocal
	}
	domain, err = idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", "", "", err
	}

	return local + "@" + domain, local, domain, nil
}

// Get returns the ecdh.PublicKey for the given recipient, or nil iff the
// recipient does not exist.  Note that this treats Normalize() failures as if
// the recipient is invalid.
func (s *Store) Get(r string) *ecdh.PublicKey {
	addr, _, _, err := s.Normalize(r)
	if err != nil {
		return nil
	}

	s.Lock()
	defer s.Unlock()

	return s.recipients[addr]
}

// GetByKey returns the identifier for the provided public key if any.
func (s *Store) GetByKey(k *ecdh.PublicKey) string {
	if k == nil {
		return ""
	}

	s.Lock()
	defer s.Unlock()

	for id, v := range s.recipients {
		if v.Equal(k) {
			return id
		}
	}
	return ""
}

// Set sets the ecdh.PublicKey for the provided recipient.  If an existing key
// is present, it will be silently overwritten.
func (s *Store) Set(r string, k *ecdh.PublicKey) error {
	addr, _, _, err := s.Normalize(r)
	if err != nil {
		return err
	}
	if k == nil {
		return errInvalidPublicKey
	}

	s.Lock()
	defer s.Unlock()

	// Updates or creates the on disk PEM formatted file for the provided recipient.
	// If the file already exists, it will be silently overwritten.

	rf := filepath.Join(s.recipientDir, r+".pem")
	err = k.ToPEMFile(rf)
	if err != nil {
		return err
	}

	s.recipients[addr] = k
	return nil
}

func (s *Store) LoadFromPEM(path string) error {
	k := new(ecdh.PublicKey)
	err := k.FromPEMFile(path)
	if err != nil {
		return err
	}
	_, f := filepath.Split(path)
	ext := filepath.Ext(f)
	addr, _, _, err := s.Normalize(f[:len(f)-len(ext)])
	if err != nil {
		return err
	}
	s.Lock()
	defer s.Unlock()
	s.recipients[addr] = k
	return nil
}

// Clear removes the recipient and corresponding ecdh.PublicKey from the Store.
func (s *Store) Clear(r string) error {
	addr, _, _, err := s.Normalize(r)
	if err != nil {
		return err
	}

	s.Lock()
	defer s.Unlock()

	rf := filepath.Join(s.recipientDir, r, ".pem")
	if err := os.Remove(rf); err != nil {
		return errNoSuchRecipient
	}
	if _, ok := s.recipients[addr]; ok {
		delete(s.recipients, addr)
		return nil
	}
	return errNoSuchRecipient
}

// CloneRecipients returns a copy of the internal recipient map.
func (s *Store) CloneRecipients() map[string]*ecdh.PublicKey {
	m := make(map[string]*ecdh.PublicKey)

	s.Lock()
	defer s.Unlock()

	for addr, pubKey := range s.recipients {
		pk := new(ecdh.PublicKey)
		pk.FromBytes(pubKey.Bytes())
		m[addr] = pk
	}
	return m
}

func (s *Store) onGetRecipient(c *thwack.Conn, l string) error {
	sp := strings.Split(l, " ")
	if len(sp) != 2 {
		c.Log().Debugf("GET_RECIPIENT invalid syntax: '%v'", l)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	pubKey := s.Get(sp[1])
	if pubKey == nil {
		c.Log().Debugf("Failed to query recipient '%v'", sp[1])
		return c.WriteReply(thwack.StatusTransactionFailed)
	}

	return c.Writer().PrintfLine("%v %v", thwack.StatusOk, pubKey)
}

func (s *Store) onSetRecipient(c *thwack.Conn, l string) error {
	sp := strings.Split(l, " ")
	if len(sp) != 3 {
		c.Log().Debugf("SET_RECIPIENT invalid syntax: '%v'", l)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	// Deserialize the public key.
	var pubKey ecdh.PublicKey
	if err := pubKey.FromString(sp[2]); err != nil {
		c.Log().Debugf("SET_RECIPIENT invalid public key: %v", err)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	if err := s.Set(sp[1], &pubKey); err != nil {
		c.Log().Errorf("Failed to add recipient '%v': %v", sp[1], err)
		return c.WriteReply(thwack.StatusTransactionFailed)
	}

	return c.WriteReply(thwack.StatusOk)
}

func (s *Store) onRemoveRecipient(c *thwack.Conn, l string) error {
	sp := strings.Split(l, " ")
	if len(sp) != 2 {
		c.Log().Debugf("REMOVE_RECIPIENT invalid syntax: '%v'", l)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	if err := s.Clear(sp[1]); err != nil {
		c.Log().Debugf("Failed to remove recipient '%v': %v", sp[1], err)
		return c.WriteReply(thwack.StatusTransactionFailed)
	}

	return c.WriteReply(thwack.StatusOk)
}

func (s *Store) onListRecipients(c *thwack.Conn, l string) error {
	if sp := strings.Split(l, " "); len(sp) != 1 {
		c.Log().Debugf("LIST_RECIPIENTS invalid syntax: '%v'", l)
		return c.WriteReply(thwack.StatusSyntaxError)
	}

	wr := c.Writer().DotWriter()
	recipients := s.CloneRecipients()
	for addr, pubKey := range recipients {
		if _, err := fmt.Fprintf(wr, "%v %v\n", addr, pubKey); err != nil {
			wr.Close()
			return err
		}
	}
	return wr.Close()
}

// New constructs a new Store instance.
func New(cfg *config.Config, t *thwack.Server) *Store {
	s := new(Store)
	s.recipients = make(map[string]*ecdh.PublicKey)
	s.recipientDir = cfg.Proxy.RecipientDir
	s.caseSensitiveUsers = cfg.Debug.CaseSensitiveUserIdentifiers

	// Register management commands.
	if t != nil {
		const (
			cmdGetRecipient    = "GET_RECIPIENT"
			cmdSetRecipient    = "SET_RECIPIENT"
			cmdRemoveRecipient = "REMOVE_RECIPIENT"
			cmdListRecipients  = "LIST_RECIPIENTS"
		)

		t.RegisterCommand(cmdGetRecipient, s.onGetRecipient)
		t.RegisterCommand(cmdSetRecipient, s.onSetRecipient)
		t.RegisterCommand(cmdRemoveRecipient, s.onRemoveRecipient)
		t.RegisterCommand(cmdListRecipients, s.onListRecipients)
	}

	return s
}
