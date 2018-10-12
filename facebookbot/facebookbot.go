package facebookbot

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
)

type Client struct {
	appSecret       string
	pageAccessToken string
}

type User struct {
	ID string `json:"id"`
}

type Message struct {
	Mid        string `json:"mid"`
	Seq        int    `json:"seq"`
	Text       string `json:"text,omitempty"`
	QuickReply struct {
		Payload string `json:"payload"`
	} `json:"quick_reply,omitempty"`
	StickerID   string `json:"sticker_id,omitempty"`
	Attachments struct {
		Payload string `json:"payload"`
	} `json:"attachments,omitempty"`
}

type Postback struct {
	Payload string `json:"payload"`
}

type Messaging struct {
	Sender    *User     `json:"sender"`
	Recipient *User     `json:"recipient"`
	Timestamp int64     `json:"timestamp"`
	Message   *Message  `json:"message,omitempty"`
	Postback  *Postback `json:"postback,omitempty"`
}

type Entry struct {
	ID         string       `json:"id"`
	Time       int64        `json:"time"`
	Messagings []*Messaging `json:"messaging"`
}

type Event struct {
	Object  string   `json:"object"`
	Entries []*Entry `json:"entry"`
}

type PushPayload struct {
	Recipient *User  `json:"recipient"`
	Message   string `json:"message"`
}

func New(appSecret string, pageAccessToken string) *Client {
	return &Client{
		appSecret:       appSecret,
		pageAccessToken: pageAccessToken,
	}
}

// ParseRequest parse request and return the result. If appSecret is empty, it will skip validating signature.
func (c *Client) ParseRequest(r *http.Request) (*Event, error) {
	defer r.Body.Close()
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}

	if c.appSecret != "" {
		if !validateSignature(c.appSecret, r.Header.Get("X-Hub-Signature"), body) {
			fmt.Println(r.Header.Get("X-Hub-Signature"))
			fmt.Println(string(body))

			return nil, errors.New("invalid signature")
		}
	}

	event := &Event{}
	if err = json.Unmarshal(body, event); err != nil {
		return nil, err
	}
	return event, nil
}

func validateSignature(appSecret, signature string, body []byte) bool {
	const signaturePrefix = "sha1="

	if !strings.HasPrefix(signature, signaturePrefix) {
		return false
	}

	xhub := signature[len(signaturePrefix):]

	hash := hmac.New(sha1.New, []byte(appSecret))
	hash.Write(body)
	expected := hex.EncodeToString(hash.Sum(nil))
	return xhub == expected
}

func (c *Client) PushMessage(psid string, text string) error {
	if c.pageAccessToken == "" {
		return errors.New("pageAccessToken variable is empty.")
	}

	payload := &PushPayload{
		Recipient: &User{
			ID: psid,
		},
		Message: text,
	}

	reqBytes, _ := json.Marshal(payload)

	reqBody := bytes.NewBufferString(string(reqBytes))

	client := &http.Client{}
	req, _ := http.NewRequest("POST", fmt.Sprintf("https://graph.facebook.com/v2.6/me/messages?access_token=%s", c.pageAccessToken), reqBody)
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)

	if err != nil {
		return err
	}

	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("http status error %d", response.StatusCode)
	}

	if _, err := ioutil.ReadAll(response.Body); err != nil {
		return err
	}

	return nil
}
