package vaultlib

import (
	"encoding/json"
	"fmt"
	"time"
	"github.com/pkg/errors"
)

// vaultAuth holds the Vault Auth response from server
type vaultAuth struct {
	ClientToken string   `json:"client_token"`
	Accessor    string   `json:"accessor"`
	Policies    []string `json:"policies"`
	Metadata    struct {
		RoleName string `json:"role_name"`
	} `json:"metadata"`
	LeaseDuration int    `json:"lease_duration"`
	Renewable     bool   `json:"renewable"`
	EntityID      string `json:"entity_id"`
}

// renew the client's token, launched at client creation time as a go routine
func (c *Client) renewToken() {
	var vaultData vaultAuth
	jsonToken := make(map[string]string)

	for {
		timeToRenewal := c.tokenTTL / 2
		time.Sleep(timeToRenewal)

		// Check if we're approaching the Max TTL
		if time.Since(c.tokenCreationTime)+timeToRenewal >= c.tokenMaxTTL {
			if err := c.reAuthenticate(); err != nil {
				c.setStatus("Error re-authenticating: " + err.Error())
				continue
			}
			c.setStatus("Re-authenticated with a new token")
			continue
		}

		url := c.address.String() + "/v1/auth/token/renew-self"

		req, _ := c.newRequest("POST", url)

		// Sending a payload (even empty) is required for vault to respond with the `auth` param
		_ = req.setJSONBody(jsonToken)

		resp, err := req.execute()
		if err != nil {
			c.setStatus("Error renewing token " + err.Error())
			continue
		}

		jsonErr := json.Unmarshal([]byte(resp.Auth), &vaultData)
		if jsonErr != nil {
			c.setStatus("Error renewing token " + jsonErr.Error())
			continue
		}

		if err := c.setTokenInfo(); err != nil {
			c.setStatus("Error renewing token " + err.Error())
			continue
		}

		c.withLockContext(func() {
			c.tokenTTL = time.Duration(vaultData.LeaseDuration) * time.Second
		})

		c.setStatus("token renewed")
	}
}

// setTokenFromAppRole get the token from Vault and set it in the client
func (c *Client) setTokenFromAppRole() error {
	var vaultData vaultAuth

	mp := "approle"
	if c.appRoleCredentials.MountPoint != "" {
		mp = c.appRoleCredentials.MountPoint
	}

	if c.appRoleCredentials.RoleID == "" || c.appRoleCredentials.SecretID == "" {
		return errors.New("No credentials provided")
	}

	url := fmt.Sprintf("%s/v1/auth/%s/login", c.address.String(), mp)

	req, _ := c.newRequest("POST", url)

	_ = req.setJSONBody(c.appRoleCredentials)

	resp, err := req.execute()
	if err != nil {
		return errors.Wrap(errors.WithStack(err), errInfo())
	}

	jsonErr := json.Unmarshal([]byte(resp.Auth), &vaultData)
	if jsonErr != nil {
		return errors.Wrap(errors.WithStack(err), errInfo())
	}
	c.withLockContext(func() {
		c.token.ID = vaultData.ClientToken
		c.tokenCreationTime = time.Now()
		c.tokenTTL = time.Duration(vaultData.LeaseDuration) * time.Second
	})

	if err = c.setTokenInfo(); err != nil {
		return errors.Wrap(errors.WithStack(err), errInfo())
	}
	if c.token.Renewable {
		c.tokenMaxTTL = time.Duration(c.token.ExplicitMaxTTL) * time.Second
		go c.renewToken()
	}

	return nil
}

// vaultSecretKV2 holds the Vault secret (kv v2)
type vaultSecretKV2 struct {
	Data     map[string]interface{} `json:"data"`
	Metadata struct {
		CreatedTime  time.Time `json:"created_time"`
		DeletionTime string    `json:"deletion_time"`
		Destroyed    bool      `json:"destroyed"`
		Version      int       `json:"version"`
	} `json:"metadata"`
}

func (c *Client) setTokenInfo() error {
	url := c.address.String() + "/v1/auth/token/lookup-self"
	var tokenInfo VaultTokenInfo

	req, _ := c.newRequest("GET", url)

	res, err := req.execute()
	if err != nil {
		return err
	}
	if err := json.Unmarshal(res.Data, &tokenInfo); err != nil {
		return err
	}
	c.withLockContext(func() {
		c.token = &tokenInfo
		c.isAuthenticated = true
	})
	return nil
}

func (c *Client) reAuthenticate() error {
	c.withLockContext(func() {
		c.isAuthenticated = false
	})
	return c.setTokenFromAppRole()
}
