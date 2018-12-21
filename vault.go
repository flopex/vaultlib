package vaultlib

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/pkg/errors"
)

//VaultResponse holds the generic json response from Vault server
type VaultResponse struct {
	RequestID     string          `json:"request_id"`
	LeaseID       string          `json:"lease_id"`
	Renewable     bool            `json:"renewable"`
	LeaseDuration int             `json:"lease_duration"`
	Data          json.RawMessage `json:"data"`
	WrapInfo      json.RawMessage `json:"wrap_info"`
	Warnings      json.RawMessage `json:"warnings"`
	Auth          json.RawMessage `json:"auth"`
}

//VaultMountResponse holds the Vault Mount list response (used to unmarshall the globa vault response)
type VaultMountResponse struct {
	Auth   json.RawMessage `json:"auth"`
	Secret json.RawMessage `json:"secret"`
}

// VaultSecretMounts hodls the vault secret engine def
type VaultSecretMounts struct {
	Name     string `json:"??,string"`
	Accessor string `json:"accessor"`
	Config   struct {
		DefaultLeaseTTL int    `json:"default_lease_ttl"`
		ForceNoCache    bool   `json:"force_no_cache"`
		MaxLeaseTTL     int    `json:"max_lease_ttl"`
		PluginName      string `json:"plugin_name"`
	} `json:"config"`
	Description string                 `json:"description"`
	Local       bool                   `json:"local"`
	Options     map[string]interface{} `json:"options"`
	SealWrap    bool                   `json:"seal_wrap"`
	Type        string                 `json:"type"`
}

func (c *VaultClient) getKVInfo(path string) (version, name string, err error) {
	req := new(request)
	req.Method = "GET"
	req.URL = c.Address
	req.URL.Path = "/v1/sys/internal/ui/mounts"
	req.Token = c.Token
	err = req.prepareRequest()
	if err != nil {
		return "", "", err
	}

	rsp, err := req.execute(c.HTTPClient)
	if err != nil {
		return "", "", errors.Wrap(errors.WithStack(err), errInfo())
	}
	var mountResponse VaultMountResponse
	var vaultSecretMount = make(map[string]VaultSecretMounts)
	jsonErr := json.Unmarshal([]byte(rsp.Data), &mountResponse)
	if jsonErr != nil {
		return "", "", errors.Wrap(errors.WithStack(err), errInfo())
	}

	jsonErr = json.Unmarshal([]byte(mountResponse.Secret), &vaultSecretMount)
	if jsonErr != nil {
		return "", "", errors.Wrap(errors.WithStack(err), errInfo())
	}

	for _, v := range vaultSecretMount {
		if strings.HasPrefix(path, v.Name) {
			name = v.Name
			if len(v.Options) > 0 {
				switch v.Options["version"].(type) {
				case string:
					version = v.Options["version"].(string)
				default:
					version = "1"
				}
			} else {
				//kv v1
				version = "1"
			}
		}
	}
	if len(version) == 0 {
		return "", "", errors.New("Could not get kv version")
	}
	return version, name, nil

}

// VaultSecretv2 holds the Vault secret (kv v2)
type VaultSecretKV2 struct {
	Data struct {
		Data     map[string]string `json:"data"`
		Metadata struct {
			CreatedTime  time.Time `json:"created_time"`
			DeletionTime string    `json:"deletion_time"`
			Destroyed    bool      `json:"destroyed"`
			Version      int       `json:"version"`
		} `json:"metadata"`
	} `json:"data"`
}

// VaultSecret holds the Vault secret (kv v1)
type VaultSecret struct {
	Data map[string]string `json:"data"`
}

func (c *VaultClient) GetVaultSecret(path string) (kv map[string]string, err error) {
	secretList := make(map[string]string)

	kvVersion, kvName, err := c.getKVInfo(path)
	if err != nil {
		return secretList, err
	}

	req := new(request)
	req.Method = "GET"
	req.URL = c.Address
	if kvVersion == "2" {
		req.URL.Path = "/v1/" + kvName + "/data/" + strings.TrimPrefix(path, kvName)
	}
	req.Token = c.Token

	err = req.prepareRequest()
	if err != nil {
		return secretList, err
	}

	rsp, err := req.execute(c.HTTPClient)
	if err != nil {
		return secretList, errors.Wrap(errors.WithStack(err), errInfo())
	}

	// parse to Vx and get a simple kv map back
	if kvVersion == "2" {
		var v2Secret VaultSecretKV2
		err = json.Unmarshal([]byte(rsp.Data), &v2Secret)
		if err != nil {
			return secretList, err
		}
		for k, v := range v2Secret.Data.Data {
			secretList[k] = v
		}
	} else if kvVersion == "1" {
		v1Secret := make(map[string]string)
		err = json.Unmarshal([]byte(rsp.Data), v1Secret)
		if err != nil {
			return secretList, err
		}
		for k, v := range v1Secret {
			secretList[k] = v
		}

	}

	return secretList, nil
}
