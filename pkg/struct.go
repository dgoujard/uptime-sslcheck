package pkg

import "encoding/json"

type Alerte struct {
	Site *SiteBdd
	Type string
	Param json.RawMessage `json:"param,omitempty"`
}