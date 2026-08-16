package types

import "github.com/blackalex1/sentinel-core/pkg/routing"

// SelectOption represents a selectable option in dropdown fields
type SelectOption struct {
	Value       string `json:"value"`
	Label       string `json:"label"`
	Description string `json:"description,omitempty"`
}

// FormField defines a single input/control in the Schema-Driven UI
type FormField struct {
	ID          string                 `json:"id"`
	TargetField string                 `json:"targetField"`
	Type        string                 `json:"type"` // "text", "number", "password", "select", "checkbox", "keypair_generator", "password_generator", "port_generator", "clients_manager", "json_editor"
	Label       string                 `json:"label"`
	Placeholder string                 `json:"placeholder,omitempty"`
	HelpText    string                 `json:"helpText,omitempty"`
	Default     interface{}            `json:"default,omitempty"`
	Options     []SelectOption         `json:"options,omitempty"`
	GridColumn  string                 `json:"gridColumn,omitempty"` // "col-12", "col-6", "col-4"
	ShowIf      map[string]interface{} `json:"showIf,omitempty"`     // Conditional visibility map
	Min         *int                   `json:"min,omitempty"`
	Max         *int                   `json:"max,omitempty"`
}

// FieldGroup defines a card/subgroup containing related fields
type FieldGroup struct {
	ID          string                 `json:"id"`
	Title       string                 `json:"title,omitempty"`
	Description string                 `json:"description,omitempty"`
	ShowIf      map[string]interface{} `json:"showIf,omitempty"`
	Fields      []FormField            `json:"fields"`
}

// TabDefinition defines a single tab in the modal with its groups and fields
type TabDefinition struct {
	ID     string       `json:"id"`
	Title  string       `json:"title"`
	Icon   string       `json:"icon,omitempty"`
	ShowIf map[string]interface{} `json:"showIf,omitempty"`
	Groups []FieldGroup `json:"groups"`
}

// ProtocolCapability defines allowed configurations for a specific protocol in the UI
type ProtocolCapability struct {
	Protocol            string              `json:"protocol"`            // "vless", "hysteria2", "trojan", etc.
	DisplayName         string              `json:"displayName"`         // "VLESS", "Hysteria 2", "Trojan", etc.
	Description         string              `json:"description,omitempty"`
	DefaultPort         int                 `json:"defaultPort"`         // 443
	SupportedEngines    []string            `json:"supportedEngines"`    // ["xray-core", "sing-box"]
	SupportedTransports []string            `json:"supportedTransports"` // ["tcp", "ws", "grpc", "xhttp"]
	SupportedSecurity   []string            `json:"supportedSecurity"`   // ["reality", "tls", "none"]
	SupportedFlows      map[string][]string `json:"supportedFlows,omitempty"` // {"reality": ["xtls-rprx-vision"], "tls": ["xtls-rprx-vision", "none"]}
	SupportedCiphers    []string            `json:"supportedCiphers,omitempty"`
	Features            []string            `json:"features,omitempty"` // ["port_hopping", "salamander_obfs", "post_quantum"]
	Tabs                []string            `json:"tabs"`               // ["basic", "stream", "security", "sniffing", "advanced"]
	TabDefinitions      []TabDefinition     `json:"tabDefinitions,omitempty"`
}

// EngineOption represents a core engine selectable in the dropdown
type EngineOption struct {
	ID          string   `json:"id"`          // "xray-core", "sing-box", "hysteria2"
	Name        string   `json:"name"`        // "Xray-core", "sing-box", "Hysteria 2"
	Description string   `json:"description"`
	Protocols   []string `json:"protocols"`   // ["vless", "trojan", ...]
}

// SniffingOption represents a sniffing protocol toggle in the modal
type SniffingOption struct {
	ID          string `json:"id"`
	DisplayName string `json:"displayName"`
	Description string `json:"description,omitempty"`
	Default     bool   `json:"default"`
}

// ConfigurationSchema is the master capability matrix sent to Sentinel-Panel frontend
type ConfigurationSchema struct {
	Language          string                        `json:"language"`
	Engines           []EngineOption                `json:"engines"`
	Protocols         map[string]ProtocolCapability `json:"protocols"`
	OutboundProtocols map[string]ProtocolCapability `json:"outboundProtocols,omitempty"`
	SniffingOptions   []SniffingOption              `json:"sniffingOptions"`
	Presets           []routing.PresetSummary       `json:"presets"`
}
