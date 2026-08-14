package events

// Event Category
type EventCategory string

const (
	CategoryCompileWarning EventCategory = "COMPILE_WARNING"
	CategoryRuntimeError   EventCategory = "RUNTIME_ERROR"
	CategoryStateChange    EventCategory = "STATE_CHANGE"
	CategoryTrafficStats   EventCategory = "TRAFFIC_STATS"
	CategoryThreatBlocked  EventCategory = "THREAT_BLOCKED"
	CategoryDiagnostic     EventCategory = "DIAGNOSTIC"
)

// Event Severity
type EventSeverity string

const (
	SeverityInfo  EventSeverity = "INFO"
	SeverityWarn  EventSeverity = "WARN"
	SeverityError EventSeverity = "ERROR"
	SeverityFatal EventSeverity = "FATAL"
)

// Standard Error / Event Codes
const (
	CodeFeatureDowngrade      = "WARN_FEATURE_DOWNGRADE"
	CodePortInUse             = "ERR_PORT_IN_USE"
	CodeBinaryNotFound        = "ERR_BINARY_NOT_FOUND"
	CodeCryptoIntegrityFailed = "ERR_CRYPTO_INTEGRITY_FAILED"
	CodeInvalidConfigSyntax   = "ERR_INVALID_CONFIG_SYNTAX"
	CodeCoreCrash             = "ERR_CORE_CRASH"
	CodeHandshakeTimeout      = "ERR_HANDSHAKE_TIMEOUT"
	CodeAdminElevationNeeded  = "ERR_ADMIN_ELEVATION_NEEDED"
	CodeThreatAppIsolated     = "INFO_THREAT_APP_ISOLATED"
	CodeHealthCheckPassed     = "INFO_HEALTH_CHECK_PASSED"
	CodeHealthCheckFailed     = "ERR_HEALTH_CHECK_FAILED"
)

// Suggested Actions
const (
	ActionNone                 = "NONE"
	ActionSwitchCoreToSingBox  = "SWITCH_CORE_TO_SINGBOX"
	ActionSwitchCoreToXray     = "SWITCH_CORE_TO_XRAY"
	ActionRerunAsAdmin         = "RERUN_AS_ADMIN"
	ActionDownloadCoreBinary   = "DOWNLOAD_CORE_BINARY"
	ActionKillConflictingPort  = "KILL_CONFLICTING_PORT"
	ActionVerifyMasterSecret   = "VERIFY_MASTER_SECRET"
)
