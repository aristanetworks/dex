// Code generated by ent, DO NOT EDIT.

package refreshtoken

import (
	"time"

	"entgo.io/ent/dialect/sql"
)

const (
	// Label holds the string label denoting the refreshtoken type in the database.
	Label = "refresh_token"
	// FieldID holds the string denoting the id field in the database.
	FieldID = "id"
	// FieldClientID holds the string denoting the client_id field in the database.
	FieldClientID = "client_id"
	// FieldScopes holds the string denoting the scopes field in the database.
	FieldScopes = "scopes"
	// FieldNonce holds the string denoting the nonce field in the database.
	FieldNonce = "nonce"
	// FieldClaimsUserID holds the string denoting the claims_user_id field in the database.
	FieldClaimsUserID = "claims_user_id"
	// FieldClaimsUsername holds the string denoting the claims_username field in the database.
	FieldClaimsUsername = "claims_username"
	// FieldClaimsEmail holds the string denoting the claims_email field in the database.
	FieldClaimsEmail = "claims_email"
	// FieldClaimsEmailVerified holds the string denoting the claims_email_verified field in the database.
	FieldClaimsEmailVerified = "claims_email_verified"
	// FieldClaimsGroups holds the string denoting the claims_groups field in the database.
	FieldClaimsGroups = "claims_groups"
	// FieldClaimsPreferredUsername holds the string denoting the claims_preferred_username field in the database.
	FieldClaimsPreferredUsername = "claims_preferred_username"
	// FieldConnectorID holds the string denoting the connector_id field in the database.
	FieldConnectorID = "connector_id"
	// FieldConnectorData holds the string denoting the connector_data field in the database.
	FieldConnectorData = "connector_data"
	// FieldToken holds the string denoting the token field in the database.
	FieldToken = "token"
	// FieldObsoleteToken holds the string denoting the obsolete_token field in the database.
	FieldObsoleteToken = "obsolete_token"
	// FieldCreatedAt holds the string denoting the created_at field in the database.
	FieldCreatedAt = "created_at"
	// FieldLastUsed holds the string denoting the last_used field in the database.
	FieldLastUsed = "last_used"
	// Table holds the table name of the refreshtoken in the database.
	Table = "refresh_tokens"
)

// Columns holds all SQL columns for refreshtoken fields.
var Columns = []string{
	FieldID,
	FieldClientID,
	FieldScopes,
	FieldNonce,
	FieldClaimsUserID,
	FieldClaimsUsername,
	FieldClaimsEmail,
	FieldClaimsEmailVerified,
	FieldClaimsGroups,
	FieldClaimsPreferredUsername,
	FieldConnectorID,
	FieldConnectorData,
	FieldToken,
	FieldObsoleteToken,
	FieldCreatedAt,
	FieldLastUsed,
}

// ValidColumn reports if the column name is valid (part of the table columns).
func ValidColumn(column string) bool {
	for i := range Columns {
		if column == Columns[i] {
			return true
		}
	}
	return false
}

var (
	// ClientIDValidator is a validator for the "client_id" field. It is called by the builders before save.
	ClientIDValidator func(string) error
	// NonceValidator is a validator for the "nonce" field. It is called by the builders before save.
	NonceValidator func(string) error
	// ClaimsUserIDValidator is a validator for the "claims_user_id" field. It is called by the builders before save.
	ClaimsUserIDValidator func(string) error
	// ClaimsUsernameValidator is a validator for the "claims_username" field. It is called by the builders before save.
	ClaimsUsernameValidator func(string) error
	// ClaimsEmailValidator is a validator for the "claims_email" field. It is called by the builders before save.
	ClaimsEmailValidator func(string) error
	// DefaultClaimsPreferredUsername holds the default value on creation for the "claims_preferred_username" field.
	DefaultClaimsPreferredUsername string
	// ConnectorIDValidator is a validator for the "connector_id" field. It is called by the builders before save.
	ConnectorIDValidator func(string) error
	// DefaultToken holds the default value on creation for the "token" field.
	DefaultToken string
	// DefaultObsoleteToken holds the default value on creation for the "obsolete_token" field.
	DefaultObsoleteToken string
	// DefaultCreatedAt holds the default value on creation for the "created_at" field.
	DefaultCreatedAt func() time.Time
	// DefaultLastUsed holds the default value on creation for the "last_used" field.
	DefaultLastUsed func() time.Time
	// IDValidator is a validator for the "id" field. It is called by the builders before save.
	IDValidator func(string) error
)

// OrderOption defines the ordering options for the RefreshToken queries.
type OrderOption func(*sql.Selector)

// ByID orders the results by the id field.
func ByID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldID, opts...).ToFunc()
}

// ByClientID orders the results by the client_id field.
func ByClientID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldClientID, opts...).ToFunc()
}

// ByNonce orders the results by the nonce field.
func ByNonce(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldNonce, opts...).ToFunc()
}

// ByClaimsUserID orders the results by the claims_user_id field.
func ByClaimsUserID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldClaimsUserID, opts...).ToFunc()
}

// ByClaimsUsername orders the results by the claims_username field.
func ByClaimsUsername(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldClaimsUsername, opts...).ToFunc()
}

// ByClaimsEmail orders the results by the claims_email field.
func ByClaimsEmail(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldClaimsEmail, opts...).ToFunc()
}

// ByClaimsEmailVerified orders the results by the claims_email_verified field.
func ByClaimsEmailVerified(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldClaimsEmailVerified, opts...).ToFunc()
}

// ByClaimsPreferredUsername orders the results by the claims_preferred_username field.
func ByClaimsPreferredUsername(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldClaimsPreferredUsername, opts...).ToFunc()
}

// ByConnectorID orders the results by the connector_id field.
func ByConnectorID(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldConnectorID, opts...).ToFunc()
}

// ByToken orders the results by the token field.
func ByToken(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldToken, opts...).ToFunc()
}

// ByObsoleteToken orders the results by the obsolete_token field.
func ByObsoleteToken(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldObsoleteToken, opts...).ToFunc()
}

// ByCreatedAt orders the results by the created_at field.
func ByCreatedAt(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldCreatedAt, opts...).ToFunc()
}

// ByLastUsed orders the results by the last_used field.
func ByLastUsed(opts ...sql.OrderTermOption) OrderOption {
	return sql.OrderByField(FieldLastUsed, opts...).ToFunc()
}
