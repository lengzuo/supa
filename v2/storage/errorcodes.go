package storage

import "errors"

// Storage error codes, as reported in Error.Code. They are the values of
// the "code" field in Storage API error bodies. The list follows
// https://supabase.com/docs/guides/storage/debugging/error-codes; the
// server may return codes that are not listed here.
const (
	CodeNoSuchBucket                 = "NoSuchBucket"
	CodeNoSuchKey                    = "NoSuchKey"
	CodeNoSuchUpload                 = "NoSuchUpload"
	CodeNoSuchLifecycleConfiguration = "NoSuchLifecycleConfiguration"
	CodeInvalidJWT                   = "InvalidJWT"
	CodeInvalidRequest               = "InvalidRequest"
	CodeTenantNotFound               = "TenantNotFound"
	CodeEntityTooLarge               = "EntityTooLarge"
	CodeInternalError                = "InternalError"
	CodeResourceAlreadyExists        = "ResourceAlreadyExists"
	CodeInvalidBucketName            = "InvalidBucketName"
	CodeInvalidKey                   = "InvalidKey"
	CodeInvalidRange                 = "InvalidRange"
	CodeInvalidMimeType              = "InvalidMimeType"
	CodeInvalidUploadID              = "InvalidUploadId"
	CodeKeyAlreadyExists             = "KeyAlreadyExists"
	CodeBucketAlreadyExists          = "BucketAlreadyExists"
	CodeDatabaseTimeout              = "DatabaseTimeout"
	CodeInvalidSignature             = "InvalidSignature"
	CodeSignatureDoesNotMatch        = "SignatureDoesNotMatch"
	CodeAccessDenied                 = "AccessDenied"
	CodeResourceLocked               = "ResourceLocked"
	CodeDatabaseError                = "DatabaseError"
	CodeMissingContentLength         = "MissingContentLength"
	CodeMissingParameter             = "MissingParameter"
	CodeInvalidUploadSignature       = "InvalidUploadSignature"
	CodeLockTimeout                  = "LockTimeout"
	CodeS3Error                      = "S3Error"
	CodeS3InvalidAccessKeyID         = "S3InvalidAccessKeyId"
	CodeS3MaximumCredentialsLimit    = "S3MaximumCredentialsLimit"
	CodeInvalidChecksum              = "InvalidChecksum"
	CodeMissingPart                  = "MissingPart"
	CodeSlowDown                     = "SlowDown"
	CodeFeatureNotEnabled            = "FeatureNotEnabled"
)

// IsErrorCode reports whether err (or any error it wraps) is an *Error
// whose Code equals code, e.g. IsErrorCode(err, CodeNoSuchKey).
func IsErrorCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}
