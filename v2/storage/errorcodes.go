package storage

import "errors"

// Storage error codes, as reported in Error.Code (the "code" field of
// Storage API error bodies).
//
// Source: every value below is copied from the ErrorCode enum in the
// Storage server, supabase/storage src/internal/errors/codes.ts (master
// at 2a3e5f7812554d1c9cbd36237c14eb3df09a9bb5); the comment on each
// constant names its enum member. The server defines more codes than are
// listed here and may add new ones, so compare Error.Code against a string
// for anything not listed. See also
// https://supabase.com/docs/guides/storage/debugging/error-codes.
const (
	// CodeNoSuchBucket is ErrorCode.NoSuchBucket.
	CodeNoSuchBucket = "NoSuchBucket"
	// CodeNoSuchKey is ErrorCode.NoSuchKey.
	CodeNoSuchKey = "NoSuchKey"
	// CodeNoSuchUpload is ErrorCode.NoSuchUpload.
	CodeNoSuchUpload = "NoSuchUpload"
	// CodeNoSuchLifecycleConfiguration is
	// ErrorCode.NoSuchLifecycleConfiguration.
	CodeNoSuchLifecycleConfiguration = "NoSuchLifecycleConfiguration"
	// CodeInvalidJWT is ErrorCode.InvalidJWT.
	CodeInvalidJWT = "InvalidJWT"
	// CodeInvalidRequest is ErrorCode.InvalidRequest.
	CodeInvalidRequest = "InvalidRequest"
	// CodeTenantNotFound is ErrorCode.TenantNotFound.
	CodeTenantNotFound = "TenantNotFound"
	// CodeEntityTooLarge is ErrorCode.EntityTooLarge.
	CodeEntityTooLarge = "EntityTooLarge"
	// CodeInternalError is ErrorCode.InternalError.
	CodeInternalError = "InternalError"
	// CodeResourceAlreadyExists is ErrorCode.ResourceAlreadyExists.
	CodeResourceAlreadyExists = "ResourceAlreadyExists"
	// CodeInvalidBucketName is ErrorCode.InvalidBucketName.
	CodeInvalidBucketName = "InvalidBucketName"
	// CodeInvalidKey is ErrorCode.InvalidKey.
	CodeInvalidKey = "InvalidKey"
	// CodeInvalidRange is ErrorCode.InvalidRange.
	CodeInvalidRange = "InvalidRange"
	// CodeInvalidMimeType is ErrorCode.InvalidMimeType.
	CodeInvalidMimeType = "InvalidMimeType"
	// CodeInvalidUploadID is ErrorCode.InvalidUploadId.
	CodeInvalidUploadID = "InvalidUploadId"
	// CodeKeyAlreadyExists is ErrorCode.KeyAlreadyExists.
	CodeKeyAlreadyExists = "KeyAlreadyExists"
	// CodeBucketAlreadyExists is ErrorCode.BucketAlreadyExists.
	CodeBucketAlreadyExists = "BucketAlreadyExists"
	// CodeDatabaseTimeout is ErrorCode.DatabaseTimeout.
	CodeDatabaseTimeout = "DatabaseTimeout"
	// CodeInvalidSignature is ErrorCode.InvalidSignature.
	CodeInvalidSignature = "InvalidSignature"
	// CodeSignatureDoesNotMatch is ErrorCode.SignatureDoesNotMatch.
	CodeSignatureDoesNotMatch = "SignatureDoesNotMatch"
	// CodeAccessDenied is ErrorCode.AccessDenied.
	CodeAccessDenied = "AccessDenied"
	// CodeResourceLocked is ErrorCode.ResourceLocked.
	CodeResourceLocked = "ResourceLocked"
	// CodeDatabaseError is ErrorCode.DatabaseError.
	CodeDatabaseError = "DatabaseError"
	// CodeMissingContentLength is ErrorCode.MissingContentLength.
	CodeMissingContentLength = "MissingContentLength"
	// CodeMissingParameter is ErrorCode.MissingParameter.
	CodeMissingParameter = "MissingParameter"
	// CodeInvalidUploadSignature is ErrorCode.InvalidUploadSignature.
	CodeInvalidUploadSignature = "InvalidUploadSignature"
	// CodeLockTimeout is ErrorCode.LockTimeout.
	CodeLockTimeout = "LockTimeout"
	// CodeS3Error is ErrorCode.S3Error.
	CodeS3Error = "S3Error"
	// CodeS3InvalidAccessKeyID is ErrorCode.S3InvalidAccessKeyId, whose
	// wire value is "InvalidAccessKeyId" (without the S3 prefix).
	CodeS3InvalidAccessKeyID = "InvalidAccessKeyId"
	// CodeS3MaximumCredentialsLimit is ErrorCode.S3MaximumCredentialsLimit,
	// whose wire value is "MaximumCredentialsLimit" (without the S3
	// prefix).
	CodeS3MaximumCredentialsLimit = "MaximumCredentialsLimit"
	// CodeInvalidChecksum is ErrorCode.InvalidChecksum.
	CodeInvalidChecksum = "InvalidChecksum"
	// CodeMissingPart is ErrorCode.MissingPart.
	CodeMissingPart = "MissingPart"
	// CodeSlowDown is ErrorCode.SlowDown.
	CodeSlowDown = "SlowDown"
	// CodeFeatureNotEnabled is ErrorCode.FeatureNotEnabled.
	CodeFeatureNotEnabled = "FeatureNotEnabled"
)

// IsErrorCode reports whether err (or any error it wraps) is an *Error
// whose Code equals code, e.g. IsErrorCode(err, CodeNoSuchKey).
func IsErrorCode(err error, code string) bool {
	var e *Error
	return errors.As(err, &e) && e.Code == code
}
