package supabase

import (
	"context"
	"fmt"
	"io"
	"net/http"
)

type storageAPI interface {
	GetPublicUrl(mediaPath string) string
	UploadFile(ctx context.Context, targetFilePath, mimeType string, fileData io.Reader) error
}

type Storage struct {
	apiKey      string
	storageHost string
	bucket      string
	httpClient  Sender
}

type StorageOption func(c *Storage)

func WithStorageClient(httpClient *http.Client, header map[string]string) StorageOption {
	return func(c *Storage) {
		c.httpClient = newRequester(httpClient, header)
	}
}

func NewStorage(apiKey, storageHost, bucket string, options ...StorageOption) *Storage {
	impl := &Storage{
		apiKey:      apiKey,
		storageHost: storageHost,
		bucket:      bucket,
		httpClient:  defaultSender(httpTimeout, make(map[string]string)),
	}
	for _, opt := range options {
		opt(impl)
	}
	return impl
}

func (i *Storage) UploadFile(ctx context.Context, targetFilePath, mimeType string, fileData io.Reader) error {
	reqURL := fmt.Sprintf("%s/object/%s/%s", i.storageHost, i.bucket, targetFilePath)
	httpResp, err := i.httpClient.Upload(ctx, reqURL, http.MethodPost, fileData, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
		req.Header.Set(HeaderAuthorization.String(), fmt.Sprintf("%s %s", authPrefix, i.apiKey))
		req.Header.Set(HeaderContentType.String(), mimeType)
	})
	if err != nil {
		logger.Error("failed in httpclient call with catch: %s", err)
		return err
	}
	if !isHTTPSuccess(httpResp.StatusCode) {
		logger.Warn("getting %d in sign out due to catch: %s", httpResp.StatusCode, httpResp.Body.String())
		return External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	return nil
}

func (i *Storage) GetPublicUrl(mediaPath string) string {
	return i.storageHost + "/object/public/" + i.bucket + "/" + mediaPath
}
