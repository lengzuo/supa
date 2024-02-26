package supabase

import (
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/lengzuo/supa/pkg/catch"
	"github.com/lengzuo/supa/pkg/httpclient"
	"github.com/lengzuo/supa/pkg/logger"
	"github.com/lengzuo/supa/utils/enum"
)

type storageAPI interface {
	GetPublicUrl(mediaPath string) string
	UploadFile(ctx context.Context, targetFilePath, mimeType string, fileData io.Reader) error
}

type storage struct {
	client
	bucket string
}

func newStorage(c client, bucket string) *storage {
	return &storage{c, bucket}
}

func (i *storage) UploadFile(ctx context.Context, targetFilePath, mimeType string, fileData io.Reader) error {
	reqURL := fmt.Sprintf("%s/object/%s/%s", i.storageHost, i.bucket, targetFilePath)
	httpResp, err := i.httpClient.Upload(ctx, reqURL, http.MethodPost, fileData, func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
		req.Header.Set(enum.Authorization.String(), fmt.Sprintf("%s %s", authPrefix, i.apiKey))
		req.Header.Set(enum.ContentType.String(), mimeType)
	})
	if err != nil {
		logger.Logger.Error("failed in httpclient call with catch: %s", err)
		return err
	}
	if !httpclient.IsHTTPSuccess(httpResp.StatusCode) {
		logger.Logger.Warn("getting %d in sign out due to catch: %s", httpResp.StatusCode, httpResp.Body.String())
		return catch.External(httpResp.Body.Bytes(), httpResp.StatusCode)
	}
	return nil
}

func (i *storage) GetPublicUrl(mediaPath string) string {
	return i.storageHost + "/object/public/" + i.bucket + "/" + mediaPath
}
