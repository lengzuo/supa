package supabase

import (
	"context"
	"fmt"
	"mime/multipart"
	"net/http"

	"github.com/lengzuo/supa/pkg/catch"
	"github.com/lengzuo/supa/pkg/httpclient"
	"github.com/lengzuo/supa/pkg/logger"
	"github.com/lengzuo/supa/utils/enum"
)

const applicationPDF = "application/pdf"

type storageAPI interface {
	UploadFile(ctx context.Context, targetFilePath string, fileHeader *multipart.FileHeader) error
}

type storage struct {
	client
	bucket string
}

func newStorage(c client, bucket string) *storage {
	return &storage{c, bucket}
}

func (i *storage) UploadFile(ctx context.Context, targetFilePath string, fileHeader *multipart.FileHeader) error {
	fileBuffer, err := httpclient.GetFileBuffer(fileHeader, nil)
	if err != nil {
		return err
	}
	reqURL := fmt.Sprintf("%s/object/%s/%s", i.storageHost, i.bucket, targetFilePath)
	httpResp, err := i.httpClient.Call(ctx, reqURL, http.MethodPost, fileBuffer.Bytes(), func(req *http.Request) {
		req.Header.Set(authorizationHeader, i.apiKey)
		req.Header.Set(enum.ContentType.String(), applicationPDF)
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
