package httpclient

import (
	"bytes"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"

	"github.com/lengzuo/supa/pkg/logger"
	"github.com/lengzuo/supa/utils/enum"
)

type Resp struct {
	Body       bytes.Buffer
	Header     http.Header
	StatusCode int
}

type StreamResp struct {
	Response *http.Response
}

func (s StreamResp) Close() error {
	return s.Response.Body.Close()
}

func AuthHeader(format string, token string) func() (string, string) {
	return func() (string, string) {
		return enum.Authorization.String(), fmt.Sprintf("%s %s", format, token)
	}
}

func GetFileBuffer(fileHeader *multipart.FileHeader, params map[string]string) (*bytes.Buffer, error) {
	file, err := fileHeader.Open()
	if err != nil {
		logger.Logger.Error("failed in open file upload file with err: %s", err)
		return nil, err
	}
	defer file.Close()
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile("", fileHeader.Filename)
	if err != nil {
		logger.Logger.Error("failed in CreateFormFile with err: %s", err)
		return nil, err
	}
	_, err = io.Copy(part, file)
	// Extra form data params
	for key, val := range params {
		_ = writer.WriteField(key, val)
	}
	err = writer.Close()
	if err != nil {
		return nil, err
	}
	return body, nil
}
