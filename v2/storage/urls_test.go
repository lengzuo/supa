package storage

import (
	"context"
	"net/http"
	"testing"
)

func newURLClient(t *testing.T) *Client {
	t.Helper()
	c, err := New(Config{URL: "https://abc.supabase.co/storage/v1/", APIKey: testKey})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// upstream: storage-js src/packages/StorageFileApi.ts getPublicUrl
// (expectations from test/storageFileApi.test.ts "Generate urls" and "Transformations")
func TestGetPublicURL(t *testing.T) {
	const base = "https://abc.supabase.co/storage/v1"
	f := newURLClient(t).From("bucket")
	tests := []struct {
		name string
		path string
		opts *URLOptions
		want string
	}{
		{"plain", "testpath/file.jpg", nil, base + "/object/public/bucket/testpath/file.jpg"},
		{"leading slashes", "//testpath/file.jpg", nil, base + "/object/public/bucket/testpath/file.jpg"},
		{"download", "p.jpg", &URLOptions{Download: true}, base + "/object/public/bucket/p.jpg?download="},
		{"download name", "p.jpg", &URLOptions{DownloadName: "test.jpg"}, base + "/object/public/bucket/p.jpg?download=test.jpg"},
		{"download name form-encoded", "p.jpg", &URLOptions{DownloadName: "my file*~.jpg"}, base + "/object/public/bucket/p.jpg?download=my+file*%7E.jpg"},
		{"transform", "p.jpg", &URLOptions{Transform: &TransformOptions{Width: 200, Height: 300, Quality: 70}},
			base + "/render/image/public/bucket/p.jpg?width=200&height=300&quality=70"},
		{"empty transform uses object endpoint", "p.jpg", &URLOptions{Transform: &TransformOptions{}}, base + "/object/public/bucket/p.jpg"},
		{"all options in upstream order", "p.jpg", &URLOptions{
			Download: true, CacheNonce: "n1", VersionID: "v1",
			Transform: &TransformOptions{Width: 200, Height: 150, Resize: ResizeCover, Format: FormatOrigin, Quality: 80},
		}, base + "/render/image/public/bucket/p.jpg?download=&width=200&height=150&resize=cover&format=origin&quality=80&cacheNonce=n1&versionId=v1"},
		{"encodeURI of path", "dir/my file é#1?.png", nil, base + "/object/public/bucket/dir/my%20file%20%C3%A9#1?.png"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := f.GetPublicURL(tt.path, tt.opts); got != tt.want {
				t.Errorf("got  %s\nwant %s", got, tt.want)
			}
		})
	}
}

// upstream: storage-js src/packages/StorageFileApi.ts createSignedUrl
func TestCreateSignedURL(t *testing.T) {
	fs := newFake(t, 200, `{"signedURL":"/object/sign/b/dir/a b.png?token=abc"}`)
	c := newTestClient(t, fs)
	base := fs.URL + "/storage/v1"
	u, err := c.From("b").CreateSignedURL(context.Background(), "dir/a b.png", 60, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := fs.last(t)
	assertReq(t, r, http.MethodPost, "/storage/v1/object/sign/b/dir/a%20b.png", "")
	assertJSONBody(t, r, `{"expiresIn":60}`)
	if want := base + "/object/sign/b/dir/a%20b.png?token=abc"; u != want {
		t.Errorf("url = %s, want %s", u, want)
	}
}

// upstream: storage-js src/packages/StorageFileApi.ts createSignedUrl (download, transform, cacheNonce, versionId)
func TestCreateSignedURLOptions(t *testing.T) {
	fs := newFake(t, 200, `{"signedURL":"/render/image/sign/b/a.png?token=abc"}`)
	c := newTestClient(t, fs)
	base := fs.URL + "/storage/v1"
	u, err := c.From("b").CreateSignedURL(context.Background(), "a.png", 60000, &URLOptions{
		Download:   true,
		Transform:  &TransformOptions{Width: 200, Height: 200, Quality: 60},
		CacheNonce: "n 1",
		VersionID:  "v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONBody(t, fs.last(t), `{"expiresIn":60000,"transform":{"width":200,"height":200,"quality":60},"versionId":"v1"}`)
	if want := base + "/render/image/sign/b/a.png?token=abc&download=&cacheNonce=n+1"; u != want {
		t.Errorf("url = %s, want %s", u, want)
	}

	// Download names are form-encoded and then passed through encodeURI,
	// exactly as upstream does (so '%' is re-encoded).
	u, err = c.From("b").CreateSignedURL(context.Background(), "a.png", 60, &URLOptions{DownloadName: "é.jpg", Transform: &TransformOptions{}})
	if err != nil {
		t.Fatal(err)
	}
	assertJSONBody(t, fs.last(t), `{"expiresIn":60}`)
	if want := base + "/render/image/sign/b/a.png?token=abc&download=%25C3%25A9.jpg"; u != want {
		t.Errorf("url = %s, want %s", u, want)
	}
}

// upstream: storage-js src/packages/StorageFileApi.ts createSignedUrl (error)
func TestCreateSignedURLError(t *testing.T) {
	fs := newFake(t, 400, notFoundBody)
	c := newTestClient(t, fs)
	_, err := c.From("b").CreateSignedURL(context.Background(), "a.png", 60, nil)
	assertAPIError(t, err, 400, CodeNoSuchKey, "Object not found")
}

// upstream: storage-js src/packages/StorageFileApi.ts createSignedUrls
func TestCreateSignedURLs(t *testing.T) {
	fs := newFake(t, 200, `[{"error":null,"path":"a.txt","signedURL":"/object/sign/b/a.txt?token=t1"},
		{"error":"Either the object does not exist or you do not have access to it","path":"missing.txt","signedURL":null}]`)
	c := newTestClient(t, fs)
	base := fs.URL + "/storage/v1"
	res, err := c.From("b").CreateSignedURLs(context.Background(), []string{"a.txt", "missing.txt"}, 60, &SignedURLsOptions{
		DownloadName: "x.txt", CacheNonce: "n1",
	})
	if err != nil {
		t.Fatal(err)
	}
	r := fs.last(t)
	assertReq(t, r, http.MethodPost, "/storage/v1/object/sign/b", "")
	assertJSONBody(t, r, `{"expiresIn":60,"paths":["a.txt","missing.txt"]}`)
	want := []SignedURLResult{
		{Path: "a.txt", SignedURL: base + "/object/sign/b/a.txt?token=t1&download=x.txt&cacheNonce=n1"},
		{Path: "missing.txt", Error: "Either the object does not exist or you do not have access to it"},
	}
	if len(res) != 2 || res[0] != want[0] || res[1] != want[1] {
		t.Errorf("res = %+v\nwant  %+v", res, want)
	}

	if _, err := c.From("b").CreateSignedURLs(context.Background(), nil, 60, nil); err != nil {
		t.Fatal(err)
	}
	assertJSONBody(t, fs.last(t), `{"expiresIn":60,"paths":[]}`)
}

func TestEncodeURI(t *testing.T) {
	in := "https://x.co/a b/é?q=1&r=a+b#frag;,:@$!~*'()%-_."
	want := "https://x.co/a%20b/%C3%A9?q=1&r=a+b#frag;,:@$!~*'()%25-_."
	if got := encodeURI(in); got != want {
		t.Errorf("got %s want %s", got, want)
	}
}
