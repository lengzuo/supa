package dto

type TransformOptions struct {
	Width   int    `json:"width"`
	Height  int    `json:"height"`
	Resize  string `json:"resize"`
	Format  string `json:"format"`
	Quality int    `json:"quality"`
}

type UrlOptions struct {
	Transform *TransformOptions `json:"transform"`
	Download  bool              `json:"download"`
}
