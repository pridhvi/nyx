package api

import "embed"

//go:embed all:web/dist
var webAssets embed.FS
