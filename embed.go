package main

import (
	"embed"
	"log/slog"
	"os"
	"path/filepath"
)

//go:embed all:embedded
var embeddedFS embed.FS

// extractEmbeddedSlipnet extracts the bundled slipnet binary to a temp directory.
// Returns the path to the extracted binary, or empty string if not embedded.
// The caller should defer os.RemoveAll on the parent directory of the returned path.
func extractEmbeddedSlipnet() (binPath string, cleanupDir string) {
	data, err := embeddedFS.ReadFile("embedded/slipnet")
	if err != nil || len(data) == 0 {
		return "", ""
	}

	tmpDir, err := os.MkdirTemp("", "dns-mux-slipnet-*")
	if err != nil {
		slog.Warn("Failed to create temp dir for embedded slipnet", "err", err)
		return "", ""
	}

	path := filepath.Join(tmpDir, "slipnet")
	if err := os.WriteFile(path, data, 0755); err != nil {
		slog.Warn("Failed to extract embedded slipnet", "err", err)
		os.RemoveAll(tmpDir)
		return "", ""
	}

	slog.Info("Extracted embedded slipnet binary", "path", path)
	return path, tmpDir
}
