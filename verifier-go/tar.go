package main

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// extractTar unpacks a single-file FRF bundle (a deterministic tar archive
// carrying the identical directory layout, with the manifest inside) into a
// fresh temporary directory, enforcing the same containment and size ceilings
// as the reference engine: paths must not escape the extraction root, and
// neither the entry count nor the total size may exceed the protocol bounds.
func extractTar(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	root, err := os.MkdirTemp("", "frf-go-bundle-*")
	if err != nil {
		return "", err
	}
	tr := tar.NewReader(f)
	const maxEntries = 10_000
	const maxBytes = 1 << 30
	count := 0
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return "", err
		}
		count++
		if count > maxEntries {
			return "", fmt.Errorf("single-file bundle exceeds the 10 000-entry ceiling")
		}
		name := filepath.Clean(hdr.Name)
		if name == "." || strings.HasPrefix(name, "..") || filepath.IsAbs(name) {
			return "", fmt.Errorf("single-file bundle refuses entry %q", hdr.Name)
		}
		target := filepath.Join(root, name)
		if !strings.HasPrefix(target, root+string(os.PathSeparator)) {
			return "", fmt.Errorf("single-file bundle entry %q escapes the extraction root", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return "", err
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return "", err
			}
			total += hdr.Size
			if total > maxBytes {
				return "", fmt.Errorf("single-file bundle exceeds the 1 GiB extraction ceiling")
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return "", err
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return "", err
			}
			if err := out.Close(); err != nil {
				return "", err
			}
		default:
			return "", fmt.Errorf("single-file bundle refuses entry %q of unsupported type", hdr.Name)
		}
	}
	return root, nil
}
