//go:build windows

package ingest

import "os"

func getInode(fi os.FileInfo) uint64 {
	return 0
}
