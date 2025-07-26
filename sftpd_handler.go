package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/sftp"
)

// RootedHandler implements sftp.FileReader, FileWriter, FileCmder, LstatFileLister(FileLister) for rootDir restriction
// simulate as Unix file system exposed via sftp
// the root "/" mapping to user's home directory and should NOT escape
type RootedHandler struct {
	root    *os.Root
	rootDir string
}

// for os.Root API, file path should not in absolute
// sftp.Request.Filepath should in absolute path by "github.com/pkg/sftp"
func (h *RootedHandler) toRootPath(fp string) string {
	if len(fp) >= 1 && fp[:1] == "/" {
		return "." + fp // "/abs-path/to-file" => "./abs-path/to-file"
	}
	return fp
}

// sftp.Request.Filepath should in absolute path by "github.com/pkg/sftp"
// map to the user's home directory as absolute path
func (h *RootedHandler) cleanPath(fp string) string {
	newFp := filepath.Join(h.rootDir, filepath.Clean("/"+fp))
	if !strings.HasPrefix(newFp, h.rootDir) {
		return h.rootDir // fallback to root
	}
	return newFp
}

func (h *RootedHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	path := h.cleanPath(r.Filepath)
	Vln(3, "[Fileread]", r.Method, r.Filepath, path)
	return h.root.Open(h.toRootPath(r.Filepath))
}
func (h *RootedHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	path := h.cleanPath(r.Filepath)
	Vln(3, "[Filewrite]", r.Method, r.Filepath, path)
	return h.root.OpenFile(h.toRootPath(r.Filepath), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
}
func (h *RootedHandler) Filecmd(r *sftp.Request) error {
	path := h.cleanPath(r.Filepath)
	Vln(3, "[Filecmd]", r.Method, r.Filepath, path)
	switch r.Method {
	case "Setstat":
		// TODO: ensure path will be same with os.Root
		return h.setstat(r, path)
	case "Rename":
		// only in golang 1.25, not yet now
		// h.root.Rename(r.Filepath, r.Target)
		newPath := h.cleanPath(r.Target)
		return os.Rename(path, newPath)
	case "Rmdir":
		return h.root.Remove(h.toRootPath(r.Filepath))
	case "Remove":
		return h.root.Remove(h.toRootPath(r.Filepath))
	case "Mkdir":
		return h.root.Mkdir(h.toRootPath(r.Filepath), 0755)

	// TODO: config for enable links
	case "Symlink":
		// NOTE: given a POSIX compliant signature: symlink(target, linkpath string)
		// this makes Request.Target the linkpath, and Request.Filepath the target.
		// r.Filepath is the target, and r.Target is the linkpath.
		// os.Symlink(h.cleanPath(r.Filepath), h.cleanPath(r.Target))
	case "Link":
	// case "PosixRename":
	// case "StatVFS":
	default:
	}
	return sftp.ErrSSHFxOpUnsupported
}

func (h *RootedHandler) setstat(r *sftp.Request, path string) error {
	attr := r.Attributes()
	if attr == nil {
		return nil
	}
	flags := r.AttrFlags()
	var err error
	if flags.Permissions {
		err = os.Chmod(path, attr.FileMode())
	}
	if err == nil && flags.UidGid {
		err = os.Chown(path, int(attr.UID), int(attr.GID))
	}
	if err == nil && flags.Acmodtime {
		err = os.Chtimes(path, attr.AccessTime(), attr.ModTime())
	}
	if err == nil && flags.Size {
		err = os.Truncate(path, int64(attr.Size))
	}
	return err
}

var _ sftp.ReadlinkFileLister = (*RootedHandler)(nil)

func (h *RootedHandler) Filelist(r *sftp.Request) (sftp.ListerAt, error) {
	path := h.cleanPath(r.Filepath)
	Vln(3, "[Filecmd]", r.Method, r.Filepath, path)
	// "Readlink" handle by h.Readlink(fp string) (string, error)
	switch r.Method {
	case "List":
		f, err := h.root.Open(h.toRootPath(r.Filepath))
		if err != nil {
			return nil, err
		}
		fis, err := f.Readdir(-1)
		f.Close()
		if err != nil {
			return nil, err
		}
		return listerAt(fis), nil

	case "Stat":
		fis, err := h.root.Stat(h.toRootPath(r.Filepath))
		if err != nil {
			return nil, err
		}
		return listerAt([]os.FileInfo{fis}), nil
	case "Lstat": // should call h.Lstat(r *sftp.Request) (sftp.ListerAt, error)
		return h.Lstat(r)
	}
	return nil, os.ErrInvalid
}

func (h *RootedHandler) Readlink(fp string) (string, error) {
	// TODO: ensure path will be same with os.Root
	path := h.cleanPath(fp)
	dst, err := os.Readlink(path)
	return dst, err
}

func (h *RootedHandler) Lstat(r *sftp.Request) (sftp.ListerAt, error) {
	fis, err := h.root.Lstat(h.toRootPath(r.Filepath))
	if err != nil {
		return nil, err
	}
	return listerAt([]os.FileInfo{fis}), nil
}

type listerAt []os.FileInfo

func (l listerAt) ListAt(ls []os.FileInfo, off int64) (int, error) {
	if int(off) >= len(l) {
		return 0, io.EOF
	}
	n := copy(ls, l[off:])
	if n < len(ls) {
		return n, io.EOF
	}
	return n, nil
}

func customSFTPHandlers(rootDir string) (*RootedHandler, error) {
	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return nil, err
	}
	h := &RootedHandler{
		root:    root,
		rootDir: rootDir,
	}
	return h, nil
}
