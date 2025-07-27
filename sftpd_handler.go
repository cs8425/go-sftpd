package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/pkg/sftp"
)

// RootedHandler implements sftp.FileReader, FileWriter, FileCmder, LstatFileLister(FileLister) for rootDir restriction
// simulate as Unix file system exposed via sftp
// the root "/" mapping to user's home directory and should NOT escape
type RootedHandler struct {
	root     *os.Root
	rootDir  string
	username string
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

var _ sftp.FileReader = (*RootedHandler)(nil)

func (h *RootedHandler) Fileread(r *sftp.Request) (io.ReaderAt, error) {
	path := h.cleanPath(r.Filepath)
	Vln(3, "[Fileread]", r.Method, r.Filepath, path)
	return h.root.Open(h.toRootPath(r.Filepath))
}

var _ sftp.FileWriter = (*RootedHandler)(nil)

func (h *RootedHandler) Filewrite(r *sftp.Request) (io.WriterAt, error) {
	path := h.cleanPath(r.Filepath)
	Vln(3, "[Filewrite]", r.Method, r.Filepath, path)
	return h.root.OpenFile(h.toRootPath(r.Filepath), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
}

var _ sftp.OpenFileWriter = (*RootedHandler)(nil)

func (h *RootedHandler) OpenFile(r *sftp.Request) (sftp.WriterAtReaderAt, error) {
	sftpFlag := r.Pflags()
	osFlag := 0
	if sftpFlag.Read && sftpFlag.Write {
		osFlag = os.O_RDWR
	}
	if sftpFlag.Read && !sftpFlag.Write {
		osFlag = os.O_RDONLY
	}
	if !sftpFlag.Read && sftpFlag.Write {
		osFlag = os.O_WRONLY
	}
	if sftpFlag.Creat {
		osFlag |= os.O_CREATE
	}
	if sftpFlag.Trunc {
		osFlag |= os.O_TRUNC
	}
	if sftpFlag.Excl {
		osFlag |= os.O_EXCL
	}
	// WriterAt will seek
	// if sftpFlag.Append {
	// 	osFlag |= os.O_APPEND
	// }
	return h.root.OpenFile(h.toRootPath(r.Filepath), osFlag, 0644)
}

var _ sftp.FileCmder = (*RootedHandler)(nil)

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
	// disable Chown
	// TODO: config?
	// if err == nil && flags.UidGid {
	// 	err = os.Chown(path, int(attr.UID), int(attr.GID))
	// }
	if err == nil && flags.Acmodtime {
		err = os.Chtimes(path, attr.AccessTime(), attr.ModTime())
	}
	if err == nil && flags.Size {
		err = os.Truncate(path, int64(attr.Size))
	}
	return err
}

// implement sftp.NameLookupFileLister
var _ sftp.NameLookupFileLister = (*RootedHandler)(nil)

// currently hard code as user name
// TODO: more config?
func (h *RootedHandler) LookupUserName(uid string) string {
	return h.username
}
func (h *RootedHandler) LookupGroupName(gid string) string {
	return h.username
}

var _ sftp.FileLister = (*RootedHandler)(nil)

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
		return NewListerAt(fis), nil

	case "Stat":
		fis, err := h.root.Stat(h.toRootPath(r.Filepath))
		if err != nil {
			return nil, err
		}
		return NewListerAt([]os.FileInfo{fis}), nil
	case "Lstat": // should call h.Lstat(r *sftp.Request) (sftp.ListerAt, error)
		return h.Lstat(r)
	}
	return nil, os.ErrInvalid
}

var _ sftp.ReadlinkFileLister = (*RootedHandler)(nil)

func (h *RootedHandler) Readlink(fp string) (string, error) {
	// TODO: ensure path will be same with os.Root
	// TODO: ensure return path not absolute and within user home(?)
	path := h.cleanPath(fp)
	dst, err := os.Readlink(path)
	return dst, err
}

var _ sftp.LstatFileLister = (*RootedHandler)(nil)

func (h *RootedHandler) Lstat(r *sftp.Request) (sftp.ListerAt, error) {
	fis, err := h.root.Lstat(h.toRootPath(r.Filepath))
	if err != nil {
		return nil, err
	}
	return NewListerAt([]os.FileInfo{fis}), nil
}

// pool for custom FileInfo
var (
	fileInfoPool = NewFileInfoPool()
)

type FileInfoPool sync.Pool

func (pl *FileInfoPool) Get() *FileInfo {
	br := ((*sync.Pool)(pl)).Get().(*FileInfo)
	return br
}

func (pl *FileInfoPool) Put(b *FileInfo) {
	((*sync.Pool)(pl)).Put(b)
}

func NewFileInfoPool() *FileInfoPool {
	return (*FileInfoPool)(&sync.Pool{
		New: func() interface{} {
			return new(FileInfo)
		},
	})
}

// implement sftp.FileInfoUidGid
var _ sftp.FileInfoUidGid = (*FileInfo)(nil)

// sftp will using ModTime() Mode() Size()
// using os.DirEntry will not provide any benefits
// https://github.com/pkg/sftp/blob/master/ls_formatting.go#L44
type FileInfo struct {
	os.FileInfo
}

// currently hard code, maybe need config?
func (fi *FileInfo) Uid() uint32 {
	return 0
}
func (fi *FileInfo) Gid() uint32 {
	return 0
}

type listerAt []*FileInfo

func NewListerAt(ls []os.FileInfo) listerAt {
	lis := make([]*FileInfo, 0, len(ls))
	for _, ofi := range ls {
		fi := fileInfoPool.Get()
		fi.FileInfo = ofi
		lis = append(lis, fi)
	}
	return lis
}

func (l listerAt) ListAt(ls []os.FileInfo, off int64) (int, error) {
	if int(off) >= len(l) {
		return 0, io.EOF
	}
	// n := copy(ls, l[off:])
	n := 0
	for i, fi := range l[off:] {
		ls[i] = fi
		n += 1
	}
	if n < len(ls) {
		return n, io.EOF
	}
	return n, nil
}
func (l listerAt) Close() error {
	for _, fi := range l {
		fileInfoPool.Put(fi)
	}
	return nil
}

func customSFTPHandlers(rootDir string, username string) (*RootedHandler, error) {
	root, err := os.OpenRoot(rootDir)
	if err != nil {
		return nil, err
	}
	h := &RootedHandler{
		root:     root,
		rootDir:  rootDir,
		username: username,
	}
	return h, nil
}
