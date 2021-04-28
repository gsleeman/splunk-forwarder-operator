package main

import (
	"io"
	"io/ioutil"
	"log"

	"os"
	"path"
	"sync"
	"syscall"

	"github.com/fsnotify/fsnotify"
	"k8s.io/apiserver/pkg/audit/policy"
)

type RotatingReader struct {
	*io.PipeReader
	Path string
	file *os.File
	*fsnotify.Watcher
	inode uint64
	sync.WaitGroup
	rotated chan struct{}
	updated chan struct{}
	writer  *io.PipeWriter
}

func NewRotatingReader(fp string) *RotatingReader {
	f := &RotatingReader{}
	f.PipeReader, f.writer = io.Pipe()
	f.monitorPath(fp)
	go func() {
		for {
		read_file:
			for {
				f.Wait()
				reader := io.TeeReader(f.file, f.writer)
				io.Copy(ioutil.Discard, reader)
				if nofollow {
					f.writer.Close()
					close(f.Events)
					<-f.updated
					close(f.updated)
					return
				}
				select {
				case <-f.rotated:
					go io.Copy(ioutil.Discard, reader)
					break read_file
				case <-f.updated:
					for {
						n, err := io.Copy(ioutil.Discard, reader)
						if n == 0 || err != nil {
							break
						}
					}
				}
			}
		}
	}()
	return f
}

func (f *RotatingReader) monitorPath(fp string) {
	f.Path = fp
	fd, err := os.Open(fp)
	if err != nil {
		f.WaitGroup.Add(1)
	}
	f.file = fd
	f.Watcher, err = fsnotify.NewWatcher()
	f.updated = make(chan struct{})
	f.rotated = make(chan struct{})
	f.Watcher.Add(fp)
	f.Watcher.Add(path.Dir(fp))
	go func() {
		for {
			<-f.Events
			if f.file == nil {
				f.file, err = os.Open(fp)
				if err != nil {
					continue
				}
				f.inode = GetInode(f)
				f.Done()
			}
			f.updated <- struct{}{}
			if f.file != nil && f.hasRotated() {
				f.file = nil
				f.rotated <- struct{}{}
				if nofollow {
					return
				}
				f.WaitGroup.Add(1)
			} else if nofollow {
				return
			}
		}
	}()
}

func (f *RotatingReader) hasRotated() bool {
	if f.inode == 0 {
		f.inode = GetInode(f.file)
	}
	return f.inode != GetInode(f.Path)
}

func GetInode(file interface{}) uint64 {
	var fi os.FileInfo
	var err error
	switch file.(type) {
	case *os.File:
		fi, err = file.(*os.File).Stat()
	default:
		fi, err = os.Stat(file.(string))
	}
	if err != nil {
		return 0
	}
	return fi.Sys().(*syscall.Stat_t).Ino
}

func WatchPolicyPath(fp string) {
	var wd *fsnotify.Watcher
	var err error
	for {
		wd, err = fsnotify.NewWatcher()
		if err != nil {
			log.Fatal(err)
		}
		wd.Add(fp)
		wd.Add(path.Dir(fp))
		wd.Add(path.Dir(path.Dir(fp)))
		for {
			select {
			case ev := <-wd.Events:
				if ev.Op&(fsnotify.Rename|fsnotify.Remove|fsnotify.Write|fsnotify.Create) == 0 {
					continue
				}
				newPolicy, err := policy.LoadPolicyFromFile(fp)
				if err != nil {
					continue
				}
				filterPolicy = newPolicy
				log.Println("policy has been reloaded")
			case err := <-wd.Errors:
				log.Println(err)
			}
			wd.Close()
			break
		}
	}
}
