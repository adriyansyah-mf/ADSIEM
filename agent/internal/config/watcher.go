package config

import (
	"log/slog"

	"github.com/fsnotify/fsnotify"
)

// Watch calls onChange whenever the file at path is modified.
func Watch(path string, onChange func(newCfg *Config)) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	if err := watcher.Add(path); err != nil {
		watcher.Close()
		return err
	}
	go func() {
		defer watcher.Close()
		for {
			select {
			case event, ok := <-watcher.Events:
				if !ok {
					return
				}
				if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
					cfg, err := Load(path)
					if err != nil {
						slog.Error("config reload failed", "err", err)
						continue
					}
					slog.Info("config reloaded", "path", path)
					onChange(cfg)
				}
			case err, ok := <-watcher.Errors:
				if !ok {
					return
				}
				slog.Error("fsnotify error", "err", err)
			}
		}
	}()
	return nil
}
