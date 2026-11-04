//go:build windows

package app

import "github.com/503329706qq/gha-github-accelerator/internal/elevate"

func isAdmin() bool { return elevate.IsAdmin() }

func relaunchAsAdmin(exe string, argv []string, hidden bool) error {
	return elevate.Relaunch(exe, argv, hidden)
}
