/*
This file is part of the Gadget command-line tools.
Copyright (C) 2017 Next Thing Co.

Gadget is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

Gadget is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Gadget.  If not, see <http://www.gnu.org/licenses/>.
*/

package libgadget

import (
	"errors"
	"fmt"
	log "gopkg.in/sirupsen/logrus.v1"
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
)

type GadgetContext struct {
	Config           GadgetConfig
	Verbose          bool
	WorkingDirectory string
}

type GadgetConfig struct {
	Spec     string
	Name     string
	UUID     string
	Type     string
	Rootfs   GadgetRootfs "rootfs,omitempty"
	Onboot   []GadgetContainer
	Services []GadgetContainer
}

type GadgetRootfs struct {
	From string
	Hash string
}

type GadgetContainer struct {
	Name         string
	UUID         string
	Image        string
	Directory    string
	Net          string
	PID          string "pid,omitempty"
	Readonly     bool
	Forking      bool
	Command      []string `yaml:",flow"`
	Binds        []string `yaml:",flow"`
	Capabilities []string `yaml:",flow"`
	Devices      []string `yaml:",flow"`
	Alias        string   "alias,omitempty"
	ImageAlias   string   "imagealias,omitempty"
}

func TemplateConfig(gName, gUu1, gUu2 string) GadgetConfig {
	return GadgetConfig{
		Spec: Version,
		Name: gName,
		UUID: gUu1,
		Type: "docker",
		Onboot: []GadgetContainer{
			{
				Name:    "hello-world",
				Image:   "arm32v7/hello-world",
				UUID:    gUu2,
				Forking: false,
			},
		},
	}
}

func ParseConfig(config []byte) (GadgetConfig, error) {
	g := GadgetConfig{}

	// Parse yaml
	err := yaml.Unmarshal(config, &g)
	if err != nil {
		log.Errorf("  gadget.yml syntax error: %v", err)
		return g, err
	}

	return g, nil
}

func CleanConfig(g GadgetConfig) GadgetConfig {

	// helper function to remove hidden config
	// items before writing the struct out

	for i := range g.Onboot {
		g.Onboot[i].Alias = ""
		g.Onboot[i].ImageAlias = ""
	}

	for i := range g.Services {
		g.Services[i].Alias = ""
		g.Services[i].ImageAlias = ""
	}

	return g
}

// helper function for walkup, determines if cwd is '/'
func isRoot(path string) bool {
	if runtime.GOOS != "windows" {
		return path == "/"
	}
	switch len(path) {
	case 1:
		return os.IsPathSeparator(path[0])
	case 3:
		return path[1] == ':' && os.IsPathSeparator(path[2])
	}
	return false
}

// isDriveLetter returns true if path is Windows drive letter (like "c:").
func isDriveLetter(path string) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	return len(path) == 2 && path[1] == ':'
}

// recursive function, returns ("", rc) on failure
// returns ("/path/to/dir", rc) on success
func WalkUp(bottom_dir string) (string, error) {

	var rc error = nil

	if _, err := os.Stat(fmt.Sprintf("%s/gadget.yml", bottom_dir)); err != nil {

		// haven't found it
		if isRoot(bottom_dir) || isDriveLetter(bottom_dir) {
			return "", errors.New("  Could not find configuration file")
		} else {
			bottom_dir, rc = WalkUp(filepath.Dir(bottom_dir))
		}
	}

	return bottom_dir, rc
}

func (g *GadgetContext) LoadConfig() error {

	g.WorkingDirectory, _ = filepath.Abs(g.WorkingDirectory)

	// find and read gadget.yml
	// TODO: this should probably get moved into the NewConfig function
	// TODO: better error checking/reporting. WHY can't the config file be opened?
	var config []byte
	var parseerr error = nil
	var cwderr error = nil

	g.WorkingDirectory, cwderr = WalkUp(g.WorkingDirectory)
	if cwderr == nil {
		// found the config
		log.Info("Running in directory:")
		log.Infof("  %s", g.WorkingDirectory)

		config, parseerr = ioutil.ReadFile(fmt.Sprintf("%s/gadget.yml", g.WorkingDirectory))
		if parseerr != nil {
			// couldn't read it
			log.Errorf("  Cannot open config file: %v", parseerr)
			return parseerr
		}
	} else {
		return cwderr
	}

	// create new config class from gadget.yml output
	// TODO: add error checking here.
	g.Config, parseerr = ParseConfig(config)

	for index, onboot := range g.Config.Onboot {
		onboot.Alias = fmt.Sprintf("%s_%s", onboot.Name, onboot.UUID)
		onboot.ImageAlias = fmt.Sprintf("%s-img", onboot.Alias)
		g.Config.Onboot[index] = onboot
	}
	for index, service := range g.Config.Services {
		service.Alias = fmt.Sprintf("%s_%s", service.Name, service.UUID)
		service.ImageAlias = fmt.Sprintf("%s-img", service.Alias)
		g.Config.Services[index] = service
	}

	if parseerr != nil || cwderr != nil {
		parseerr = errors.New("Failed to parse config")
		log.Errorf("  Cannot open config file: %v", parseerr)
	}

	return parseerr
}

type GadgetContainers []GadgetContainer

func (containers GadgetContainers) Find(name string) (GadgetContainer, error) {
	for _, container := range containers {
		if container.Name == name {
			return container, nil
		}
	}
	return GadgetContainer{}, errors.New(fmt.Sprintf("[CONFIG]  could not find container: %s", name))
}
