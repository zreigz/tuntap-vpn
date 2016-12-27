/*
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Lukasz Zajaczkowski <zreigz@gmail.com>
 *
 */
package utils

import (
	"errors"

	"github.com/scalingdata/gcfg"
)

// Server Config
type ServerConfig struct {
	PortStart   int
	PortEnd     int
	ListenAddr  string
	VpnAddr     string
	MTU         int
}

// Client Config
type ClientConfig struct {
	Server             string
	PortStart          int
	PortEnd            int
	MTU                int
}

type VpnConfig struct {
	Default struct {
			Mode string
		}
	Server  ServerConfig
	Client  ClientConfig
}

func ParseConfig(filename string) (interface{}, error) {
	cfg := new(VpnConfig)
	err := gcfg.ReadFileInto(cfg, filename)
	if err != nil {
		return nil, err
	}
	switch cfg.Default.Mode {
	case "server":
		return cfg.Server, nil
	case "client":
		return cfg.Client, nil
	default:
		return nil, errors.New("Wrong config data")
	}
}

