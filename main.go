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

package main

import (
	"flag"
	"os"
	"runtime"

	. "github.com/zreigz/tuntap-vpn/utils"
	server "github.com/zreigz/tuntap-vpn/vpn"
	client "github.com/zreigz/tuntap-vpn/vpn"
)

var debug bool
var cfgFile string


func main() {
	flag.BoolVar(&debug, "debug", false, "Provide debug info")
	flag.StringVar(&cfgFile, "config", "", "configfile")
	flag.Parse()


	InitLogger(debug)
	logger := GetLogger()

	checkerr := func(err error) {
		if err != nil {
			logger.Error(err.Error())
			os.Exit(1)
		}
	}

	if cfgFile == "" {
		cfgFile = flag.Arg(0)
	}

	logger.Info("using config file: ", cfgFile)

	icfg, err := ParseConfig(cfgFile)
	logger.Debug(icfg)
	checkerr(err)

	maxProcs := runtime.GOMAXPROCS(0)
	if maxProcs < 2 {
		runtime.GOMAXPROCS(2)
	}

	switch cfg := icfg.(type) {
	case ServerConfig:
		err := server.NewServer(cfg)
		checkerr(err)
	case ClientConfig:
		err := client.NewClient(cfg)
		checkerr(err)
	default:
		logger.Error("Invalid config file")
	}
}
