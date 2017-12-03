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
	"bufio"
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/tmc/scp"
	"golang.org/x/crypto/ssh"
	log "gopkg.in/sirupsen/logrus.v1"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

var (
	defaultKey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEApDqwmXssH0AIk6pec02wSYDrORY9J7VlE/45IqAACzTQuD7X
CifmEZ6lzKCqvGSSXBFpfm/nh8W0vcTn20yfehkz1xI9yP+sJSUhNavkW+5hl9Yo
uXFK91sbRKuvAUqu+ozV5wD3ZP4tFtoH39SxzldBJaiW9NQ1XdCgGy7RulREuMBP
3tFUHP1o1btiql5YO3YoHrizAwcIbfoyCgnwVlMldq249AGBO5jvEoRnhO4Toikh
TZik5isKsVx1hfMp6fkk5pdCnRWXCTNOXo+DbsUAzXKoFLoA9c5reIeOjeZG6+3L
T/G+QBEwjimTRXoPFmPYcJ/KMurp2P/o1+QVbQIDAQABAoIBAC5Pwpc1bcbONtz1
UTcwtEK2ER8DD3HQLFXL/e6usfR3C1i5l8hsYeucEmM2946yybcezeHyypa2APb2
vO9RlzNGQiEnKrcwqim7Y7cP5xCpk2nO4aMRuLMyROlDhNFXbyqGZpeC5UDckHh+
OXQ8NXvbjSqCdTdLVFVFTLD9rfTd9L85lSxAD6jUhMbiu62b+9j14xWRAvUkt/sd
1cr/5yh7x0MYcJkHfShMNai/ExU8cUSwNF/JfxhmIt1aO7sefshLhxJUuAPT1ljd
mnD0ZeGWUt52yqrjaWLMKgtTtJuSUiRsTQ9Qx4eIzP6PJWJIL6+j63M3VL25yRz5
D8SOpEECgYEA2Xc0Gtl3RPPv+AakGEJb/TdW/mz5Fa6yTVjjimB/UcVrwOFT6y5h
kpoqSH/SzBZxdkdNli6Cgyr0ajNb6oXL/rf/0R7Do+VNQYxZIvrT95ANxCH6HEy4
4UMLGT8Xz5gOEBKH27+j/sdUqqT/dsv8iLRXVk6yGQZXHfYjXBcLOPECgYEAwVSM
U4aE4JBDAxTGDejaGFjNlmKcPjSEa/Yv5Qd5/qcGyQM6wHCV8TXE1ry9DSONviCI
qmnR9BqjFb4/I6jI7zuHDneAXUJja1Kap01rTbrWCaRJTwRGDELNj1/aDC6HOaaf
zZN21dafAsg8d0vv1SXzQThJ63LwQt1qTTSPxD0CgYEAkwerbPPXVgFwH8utqtFD
DMMbyE25Y1WILA+LWIXBz3GhVvmCGaJ0SgB90iLKTT5nXEb9SCsOBs1GD3/GB5yK
vh99kNAyCmAAie7wXVwlcF4vUIqAZh3hajxABsPHv43ZBDjjLko2AQ6YSf/g0Vs9
1NfJrQrsE0tcH1/JrHvQFKECgYBEjn7Uf7dPCtk4ln1FIXV1fMgqs/1D8cujnUGO
rgAM1Z4KWiLTaxlA2BhdLcC8kAcLjO3pwGy7a1a5tyUcuBXJAAr8jlPuvkQTIs/E
1CdhAQg1kxSL+K/+WRIb7ZmdCELbpsK0W76gReNNUURf6YW6yCJi1lsgKzoX+/xe
NG1m4QKBgG2UOBk+9hF3bcq0Wo4zSDa3wTzPlTlySnUOU1m6pMlUW97qhmUzKdj/
EGjLLdEY/nQkBYT5HmV4lilHlrb+fZcM0+FegopkKXAOzEqkLTI2ibiItCT12nLB
FwRYLLbqbGByhykSn5ybp/DuSQpH4blitu/fEYOg6QX/I/6zayd+
-----END RSA PRIVATE KEY-----
`

	ip     = ""
	hostIp = ""

	sshLocation            = ""
	defaultPrivKeyLocation = ""
	GadgetPrivKeyLocation  = ""
	GadgetPubKeyLocation   = ""
)

func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func GenGadgetKeys() (string, string, error) {

	randSeedSource := rand.NewSource(time.Now().UnixNano())
	randSeed := rand.New(randSeedSource)

	privateKey, err := rsa.GenerateKey(randSeed, 2048)
	if err != nil {
		return "", "", err
	}

	privateKeyDer := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privateKeyDer,
	}
	privateKeyPem := string(pem.EncodeToMemory(&privateKeyBlock))

	publicKey := privateKey.PublicKey

	pub, err := ssh.NewPublicKey(&publicKey)
	if err != nil {
		return privateKeyPem, "", err
	}

	pubString := string(ssh.MarshalAuthorizedKey(pub))

	return privateKeyPem, pubString, err
}

func RequiredSsh() error {

	usr, err := user.Current()
	if err != nil {
		log.WithFields(log.Fields{
			"function": "RequiredSsh",
			"error":    err,
		}).Error("Couldn't determine username.")
		return err
	}

	// get proper homedir locations
	sshLocation = filepath.Join(usr.HomeDir, ".ssh")
	defaultPrivKeyLocation = filepath.Join(sshLocation, "gadget_default_rsa")
	GadgetPrivKeyLocation = filepath.Join(sshLocation, "gadget_rsa")
	GadgetPubKeyLocation = filepath.Join(sshLocation, "gadget_rsa.pub")

	ipPresent := false
	if ip, ipPresent = os.LookupEnv("GADGET_ADDR"); ipPresent == false {
		// check OS for IP address
		if runtime.GOOS == "windows" {
			ip = "192.168.82.1:22"
		} else {
			ip = "192.168.81.1:22"
		}
	}

	hostIpPresent := false
	if hostIp, hostIpPresent = os.LookupEnv("GADGET_HOST_ADDR"); hostIpPresent == false {
		// check OS for IP address
		if runtime.GOOS == "windows" {
			hostIp = "192.168.82.2"
		} else {
			hostIp = "192.168.81.2"
		}
	}	

	// check/create ~/.ssh
	sshDirExists, err := PathExists(sshLocation)
	if err != nil {
		log.WithFields(log.Fields{
			"function": "RequiredSsh",
			"error":    err,
		}).Error("Couldn't determine if the ~/.ssh directory exists.")
		return err
	}

	if !sshDirExists {
		err = os.Mkdir(sshLocation, 0700)
		if err != nil {
			log.WithFields(log.Fields{
				"function": "RequiredSsh",
				"error":    err,
			}).Error("Couldn't create the ~/.ssh directory.")
			return err
		}
	}

	// check/create ~/.ssh/gadget_default_rsa
	defaultPrivExists, err := PathExists(defaultPrivKeyLocation)
	if err != nil {
		log.WithFields(log.Fields{
			"function":    "RequiredSsh",
			"error":       err,
			"keyLocation": defaultPrivKeyLocation,
		}).Error("Couldn't determine if the default private key exists.")
		return err
	}

	if !defaultPrivExists {
		log.Info("Creating default gadget ssh key..")

		log.WithFields(log.Fields{
			"function": "RequiredSsh",
		}).Debug("default private key: ~/.ssh/gadget_default_rsa")

		outBytes := []byte(defaultKey)
		err = ioutil.WriteFile(defaultPrivKeyLocation, outBytes, 0600)
		if err != nil {
			return err
		}
	}

	// check/create ~/.ssh/gadget_rsa[.pub]
	gadgetPrivExists, err := PathExists(GadgetPrivKeyLocation)
	if err != nil {
		log.WithFields(log.Fields{
			"function":    "RequiredSsh",
			"keyLocation": GadgetPrivKeyLocation,
			"error":       err,
		}).Error("something went wrong with gadgetPubExists")
		return err
	}
	gadgetPubExists, err := PathExists(GadgetPubKeyLocation)
	if err != nil {
		log.WithFields(log.Fields{
			"function":    "RequiredSsh",
			"keyLocation": GadgetPubKeyLocation,
			"error":       err,
		}).Error("something went wrong with gadgetPubExists")
		return err
	}

	if !gadgetPrivExists && !gadgetPubExists {
		log.Info("Creating personal gadget ssh keys..")

		log.WithFields(log.Fields{
			"function":    "RequiredSsh",
			"keyLocation": GadgetPubKeyLocation,
			"error":       err,
		}).Debug("private key: ~/.ssh/gadget_rsa[.pub]")

		privkey, pubkey, err := GenGadgetKeys()
		if err != nil {
			log.WithFields(log.Fields{
				"function": "RequiredSsh",
				"error":    err,
			}).Error("something went wrong with genGadgetKeys")
			return err
		}

		log.Info("    private key: ~/.ssh/gadget_rsa")
		outBytes := []byte(privkey)
		err = ioutil.WriteFile(GadgetPrivKeyLocation, outBytes, 0600)
		if err != nil {
			log.WithFields(log.Fields{
				"function":    "RequiredSsh",
				"keyLocation": GadgetPrivKeyLocation,
				"error":       err,
			}).Error("something went wrong with gadgetPrivKey")
			return err
		}

		log.Info("    public key: ~/.ssh/gadget_rsa.pub")
		outBytes = []byte(pubkey)
		err = ioutil.WriteFile(GadgetPubKeyLocation, outBytes, 0600)
		if err != nil {
			log.WithFields(log.Fields{
				"function":    "RequiredSsh",
				"keyLocation": GadgetPrivKeyLocation,
				"error":       err,
			}).Error("something went wrong with gadgetPrivKey")
			return err
		}
	}

	return nil
}

func EnsureIp() error {

	ifaces, _ := net.Interfaces()
	// handle err
	for _, i := range ifaces {
		addrs, _ := i.Addrs()
		// handle err
		for _, addr := range addrs {
			var localIP net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				localIP = v.IP
				log.Debugf("Found IP: %s", localIP.String())
				log.Debugf("Searching for: %s", hostIp)
				if localIP.String() == hostIp {
					return nil
				}
			}
		}
	}

	return errors.New("Could not find Gadget IP")

}

func GadgetLogin(keyLocation string) (*ssh.Client, error) {

	key, err := ioutil.ReadFile(keyLocation)
	if err != nil {
		log.WithFields(log.Fields{
			"function":    "RequiredSsh",
			"keyLocation": GadgetPrivKeyLocation,
			"error":       err,
		}).Error("something went wrong with gadgetPrivKey")
		return nil, err
	}

	// Create the Signer for this private key.
	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		return nil, err
	}

	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         (time.Second * 3),
	}

	// Connect to the remote server and perform the SSH handshake.
	client, err := ssh.Dial("tcp", ip, config)
	if err != nil {
		return nil, err
	}

	return client, err
}

func GadgetInstallConfig(g *GadgetContext) error {
	configLocation := fmt.Sprintf("%s/gadget.yml", g.WorkingDirectory)

	key, err := ioutil.ReadFile(GadgetPrivKeyLocation)
	if err != nil {
		log.WithFields(log.Fields{
			"function": "GadgetInstallConfig",
			"file":     GadgetPrivKeyLocation,
		}).Error("Failed to read private key")
		return err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.WithFields(log.Fields{
			"function": "GadgetInstallConfig",
			"file":     GadgetPrivKeyLocation,
		}).Error("Failed parse private key")
		return err
	}

	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         (time.Second * 3),
	}

	client, err := ssh.Dial("tcp", ip, config)
	if err != nil {
		log.WithFields(log.Fields{
			"function": "GadgetInstallConfig",
			"tcp":      ip,
		}).Error("Failed to dial ssh")
		return err
	}

	session, err := client.NewSession()
	if err != nil {
		log.WithFields(log.Fields{
			"function": "GadgetInstallConfig",
		}).Error("Failed to create new ssh client session")
		client.Close()
		return err
	}

	dest := "/data/gadget.yml"
	log.WithFields(log.Fields{
		"function": "GadgetInstallConfig",
		"gadget":   dest,
	}).Debug("Installing personal gadget ssh key..")

	err = scp.CopyPath(configLocation, dest, session)
	if _, err := os.Stat(configLocation); os.IsNotExist(err) {
		log.WithFields(log.Fields{
			"function":                    "GadgetInstallConfig",
			"gadget":                      dest,
			"GadgetInstallConfigLocation": configLocation,
		}).Error("Config file copy failed")
	}

	defer client.Close()
	return nil
}

func GadgetInstallKeys() error {
	key, err := ioutil.ReadFile(defaultPrivKeyLocation)
	if err != nil {
		log.WithFields(log.Fields{
			"function": "GadgetInstallKeys",
			"file":     defaultPrivKeyLocation,
		}).Error("Failed to read private key")
		return err
	}

	signer, err := ssh.ParsePrivateKey(key)
	if err != nil {
		log.WithFields(log.Fields{
			"function": "GadgetInstallKeys",
			"file":     defaultPrivKeyLocation,
		}).Error("Failed parse private key")
		return err
	}

	config := &ssh.ClientConfig{
		User: "root",
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         (time.Second * 3),
	}

	client, err := ssh.Dial("tcp", ip, config)
	if err != nil {
		log.WithFields(log.Fields{
			"function": "GadgetInstallKeys",
			"tcp":      ip,
		}).Error("Failed to dial ssh")
		return err
	}

	session, err := client.NewSession()
	if err != nil {
		log.WithFields(log.Fields{
			"function": "GadgetInstallKeys",
		}).Error("Failed to create new ssh client session")
		client.Close()
		return err
	}

	dest := "/data/root/.ssh/authorized_keys"
	log.WithFields(log.Fields{
		"function": "RequiredSsh",
		"gadget":   dest,
	}).Debug("Installing personal gadget ssh key..")

	err = scp.CopyPath(GadgetPubKeyLocation, dest, session)
	if _, err := os.Stat(GadgetPubKeyLocation); os.IsNotExist(err) {
		log.WithFields(log.Fields{
			"function":             "RequiredSsh",
			"gadget":               dest,
			"GadgetPubKeyLocation": GadgetPubKeyLocation,
		}).Error("Public key file does not exist")
	}

	defer client.Close()
	return nil
}

func EnsureKeys() error {

	err := EnsureIp()
	if err != nil {
		log.Error("Gadget device is either not connected, or not ready")
		return err
	}

	_, err = GadgetLogin(GadgetPrivKeyLocation)
	if err != nil {
		log.Warn("  Private key login failed, trying default key")

		log.WithFields(log.Fields{
			"function":               "EnsureKeys",
			"GadgetPrivKeyLocation":  GadgetPrivKeyLocation,
			"defaultPrivKeyLocation": defaultPrivKeyLocation,
		}).Debug("  Private key login failed, trying default key")

		_, err = GadgetLogin(defaultPrivKeyLocation)
		if err != nil {
			log.Error("  Default key login also failed")
			log.Warn("  Is the gadget connected and powered on?")
			log.Warn("  Was the gadget first used on another computer/account?")
			return err
		} else {
			log.WithFields(log.Fields{
				"function": "EnsureKeys",
			}).Debug("  Default key login success")

			log.WithFields(log.Fields{
				"function":             "EnsureKeys",
				"GadgetPubKeyLocation": GadgetPubKeyLocation,
			}).Debug("  Public key file does not exist")

			err = GadgetInstallKeys()
			if err != nil {
				return err
			}
		}
	} else {
		log.WithFields(log.Fields{
			"function": "EnsureKeys",
		}).Debug("  Private key login success")
	}

	return err
}

func EnsureDocker(binary string, g *GadgetContext) error {

	stdout, stderr, err := RunLocalCommand(binary,
		"", g,
		"version")

	if g.Verbose {
		log.WithFields(log.Fields{
			"function": "EnsureDocker",
		}).Debugf(stdout)

		log.WithFields(log.Fields{
			"function": "EnsureDocker",
		}).Debugf(stderr)
	}

	return err
}

func RunRemoteCommand(client *ssh.Client, cmd ...string) (*bytes.Buffer, *bytes.Buffer, error) {
	session, err := client.NewSession()
	if err != nil {
		client.Close()
		return nil, nil, err
	}

	err = session.Start(strings.Join(cmd[:], " "))
	if err != nil {
		return nil, nil, err
	}
	var outBuffer bytes.Buffer
	var errBuffer bytes.Buffer
	session.Stdout = &outBuffer
	session.Stderr = &errBuffer
	err = session.Wait()

	return &outBuffer, &errBuffer, err
}

func RunLocalCommand(binary string, filter string, g *GadgetContext, arguments ...string) (string, string, error) {
	log.Debugf("Calling %s %s", binary, arguments)

	cmd := exec.Command(binary, arguments...)

	cmd.Env = os.Environ()

	stdOutReader, execErr := cmd.StdoutPipe()
	if execErr != nil {
		log.Debugf("Couldn't connect to cmd.StdoutPipe()")
	}

	stdErrReader, execErr := cmd.StderrPipe()
	if execErr != nil {
		log.Debugf("Couldn't connect to cmd.StderrPipe()")
	}

	outScanner := bufio.NewScanner(stdOutReader)
	errScanner := bufio.NewScanner(stdErrReader)

	var outBuffer bytes.Buffer
	var errBuffer bytes.Buffer

	// goroutines to print stdout and stderr [doesn't quite work]
	go func() {
		if g.Verbose {
			for outScanner.Scan() {
				log.Debugf(string(outScanner.Text()))
				outBuffer.WriteString(string(outScanner.Text()))
			}
		} else {
			for outScanner.Scan() {
				if filter != "" && strings.Contains(outScanner.Text(), filter) {
					log.Infof("    %s", string(outScanner.Text()))
				}
				outBuffer.WriteString(string(outScanner.Text()))
			}
		}
	}()

	printedStderr := false

	go func() {
		for errScanner.Scan() {
			log.Warnf(string(errScanner.Text()))
			printedStderr = true
			errBuffer.WriteString(string(errScanner.Text()))
		}
	}()

	execErr = cmd.Run()

	if printedStderr && !g.Verbose {
		log.Warn("Use `gadget -v <command>` for more info.")
	}

	return outBuffer.String(), errBuffer.String(), execErr
}

func PrependToStrings(stringArray []string, prefix string) []string {

	if len(stringArray) == 0 || (len(stringArray) == 1 && stringArray[0] == "") {
		return []string{""}
	}

	for key, value := range stringArray {
		s := []string{prefix, value}
		stringArray[key] = strings.Join(s, "")
	}
	return stringArray
}

func FindStagedContainers(args []string, containers GadgetContainers) (GadgetContainers, error) {
	var stagedContainers GadgetContainers
	var unavailableContainers []string

	// if we have any arguments, we're specifying containers to build
	if len(args) > 0 {
		for _, arg := range args {
			c, err := containers.Find(arg)
			if err != nil {
				log.Errorf("Could not find container: '%s'", arg)
				unavailableContainers = append(unavailableContainers, arg)
			} else {
				stagedContainers = append(stagedContainers, c)
			}
		}
	}

	if len(stagedContainers) == 0 {
		if len(args) > 0 {
			log.Warn("Any/all argument[s] invalid")
			log.Warn("Performing operation across all containers in gadget.yml")
		}
		stagedContainers = containers
	}
	err := errors.New(fmt.Sprintf("  Could not find containers: %s", strings.Join(unavailableContainers, ", ")))
	return stagedContainers, err
}
