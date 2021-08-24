package persist

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/rancher/machine/libmachine/host"
	"github.com/rancher/machine/libmachine/log"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	corev1types "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	machineConfigSecretKey = "extractedConfig"
	ipAddressSecretKey     = "publicIPAddress"
)

type secretStore struct {
	Store
	SecretName, SecretNamespace string
	SecretClient                corev1types.SecretInterface
	secret                      *v1.Secret
}

func NewSecretStore(store Store, secretName, secretNamespace, kubeConfigPath string) (Store, error) {
	var config *rest.Config
	var err error
	if kubeConfigPath != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeConfigPath)
	} else {
		config, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, err
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	s := &secretStore{Store: store, SecretName: secretName, SecretNamespace: secretNamespace, SecretClient: clientset.CoreV1().Secrets(secretNamespace)}
	if err := s.extractConfig(); err != nil {
		return nil, err
	}

	return s, nil
}

func (s *secretStore) Remove(name string) error {
	if err := s.Store.Remove(name); err != nil {
		return fmt.Errorf("error removing directories for host %v: %v", name, err)
	}
	return s.saveSecret(nil)
}

func (s *secretStore) Save(host *host.Host) error {
	if err := s.Store.Save(host); err != nil {
		return fmt.Errorf("error saving with file store: %v", err)
	}
	return s.saveSecret(host)
}

func (s *secretStore) saveSecret(host *host.Host) error {
	// create the tar.gz file
	destFile := &bytes.Buffer{}

	fileWriter := gzip.NewWriter(destFile)
	tarfileWriter := tar.NewWriter(fileWriter)

	if err := s.addDirToArchive(tarfileWriter); err != nil {
		tarfileWriter.Close()
		fileWriter.Close()
		return err
	}

	tarfileWriter.Close()
	fileWriter.Close()

	secret, err := s.loadSecret()
	if err != nil {
		return fmt.Errorf("unable to load secret : %v", err)
	}

	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}

	var updateSecret bool
	if !bytes.Equal(secret.Data[machineConfigSecretKey], destFile.Bytes()) {
		updateSecret = true
		secret.Data[machineConfigSecretKey] = destFile.Bytes()
	}

	if host != nil {
		ipAddress, err := host.Driver.GetIP()
		if err == nil && !bytes.Equal(secret.Data[ipAddressSecretKey], []byte(ipAddress)) {
			updateSecret = true
			secret.Data[ipAddress] = []byte(ipAddress)
		}
	}

	if updateSecret {
		secret, err = s.SecretClient.Update(context.Background(), secret, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("unable to update secret: %v", err)
		}
	}

	return nil
}

func (s *secretStore) addDirToArchive(tarfileWriter *tar.Writer) error {
	baseDir := s.GetMachinesDir()

	return filepath.Walk(baseDir,
		func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}

			if path == baseDir || strings.HasSuffix(info.Name(), ".iso") ||
				strings.HasSuffix(info.Name(), ".tar.gz") ||
				strings.HasSuffix(info.Name(), ".vmdk") ||
				strings.HasSuffix(info.Name(), ".img") {
				return nil
			}

			header, err := tar.FileInfoHeader(info, info.Name())
			if err != nil {
				return err
			}

			header.Name = path

			if err := tarfileWriter.WriteHeader(header); err != nil {
				return err
			}

			if info.IsDir() {
				return nil
			}

			file, err := os.Open(path)
			if err != nil {
				return err
			}
			defer file.Close()

			_, err = io.Copy(tarfileWriter, file)
			return err
		})
}

func (s *secretStore) loadSecret() (*v1.Secret, error) {
	secret, err := s.SecretClient.Get(context.Background(), s.SecretName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error getting secret from kubernetes: %v", err)
	}

	return secret, nil
}

func (s *secretStore) extractConfig() error {
	secret, err := s.loadSecret()
	if err != nil {
		return fmt.Errorf("error getting secret from kubernetes: %v", err)
	}

	extractedConfig, ok := secret.Data[machineConfigSecretKey]
	if !ok {
		log.Debugf("no data in %s", machineConfigSecretKey)
		return nil
	}

	gzipReader, err := gzip.NewReader(bytes.NewReader(extractedConfig))
	if err != nil {
		return err
	}
	tarReader := tar.NewReader(gzipReader)
	baseDir := s.GetMachinesDir()

	for {
		header, err := tarReader.Next()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("error reinitializing config (tarRead.Next). Config Dir: %v. Error: %v", baseDir, err)
		}

		filePath := header.Name
		log.Debugf("Extracting %v", filePath)

		info := header.FileInfo()
		if info.IsDir() {
			if err := os.MkdirAll(filePath, os.FileMode(header.Mode)); err != nil {
				return fmt.Errorf("error reinitializing config (Mkdirall). Config Dir: %v. Dir: %v. Error: %v", baseDir, info.Name(), err)
			}
			continue
		}

		file, err := os.OpenFile(filePath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode())
		if err != nil {
			return fmt.Errorf("error reinitializing config (OpenFile). Config Dir: %v. File: %v. Error: %v", baseDir, info.Name(), err)
		}

		_, err = io.Copy(file, tarReader)
		file.Close()
		if err != nil {
			return fmt.Errorf("error reinitializing config (Copy). Config Dir: %v. File: %v. Error: %v", baseDir, info.Name(), err)
		}
	}
}
