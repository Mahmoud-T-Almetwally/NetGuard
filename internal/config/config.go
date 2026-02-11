package config

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Constants for configuration
const (
	DefaultConfigPath = "/etc/netguard/config.yaml"
	GitHubConfigURL   = "https://raw.githubusercontent.com/Mahmoud-T-Almetwally/NetGuard/refs/heads/main/configs/config.yaml"
)

type Config struct {
	App      AppConfig      `yaml:"app"`
	Network  NetworkConfig  `yaml:"network"`
	Blocking BlockingConfig `yaml:"blocking"`
	AI       AIConfig       `yaml:"ai"`
}

type AppConfig struct {
	UpdateInterval int    `yaml:"update_interval_hours"`
	LogLevel       string `yaml:"log_level"`
}

type NetworkConfig struct {
	QueueNum  int `yaml:"queue_num"`
	QueueSize int `yaml:"queue_size"`
}

type BlockingConfig struct {
	Sources   []SourceConfig `yaml:"sources"`
	Blacklist []string       `yaml:"blacklist"`
	Whitelist []string       `yaml:"whitelist"`
}

type AIConfig struct {
	EnableAdwareModel  bool `yaml:"enable_adware_model"`
	EnableMalwareModel bool `yaml:"enable_malware_scanner"`
}

type SourceConfig struct {
	Name         string `yaml:"name"`
	URL          string `yaml:"url"`
	Format       string `yaml:"format"`
	TargetColumn string `yaml:"target_column"`
}

func Load() (*Config, error) {
	searchPaths := []string{
		"configs/config.yaml",
		"./config.yaml",
		"/etc/netguard/config.yaml",
		"/var/lib/netguard/configs/config.yaml",
	}

	var loadedPath string

	for _, p := range searchPaths {
		if _, err := os.Stat(p); err == nil {
			loadedPath = p
			break
		}
	}

	if loadedPath == "" {
		log.Println("Config file not found locally. Attempting to download from GitHub...")
		if err := downloadAndSaveConfig(GitHubConfigURL, DefaultConfigPath); err != nil {
			return nil, fmt.Errorf("failed to download default config: %w", err)
		}
		loadedPath = DefaultConfigPath
		log.Printf("Config downloaded and saved to: %s", loadedPath)
	}

	log.Printf("Loading config from: %s", loadedPath)

	return parseConfigFile(loadedPath)
}

func parseConfigFile(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg Config
	decoder := yaml.NewDecoder(f)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("failed to decode config file: %w", err)
	}

	return &cfg, nil
}

func downloadAndSaveConfig(url, dst string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	dir := filepath.Dir(dst)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %w", dir, err)
	}

	out, err := os.Create(dst)
	if err != nil {
		return fmt.Errorf("failed to create file %s: %w", dst, err)
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return err
	}

	return nil
}