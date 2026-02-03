package config

import (
	"os"
	"gopkg.in/yaml.v3"
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
	Blacklist []string `yaml:"blacklist"`
	Whitelist []string `yaml:"whitelist"`
}

type AIConfig struct {
	EnableAdwareModel  bool `yaml:"enable_adware_model"`
	EnableMalwareModel  bool `yaml:"enable_malware_scanner"`
}

type SourceConfig struct {
	Name         string `yaml:"name"`          
	URL          string `yaml:"url"`
	Format       string `yaml:"format"`       
	TargetColumn string `yaml:"target_column"`
}

func Load(path string) (*Config, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg Config
	decoder := yaml.NewDecoder(f)
	if err := decoder.Decode(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}