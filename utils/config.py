"""Configuration management"""

import os
import yaml
from pathlib import Path
from typing import Optional, Dict, Any


class Config:
    """Manages configuration for Vibe Probe"""

    def __init__(self, config_path: Optional[str] = None, args: Any = None):
        self.config_data = {}
        self.args = args

        # Load from config file if provided
        if config_path and Path(config_path).exists():
            with open(config_path, 'r') as f:
                self.config_data = yaml.safe_load(f)

        # Load from environment variables
        self._load_env_vars()

        # Override with command-line arguments
        if args:
            self._load_args(args)

    def _load_env_vars(self):
        """Load API keys and sensitive data from environment"""
        env_vars = {
            "shodan_api_key": os.getenv("SHODAN_API_KEY"),
            "censys_api_id": os.getenv("CENSYS_API_ID"),
            "censys_api_secret": os.getenv("CENSYS_API_SECRET"),
            "virustotal_api_key": os.getenv("VIRUSTOTAL_API_KEY"),
            "github_token": os.getenv("GITHUB_TOKEN"),
            "twitter_bearer_token": os.getenv("TWITTER_BEARER_TOKEN"),
            "newsapi_key": os.getenv("NEWSAPI_KEY"),
            "hibp_api_key": os.getenv("HIBP_API_KEY"),
            "securitytrails_api_key": os.getenv("SECURITYTRAILS_API_KEY"),
        }

        # Only add non-None values
        for key, value in env_vars.items():
            if value:
                self.config_data[key] = value

    def _load_args(self, args):
        """Load configuration from command-line arguments"""
        if hasattr(args, 'verbose'):
            self.verbose = args.verbose
        if hasattr(args, 'output'):
            self.output_dir = args.output
        if hasattr(args, 'probes'):
            self.selected_probes = args.probes.split(',') if args.probes else None

    @property
    def verbose(self) -> bool:
        return self.config_data.get('verbose', False)

    @verbose.setter
    def verbose(self, value: bool):
        self.config_data['verbose'] = value

    @property
    def output_dir(self) -> str:
        return self.config_data.get('output_dir', './reports')

    @output_dir.setter
    def output_dir(self, value: str):
        self.config_data['output_dir'] = value

    @property
    def selected_probes(self) -> Optional[list]:
        return self.config_data.get('selected_probes')

    @selected_probes.setter
    def selected_probes(self, value: Optional[list]):
        self.config_data['selected_probes'] = value

    def should_run_probe(self, probe_name: str) -> bool:
        """Check if a probe should be run based on configuration"""
        if self.selected_probes is None:
            return True
        return probe_name in self.selected_probes

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value"""
        return self.config_data.get(key, default)

    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for a service"""
        key_name = f"{service.lower()}_api_key"
        return self.config_data.get(key_name)
