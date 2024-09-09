from himl import ConfigProcessor
from yaml import dump
from appdirs import AppDirs

from dataclasses import dataclass, field, asdict
from dacite import from_dict
from typing import Optional
import os

app_name = "r2ai"
appauthor = "radare2"
dirs = AppDirs(app_name, appauthor)
    

@dataclass
class ModelType:
    name: str = ""
    base_url: Optional[str] = None

@dataclass
class Model:
    type: ModelType = field(default_factory=ModelType)
    name: str = ""


@dataclass
class BaseConfig:
    model: Model = field(default_factory=Model)


class Config:
    # TODO: Better documentation
    """Config class holding configuration data.
       All changes must be commited after modifying.
       Eg:
          from r2ai import CONFIG
          CONFIG.config.model.name = "gpt-4"
          CONFIG.commit()
    """
    def __init__(self):
        # fetch the default commit and dumps it to a yml str
        self.config = BaseConfig()
        yml = dump(asdict(self.config))

        # sets up directories for configs
        self._base_config_dir = os.path.join(dirs.user_config_dir)
        self._prod_config_dir = os.path.join(self._base_config_dir, "production")
        self._base_file_path = os.path.join(self._base_config_dir, "default.yaml")
        self._prod_file_path = os.path.join(self._prod_config_dir, "env.yaml")

        # production, used for the actual configuration
        if not os.path.exists(self._prod_config_dir):
            os.makedirs(self._prod_config_dir)
        # template for the configuration. we need that latter to be processed
        ## with the processor which will create an updated production config with all the posible newly added configuration
        ### it's better to override this every time so users can't break it
        with open(self._base_file_path, "w") as outf:
            outf.write(yml)
        # the actual production file
        if not os.path.exists(self._prod_file_path):
            with open(self._prod_file_path, "w") as outf:
                outf.write(yml)
        # process the new (default) and old (prod) config and merge them
        config_processor = ConfigProcessor()
        data = config_processor.process(path=self._prod_config_dir, filters=(), exclude_keys=(),
                         output_format="yaml")
        self.config = from_dict(data_class=BaseConfig, data=data)

    # this is to save the changes at runtime, but I actually think or just having the configuration edited manually
    # it's yml and it's easy to write
    def commit(self):
        """Commit changes"""
        with open(self._prod_file_path, "w") as outf:
            outf.write(dump(asdict(self.config)))
        