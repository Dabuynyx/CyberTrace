"""Forensic Module Registry for CyberTrace."""

from typing import Dict, Type, List
from cybertrace.core.interfaces import BaseForensicModule

class ModuleRegistry:
    _modules: Dict[str, Type[BaseForensicModule]] = {}

    @classmethod
    def register(cls, module_cls: Type[BaseForensicModule]):
        cls._modules[module_cls.__name__] = module_cls
        return module_cls

    @classmethod
    def get(cls, name: str) -> Type[BaseForensicModule]:
        return cls._modules.get(name)

    @classmethod
    def list_modules(cls) -> List[str]:
        return list(cls._modules.keys())

    @classmethod
    def get_instances(cls) -> List[BaseForensicModule]:
        return [mod_cls() for mod_cls in cls._modules.values()]
