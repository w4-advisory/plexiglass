"""Plexiglass security evaluation SDK (no optional ML imports)."""
from importlib.resources import files

__version__ = files(__package__).joinpath("version").read_text().strip()
