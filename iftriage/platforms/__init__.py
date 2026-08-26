"""Platform profiles. Importing this package registers all profiles."""

from . import eos, ios_xe, nxos  # noqa: F401  (registration side effect)
from .base import PlatformProfile, get_profile  # noqa: F401
