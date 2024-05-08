from binaryninjaui import ViewType
from .modules.RopViewType import RopViewType

ViewType.registerViewType(RopViewType())
