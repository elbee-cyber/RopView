from binaryninja import *
from binaryninjaui import ViewType
from .modules.RopViewType import RopViewType
import logging

logging.info("Plugin loaded!","Untitled ROP Plugin")
ViewType.registerViewType(RopViewType())
