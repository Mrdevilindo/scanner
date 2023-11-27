import copy
import pdb
from urllib.parse import urlparse, quote, unquote
from core import config
from core.checker import checker
from core.colors import end, green, que
import core.config
from core.dom import dom
from core.filterChecker import filterChecker
from core.generator import generator
from core.htmlParser import htmlParser
from core.requester import requester
from core.utils import getUrl, getParams
from core.wafDetector import wafDetector
from core.log import setup_logger
from modes import scan
from common import banner
from modes.scan import parse_args  # Import parse_args and scan from scan module

logger = setup_logger(__name__)

if __name__ == "__main__":
    banner.banner()  # Assuming display_banner is the function to show your banner
    
    args = parse_args()
    
    # Assuming you have some logic to define paramData, encoding, headers, etc.
    paramData = ...  # Define paramData here or wherever is appropriate
    encoding = ...  # Define encoding
    headers = ...   # Define headers
    delay = ...     # Define delay
    timeout = ...   # Define timeout
    skipDOM = ...   # Define skipDOM
    skip = ...      # Define skip

    if args:
        scan.scan(args, paramData, encoding, headers, delay, timeout, skipDOM, skip)
    else:
        # Display the available arguments
        print("Available arguments:")
        for arg, value in vars(args).items():
            print(f'--{arg}: {value}')
