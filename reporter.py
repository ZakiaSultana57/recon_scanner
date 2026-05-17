"""
ReconX - Banner Module
"""

BANNER = r"""
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗██╗  ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚██╗██╔╝
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║ ╚███╔╝ 
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║ ██╔██╗ 
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██╔╝ ██╗
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝
"""

VERSION = "1.0.0"
AUTHOR  = "ReconX Security Tool"
TAGLINE = "Automated Reconnaissance & Vulnerability Scanner"


def print_banner():
    """Print the ASCII banner with color codes."""
    CYAN   = "\033[96m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    RESET  = "\033[0m"
    DIM    = "\033[2m"

    print(f"{CYAN}{BANNER}{RESET}")
    print(f"{GREEN}  {TAGLINE}{RESET}")
    print(f"{DIM}  Version {VERSION}  |  {AUTHOR}{RESET}")
    print(f"{YELLOW}  ⚠  Only scan systems you are authorized to test  ⚠{RESET}")
    print()
