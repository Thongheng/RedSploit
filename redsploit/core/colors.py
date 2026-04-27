class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    DIM = '\033[2m'


# Rich-based log functions (backward compatible API)
def log_info(msg: str) -> None:
    """Display info message using Rich."""
    from .rich_output import get_formatter
    get_formatter().info(msg)


def log_success(msg: str) -> None:
    """Display success message using Rich."""
    from .rich_output import get_formatter
    get_formatter().success(msg)


def log_warn(msg: str) -> None:
    """Display warning message using Rich."""
    from .rich_output import get_formatter
    get_formatter().warn(msg)


def log_error(msg: str) -> None:
    """Display error message using Rich."""
    from .rich_output import get_formatter
    get_formatter().error(msg)


def log_run(cmd: str) -> None:
    """Display command execution using Rich."""
    from .rich_output import get_formatter
    get_formatter().run(cmd)
