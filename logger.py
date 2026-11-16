# JSON log format
JSON_FORMAT = "%(asctime)s %(correlation_id)s %(levelname)s %(module)s %(message)s"


class CorrelationFormatter(logging.Formatter):
    """Formatter that includes correlation ID in log records."""

    def format(self, record: logging.LogRecord) -> str:
        # Add correlation ID if available
        if _correlation_id:
            record.correlation_id = f"cid:{_correlation_id}"
        else:
            record.correlation_id = "cid:None"
        
        # Add module name if not present
        if not record.module:
            record.module = self.module or "unknown"
        
        return super().format(record)


def setup_json_logging(
    log_file: str | Path = "output/phots-live.log",
    correlation_id: str | None = None,
    enable_console: bool = True,
) -> str:
    """Set up structured JSON logging for the Phots application."""
    global _correlation_id, _console_handler
    
    # Set correlation ID
    cid = set_correlation_id(correlation_id)
    
    # Configure log file
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    # Create formatter
    formatter = CorrelationFormatter(
        JSON_FORMAT,
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )
    
    # File handler
    file_handler = logging.handlers.RotatingFileHandler(
        log_path,
        maxBytes=10 * 1024 * 1024,  # 10 MiB
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging.INFO)
    
    # Get the root phots logger
    root_logger = logging.getLogger("phots")
    root_logger.setLevel(logging.INFO)
    
    # Remove existing handlers to avoid duplicates
    for h in root_logger.handlers[:]:
        root_logger.removeHandler(h)
    
    root_logger.addHandler(file_handler)
    
    # Console handler (optional)
    if enable_console and _console_handler is None:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        console_handler.setLevel(logging.INFO)
        root_logger.addHandler(console_handler)
        _console_handler = console_handler
    
    # Log the setup
    root_logger.info(
        "Structured JSON logging initialized",
        extra={"log_file": str(log_path), "correlation_id": cid},
    )
    
    return cid