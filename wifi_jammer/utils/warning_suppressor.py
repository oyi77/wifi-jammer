"""
Warning suppression utilities for the WiFi jammer tool.
"""

import warnings
import logging
import sys
import os
from typing import Optional


class WarningSuppressor:
    """Utility class to suppress various warnings."""
    
    @staticmethod
    def suppress_scapy_warnings():
        """Suppress scapy-related warnings."""
        # Suppress deprecation warnings
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        warnings.filterwarnings("ignore", category=UserWarning)
        warnings.filterwarnings("ignore", category=FutureWarning)
        
        # Suppress specific scapy warnings
        warnings.filterwarnings("ignore", message=".*TripleDES.*")
        warnings.filterwarnings("ignore", message=".*cryptography.*")
        warnings.filterwarnings("ignore", message=".*No IPv4 address found.*")
        warnings.filterwarnings("ignore", message=".*more.*")
        
        # Suppress IPv4 address warnings
        warnings.filterwarnings("ignore", message=".*No IPv4 address found.*")
        
        # Suppress all scapy warnings
        warnings.filterwarnings("ignore", module="scapy.*")
    
    @staticmethod
    def suppress_logging_warnings():
        """Suppress logging warnings."""
        logging.getLogger("scapy").setLevel(logging.ERROR)
        logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        logging.getLogger("scapy.layers").setLevel(logging.ERROR)
        
        # Suppress all scapy loggers
        for logger_name in logging.Logger.manager.loggerDict:
            if 'scapy' in logger_name.lower():
                logging.getLogger(logger_name).setLevel(logging.ERROR)
    
    @staticmethod
    def suppress_stdout_stderr():
        """Suppress stdout/stderr for specific operations."""
        # Redirect stderr to /dev/null for scapy operations
        if hasattr(sys, 'stderr'):
            sys.stderr = open(os.devnull, 'w')
    
    @staticmethod
    def suppress_all_warnings():
        """Suppress all warnings."""
        WarningSuppressor.suppress_scapy_warnings()
        WarningSuppressor.suppress_logging_warnings()
        
        # Suppress all warnings if needed
        if not sys.warnoptions:
            warnings.filterwarnings("ignore")
        
        # Set environment variables to suppress warnings
        os.environ['PYTHONWARNINGS'] = 'ignore'
        os.environ['SCAPY_SUPPRESS_WARNINGS'] = '1'
    
    @staticmethod
    def suppress_tripledes_warnings():
        """Specifically suppress TripleDES deprecation warnings."""
        # Suppress TripleDES deprecation warnings
        warnings.filterwarnings("ignore", message=".*TripleDES.*")
        warnings.filterwarnings("ignore", message=".*cryptography.*")
        
        # Suppress specific cryptography warnings
        warnings.filterwarnings("ignore", message=".*has been moved to cryptography.hazmat.decrepit.*")
        warnings.filterwarnings("ignore", message=".*will be removed from this module.*")
        
        # Set environment variable to disable cryptography warnings
        os.environ['CRYPTOGRAPHY_DISABLE_FIPS'] = '1'
    
    @staticmethod
    def modern_warning_suppression():
        """Modern approach to warning suppression using latest libraries."""
        # Use the latest warning suppression methods
        WarningSuppressor.suppress_scapy_warnings()
        WarningSuppressor.suppress_tripledes_warnings()
        
        # Suppress IPv4 address warnings (common in modern networks)
        warnings.filterwarnings("ignore", message=".*No IPv4 address found.*")
        
        # Suppress network interface warnings
        warnings.filterwarnings("ignore", message=".*more.*")
        
        # Set modern environment variables
        os.environ['PYTHONWARNINGS'] = 'ignore'
        os.environ['SCAPY_SUPPRESS_WARNINGS'] = '1'
        os.environ['CRYPTOGRAPHY_DISABLE_FIPS'] = '1'


def setup_warning_suppression():
    """Setup modern warning suppression for the entire application."""
    WarningSuppressor.modern_warning_suppression() 