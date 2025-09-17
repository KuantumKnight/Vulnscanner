import os
from pathlib import Path

def get_file_size(file_path):
    """Get file size in bytes"""
    return os.path.getsize(file_path)

def is_supported_file(file_path):
    """Check if file extension is supported"""
    supported_extensions = ['.py', '.js']
    return Path(file_path).suffix.lower() in supported_extensions

def filter_files(file_list, max_size=1024*1024):
    """Filter files by size and extension"""
    filtered_files = []
    for file_path in file_list:
        if (is_supported_file(file_path) and 
            get_file_size(file_path) <= max_size):
            filtered_files.append(file_path)
    return filtered_files

def format_severity(severity):
    """Format severity for display"""
    return severity.capitalize()