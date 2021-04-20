#! /usr/bin/env python3

"""
A helper file for the system analysis rules.
"""

def get_file_contents(filename):
    """
    Opens a file and returns the data inside
    :param filename: The name of the file to return
    :return: The full data read from a file, or nothing if an error is thrown while the file is opened
    """
    # Depending on the file and the setup, the file may not exist. Use the try to avoid errors
    try:
        with open(filename, "r") as file:
            data = file.read()
            return data
    except FileNotFoundError:
        return
