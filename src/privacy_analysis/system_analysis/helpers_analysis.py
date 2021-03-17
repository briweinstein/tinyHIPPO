#! /usr/bin/env python3

# Opens a file and returns the data
def get_file_contents(filename):
    # Depending on the file and the setup, the file may not exist. Try to avoid errors
    try:
        with open(filename, "r") as file:
            data = file.read()
            return data
    except FileNotFoundError:
        return
