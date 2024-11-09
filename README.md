# Encryption Application with Logging

This repository contains a Python-based encryption and decryption application with integrated logging functionality to track key operations and errors during execution.

## Files in this Repository

- **encryption_app.py**: A Python script that implements encryption and decryption functions, potentially using a cipher like the Vigenère or AES. The script integrates logging to capture important events and errors.

- **encryption_app.txt**: A log.

## Project Overview
In this assignment, you will enhance a Python encryption application by adding logging functionality. The goal is to provide comprehensive logs that will help in debugging, monitoring, and understanding the application's behavior. Run the python code within Kali Linux, and ensure that the application's output is directed to appropriate log files.

Here is copy of the Encryption Application to use (encryption_app.py)

Instructions:

Modify the Python Encryption Application:
Open the Python file provided.
Import the logging module at the beginning of your script.
Configure the logging module by adding code to produce logs at appropriate places within your code.
Add Log Messages:
Throughout your code, strategically place log messages of different levels to capture different levels of information.
In the comments of your code, describe each log message and explain why you chose the corresponding logging level. For example:
 # This log message provides information about the processing of input files and is set at DEBUG level for detailed debugging. logging.debug("Processing input file: %s", input_file) 
Run the Code within Kali Linux:
Ensure that your Kali Linux environment is set up and running. Open a terminal and navigate to the directory containing your Python file.
Observe the output on the terminal and verify that log messages are being generated.
Check Log Files:
Locate the file that you have configured for logs to output to.
Open the log file using a text editor and examine the logged messages.

### Application Features

1. **Encryption and Decryption**:
   - Supports encryption and decryption of text using a specified algorithm.
   - Allows user input for text and keys directly from the command line.

2. **Logging**:
   - Logs key events, including successful encryption/decryption operations, errors, and other relevant actions.
   - Provides error handling to capture and log any issues encountered during runtime.
