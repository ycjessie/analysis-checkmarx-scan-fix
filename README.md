# analysis-checkmarx-scan-fix

Checkmarx scans to identify vulnerabilities in code and provides validation mechanisms for critical inputs

Checkmarx Scan

## Overview

This repository contains a Python application that validates command ingestion parameters, including `application_name`, `region_key`, `configuration`, OS-related file paths, and database connection strings. Security measures are implemented to prevent risks such as OS access violations, invalid file paths, and unsafe connection strings.Additionally, Checkmarx scans are integrated to identify and mitigate security vulnerabilities.

## Target Audience

- **Data Engineers**: Ensure and maintain reliable data ingestion pipelines
- **DevOps Professionals**: Automate security testing in CI/CD pipelines
- **Software Developers**: Protect applications from command injection vulnerabilities
- **Security Analysts**: Identifie and addresse potential security risks

## Features

### Command Validation

- Validates `sys.argv` inputs for `application_name`, `input_file`,`api_key`, `bucket_name`, `env_var`, `output_file` etc..
- Sanitizes OS path inputs to prevent access violations
- Implements file validation to ensure that files exist and maintain their integrity

### Connection String Validation

- Parses and validates database connection strings for secure ingestion
- Prevents injection attacks by sanitizing user-provided connection strings
- Supports validation for PostgreSQL, MySQL, and other database formats

### Checkmarx Integration

- Runs Checkmarx Static Application Security Testing (SAST) scans
- Provides detailed reports on security vulnerabilities

## Risks and Fixes

### Command-Line Arguments and Connection String Injection

**OS Access Violation**:
   - Malicious users can manipulate the input to delete critical system files.
   - Example: 
     ```python
     import os
     file_path = input("Enter file path: ")  # User-controlled input
     os.remove(files) #delete the file
     ```
   - **Solution**: Validate file path and files
     ```python
     import subprocess
     import re
     import sys
     DIR_PATTERN = r"^\/(?!.*\/\/)([a-zA-Z._-]+\/?)*$"
     FILE_PATTERN = r"^[^\s]+\.((xlsx|csv|pdf|html))$"
     dir_path=sys.arg[1]
     def validation(value, pattern, parameter_name):
        if not re.fullmatch(pattern, str(value)):
            raise ValueError(f"Invalid {parameter_name}: '{value}'")
        return True
    
     # Validate directory path
     try:
        DIR = validation(dir_path, DIR_PATTERN, "dir_path")
     # Validate each file in test_files
        validated_files = []
        for file_name in test_files:
            try:
                validated_file = validation(file_name, FILE_PATTERN, "file_name")
                validated_files.append(validated_file)
            except ValueError as e:
                print(f"Skipping invalid file: {str(e)}")
     except ValueError as e:
        print(f"Validation error: {str(e)}")
        sys.exit(1)
    
     # Use subprocess to delete the file
     try:
        subprocess.run(['rm', '-f', file_path], check=True)
        print(f"complete delete files: {file_path}")
     except subprocess.CalledProcessError as e:
        print(f"Error deleting file: {str(e)}")
     ```


**Command-Line Argument**:

   - Malicious users inject malicious inputs via `sys.argv`.
   - Example:
     - Malicious `env_var` values that override environment settings or inject harmful data.
     - Example: `python app.py --region "../../etc/passwd" --env_var "DROP DATABASE;"`
   - **Solution**: Sanitize inputs using a whitelist.

     - Example: Validates the `region` parameter using an `if ... in ... else` structure:

     ```python
     allowed_regions = ['us-east-1', 'us-west-2']
     if args['region'] in allowed_regions:
         print(f"Region '{args['region']}' is allowed.")
     else:
         raise ValueError("Region not allowed")
     ```

   - **Solution**: Validate host, database, and user parameters securely using regex patterns

   ```python
   import re
   import sys

   # Define patterns
   host_pattern = r"^(([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$|^(?:\d{1,3}\.){3}\d{1,3})$" #Hostname or IP address
   db_pattern = r"^[a-zA-Z0-9_-]+$"  # Database name
   user_pattern = r"^[a-zA-Z0-9_.]+$"  # Username
   password_pattern = r"^[a-zA-Z0-9_.!@#$%^&*]+$"  # Password with special characters
   region_pattern = r"^(us-east-1|us-west-2|eu-central-1)$"  # AWS regions whitelist

   # Inputs to validate
   host = "example.com"
   database = "my_database"
   user = "admin_user"
   password = "admin_password"
   regin_var="us-west-2"
   db_port = "5432"

   def validation(value, pattern, parameter_name):
        if not re.fullmatch(pattern, str(value)):
            raise ValueError(f"Invalid {parameter_name}: '{value}'")
        return True
   # Validate db_port
   def validate_db_port(db_port):
        if not db_port or not (0 < int(db_port) < 65536):
            raise ValueError(f"Invalid db_port: '{db_port}'. It must be an integer between 1 and 65535.")
        return int(db_port)
   try:
      # Validate all parameters using the standalone regex patterns
      HOST = validation(host, host_pattern, "host")
      DATABASE = validation(database, db_pattern, "database")
      USER = validation(user, user_pattern, "user")
      REGION_KEY = validation(region, region_pattern, "region")
      PASSWORD=validation(user, password_pattern, "password")
      DB_PORT = validate_db_port(db_port)

      print("All parameters are valid!")
   except ValueError as e:
      print(f"Validation db port error: {str(e)}")
      sys.exit(1)
   ```

---

### Connection String Ingestion Risks

**Injection Attacks**:
   - Malicious users could inject harmful SQL commands via unsafe connection strings.
   - Example:
     ```python
     dbcon=psycopg2.connect("dbname=test user=admin password=' OR '1'='1'")
     ```
   - **Solution**: Use parameterized queries to prevent Database injection.
   ```python
   import psycopg2
   dbcon=database_connection(HOST,DATAASE,USER,PASSWORD,DB_PORT,RETION_KEY)
   def database_connection(host, db_name, db_user, db_password, db_port, region):
    """
    Function to establish a database connection.
    """
    try:
        # Establish the database connection
        dbcon = psycopg2.connect(
            database=db_name,
            host=host,
            port=int(db_port),  # Ensure port is an integer
            user=db_user,
            password=db_password
        )
        print(f"Connected to the database successfully in region: {region}")
        return dbcon
    except psycopg2.Error as e:
        print(f"Database connection error: {str(e)}")
        return None  # Return None if the connection fails
   ```