# OWASP SQL Injection Sandbox Lab

## Overview
SQL Injection (SQLi) occurs when an application takes user input and uses it to construct a SQL query without proper sanitization. This allows malicious actors to execute arbitrary SQL commands.

## Core Concepts
- **Bypass Authentication**: Injecting `' OR 1=1 --` tricks the database into evaluating the query condition as always TRUE, bypassing login password validations.

## Lab Instructions
1. Run `ls` to view the schema log file `db_schema.sql`.
2. Input the SQL injection bypass payload into the terminal to bypass login.
3. Once bypassed, copy the flag: `NCAS{sqli_admin_bypass_success}`.
