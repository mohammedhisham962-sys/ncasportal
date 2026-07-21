# Linux Privilege Escalation Lab

## Overview
Privilege Escalation involves moving from a low-privileged account (like `student-hacker`) to a high-privileged account (like `root`).

## Core Concepts
- **Sudo Misconfigurations**: Checking command configurations with `sudo -l` highlights files that can be run with root rights without entering passwords.

## Lab Instructions
1. Run `sudo -l` to audit the binary execution permissions.
2. Observe that `/usr/bin/cat` is allowed for `/root/flag.txt` without a password.
3. Retrieve the root flag and submit it for validation.
