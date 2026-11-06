# Security Policy

## Supported versions

Only the latest commit on the `main` branch receives security fixes.

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report them privately through GitHub: open the **Security** tab of this repository and choose **Report a vulnerability**.

Include, when possible:

- the module and command involved
- the version or commit
- steps to reproduce, with sample input files if needed
- the impact you expect

Reports are handled on a best-effort basis. You will get an answer, and credit in the fix if you want it.

## What is in scope

Problems in the toolkit itself, for example:

- command or argument injection
- path traversal, unsafe temporary files or unsafe handling of symbolic links
- sensitive data (passwords, hashes, keys) written to output, logs or files with weak permissions
- crashes or excessive resource use caused by crafted input files, logs, DNS or RDAP responses
- mistakes in the cryptographic design of the File Encryption module

## What is out of scope

- findings that the tools correctly report about an insecure system
- the sample files in `samples/`, which are intentionally insecure and use fake hashes
- weaknesses of third-party services queried by the IP Analyzer

## Important notes

- The File Encryption module uses its own file format and has not been audited by a third party. For production secrets, use an audited tool such as `age` or GPG.
- Some modules need elevated privileges to read system files. Review what a container can see before mounting host directories into it.
