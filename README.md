# Linux Forensic Toolkit

A personal collection of Linux forensic and incident-response helper
scripts.

## Contents

-   `linux_forensic_baseline.sh` --- collects a baseline of system
    information and identifies files modified within a specified time
    window.

## Requirements

-   Ubuntu or a compatible Linux distribution
-   Bash
-   `sudo` privileges for collecting system-level information
-   Standard Linux utilities; some optional commands may not be
    installed on every system

## Download

Download the script directly from this GitHub repository:

``` bash
wget -O linux_forensic_baseline.sh \
  https://raw.githubusercontent.com/YOUR-USERNAME/linux-forensic-toolkit/main/linux_forensic_baseline.sh
```

Replace `YOUR-USERNAME` with your GitHub username or organization.

## Verify SHA256

On the trusted machine where the original script is stored, calculate
its checksum:

``` bash
sha256sum linux_forensic_baseline.sh
```

On the Ubuntu target machine, calculate it again:

``` bash
sha256sum linux_forensic_baseline.sh
```

Compare the complete SHA256 values. They must match exactly before you
run the script.

> Keep the trusted checksum somewhere separate from the downloaded
> script/repository when using this check as an integrity control. A
> checksum downloaded from the same repository does not independently
> prove who published the script.

## Run

Make the script executable:

``` bash
chmod 750 linux_forensic_baseline.sh
```

Review the script before execution, then run it with the incident time
window and evidence output directory:

``` bash
sudo ./linux_forensic_baseline.sh \
  "2026-11-01 00:00:00" \
  "2026-11-03 23:59:59" \
  /mnt/evidence
```

Argument format:

``` text
sudo ./linux_forensic_baseline.sh "START_DATETIME" "END_DATETIME" "OUTPUT_DIRECTORY"
```

Use timestamps in the target system's local time zone. Confirm the
system time and time zone before collecting evidence.

## Output

The script is designed to create text reports such as:

-   System baseline report
-   Files changed during the specified time window
-   SHA256 hashes of collected changed files

The exact filenames include the hostname and collection timestamp.

## Important forensic notes

-   This is a triage and baseline collection helper, not a full forensic
    imaging tool.
-   `mtime` indicates content modification time; `ctime` indicates inode
    metadata change time. Neither reliably identifies the person or
    process responsible.
-   A normal filesystem search cannot list files that have already been
    deleted.
-   File timestamps can be altered and should not be treated as
    conclusive evidence.
-   The script may create activity on the investigated host. For a
    high-priority incident, follow your incident-response procedure and
    collect volatile evidence first where appropriate.
-   Prefer writing output to approved external evidence storage rather
    than the investigated system's own disk.
-   Record the hostname, collection time, operator, script version, and
    trusted SHA256 value in your evidence log.

## Disclaimer

Use this script only on systems you are authorized to investigate.
Review and test changes before using the script in a production
incident.
