# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_vlz_global_optspecs
	string join \n v/verbose c/config= env-overrides= h/help V/version
end

function __fish_vlz_needs_command
	# Figure out if the current invocation already has a command.
	set -l cmd (commandline -opc)
	set -e cmd[1]
	argparse -s (__fish_vlz_global_optspecs) -- $cmd 2>/dev/null
	or return
	if set -q argv[1]
		# Also print the command, so this can be used to figure out what it is.
		echo $argv[1]
		return 1
	end
	return 0
end

function __fish_vlz_using_subcommand
	set -l cmd (__fish_vlz_needs_command)
	test -z "$cmd"
	and return 1
	contains -- $cmd[1] $argv
end

complete -c vlz -n "__fish_vlz_needs_command" -s c -l config -d 'Override configuration file location' -r
complete -c vlz -n "__fish_vlz_needs_command" -l env-overrides -d 'Set environment variable overrides (VLZ_*)' -r
complete -c vlz -n "__fish_vlz_needs_command" -s v -l verbose -d 'Increase verbosity (multiple times = more detail)'
complete -c vlz -n "__fish_vlz_needs_command" -s h -l help -d 'Print help'
complete -c vlz -n "__fish_vlz_needs_command" -s V -l version -d 'Print version'
complete -c vlz -n "__fish_vlz_needs_command" -f -a "scan" -d 'Scan a directory tree for manifests and CVEs'
complete -c vlz -n "__fish_vlz_needs_command" -f -a "list" -d 'List registered language/plugin names'
complete -c vlz -n "__fish_vlz_needs_command" -f -a "config" -d 'Show or set configuration values'
complete -c vlz -n "__fish_vlz_needs_command" -f -a "db" -d 'Database sub‑commands (stats, verify, migrate, list-providers, …)'
complete -c vlz -n "__fish_vlz_needs_command" -f -a "fp" -d 'False-positive markings'
complete -c vlz -n "__fish_vlz_needs_command" -f -a "preload" -d 'Pre-populate CVE cache from remote provider (placeholder)'
complete -c vlz -n "__fish_vlz_needs_command" -f -a "help" -d 'Show manual page'
complete -c vlz -n "__fish_vlz_needs_command" -f -a "generate-completions" -d 'Generate shell completion scripts'
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l format -d 'Output format (plain, json, sarif, cyclonedx, spdx)' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l summary-file -d 'Generate additional files: e.g. html:/tmp/out.html,cyclonedx:/tmp/sbom.json' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l provider -d 'Force a particular CVE provider' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l parallel -d 'Parallel query limit (default 10, max 50)' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l cache-db -d 'Override cache database path' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l ignore-db -d 'Override ignore (false-positive) database path' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l cache-ttl-secs -d 'Default TTL in seconds for new cache entries (default: 432000 = 5 days). Does not change existing entries; use `vlz db set-ttl` to update those' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l min-score -d 'Minimum CVSS score to count toward exit code' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l min-count -d 'Minimum count of CVEs meeting min-score to trigger CVE exit code (0 = any)' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l exit-code-on-cve -d 'Exit code when CVEs meet threshold (default 86)' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l fp-exit-code -d 'Exit code when only false-positives are present (default 0)' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l project-id -d 'Project ID for false-positive scoping (FR-015); only FPs for this project or global apply' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l backoff-base -d 'Base delay in ms for retry backoff (default 100)' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l backoff-max -d 'Maximum delay in ms for retry backoff (default 30000)' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l max-retries -d 'Maximum retries for transient errors (default 5)' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l severity-v2-critical-min -d 'CVSS v2 critical severity minimum score (default 9.0)' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l severity-v2-high-min -d 'CVSS v2 high severity minimum score (default 7.0)' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l severity-v2-medium-min -d 'CVSS v2 medium severity minimum score (default 4.0)' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l severity-v2-low-min -d 'CVSS v2 low severity minimum score (default 0.1)' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l severity-v3-critical-min -d 'CVSS v3 critical severity minimum score (default 9.0)' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l severity-v3-high-min -d 'CVSS v3 high severity minimum score (default 7.0)' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l severity-v3-medium-min -d 'CVSS v3 medium severity minimum score (default 4.0)' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l severity-v3-low-min -d 'CVSS v3 low severity minimum score (default 0.1)' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l severity-v4-critical-min -d 'CVSS v4 critical severity minimum score (default 9.0)' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l severity-v4-high-min -d 'CVSS v4 high severity minimum score (default 7.0)' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l severity-v4-medium-min -d 'CVSS v4 medium severity minimum score (default 4.0)' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l severity-v4-low-min -d 'CVSS v4 low severity minimum score (default 0.1)' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -s c -l config -d 'Override configuration file location' -r
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l offline -d 'Disable network access'
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l benchmark -d 'Benchmark mode (no cache, no network, parallel=1)'
complete -c vlz -n "__fish_vlz_using_subcommand scan" -l package-manager-required -d 'Require package manager on PATH; exit 3 with hint if missing'
complete -c vlz -n "__fish_vlz_using_subcommand scan" -s h -l help -d 'Print help'
complete -c vlz -n "__fish_vlz_using_subcommand list" -s c -l config -d 'Override configuration file location' -r
complete -c vlz -n "__fish_vlz_using_subcommand list" -s h -l help -d 'Print help'
complete -c vlz -n "__fish_vlz_using_subcommand config" -l set -d 'Set a key (e.g. python.regex="^requirements\\\\.txt$")' -r
complete -c vlz -n "__fish_vlz_using_subcommand config" -s c -l config -d 'Override configuration file location' -r
complete -c vlz -n "__fish_vlz_using_subcommand config" -l list
complete -c vlz -n "__fish_vlz_using_subcommand config" -l example -d 'Output verilyze.conf.example with effective values for this environment'
complete -c vlz -n "__fish_vlz_using_subcommand config" -s h -l help -d 'Print help'
complete -c vlz -n "__fish_vlz_using_subcommand db; and not __fish_seen_subcommand_from stats verify migrate list-providers show set-ttl" -l cache-ttl-secs -d 'Default TTL in seconds when opening the cache (default: 432000 = 5 days). Does not change existing entries; use `vlz db set-ttl` to update those' -r
complete -c vlz -n "__fish_vlz_using_subcommand db; and not __fish_seen_subcommand_from stats verify migrate list-providers show set-ttl" -s c -l config -d 'Override configuration file location' -r
complete -c vlz -n "__fish_vlz_using_subcommand db; and not __fish_seen_subcommand_from stats verify migrate list-providers show set-ttl" -s h -l help -d 'Print help'
complete -c vlz -n "__fish_vlz_using_subcommand db; and not __fish_seen_subcommand_from stats verify migrate list-providers show set-ttl" -f -a "stats"
complete -c vlz -n "__fish_vlz_using_subcommand db; and not __fish_seen_subcommand_from stats verify migrate list-providers show set-ttl" -f -a "verify"
complete -c vlz -n "__fish_vlz_using_subcommand db; and not __fish_seen_subcommand_from stats verify migrate list-providers show set-ttl" -f -a "migrate"
complete -c vlz -n "__fish_vlz_using_subcommand db; and not __fish_seen_subcommand_from stats verify migrate list-providers show set-ttl" -f -a "list-providers" -d 'List supported CVE providers'
complete -c vlz -n "__fish_vlz_using_subcommand db; and not __fish_seen_subcommand_from stats verify migrate list-providers show set-ttl" -f -a "show" -d 'Display cache entries with TTL and added timestamp'
complete -c vlz -n "__fish_vlz_using_subcommand db; and not __fish_seen_subcommand_from stats verify migrate list-providers show set-ttl" -f -a "set-ttl" -d 'Update TTL for existing cache entries'
complete -c vlz -n "__fish_vlz_using_subcommand db; and __fish_seen_subcommand_from stats" -s c -l config -d 'Override configuration file location' -r
complete -c vlz -n "__fish_vlz_using_subcommand db; and __fish_seen_subcommand_from stats" -s h -l help -d 'Print help'
complete -c vlz -n "__fish_vlz_using_subcommand db; and __fish_seen_subcommand_from verify" -s c -l config -d 'Override configuration file location' -r
complete -c vlz -n "__fish_vlz_using_subcommand db; and __fish_seen_subcommand_from verify" -s h -l help -d 'Print help'
complete -c vlz -n "__fish_vlz_using_subcommand db; and __fish_seen_subcommand_from migrate" -s c -l config -d 'Override configuration file location' -r
complete -c vlz -n "__fish_vlz_using_subcommand db; and __fish_seen_subcommand_from migrate" -s h -l help -d 'Print help'
complete -c vlz -n "__fish_vlz_using_subcommand db; and __fish_seen_subcommand_from list-providers" -s c -l config -d 'Override configuration file location' -r
complete -c vlz -n "__fish_vlz_using_subcommand db; and __fish_seen_subcommand_from list-providers" -s h -l help -d 'Print help'
complete -c vlz -n "__fish_vlz_using_subcommand db; and __fish_seen_subcommand_from show" -l format -d 'Output format (e.g. json for full payload)' -r
complete -c vlz -n "__fish_vlz_using_subcommand db; and __fish_seen_subcommand_from show" -s c -l config -d 'Override configuration file location' -r
complete -c vlz -n "__fish_vlz_using_subcommand db; and __fish_seen_subcommand_from show" -l full -d 'Include full CVE payload for each entry'
complete -c vlz -n "__fish_vlz_using_subcommand db; and __fish_seen_subcommand_from show" -s h -l help -d 'Print help'
complete -c vlz -n "__fish_vlz_using_subcommand db; and __fish_seen_subcommand_from set-ttl" -l entry -d 'Update a single entry by key (e.g. "name::version")' -r
complete -c vlz -n "__fish_vlz_using_subcommand db; and __fish_seen_subcommand_from set-ttl" -l pattern -d 'Update entries matching pattern' -r
complete -c vlz -n "__fish_vlz_using_subcommand db; and __fish_seen_subcommand_from set-ttl" -l entries -d 'Update multiple entries (comma-separated keys)' -r
complete -c vlz -n "__fish_vlz_using_subcommand db; and __fish_seen_subcommand_from set-ttl" -s c -l config -d 'Override configuration file location' -r
complete -c vlz -n "__fish_vlz_using_subcommand db; and __fish_seen_subcommand_from set-ttl" -l all -d 'Update all entries'
complete -c vlz -n "__fish_vlz_using_subcommand db; and __fish_seen_subcommand_from set-ttl" -s h -l help -d 'Print help'
complete -c vlz -n "__fish_vlz_using_subcommand fp; and not __fish_seen_subcommand_from mark unmark" -s c -l config -d 'Override configuration file location' -r
complete -c vlz -n "__fish_vlz_using_subcommand fp; and not __fish_seen_subcommand_from mark unmark" -s h -l help -d 'Print help'
complete -c vlz -n "__fish_vlz_using_subcommand fp; and not __fish_seen_subcommand_from mark unmark" -f -a "mark" -d 'Mark a CVE as false positive'
complete -c vlz -n "__fish_vlz_using_subcommand fp; and not __fish_seen_subcommand_from mark unmark" -f -a "unmark" -d 'Remove false-positive marking for a CVE'
complete -c vlz -n "__fish_vlz_using_subcommand fp; and __fish_seen_subcommand_from mark" -l comment -d 'Optional comment' -r
complete -c vlz -n "__fish_vlz_using_subcommand fp; and __fish_seen_subcommand_from mark" -l project-id -d 'Optional project scope' -r
complete -c vlz -n "__fish_vlz_using_subcommand fp; and __fish_seen_subcommand_from mark" -s c -l config -d 'Override configuration file location' -r
complete -c vlz -n "__fish_vlz_using_subcommand fp; and __fish_seen_subcommand_from mark" -s h -l help -d 'Print help'
complete -c vlz -n "__fish_vlz_using_subcommand fp; and __fish_seen_subcommand_from unmark" -s c -l config -d 'Override configuration file location' -r
complete -c vlz -n "__fish_vlz_using_subcommand fp; and __fish_seen_subcommand_from unmark" -s h -l help -d 'Print help'
complete -c vlz -n "__fish_vlz_using_subcommand preload" -s c -l config -d 'Override configuration file location' -r
complete -c vlz -n "__fish_vlz_using_subcommand preload" -s h -l help -d 'Print help'
complete -c vlz -n "__fish_vlz_using_subcommand help" -s c -l config -d 'Override configuration file location' -r
complete -c vlz -n "__fish_vlz_using_subcommand help" -s h -l help -d 'Print help'
complete -c vlz -n "__fish_vlz_using_subcommand generate-completions" -s c -l config -d 'Override configuration file location' -r
complete -c vlz -n "__fish_vlz_using_subcommand generate-completions" -s h -l help -d 'Print help'
