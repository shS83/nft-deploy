# NFT-Deploy

This is my attempt at a safe Nftables configuration updater which runs failsafe background process which checks if nftables is ok 
after deploying the new configuration and if not tries to restart it and if it doesn't work, it rolls back the backuped previous config and restarts nftables.

Port changes use TCP destination ports. `--input` (the default), `--output`,
and `--forward` select the chains for all `--port` and `--close-port` options,
regardless of argument order. Multiple chain flags can be combined.

`--port`, `--ports`, and `-p` accept a single port or comma-separated ports,
and can be repeated. For example:

```sh
sudo ./nft-deploy --use-current-rules --input --ports 80,443,8080 --dry-run
```

Each port must be between 1 and 65535. Empty list entries are rejected;
quote lists containing spaces, e.g. `--ports "80, 443"`.

Preview closing port 8080 in the existing configuration:

```sh
sudo ./nft-deploy --use-current-rules --input --close-port 8080 --dry-run
sudo ./nft-deploy --use-current-rules --output --forward --close-port 8080 --dry-run
sudo ./nft-deploy --use-current-rules --input --close-ports 80,443,8080 --dry-run
```

`--close-port` (also `--close-ports` or `-x`) takes one numeric port or a
comma-separated list and can be repeated. Each port must be between 1 and
65535; empty list entries are rejected. Quote lists containing spaces, e.g.
`--close-ports "80, 443"`. It removes matching single-port TCP `accept` lines from each
selected chain, including newly merged rules. If no such line exists, it
adds a `tcp dport PORT drop` rule before executable rules, for all sources.
Port sets, ranges, and service names are preserved and use this fallback.
Rules must use the usual multiline chain layout with one rule per line.
When removing the last rule leaves matching generated `# Begin of ...` and
`# End of ...` markers directly adjacent, those two markers are removed too.
Other comments and markers around rules that remain are preserved.

Removing an accept line does not guarantee that traffic is blocked: other
rules or an `accept` policy can still permit it. This operation deliberately
does not add a drop rule when it removes an accept line. Use
`--use-current-rules` to edit the configured ruleset; otherwise the existing
default-base behavior applies. Replace `--dry-run` with `--deploy` to apply.

Add individual rules with `--input-rule`, `--output-rule`, or `--forward-rule`.
Quote each rule as one shell argument and repeat the option for more rules:

```sh
sudo ./nft-deploy -U --dry-run \
  --input-rule 'tcp dport 8443 accept comment "Web service"' \
  --input-rule 'udp dport 5353 accept' \
  --output-rule 'udp dport 53 accept' \
  --forward-rule 'ip saddr 192.0.2.0/24 accept'
```

Rules go to the chain named in the option, independently of the port chain
flags. Within each chain, inline rules keep their supplied order and follow
rules loaded from files. They use the same insertion point as file rules
(before `pkttype`, if present, otherwise at the end of the chain).
Like rule files, inline rules suppress the automatic Promethean additions;
an explicitly selected `--default` profile is still included.
Empty or multiline arguments are rejected. The existing nft validation checks
rule syntax during dry-run or deployment. Port closing runs after merging
these rules, including cleanup of empty inline rule block markers.
