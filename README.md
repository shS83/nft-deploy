# NFT-Deploy

This is my attempt at a safe Nftables configuration updater which runs failsafe background process which checks if nftables is ok 
after deploying the new configuration and if not tries to restart it and if it doesn't work, it rolls back the backuped previous config and restarts nftables.
