The script clones SonicWall access rules that reference a given source Address Object (directly or via groups) and recreates them for a target Address Object, adjusting zones automatically.
It mirrors the firewall’s JSON shapes for address and service groups, falls back across compatible formats, and skips duplicates using a rule signature.
Only safe, minimal fields are posted (action, zones, source/destination, service, optional name/comment and simple “any” ports), then changes can be committed or previewed with dry‑run.
Logs are human‑friendly and include source, destination, service, and any port hints for each skipped or created rule.
