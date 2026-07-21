local REPO = "Aetf/homelab-ops"

--- Any git ref (full commit SHA, tag, branch) works. The /archive/ URL is
--- used instead of codeload because mise detects the archive format from
--- the filename, which must end in .tar.gz.
function PLUGIN:PreInstall(ctx)
    return {
        version = ctx.version,
        url = "https://github.com/" .. REPO .. "/archive/" .. ctx.version .. ".tar.gz",
    }
end
