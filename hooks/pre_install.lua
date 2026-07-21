local REPO = "Aetf/homelab-ops"

--- Any git ref (full commit SHA, tag, branch) works: codeload serves a
--- tarball for it directly.
function PLUGIN:PreInstall(ctx)
    return {
        version = ctx.version,
        url = "https://codeload.github.com/" .. REPO .. "/tar.gz/" .. ctx.version,
    }
end
