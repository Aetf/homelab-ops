local http = require("http")
local json = require("json")

local REPO = "Aetf/homelab-ops"

--- Versions are git refs of this repo itself: tags first, then recent
--- commit SHAs (installs are normally pinned to a full SHA in mise config).
function PLUGIN:Available(ctx)
    local result = {}

    local resp, err = http.get({
        url = "https://api.github.com/repos/" .. REPO .. "/tags?per_page=20",
    })
    if err == nil and resp.status_code == 200 then
        for _, tag in ipairs(json.decode(resp.body)) do
            table.insert(result, { version = tag.name, note = "tag" })
        end
    end

    resp, err = http.get({
        url = "https://api.github.com/repos/" .. REPO .. "/commits?per_page=30",
    })
    if err == nil and resp.status_code == 200 then
        for _, c in ipairs(json.decode(resp.body)) do
            local subject = (c.commit.message or ""):match("^[^\n]*") or ""
            table.insert(result, {
                version = c.sha,
                note = string.sub(c.commit.committer.date or "", 1, 10) .. " " .. subject,
            })
        end
    end

    return result
end
