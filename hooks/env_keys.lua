function PLUGIN:EnvKeys(ctx)
    return {
        { key = "HOMELAB_OPS_HOME", value = ctx.path },
        { key = "PATH", value = ctx.path .. "/bin" },
    }
end
