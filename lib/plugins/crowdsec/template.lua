local template = {}

-- Gather template variables from the current request context
-- Can be extended with extra_vars table
function template.get_request_vars(extra_vars)
    local vars = {
        -- Request identification (requires nginx request_id module)
        request_id = ngx.var.request_id or "",

        -- Client information
        client_ip = ngx.var.remote_addr or "",
        client_port = ngx.var.remote_port or "",

        -- Request details
        request_uri = ngx.var.request_uri or "",
        request_method = ngx.var.request_method or "",
        host = ngx.var.host or "",
        server_name = ngx.var.server_name or "",
        scheme = ngx.var.scheme or "",

        -- User agent and headers
        user_agent = ngx.var.http_user_agent or "",
        referer = ngx.var.http_referer or "",

        -- Timing
        timestamp = os.date("%Y-%m-%d %H:%M:%S"),
        timestamp_iso = os.date("!%Y-%m-%dT%H:%M:%SZ"),
        timestamp_unix = tostring(os.time()),

        -- Server info
        server_addr = ngx.var.server_addr or "",
        server_port = ngx.var.server_port or "",
    }

    -- Merge in any extra variables passed
    if extra_vars then
        for k, v in pairs(extra_vars) do
            vars[k] = v
        end
    end

    return vars
end

-- Helper function to check if a value is truthy
local function is_truthy(value)
    if value == nil then return false end
    if type(value) == "boolean" then return value end
    if type(value) == "string" then return value ~= "" end
    if type(value) == "number" then return value ~= 0 end
    if type(value) == "table" then return next(value) ~= nil end
    return true
end

-- Escape special characters in a value for use in gsub replacement
local function escape_replacement(str)
    if type(str) ~= "string" then
        str = tostring(str)
    end
    -- Escape % which is special in Lua replacement strings
    return str:gsub("%%", "%%%%")
end

-- Escape special characters in pattern for literal matching
local function escape_pattern(str)
    return str:gsub("([%(%)%.%%%+%-%*%?%[%]%^%$])", "%%%1")
end

-- Parse template into segments for fast rendering
-- Returns a list of segments: {type="text|var|cond", ...}
local function parse_template(template_str)
    local segments = {}
    local pos = 1
    local len = #template_str

    while pos <= len do
        -- Look for next {{
        local start_pos = template_str:find("{{", pos, true)

        if not start_pos then
            -- No more placeholders, add remaining text
            if pos <= len then
                table.insert(segments, {type = "text", content = template_str:sub(pos)})
            end
            break
        end

        -- Add text before the placeholder
        if start_pos > pos then
            table.insert(segments, {type = "text", content = template_str:sub(pos, start_pos - 1)})
        end

        -- Check if this is a conditional
        local cond_match = template_str:match("^{{#if%s+([^}]+)}}", start_pos)
        if cond_match then
            -- Find matching {{/if}}
            local cond_start = start_pos
            local cond_open_end = template_str:find("}}", start_pos, true) + 2
            local depth = 1
            local search_pos = cond_open_end

            while depth > 0 and search_pos <= len do
                local next_if = template_str:find("{{#if", search_pos, true)
                local next_endif = template_str:find("{{/if}}", search_pos, true)

                if not next_endif then
                    -- Malformed template, treat rest as text
                    break
                end

                if next_if and next_if < next_endif then
                    depth = depth + 1
                    search_pos = next_if + 5
                else
                    depth = depth - 1
                    if depth == 0 then
                        -- Found matching endif
                        local inner_content = template_str:sub(cond_open_end, next_endif - 1)
                        local var_name = cond_match:match("^%s*(.-)%s*$")
                        local negated = false

                        if var_name:sub(1, 1) == "!" then
                            negated = true
                            var_name = var_name:sub(2):match("^%s*(.-)%s*$")
                        end

                        -- Split by {{else}}
                        local if_content, else_content = inner_content:match("^(.-){{else}}(.*)$")
                        if not if_content then
                            if_content = inner_content
                            else_content = ""
                        end

                        -- Recursively parse the if and else branches
                        table.insert(segments, {
                            type = "cond",
                            var = var_name,
                            negated = negated,
                            if_branch = parse_template(if_content),
                            else_branch = parse_template(else_content)
                        })

                        pos = next_endif + 7  -- skip past {{/if}}
                        break
                    end
                    search_pos = next_endif + 7
                end
            end

            if depth > 0 then
                -- Malformed, add as text
                table.insert(segments, {type = "text", content = template_str:sub(start_pos, cond_open_end - 1)})
                pos = cond_open_end
            end
        else
            -- Regular variable {{var}}
            local end_pos = template_str:find("}}", start_pos, true)
            if end_pos then
                local var_content = template_str:sub(start_pos + 2, end_pos - 1)
                -- Skip special markers like {{else}}, {{/if}}
                if var_content:match("^/") or var_content == "else" then
                    table.insert(segments, {type = "text", content = template_str:sub(start_pos, end_pos + 1)})
                else
                    table.insert(segments, {type = "var", name = var_content})
                end
                pos = end_pos + 2
            else
                -- No closing }}, add as text
                table.insert(segments, {type = "text", content = template_str:sub(start_pos)})
                break
            end
        end
    end

    return segments
end

-- Render parsed segments with given variables
local function render_segments(segments, args)
    local result = {}

    for _, segment in ipairs(segments) do
        if segment.type == "text" then
            table.insert(result, segment.content)
        elseif segment.type == "var" then
            local value = args[segment.name]
            if value ~= nil then
                table.insert(result, tostring(value))
            else
                -- Keep placeholder if variable not provided
                table.insert(result, "{{" .. segment.name .. "}}")
            end
        elseif segment.type == "cond" then
            local value = args[segment.var]
            local condition_met = is_truthy(value)

            if segment.negated then
                condition_met = not condition_met
            end

            if condition_met then
                table.insert(result, render_segments(segment.if_branch, args))
            else
                table.insert(result, render_segments(segment.else_branch, args))
            end
        end
    end

    return table.concat(result)
end

-- Precompile a template string into a parsed structure
-- Call this once at init time
function template.precompile(template_str)
    if template_str == nil or template_str == "" then
        return nil
    end
    return {
        segments = parse_template(template_str),
        raw = template_str
    }
end

-- Render a precompiled template with variables
-- Call this at request time for fast rendering
function template.render(compiled, args)
    if compiled == nil then
        return ""
    end
    if args == nil then
        args = {}
    end
    return render_segments(compiled.segments, args)
end

-- Original compile function for backward compatibility
-- Parses and renders in one step (less efficient for repeated use)
function template.compile(template_str, args)
    if args == nil then
        args = {}
    end

    local compiled = template.precompile(template_str)
    if compiled == nil then
        return template_str or ""
    end

    return template.render(compiled, args)
end

return template
