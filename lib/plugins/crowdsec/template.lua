local template = {}

-- Helper function to check if a value is truthy
local function is_truthy(value)
    if value == nil then return false end
    if type(value) == "boolean" then return value end
    if type(value) == "string" then return value ~= "" end
    if type(value) == "number" then return value ~= 0 end
    if type(value) == "table" then return next(value) ~= nil end
    return true
end

-- Process if/else conditionals
-- Syntax: {{#if variable}}content{{else}}other content{{/if}}
-- Supports negation: {{#if !variable}}content{{/if}}
-- The else block is optional
local function process_conditionals(template_str, args)
    -- Pattern to match {{#if var}}...{{else}}...{{/if}} or {{#if var}}...{{/if}}
    -- Using a loop to handle nested conditionals from innermost out
    local max_iterations = 100  -- Safety limit to prevent infinite loops
    local iteration = 0

    while iteration < max_iterations do
        iteration = iteration + 1

        -- Find the innermost if block (one that doesn't contain another #if)
        -- Match {{#if ...}}...{{/if}} where the content doesn't contain {{#if
        local found = false

        template_str = template_str:gsub(
            "{{#if%s+([^}]+)}}(.-){{\\/if}}",
            function(condition, content)
                -- Check if this block contains a nested #if - if so, skip it for now
                if content:match("{{#if") then
                    return "{{#if " .. condition .. "}}" .. content .. "{{/if}}"
                end

                found = true
                local negated = false
                local var_name = condition:match("^%s*(.-)%s*$")  -- trim whitespace

                -- Check for negation
                if var_name:sub(1, 1) == "!" then
                    negated = true
                    var_name = var_name:sub(2):match("^%s*(.-)%s*$")  -- trim again
                end

                -- Split content by {{else}}
                local if_content, else_content = content:match("^(.-){{else}}(.*)$")
                if not if_content then
                    if_content = content
                    else_content = ""
                end

                -- Evaluate condition
                local value = args[var_name]
                local condition_met = is_truthy(value)

                if negated then
                    condition_met = not condition_met
                end

                if condition_met then
                    return if_content
                else
                    return else_content
                end
            end
        )

        -- If no substitution was made, we're done
        if not found then
            break
        end
    end

    return template_str
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

function template.compile(template_str, args)
    if args == nil then
        args = {}
    end

    -- First process conditionals
    template_str = process_conditionals(template_str, args)

    -- Then do variable substitution
    for k, v in pairs(args) do
        local var = "{{" .. k .. "}}"
        local escaped_var = escape_pattern(var)
        local escaped_value = escape_replacement(v)
        template_str = template_str:gsub(escaped_var, escaped_value)
    end

    return template_str
end

return template
