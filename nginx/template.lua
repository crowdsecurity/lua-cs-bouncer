local template = {}

function template.escape(data)
  return tostring(data or ''):gsub("[\">/<'&]", {
    ["&"] = "&amp;",
    ["<"] = "&lt;",
    [">"] = "&gt;",
    ['"'] = "&quot;",
    ["'"] = "&#39;",
    ["/"] = "&#47;"
  })
end

function template.compile(template_str, args)

    for k, v in pairs(args) do
        local var = "{{" .. k .. "}}"
        template_str = template_str:gsub(var, v)
    end

    return template.escape(template_str)
end

return template