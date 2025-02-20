local osinfo = {}


local function parse_os_release()
	local os_release = {}
	local f = io.open("/etc/os-release", "r")
	if f then
		for line in f:lines() do
			local key, value = line:match("([^=]+)=(.*)")
			if key and value then
				os_release[key] = value
			end
		end
		f:close()
	end
	return os_release
end

local function parse_lsb_release()
	local lsb_release = {}
	local f = io.open("/etc/lsb-release", "r")
	if f then
		for line in f:lines() do
			local key, value = line:match("([^=]+)=(.*)")
			if key and value then
				lsb_release[key] = value
			end
		end
		f:close()
	end
	return lsb_release
end


function osinfo.get_os_info()

	local os_info = parse_os_release()
	if not os_info["NAME"] then
		os_info = parse_lsb_release()
	end

	if not os_info["NAME"] then
		os_info["NAME"] = "Unknown"
	end

	if not os_info["VERSION_ID"] then
		os_info["VERSION_ID"] = "Unknown"
	end

	-- remove quotes
	-- some distros have quotes around the values
	-- e.g. "Ubuntu"
	-- this is not the case for all distros
	-- so we need to check if the first character is a quote
	-- and remove it if it is
	for k, _ in pairs(os_info) do
		if string.sub(os_info[k], 1, 1) == '"' then
			os_info[k] = string.sub(os_info[k], 2, -1)
		end
		if string.sub(os_info[k], -1) == '"' then
			os_info[k] = string.sub(os_info[k], 1, -2)
		end
	end
	return os_info
end

return osinfo
