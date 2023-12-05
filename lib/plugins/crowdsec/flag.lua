local bit
if _VERSION == "Lua 5.1" then bit = require "bit" else bit = require "bit32" end

M.BOUNCER_SOURCE = 0x1
M.APPSEC_SOURCE = 0x2
M.VERIFY_STATE = 0x4
M.VALIDATED_STATE = 0x8


function M.GetFlags(flags)
  local source = 0x0
  local err = ""
  local state = 0x0

  if flags == nil then
    return source, state, err
  end

  if bit.band(flags, M.BOUNCER_SOURCE) then
    source = M.BOUNCER_SOURCE
  elseif bit.band(flags, M.APPSEC_SOURCE) then
    source = M.APPSEC_SOURCE
  end

  if bit.band(flags, M.VERIFY_STATE) then
    state = M.VERIFY_STATE
  elseif bit.band(flags, M.VALIDATED_STATE) then
    state = M.VALIDATED_STATE
  end
  return source, state, err    

end

function M.GetStateID(state)
    for k, v in pairs(M.State) do
        if v == state then
            return tonumber(k)
        end
    end
    return nil
end