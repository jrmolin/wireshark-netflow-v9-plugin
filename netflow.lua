if not package.loading then package.loading = {} end
function import(x)
  if package.loading[x] == nil then
    package.loading[x] = true
    require(x)
    package.loading[x] = nil
  end
end

local header = require("netflow/header")
local flows = require("netflow/flows")

mongodb_protocol = Proto("NetFlowV9",  "NetFlow v9 Protocol")

netflow_globals = {
  templates = {
    -- obs => table
  }
}

function merge_tables(from, to)
  for k,v in pairs(from) do to[k] = v end
end

merge_tables(header.get_fields(), mongodb_protocol.fields)
merge_tables(flows.get_fields(), mongodb_protocol.fields)

function mongodb_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = mongodb_protocol.name

  local subtree = tree:add(mongodb_protocol, buffer(), "NetFlow V9 Data")

  local headerSubtree = subtree:add(mongodb_protocol, buffer(), "Header")
  local header = header.parse(headerSubtree, buffer)

  local flowsSubtree = subtree:add(mongodb_protocol, buffer(), "Flows")

  flows.parse(netflow_globals, header, flowsSubtree, buffer, 20)

end

local udp_port = DissectorTable.get("udp.port")
udp_port:add(7104, mongodb_protocol)

