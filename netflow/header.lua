
-- header fields
local m = {
  version      = ProtoField.uint16("netflow.version", "version", base.DEC),
  record_count = ProtoField.uint16("netflow.record_count", "record_count", base.DEC),
  uptime       = ProtoField.uint32("netflow.uptime"     , "uptime"    , base.DEC),
  export_time  = ProtoField.uint32("netflow.export_time"    , "export_time"   , base.DEC),
  sequence_num = ProtoField.uint32("netflow.sequence_num"        , "sequence_num"       , base.DEC),
  obs_domain   = ProtoField.uint32("netflow.obs_domain"        , "obs_domain"       , base.DEC)
}

function m.get_fields()
  local fields = {
    version      = m.version,
    record_count = m.record_count,
    uptime       = m.uptime,
    export_time  = m.export_time,
    sequence_num = m.sequence_num,
    obs_domain   = m.obs_domain,
  }

  return fields
end

function m.parse(st, buffer)
  length = buffer:len()
  if length == 0 then return end

  st:add(m.version,      buffer( 0,2))
  st:add(m.record_count, buffer( 2,2))
  st:add(m.uptime,       buffer( 4,4))
  st:add(m.export_time,  buffer( 8,4))
  st:add(m.sequence_num, buffer(12,4))
  st:add(m.obs_domain,   buffer(16,4))

  local header = {
    version      = buffer( 0,2):uint(),
    record_count = buffer( 2,2):uint(),
    uptime       = buffer( 4,4):uint(),
    export_time  = buffer( 8,4):uint(),
    sequence_num = buffer(12,4):uint(),
    obs_domain   = buffer(16,4):uint()
  }

  return header
end

return m
