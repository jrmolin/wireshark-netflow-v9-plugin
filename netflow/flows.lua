
-- flow fields
local m = {
  set_id     = ProtoField.uint16("netflow.set_id",     "set_id",     base.DEC),
  set_length = ProtoField.uint16("netflow.set_length", "set_length", base.DEC),
  -- template fields

  template_id  = ProtoField.uint16("netflow.template_id",  "template_id",  base.DEC),
  field_count  = ProtoField.uint16("netflow.field_count",  "field_count",  base.DEC),
  field_id     = ProtoField.uint16("netflow.field_id",     "field_id",     base.DEC),
  field_length = ProtoField.uint16("netflow.field_length", "field_length", base.DEC),
  field_value  = ProtoField.uint32("netflow.field_value",  "field_value",  base.HEX),

  -- data fields
  fields = ProtoField.none(  "netflow.fields",  "fields", base.DEC),
  u8     = ProtoField.uint8( "netflow.data_8",  "value",  base.HEX),
  u16    = ProtoField.uint16("netflow.data_16", "value",  base.HEX),
  u32    = ProtoField.uint32("netflow.data_32", "value",  base.HEX),

  -- just notes
  notes = ProtoField.none("netflow.note", "note",  base.STRING),
  blob = ProtoField.bytes("netflow.blob", "value", base.COLON)
}

function m.get_fields()
  local f = {
    set_id       = m.set_id,
    set_length   = m.set_length,
    template_id  = m.template_id,
    field_count  = m.field_count,
    field_id     = m.field_id,
    field_length = m.field_length,
    field_value  = m.field_value,
    u8           = m.u8,
    u16          = m.u16,
    u32          = m.u32,

    fields       = m.fields,

    notes        = m.notes,
    blob         = m.blob
  }
  return f
end


netflow_globals = {
  templates = {
    -- obs => table
  }
}

function m.parse_record(template, buffer, index, set_length)
  local result = {
    length = 0,
    padding = 0,
    index = index,
    field_count = 0,
    done = false,
  }

  local buflen = buffer:len()

  local remaining = buflen - index
  if remaining < 4 then
    if remaining >= 0 then
      result.padding = remaining
      result.length = remaining
    end
    result.done = true
    return result
  end

  result.field_count = template.field_count
  result.fields = {}
  local i = 1
  local so_far = 0
  while i <= template.field_count do
    local template_field = template.fields[i]

    local field_obj = {
      text  = "Field " .. i .. " (of ".. template.field_count .. "), Id " .. template_field.id .. ": ",
      tvb   = buffer(index+so_far, template_field.length),
      ftype = m.blob,
    }
    if template_field.length == 4 then
      field_obj.ftype = m.u32
    elseif template_field.length == 2 then
      field_obj.ftype = m.u16
    elseif template_field.length == 1 then
      field_obj.ftype = m.u8
    else
      field_obj.ftype = m.blob
    end

    result.fields[i] = field_obj
    i = i + 1
    so_far = so_far + template_field.length

  end
  result.length = so_far

  return result

end

function m.parse_data(template, parent_tree, buffer, index)
  local template_id = buffer(index, 2):uint()
  local set_length = buffer(index+2, 2):uint()

  -- maybe this happens
  if template_id ~= template.id then
    parent_tree:add(mongodb_protocol, buffer(index, set_length), "invalid template id: " .. template_id .. " in code, but passed in " .. template.id .. "")
    return set_length
  end

  local records = {}
  local record_count = 0
  local so_far = 4 -- template id, set_length
  while so_far < set_length do
    record_count = record_count + 1
    local record_obj = m.parse_record(template, buffer, index + so_far, set_length)
    records[record_count] = record_obj

    so_far = so_far + record_obj.length
    if record_obj.done then
      break
    end
  end

  local record_string = " record"
  if record_count > 1 then
    record_string = record_string .. "s"
  end

  local data = parent_tree:add(mongodb_protocol, buffer(index, so_far), "Data Flow (" .. record_count .. " " .. record_string .. ")")

  local record_index = 1
  while record_index <= record_count do
    local record_obj = records[record_index]

    local record_item
    if record_obj.padding > 0 then
      local padding_string = " " .. record_obj.padding .. " byte"
      if record_obj.padding > 1 then
        padding_string = padding_string .. "s"
      end
      record_item = data:add(mongodb_protocol, buffer(record_obj.index, record_obj.padding), "Padding (record " .. record_index .. "): " .. padding_string)
      break
    elseif record_obj.done then
      record_item = data:add(mongodb_protocol, buffer(), "Off-by-one errors, am I right? This is record " .. record_index)
      break
    else
      record_item = data:add(mongodb_protocol, buffer(record_obj.index, record_obj.length), "Record " .. record_index)
    end

    local field_index = 1
    local num_fields = record_obj.field_count
    while field_index <= num_fields do
      local field = record_obj.fields[field_index]
      record_item:add(field.ftype, field.tvb):prepend_text(field.text)
      field_index = field_index + 1
    end

    record_index = record_index + 1

  end

  return set_length
end

function m.parse_template(parent_subtree, buffer, index)

  local set_length = buffer(index+2,2):uint()
  local template_id = buffer(index+4,2):uint()
  local st = parent_subtree:add(mongodb_protocol, buffer(index, set_length), "Template set " .. template_id)
  st:add(m.set_id,         buffer(index,2)):append_text(" (template set)")
  st:add(m.set_length,         buffer(index+2,2))
  st:add(m.template_id,         buffer(index+4,2))
  st:add(m.field_count,         buffer(index+6,2))

  local fields = {}
  local field_count = buffer(index+6,2):uint()
  local template = {
    id = template_id,
    field_count = field_count,
  }
  -- now, loop!
  local i = 8
  local field = 1
  while field <= field_count do

    local field_id = buffer(index+i, 2):uint()
    local field_length = buffer(index+i+2, 2):uint()
    local field_obj = {
      id = field_id,
      length = field_length,
    }
    fields[field] = field_obj
    st:add(m.field_id, buffer(index+i, 2))
    st:add(m.field_length, buffer(index+i+2, 2))
    field = field + 1
    i = i + 4
  end

  template["fields"] = fields
  template["length"] = i

  return template
end

function m.parse(globs, header, st, buffer, index)
  local length = buffer:len()
  if length == 0 then return end

  local obs = globs[header.obs_domain]
  if obs == nil then
    globs[header.obs_domain] = {}
  end

  while index < length do
    local flow_length = buffer(index+2,2):uint()

    -- flow fields
    local set_code = buffer(index,2):uint()
    if set_code == 0 then
      local template = m.parse_template(st, buffer, index)

      globs[header.obs_domain][template.id] = template

      flow_length = template["length"]
    elseif set_code == 1 then
      st:add(m.set_id,     buffer(index,2))
      st:add(m.set_length, buffer(index+2,2))

    else
      local template_id = buffer(index, 2):uint()
      local set_length = buffer(index+2, 2):uint()
      local template = globs[header.obs_domain][template_id]

      if template ~= nil then
        m.parse_data(template, st, buffer, index)
      else
        local data = st:add(mongodb_protocol, buffer(index,set_length), "Data Flow (no template found for " .. template_id .. ")")

        data:add(m.set_id,     buffer(index,2)):set_text("Template id " .. template_id)
        data:add(m.set_length, buffer(index+2,2)):set_text("Covers " .. set_length .. " bytes")

      end

    end

    index = index + flow_length
  end


end

return m
