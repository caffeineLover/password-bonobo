-- Keep wide compatibility tables and long machine identifiers inside review-PDF page bounds.

local FEATURE_MATRIX_WIDTHS = {
  0.10,
  0.15,
  0.11,
  0.14,
  0.07,
  0.10,
  0.08,
  0.08,
  0.17,
}

local PROVENANCE_WIDTHS = {
  [7] = {0.11, 0.15, 0.34, 0.14, 0.06, 0.10, 0.10},
  [8] = {0.20, 0.13, 0.15, 0.15, 0.09, 0.08, 0.09, 0.11},
  [10] = {0.13, 0.05, 0.15, 0.08, 0.14, 0.15, 0.05, 0.05, 0.09, 0.06},
}

local URL_AUDIT_COMPONENT_IDS = {
  ['gorilla::URLAudit'] = 'url-audit',
  ['gorilla::URLAudit::URL'] = 'url',
  ['gorilla::URLAudit::HTTP'] = 'http',
  ['gorilla::URLAudit::Classifier'] = 'classifier',
  ['gorilla::URLAudit::Dialog'] = 'dialog',
  ['gorilla::URLAudit::Archive'] = 'archive',
}

-- Render long, whitespace-free code spans through URL's break-aware monospace command.
function Code(inline)
  local text = inline.text
  if #text >= 10 and not text:match('%s') and not text:match('[{}]') then
    return pandoc.RawInline('latex', '\\nolinkurl{' .. text .. '}')
  end
  return inline
end

-- Shorten generated labels for namespace-only component headings without changing visible or semantic content.
function Header(block)
  local identifier = URL_AUDIT_COMPONENT_IDS[pandoc.utils.stringify(block.content)]
  if identifier then
    block.identifier = identifier
  end
  return block
end

-- Give one wide feature or provenance table explicit proportional widths.
local function configure_wide_table(block)
  local widths = PROVENANCE_WIDTHS[#block.colspecs]
  if #block.colspecs == #FEATURE_MATRIX_WIDTHS then
    widths = FEATURE_MATRIX_WIDTHS
  end
  if not widths then
    return false
  end
  for index, width in ipairs(widths) do
    block.colspecs[index] = {block.colspecs[index][1], width}
  end
  return true
end

-- Keep each wide table with its nearest section heading and introductory blocks in one landscape environment.
function Pandoc(document)
  local output = {}
  for _, block in ipairs(document.blocks) do
    if block.t == 'Table' and configure_wide_table(block) then
      local section_start = #output + 1
      for index = #output, 1, -1 do
        if output[index].t == 'Header' then
          section_start = index
          break
        end
      end

      local section = {}
      for index = section_start, #output do
        table.insert(section, output[index])
      end
      for index = #output, section_start, -1 do
        table.remove(output, index)
      end

      table.insert(output, pandoc.RawBlock('latex', '\\begin{landscape}'))
      for _, section_block in ipairs(section) do
        table.insert(output, section_block)
      end
      table.insert(output, block)
      table.insert(output, pandoc.RawBlock('latex', '\\end{landscape}'))
    else
      table.insert(output, block)
    end
  end
  document.blocks = pandoc.Blocks(output)
  return document
end
