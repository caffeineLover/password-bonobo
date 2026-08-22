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
  if #text >= 32 and not text:match('%s') and not text:match('[{}]') then
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

-- Give the nine-column feature matrix explicit proportional widths so every cell can wrap.
function Table(block)
  if #block.colspecs ~= #FEATURE_MATRIX_WIDTHS then
    return block
  end
  for index, width in ipairs(FEATURE_MATRIX_WIDTHS) do
    block.colspecs[index] = {block.colspecs[index][1], width}
  end
  return {
    pandoc.RawBlock('latex', '\\begin{landscape}'),
    block,
    pandoc.RawBlock('latex', '\\end{landscape}'),
  }
end
