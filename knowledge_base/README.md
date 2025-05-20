# Knowledge Base

This directory contains reference documentation, guides, API specs, and other knowledge resources that can be searched and accessed by the `knowledge_base_osint.py` tool.

## Structure

The knowledge base has a flat structure - all files are stored in this directory and indexed automatically.

## Supported File Types

The knowledge base supports the following file types:
- PDF documents (`.pdf`)
- Markdown files (`.md`)
- Plain text files (`.txt`)
- HTML documents (`.html`)
- reStructuredText files (`.rst`)
- JSON documents (`.json`)
- YAML documents (`.yaml`, `.yml`)
- CSV data (`.csv`)
- Source code files (`.py`, `.js`, `.sh`, `.bat`, `.ps1`)

## Adding Documents

You can add documents to the knowledge base in several ways:

1. **Manual**: Simply copy files into this directory
2. **API**: Use the `add_document_to_knowledge_base` function from the `knowledge_base_osint.py` script
3. **CLI**: Run `python OSINT/knowledge_base_osint.py add /path/to/file.pdf`

## Searching the Knowledge Base

You can search the knowledge base using:

1. **API**: Call the `search_knowledge_base` function
2. **CLI**: Run `python OSINT/knowledge_base_osint.py search "your query here"`

## Best Practices

1. **Naming**: Use descriptive filenames with relevant keywords
2. **Metadata**: Add a header section to text-based documents with key information
3. **Organization**: Consider prefixing filenames with categories (e.g., `api_google_maps.pdf`, `guide_nmap_advanced.md`)
4. **Updates**: When updating documents, keep the same filename to preserve search history

## Example Documents to Add

The knowledge base is particularly useful for:

- API documentation
- Tool usage guides
- Cheatsheets
- Reference manuals
- Technical specifications
- Tutorials
- Industry reports

## Environment Variables

- `KNOWLEDGE_BASE_DIR`: Override the default knowledge base directory location