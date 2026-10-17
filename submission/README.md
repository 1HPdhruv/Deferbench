# Idea-submission deck

| file | what |
|---|---|
| `DeferBench_Idea_Submission.pptx` | primary deliverable: 9 slides, 16:9, editable text/shapes (the slide background is the template artwork) |
| `DeferBench_Idea_Submission.pdf` | converted from the .pptx with LibreOffice 26.8.1 (fonts embedded) |
| `SLIDE_CONTENT.md` | all slide text and speaker notes, generated from the final .pptx |
| `SOURCES_AND_DISCLOSURES.md` | related work, third-party tools, licences, AI-tool disclosure |

Install the fonts in `assets/fonts/` (DM Sans, DM Serif Display, SIL OFL) before opening the .pptx, or PowerPoint will substitute fonts.
The team slide contains editable placeholders for the two members' names and photos.

## Rebuild
```
python -m venv .deckvenv && . .deckvenv/bin/activate && pip install python-pptx pillow numpy
python submission/build/make_backgrounds.py     # template artwork from submission/assets/template (1.5x raster)
python submission/build/build_deck.py           # reads numbers from results/final/development_release_rerun/results.json
python submission/build/export_content.py       # SLIDE_CONTENT.md from the built deck
# PDF: soffice --headless --convert-to pdf --outdir submission submission/DeferBench_Idea_Submission.pptx
```
