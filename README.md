# Event Log Analyzer

Windows desktop app that parses an exported Event Viewer log (`.evtx`), groups the
errors and warnings into distinct issues, and shows plain-English explanations and
fixes for the ones it recognises.

## Web version — https://ev.42p.uk

The same analyzer also runs as a static web app at **[ev.42p.uk](https://ev.42p.uk)**
(source in [web/](web/)). It parses the `.evtx` binary format entirely in the
browser — files are never uploaded — and uses the same [rules.json](rules.json)
knowledge base. One limitation vs. the desktop app: rendering full event messages
needs the provider's message DLLs, so the web version shows the raw event data
fields instead (breakdowns, grouping and advice are identical).

Hosting: a Cloudflare Pages project (`event-viewer`) connected to this GitHub
repository. Every push to `main` triggers a build that runs
`cp rules.json web/` and publishes the `web/` directory. The custom domain
`ev.42p.uk` is attached to the project, with `ev.p42.uk` redirecting to it like
every other p42 subdomain.

## How it works

- Parsing uses the built-in Windows Event Log API (`EventLogReader`) — no third-party
  parser, and it renders the same human-readable messages Event Viewer shows.
- Events at level Critical/Error/Warning are grouped by **(Provider, Event ID)** and
  counted, with first/last occurrence times.
- Each group is matched against [rules.json](rules.json), a knowledge base keyed on
  provider + event ID. Matches get a title, an explanation, and a numbered fix list.
  Unmatched groups are still listed with generic guidance.
- Findings are sorted by severity, then by how often they occurred.

## Running it

Requires the .NET 8 SDK to build:

```powershell
dotnet run --project EventLogAnalyzer.csproj
```

Or build a standalone exe:

```powershell
dotnet publish -c Release
# output: bin\Release\net8.0-windows\win-x64\publish\EventLogAnalyzer.exe
```

Browse to an `.evtx` file (or drag one onto the window). Get one by opening
Event Viewer → right-click a log (e.g. **System**) → **Save All Events As...**,
or straight from `C:\Windows\System32\winevt\Logs\` (needs admin).

You can also pass an `.evtx` file as an argument to open the UI with it already
analyzed (works with "Open with" and dragging a file onto the exe):

```powershell
EventLogAnalyzer.exe C:\path\to\System.evtx
```

### Headless mode

```powershell
EventLogAnalyzer.exe --report C:\path\to\System.evtx [report.txt]
```

Writes the full findings report to a text file instead of opening the UI
(defaults to `<file>.evtx.report.txt`).

## Extending the rules

Add entries to `rules.json` (it's copied next to the exe at build time):

```json
{
  "provider": "Provider name as shown in the grid",
  "altProviders": ["optional", "aliases"],
  "eventId": 123,
  "severity": "critical | high | medium | low | info",
  "title": "Short issue name",
  "cause": "What it means in plain English.",
  "solutions": ["Step 1", "Step 2"],
  "breakdownProps": [{ "index": 0, "name": "Service" }]
}
```

`breakdownProps` is optional: it names positions in the event's data properties
that identify the culprit (faulting app, service name, driver, ...). When set,
the detail pane shows an occurrence count per distinct value — e.g. which
specific applications account for 233 crash events. Find the right index by
looking at the EventData fields in Event Viewer's Details tab (they are
zero-based, in order).
