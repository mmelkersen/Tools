#Requires -Version 5.1

<#
.SYNOPSIS
ZeroAdmin (Community Edition). Helps you build the Microsoft Intune Endpoint Privilege
Management (EPM) rules that eliminate local administrative usage in your environment.

.DESCRIPTION
ZeroAdmin provides a WPF-based graphical user interface, plus a headless reporting interface,
to streamline working with Microsoft Intune Endpoint Privilege Management (EPM) elevation
rules during an audit and implementation phase - so that "everyone is a local admin" becomes
"nobody needs to be."

THE ONE RULE OF THIS EDITION: a CERTIFICATE rule is only ever created on the Scan Path tab, from
the actual binary. An "unmanaged elevations" audit export or the live elevation report records
that an elevation happened - file name, publisher name, user, device - but neither carries the
signing certificate itself, so neither can yield a reusable certificate setting worth trusting.
A publisher NAME is easy to spoof; a certificate is not. Reading the file itself is the only way
to get one.

A HASH rule is different and is exposed directly from an audit row (Audit Import) or a CSV
import, one row at a time: the hash on that row was computed by the EPM agent from the real
binary at the exact moment it elevated, so it is exact, not a guess - equivalent to extracting it
from the file directly. Audit data is otherwise used to work out WHAT needs covering; the Scan
Path files are used to build a CERTIFICATE rule, or a hash rule when no audit hash is on record.

It can:
- Read the EPM elevation report straight out of the tenant, so no CSV export is needed. This
  issues the same Microsoft Graph request the Intune portal makes when the elevation report is
  opened (deviceManagement/privilegeManagementElevations, filtered on the event time range),
  over a chosen window of up to 30 days, optionally narrowed to unmanaged elevations.
- Import an exported "unmanaged elevations" audit CSV and normalize the rows into
  candidate elevation rules (auto-detecting common column names, with optional mapping).
  Both sources produce identical rows, so everything downstream behaves the same.
- Mark one candidate row on the Audit Import tab and add it straight to a chosen EPM policy as a
  hash rule, picking only the target policy, elevation type and child process behavior - the rule
  name, file name and hash come from the row itself. Blocked with a clear reason when the row has
  no recorded hash (a CSV export that omitted one).
- Score how many imported unmanaged elevations are already covered by existing EPM persona rules,
  break the coverage down per persona, and recommend which persona each user should be assigned to
  so the most of their unmanaged elevations are covered.
- Report which applications are not covered by any existing persona rule, so the gap is an
  explicit list rather than an impression.
- Look through all existing EPM elevation rules across every EPM rules policy and report
  duplicate or similar rules for the same executable, including the owning policy and rule.
- Surface best-practice guidance for each candidate rule (prefer certificate matching, avoid
  broad wildcards, prefer least-privilege elevation types, consistent naming).
- Scan a folder for .exe, .msi and .ps1 files and build elevation rules directly from them, as a
  three-step flow on the Scan Path tab:
    1. Scan the folder and list each binary with its publisher, hash, internal name and product.
    2. Mark a file and extract its signing certificate with the EpmTools cmdlet. The whole chain is
       written to the temp working directory configured on the Settings tab and offered for
       selection, labelled signer / intermediate CA / root CA, so the operator decides how broadly
       the rule should match. The reusable setting is named after the certificate's issuer by
       default, can be checked against the tenant by thumbprint before uploading, and is uploaded
       only when signed in.
    3. Load the EPM policies, pick the target policy and the match type. Choosing a certificate
       match selects the reusable setting that was just uploaded (or matched) and fills in the
       internal name read from the file, then the rule is created with the chosen elevation type,
       validation and child process behavior.
- Replicate an existing rule from one EPM policy into another EPM policy so the same rule does
  not have to be recreated for different persona types. This copies a rule that already carries a
  verified certificate or hash; it does not author a new one.
- Inspect EPM reusable settings and, for a chosen reusable setting, list every rule (by rule
  name) and policy that references it so usage is easy to identify.

Every write to the tenant happens from the GUI behind an explicit button and a confirmation
prompt. The headless interface reports and exports only, with the single exception of
-SourcePolicyId/-TargetPolicyId replication, which still requires -Apply.

Required Microsoft Graph delegated scope: DeviceManagementConfiguration.ReadWrite.All.

.PARAMETER CsvPath
The path to an exported Intune EPM "unmanaged elevations" audit CSV file to import and report on.

.PARAMETER SourcePolicyId
The Intune configuration policy ID (GUID) of the EPM elevation rules policy to copy a rule
from when replicating a rule in headless mode.

.PARAMETER TargetPolicyId
The Intune configuration policy ID (GUID) of the EPM elevation rules policy to copy a rule
into when replicating a rule in headless mode.

.PARAMETER RuleName
The display name of the EPM elevation rule to replicate in headless mode.

.PARAMETER ReusableSettingId
The ID of an EPM reusable setting to resolve usage for in headless mode.

.PARAMETER ColumnMap
An optional hashtable that maps normalized field names (FilePath, FileName, FileHash,
Publisher, Product, Description, User, Device, ElevationType) to the column headers present
in the CSV when the headers cannot be auto-detected.

.PARAMETER MatchType
The match type reported for each candidate. 'Auto' reports a certificate (publisher) match
when the audit row indicates the file was signed and falls back to a file hash otherwise.
'Certificate' forces a publisher match and 'Hash' forces a file hash match.

.PARAMETER OutputPath
Optional path for exported candidate payloads or reports. Defaults to creating a timestamped
file in the reports directory next to the script.

.PARAMETER Apply
Switch to actually replicate a rule into the target policy in headless mode. Without it the
replication is previewed and nothing is written. Rule creation is GUI-only and lives on the
Scan Path tab, so this switch does not apply to the CSV report.

.PARAMETER NoGui
Switch to run in headless/automation mode from the command line, bypassing the WPF GUI.

.PARAMETER GraphAuthMode
Controls how the tool authenticates to Microsoft Graph. Interactive uses the default
Connect-MgGraph interactive flow. DeviceCode uses device-code authentication so FIDO2 security
keys can be used in the system browser during sign-in.

.PARAMETER LogPath
Optional path to the debug log file. The tool always writes a detailed diagnostic log (every
Graph request, response counts, EPM detection decisions and full error responses) so issues can
be reproduced and shared. Defaults to a rolling .log file in the reports directory next to the
script, falling back to %LOCALAPPDATA%\ZeroAdmin\reports when that folder is not writable.

.EXAMPLE
.\ZeroAdmin.ps1
Launches the WPF GUI for coverage analysis, file-based rule building, reusable settings and
replication.

.EXAMPLE
.\ZeroAdmin.ps1 -CsvPath "C:\temp\UnmanagedElevations.csv" -NoGui
Imports the audit CSV, builds candidate rules and prints a duplicate and best-practice report
without writing anything to Intune.

.EXAMPLE
.\ZeroAdmin.ps1 -SourcePolicyId "1111..." -TargetPolicyId "2222..." -RuleName "Contoso Tool" -Apply -NoGui
Replicates the "Contoso Tool" elevation rule from the source EPM policy into the target EPM
policy.

.NOTES
    Version:        7.2 (Community Edition)
    Author:         Mattias Melkersen
    Creation Date:  2026-06-24

    CHANGELOG
    ---------------
    2026-09-02 - v7.2 - Fixed the GUI being genuinely unusable on smaller screens: the window opened at a fixed 940px tall with a 780px minimum, which cannot fit within even a 1366x768 laptop's work area once the taskbar is accounted for - confirmed by rendering the actual shipping XAML at that size, which cuts off all of step 3 on the Scan Path tab (target policy, elevation type, Create Rule(s) - unreachable). Four independent fixes: (1) requests Per-Monitor-V2 DPI awareness via SetProcessDpiAwarenessContext before any window is created, so the GUI renders at native resolution regardless of whether the launching host (powershell.exe, pwsh.exe, VS Code's terminal) declared DPI awareness in its own manifest - previously inherited whatever the host happened to set, unaware or System-aware on some hosts, which is a common reason WPF content looks the wrong size or slightly blurry on a scaled display; (2) MinHeight/MinWidth lowered from 780x1040 to 600x900, and the startup size is now clamped to the actual screen's SystemParameters.WorkArea (with a margin) so the window never opens larger than the screen it lands on; (3) a real zoom control - Ctrl+MouseWheel, Ctrl+Plus/Minus/Ctrl+0 (the same gesture every browser already uses), and footer +/-/Reset buttons - scales the whole window via a LayoutTransform on the root Grid, applied after the normal layout/measure pass so it never changes how much space a Height="*" row or the DataGrid inside it computes; verified that 75% zoom fits the entire 3-step Scan Path tab, all of step 3 included, inside the exact 1326x688 window that clipped it at 100%. Zoom is persisted to settings.json (extends Get-EpmToolDefaultSettings/Initialize-EpmToolSettings/Save-EpmToolSettings, clamped to 60%-160% on load in case of a hand-edited file) so it survives a restart, remembered the same way the temp working directory already is. (4) A ScrollViewer around the tab content was deliberately NOT added, despite being the more obvious fix: it would have measured every tab's DataGrid with infinite available height, silently breaking row virtualization - the exact bug already fixed once in v4.2 ("very slow CSV import for large files"), reintroduced one level up. Left a comment on the TabControl template explaining why, for whoever is tempted to add one later. Verified the merge logic in Save-EpmToolSettings so a zoom-only save can never clobber a previously saved temp working directory or vice versa, and that SetProcessDpiAwarenessContext genuinely returns true on a real Windows 11 machine rather than being silently swallowed by its own try/catch.
    2026-09-02 - v7.1 - Re-themed the GUI to match the MSEndpointMgr brand mark instead of the tool's original, unrelated navy blue. Sampled the actual pixels of LogoSmall_Transparent.png rather than guessing a hex value: the swirl's dominant red clusters tightly around #D01412, with a deep shadow red near #720000. Every navy-family color (23 distinct roles - primary accent, hover/pressed states, header gradient, tab underline, selected-state backgrounds, info-bar tints, disabled states, input hover borders, drop-shadow tint) was mapped 1:1 to a red derived from those samples; the header gradient runs from a dark red (`#8A0E0C`, doubling as the primary accent used everywhere else) to the brighter sampled red (`#D01412`) as its one highlight corner, echoing how the logo's own swirl shades from shadow to highlight. Every text/background pairing in the new palette was checked against WCAG relative-luminance contrast before committing, including the tightest case - header subtitle text against the gradient's brightest corner - which came out at 4.69:1, clearing the 4.5:1 AA threshold. The semantic status colors were deliberately left untouched: Get-EpmCoverageColor's green/amber/red/grey (which mean strong/moderate/weak/no coverage) and the Graph connection dot's green/red carry real meaning, not brand identity, and touching them would have made the coverage cards harder to read at a glance. Purely a palette change - no control, layout or behavior changed - [Mattias Melkersen]
    ---------------
    2026-09-02 - v7.0 - Rebranded as ZeroAdmin, and the script itself renamed from Build-EpmRules.ps1 to ZeroAdmin.ps1. Tagline: "Helps you build the EPM rules that eliminate local administrative usage in your environment." Header now carries the real MSEndpointMgr brand mark (LogoSmall_Transparent.png), embedded as base64 PNG so the tool stays one self-contained file with no separate .ico to lose - decoded once at startup into both the header badge and the window/taskbar icon. User-scoped settings moved from %LOCALAPPDATA%\Build-EpmRules to %LOCALAPPDATA%\ZeroAdmin; a one-time migration carries an existing TempWorkingDirectory preference over on first run so the rename does not silently reset it, without touching the old Temp scratch folder. $scriptName and the debug log name are already derived from the running file name, so both picked up the new name for free.
                                     Added an Export Rules tab: pick one EPM policy or "All EPM Policies", Preview, then Export to CSV for documentation in Excel. One row per rule - policy, rule name, match type, elevation type, validation, child process behavior, internal name, file name/hash, and (for certificate rules) the reusable certificate's own display name - with every choice value resolved to the words the policy itself defines rather than the raw setting-catalog id, read live per policy so rules from different template versions still resolve correctly; export writes exactly what the preview grid shows. New Get-EpmRuleExportData/ConvertTo-EpmRuleExportRow/Get-EpmRuleOptionDisplayLookup/Get-EpmChoiceDisplayName built entirely on existing, already-proven helpers (Get-EpmPolicyRule, Get-AllEpmRule, Get-EpmRuleChoiceOption, Get-EpmReusableSetting). A policy whose setting definitions cannot be read still contributes its rules to the export, with raw values shown instead of display names for that policy only, rather than silently dropping it.
                                     Building the export required reading two rule fields the parser never exposed: internal name and child process behavior (both direct children, easy), and validation and certificate type, which are nested one level inside the ruletype and signaturesource choices respectively - not direct children of the rule at all. ConvertFrom-EpmRuleInstance now extracts all four, benefiting every existing caller for free. This surfaced a genuine gap: Get-EpmSettingInstanceValue had no case at all for choiceSettingCollectionValue (validation's real settings-catalog shape - a ChoiceSettingCollectionInstance), so any code reading it got Kind='Unknown' and no value; validation reads now work anywhere in the tool, not just in the export. Given the new nested nature of these lookups, also added defensive handling for the same empty-array-unrolls-to-null PowerShell pitfall fixed for group/simple collections in v6.8, applied here too. Verified by round-tripping every rule variant through New-EpmElevationRuleGroupEntry -> ConvertFrom-EpmRuleInstance and confirming every field, including the two new nested ones, comes back exactly as built - [Mattias Melkersen]
    2026-08-31 - v6.9 - Removed the "Match type" drop-down and "Use Get-FileAttributes when the file is local" checkbox from Audit Import - traced every consumer first and neither ever changed an outcome. MatchType on a candidate only reached the grid's display column and one field in the uncovered-elevations CSV export; Coverage Analysis scoring, the uncovered-elevations summary's own suggested-match column, and the new hash-rule-from-audit-row panel (which always writes Hash regardless) all ignore it. Enrichment only ever fired when the exact FilePath an audit row recorded happened to still exist on the machine running the tool, which defeats the purpose of a centralized audit report. Both were pure UI noise. ConvertTo-EpmRuleCandidate now always runs as 'Auto' with no enrichment from this tab - the exact default behaviour for anyone who never touched the removed controls, so nothing changes for them. Removed the now-fully-dead -Enrich switch and Get-EpmFileAttribute (the CLI's own -MatchType still works and is kept, since that is a real, different use case - deterministic output for scripted report generation). The Search toolbar is now a single clean row - [Mattias Melkersen]
    2026-08-31 - v6.8 - Audit Import can now create a hash rule directly from one marked candidate row, without going through Scan Path. This is a deliberate, narrow exception to the "only Scan Path writes rules" principle: the hash on an audit row was computed by the EPM agent from the real binary at the moment it elevated, so it is exact - equivalent to reading the file directly - unlike the publisher NAME on the same row, which is just text and proves nothing about a certificate. The panel offers exactly three choices (target policy, elevation type, child process behavior); rule name, file name and hash all come from the row. Blocked with a clear message when the row has no recorded hash or file name, or when more than one row is marked (each rule needs its own hash). Reuses the same live-from-policy option loading and Add-EpmScannedRuleToPolicy write path Scan Path already uses, so the produced payload is identical in shape - verified by writing a real candidate through the full chain and inspecting the captured PUT body. Building this test surfaced and fixed a real bug it would otherwise have hit in production: Get-EpmSettingInstanceValue detected the elevation-rules group by checking a value already read through Get-GraphResponseProperty, but PowerShell unrolls a function's `return @()` to $null for the caller, so a target policy with genuinely ZERO existing rules made that value indistinguishable from the property being absent, and Find-EpmRuleGroupInstance/Set-EpmPolicyRule threw "Unable to locate the elevation rules collection" - silently contradicting the v6.3 claim that a policy's first rule could be created. Fixed by detecting the group (and simple) setting collection kinds from the setting instance's own @odata.type, which survives the round-trip, instead of trusting the already-lost value. This also fixes Scan Path rule creation into a policy with no existing rules. The Audit Import info bar was rewritten to explain the hash exception precisely - [Mattias Melkersen]
    2026-08-31 - v6.7 - Merged the Replicate and Reusable Settings tabs into one "Replicate and Reusable Settings" tab, each under its own heading and separated by a rule. The Replicate log had Height="*" so it filled the entire remaining tab - most of the page - for a handful of status lines; it is now a fixed 80px console box, and the reclaimed space instead goes to the reusable-setting usage DataGrid, which is real data and benefits from the room. No control names or event wiring changed - [Mattias Melkersen]
    2026-08-31 - v6.6 - The reusable certificate drop-down on the Scan Path tab is now greyed out, with its label, when the match type is Hash. A hash rule matches on the file SHA256 and carries no certificate at all, so leaving the field live implied it had some effect on the rule. It stays available for Certificate and for Suggested, which decides per file. The match-type handler moved into a named Update-GuiMatchTypeState so the same logic sets the initial state at startup - the match type is selected before the handlers are wired, so a selection-change event never fires for it - [Mattias Melkersen]
    2026-08-31 - v6.5 - Added a Rule name field to step 3 of the Scan Path tab, suggested from the marked file. The rule name was previously the bare file name with no way to change it. The suggestion is the product name, or the publisher's common name when the file carries no product, plus the file name - for example "Windows Installer - Unicode - msiexec.exe". Fixed the suggestion source while doing it: it was built from the certificate's full subject DN, which would have produced rule names like "CN=Contoso Ltd, O=Contoso, L=Oslo, C=NO - setup.exe". The scan now resolves the publisher's common name for naming and keeps the full DN for the Publisher column. Rule name and internal name are both re-suggested when a different file is marked and stop being overwritten as soon as they are edited, so changing the match type no longer discards a typed name. With more than one file marked the field cannot apply, so it is disabled and each rule is named from its own file. Step 3 is now laid out as identity (rule name, internal name, file name) and behaviour (elevation type, validation, child process) on separate lines, which also removed the wrapping the extra field would have caused - [Mattias Melkersen]
    2026-08-31 - v6.4 - Scanning is now read-only. Scan called EpmTools Get-FileAttributes once per file purely to read metadata, but that cmdlet exports the signing certificate as a side effect and, with no destination given, writes a "<file> Certificate Chain" folder of .cer files into the current working directory - so simply clicking Scan littered the folder the tool was started from. The scan no longer calls it at all: publisher comes from the Authenticode signature, hash from Get-FileHash (SHA256, the same value the rule writer uses), and product and internal name from the file's version resource, so the scan reads and writes nothing. Certificate extraction stays where it belongs, on the explicit step 2 button, writing into the configured temp working directory. Because the publisher now comes only from Authenticode, the signature check no longer requires Status to be 'Valid' - a correctly signed binary reports NotTrusted on a machine that does not chain to the issuing CA, and treating that as unsigned would have hidden files that certificate matching handles fine. The opt-in "Use Get-FileAttributes when the file is local" enrichment on the Audit Import tab had the same side effect and now always directs the export into a throwaway directory it deletes, skipping enrichment entirely if the installed EpmTools exposes no such parameter. New Get-EpmToolsCertificateParameterName resolves that parameter name once for both callers. The post-scan warning no longer claims EpmTools affected the scan results, since it no longer does - [Mattias Melkersen]
    2026-08-31 - v6.3 - Fixed reusable certificate upload and rebuilt rule creation against payloads captured from the Intune portal. The upload was sending the certificate as a deviceManagementConfigurationSecretSettingValue with a valueState; the portal sends a plain deviceManagementConfigurationStringSettingValue, and the entity also needs a top-level settingDefinitionId and @odata.type. The previous code tried to clone an existing reusable setting to stay template-aligned, which is what produced the secret shape - reading a stored certificate back returns it as a secret - so the body is now constructed outright and also works in a tenant with no reusable setting to copy. PEM armour is stripped and the value is parsed as a certificate before upload, because Graph accepts a malformed value that only fails later when a rule references it. Rule creation no longer clones an existing rule: new New-EpmElevationRuleGroupEntry builds the payload from the setting-catalog definition ids, so the first rule in an empty policy can be created and a certificate rule no longer requires the policy to already contain one. It supports all three portal variants - certificate or hash matching, user confirmed (with optional validation) or automatic, with optional file name and internal name. Structural details that were previously wrong or unreachable: the certificate reference is a ReferenceSettingValue nested under the signaturesource choice alongside certificatetype, and validation is a ChoiceSettingCollectionInstance nested inside the ruletype choice that must be absent entirely for an automatic rule. The policy PUT now also echoes creationSource. Added an "Include file name" option (always on for hash rules, matching the portal) and the validation drop-down is disabled for automatic elevation. Removed six functions that only existed to support cloning: ConvertTo-EpmRuleGroupEntry, Resolve-EpmGroupChildValue, Resolve-EpmGroupChildCollectionValue, Remove-EpmGroupChildNode, Set-EpmRuleReusableReference and Set-EpmReusableCertificateValue. Verified by rebuilding all three captured rule variants and the reusable-setting body and diffing the complete request payloads against the portal's - all identical - [Mattias Melkersen]
    2026-08-31 - v6.2 - Reworked the Scan Path tab into the three numbered steps the workflow actually follows: scan, certificate, rule. The certificate step no longer decides for you which certificate to upload - the full chain extracted from the marked file is now offered in a picker, each entry labelled as signer, intermediate CA or root CA with its subject, issuer and expiry, because that choice decides whether the rule matches one publisher certificate or everything a CA signs. The reusable setting name now defaults to the selected certificate's ISSUER common name (falling back to the subject for a self-signed root), and stops being overwritten as soon as the operator types their own. "Check if already in Intune" now tests the selected certificate rather than every certificate in the folder, and a thumbprint hit is remembered so no duplicate upload is needed. Upload is gated on a Graph session and disabled with a tooltip explaining why when not signed in, and its confirmation now states the role, subject, issuer and thumbprint being uploaded. In step 3, switching the match type to Certificate auto-selects the reusable setting uploaded or matched in this session and fills the internal name read from the marked file; marking a row also fills the internal name and reloads any chain already extracted for that file from the temp working directory, so a chain extracted in an earlier session is not re-extracted. The Scan Path tab states where certificates are written and follows the Settings tab when that path changes. .ps1 is now scanned by default alongside .exe and .msi. New helper New-EpmCertificateDetail produces the one certificate shape used by both a fresh extraction and a chain read back from disk, and chain de-duplication now happens before the files are written so the role labels match the files produced - [Mattias Melkersen]
    2026-08-25 - v6.1 - The Audit Import tab can now read the EPM elevation report straight from the tenant, so exporting a CSV from the portal first is optional. New Get-EpmElevationReport replicates the request the Intune portal issues when the elevation report blade is opened (captured from a portal HAR): GET /beta/deviceManagement/privilegeManagementElevations?$top=50&$filter=(EventDateTime gt <from> and EventDateTime le <to>)&$orderby=eventDateTime desc, paged through @odata.nextLink. The period is selectable (24 hours / 7 / 14 / 30 days - Intune retains this report for 30 days) and a checkbox limits the result to unmanaged elevations. Only the time range is filtered server-side because that is the only filter the portal itself uses on this collection; the unmanaged narrowing is applied client-side rather than risking a BadRequest on an unsupported filter. Rows are normalized to exactly the shape Import-EpmAuditCsv returns - companyName maps to Publisher, productName to Product, hash to FileHash, upn to User, deviceName to Device - so candidate building, search, coverage analysis and export are identical for both sources. New ConvertTo-EpmCleanString converts the report's literal "<Null>" placeholder to a real null, without which every unsigned binary would look like it was published by a company called "<Null>" and be built as a certificate match. The CSV and Graph paths now share one Set-GuiCandidateSource helper instead of duplicating the binding logic, and the candidate counter only shows "x of y" while a search is actually narrowing the list - [Mattias Melkersen]
    2026-08-25 - v6.0 - Community Edition. Rule creation is now only possible from the Scan Path tab, where the real binary is read: an audit export records that an elevation happened but does not carry the file, so it cannot yield a certificate or hash worth granting admin rights to. The "Add selected to policy" control, its policy picker and Add-EpmRuleToPolicy/Get-EpmUniqueRuleName were removed, and the CSV parameter set became a report-only set ('Report', was 'Build') that no longer accepts -PolicyId or -Apply. The "Import and Ingest" tab is now "Audit Import" and states what it is for. Removed the "My Device" tab and the eight functions behind it (Get-RunningDeviceIdentity, Get-EpmAgentLogState, Invoke-EpmPolicySync and the already-dead Get-EpmPolicyAssignment/Test-EpmAssignmentTarget/Get-EntraTransitiveGroupId/Test-EpmRuleApplied/New-EpmPolicyLogBucket assignment chain). Graph scopes dropped from five to one (DeviceManagementConfiguration.ReadWrite.All) now that no device, group or directory data is read. Replicate is unchanged and still copies rules that already carry a verified certificate or hash - [Mattias Melkersen]
    2026-08-25 - v5.5 - Correctness and robustness pass. "Review Certs and Reusables" now matches the extracted certificate against the tenant's reusable settings by THUMBPRINT via the previously unused Find-EpmReusableCertificateMatch, instead of guessing from display-name tokens - a name guess could select a different publisher's certificate and silently elevate the wrong code, so a reusable setting is now only auto-selected on an exact thumbprint match and display-name hits are reported as low-confidence only. Rule creation validates the whole selection before writing, so a bad row no longer aborts part-way through leaving rules already created in the tenant. Signing in or out clears every cached policy, rule and reusable-setting list so a stale id from another tenant cannot be acted on. Reports and the debug log now resolve next to the script (falling back to %LOCALAPPDATA%) instead of assuming a repository three folders up, so the single-file download works anywhere. Renamed Normalize-CertificateName to the approved-verb Get-NormalizedCertificateName, stopped shadowing the automatic $Matches variable, and removed the dead Get-CertificateThumbprintFromBase64 - [Mattias Melkersen]
    2026-08-19 - v5.4 - Modernized the GUI. The window now uses a single design-token palette (brand navy accent on a neutral surface/border/text ramp) and fully re-templated controls: flat underline tabs instead of folder tabs, rounded 6px inputs with hover/focus states, a custom combo box with a shadowed rounded drop-down, a custom check box, thin chromeless scroll bars, a slim progress bar with a real indeterminate sweep, and a light DataGrid header with tinted row hover/selection instead of the heavy navy header. Each tab's content sits on a rounded card, dense control rows are grouped into toolbar panels, read-only output panes are styled as monospaced consoles, and the header carries a gradient with a status pill. Dense toolbars now use WrapPanel so they reflow instead of running off the edge when the window is narrow, the Scan Path column widths were adjusted so no header clips, and the default window size grew to 1220x880. No control names, event wiring or behaviour changed - verified with off-screen WPF render tests of every tab plus a live launch of the tool - [Mattias Melkersen]
    2026-06-25 - v5.3 - Fixed the tool wrongly reporting that EpmTools is "not installed on this device" when it actually is. Get-FileAttributes ships in the EpmTools module under "%ProgramFiles%\Microsoft EPM Agent\EpmTools", which is not on the PowerShell module auto-load path, so Get-Command could not see it until that folder was the current directory. Test-EpmToolsAvailable now locates and imports the EpmTools module (psd1/psm1/dll) from the EPM Agent folder before deciding, and caches the result. Also corrected the EpmTools attribute property names the scan reads to the real ones (FileHash and ProductName, not Hash/Product; publisher is resolved from the signing certificate since EpmTools returns no Publisher field), and fixed certificate extraction to treat the EpmTools certificate-export parameter as a folder (for example -CertOutputPath C:\temp\EPM\), collecting the produced .cer from that directory - [Mattias Melkersen]
    2026-06-25 - v5.2 - The Scan Path results grid can now be copied from. Right-click offers "Copy row(s)" (selected rows as tab-separated text with a header) and "Copy cell" (the current cell), Ctrl+C copies the selected rows (ClipboardCopyMode=IncludeHeader), and double-clicking a cell copies its value (falling back to the whole row when the cell is empty). New GUI helpers Set-GuiClipboardText, Get-DataGridCellText and Copy-DataGridSelection back the behaviour - [Mattias Melkersen]
    2026-06-25 - v5.1 - Scan Path tab now only scans for file types EPM can actually elevate. Removed the ".dll" scan option (a DLL is loaded into a host process and cannot be the target of an EPM elevation rule), leaving ".exe" and ".msi" (now both checked by default) - [Mattias Melkersen]
    2026-06-25 - v5.0 - Fixed a BadRequest ("Selected Option supportarbitrated does not match with the list of expected options") when creating a rule from the new Scan Path tab. Get-EpmRuleChoiceOption now stores the option's full itemId (for example device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}_supportarbitrated) as the combo box value instead of the short optionValue.value token, which EPM rejected, and falls back to the trailing token for the display name when the option has no displayName. Resolve-EpmGroupChildValue now walks the rule's setting tree breadth-first so validation and child process behavior - which live nested under the elevation type choice's children - are reliably set, while a shallow (top-level) match still wins to avoid mismatches - [Mattias Melkersen]
    2026-06-25 - v4.9 - Added a "Scan Path" tab to build elevation rules straight from a folder of executables. It scans a path (optionally recursively, for .exe/.msi/.dll) and lists each file with its publisher, file hash, internal name, product and a suggested match type (Certificate when signed, otherwise Hash). For a selected signed file it extracts the signing certificate with the EpmTools Get-FileAttributes cmdlet and uploads it as a named EPM reusable certificate setting (cloning an existing reusable setting's body when one exists so the payload matches the tenant template, otherwise constructing it from the certificate setting definition). It then creates one or more rules in a chosen EPM policy with a full set of attributes - elevation type, validation, child process behavior, internal name and the reusable certificate reference. The elevation type/validation/child process options are read live from the selected policy's setting definitions (no hardcoded option strings); Resolve-EpmGroupChildValue now also sets choice values, and a new Set-EpmRuleReusableReference points a cloned rule at the chosen reusable certificate. New helpers: Get-EpmExecutableFromPath, Export-EpmFileCertificate, New-EpmReusableCertificateSetting, Get-EpmRuleChoiceOption, Add-EpmScannedRuleToPolicy. All tenant writes are gated behind explicit buttons and a confirmation prompt - [Mattias Melkersen]
    2026-06-25 - v4.8 - Added "uncovered elevations" visibility to the Coverage Analysis tab so it is easy to see which applications are NOT yet covered by any existing persona rule. The user/uncovered grids now live in a nested tab control with two tabs - "Recommended persona per user" and "Uncovered elevations". The uncovered tab shows the gap grouped by application (file name + publisher) with the occurrence count, distinct users, distinct devices, a suggested match type (Certificate when signed, otherwise Hash) and a sample hash, sorted by occurrences. A new "Export Uncovered (CSV)" button exports the full per-elevation uncovered list (file, publisher, product, hash, match type, user, device, rule name). Get-EpmCoverageReport now also returns UncoveredElevations, UncoveredSummary and UncoveredDetails - [Mattias Melkersen]
    2026-06-25 - v4.7 - Fixed the Coverage Analysis persona cards showing blank "Elevations" and "Existing rules" values. The TabItem style set Foreground=White on the whole selected TabItem, which WPF inherits into the selected tab's content - so any card text without an explicit Foreground (the two numeric values) rendered white-on-white and was invisible. The white selected-state colour is now scoped to the tab header's ContentPresenter (TextElement.Foreground) only, and the header's default/grey colour was moved onto the same presenter, leaving the tab body to use the default dark text. Verified with off-screen WPF render tests: selected header is white while card values render in the default dark colour - [Mattias Melkersen]
    2026-06-25 - v4.6 - Simplified the My Device tab: removed the "Check Selected Policy" button and the policy drop-down. The local agent-log check no longer needs a policy to be picked - "Check Local Applied State" now reads the Microsoft EPM Agent logs and lists every EPM policy that applied on this device (applied state, compliance, user applicability and the per-rule file/internal name/status for each). Get-EpmAgentLogState now discovers all policies by their payload SettingId instead of taking a PolicyId parameter, and reports them as a Policies collection (new helper New-EpmPolicyLogBucket accumulates per-policy data). Removed the elevation warning from the local check - the EPM agent logs are readable without an administrative session - [Mattias Melkersen]
    2026-06-25 - v4.5 - My Device "Check Local Applied State" now reads the Microsoft EPM Agent logs (%ProgramFiles%\Microsoft EPM Agent\Logs\EPM-*.log) for the selected policy id to definitively confirm whether the policy applied and to list the elevation rules it delivered. New Get-EpmAgentLogState parses the CMTrace-formatted logs: it reads the policy id from the agent's payload "SettingId", extracts each rule (file name, internal name and file/cert hash) from the parsed policy payload, reads the per-rule compliance status from the agent's inventory payload (tagged with the same SettingId), and captures the overall Test result (Compliant TRUE/FALSE) and the user-applicability note. Validated against a real log: policy 007b627b... reported applied/COMPLIANT (5/5 rules: git.exe, powershell.exe, cmd.exe, wsl.exe, git-credential-manager.exe). Requires an elevated session to read the Program Files logs - [Mattias Melkersen]
    2026-06-25 - v4.4 - Fixed the My Device "Check Selected Policy" wrongly reporting Assigned: False for policies that ARE assigned to the device. Get-RunningDeviceIdentity took the Entra device id from the CloudDomainJoin JoinInfo registry sub-key name, but that sub-key is named with the device certificate THUMBPRINT (40 hex chars), not the Entra device id GUID - so the Graph lookup "devices?$filter=deviceId eq '<thumbprint>'" matched nothing, the device resolved to zero groups, and device-targeted assignments were never detected. Now reads the device id GUID from dsregcmd as the authoritative source and only falls back to the registry sub-key when it is actually a GUID - [Mattias Melkersen]
    2026-06-25 - v4.3 - Reworked the per-user persona recommendation: instead of picking whichever persona covers the most elevations by raw count (which made every user default to "Developer" because its broad rules matched the most common apps while specialised personas matched none), it now uses a weighted scoring model - exact file-hash match = 3 points, partial file-name match = 1 point, strongest match per persona counted once per elevation - and reports a coverage ratio plus a High/Medium/Low/None confidence band so weak matches are flagged for a tailored persona rather than silently assigned. Added colour throughout the GUI: branded blue buttons/tab headers/grid headers, a coverage-score banner and persona cards colour-coded green/amber/red/grey by coverage, and a Confidence column on the user recommendation grid - [Mattias Melkersen]
    2026-06-25 - v4.2 - Fixed very slow CSV import for large files (6000+ rows): the v3.6 DataGrid style set ScrollViewer.CanContentScroll=False for smooth trackpad scrolling, which DISABLES UI virtualization so WPF rendered every row at once. Re-enabled virtualization with container recycling and pixel-based scroll unit (keeps smooth scrolling AND performance), and optimized ConvertTo-DataTable with BeginLoadData/EndLoadData plus cached property names (6000 rows build in ~170 ms) - [Mattias Melkersen]
    2026-06-25 - v4.1 - Fixed CSV import failing with "Value cannot be null. (Parameter 'key')": ConvertTo-DataTable returned the DataTable via `return $dt`, which PowerShell enumerated (DataTable is IEnumerable) so callers received its DataRows instead of the table - DefaultView/RowFilter were missing and the WPF DataGrid binding/sorting/search broke. Both returns now use the comma operator (`return , $dt`) so a real DataTable is returned. Also fixes the Coverage and Reusable usage grids that had the same latent issue - [Mattias Melkersen]
    2026-06-25 - v4.0 - Improved the STA relaunch so a standalone PowerShell 7 console (pwsh defaults to MTA) also works: the GUI now relaunches in a separate STA process using the SAME host executable with -STA (pwsh stays on pwsh 7, keeping runtime/modules), falling back to Windows PowerShell 5.1; verified working from both STA and MTA pwsh sessions - [Mattias Melkersen]
    2026-06-25 - v3.9 - Hardened the STA relaunch from v3.8: the in-process STA runspace was still unreliable in the VS Code PowerShell Integrated Console (GUI still failed with the ComboBox/"calling thread must be STA" error). Show-WpfGui now relaunches the GUI in a separate, always-STA Windows PowerShell process (powershell.exe -STA -File) when the current thread is not STA, which works from any host - [Mattias Melkersen]
    2026-06-25 - v3.8 - Fixed "Exception calling Load ... Initialization of System.Windows.Controls.ComboBox threw an exception" (inner: "The calling thread must be STA") when launching the GUI from an MTA host such as the VS Code PowerShell Integrated Console; Show-WpfGui now detects a non-STA thread and relaunches the GUI on a dedicated STA runspace thread so it works regardless of how the script is started - [Mattias Melkersen]
    2026-06-25 - v3.7 - Fixed CSV import failing with "Value cannot be null. (Parameter 'key')" introduced in v3.6: a DataView-backed DataGrid does not support the WPF CollectionView.Filter predicate, so candidate search now uses the DataView's native RowFilter expression; selected rows (DataRowView) are mapped back to the original candidate objects via a hidden CandidateIndex column so adding rules still works - [Mattias Melkersen]
    2026-06-25 - v3.6 - Fixed GUI usability: injected a WPF DataGrid style so `ScrollViewer.CanContentScroll` is false (resolving scrolling issues with laptop trackpads); added a `ConvertTo-DataTable` helper so all tables support clicking column headers to sort; redesigned the Coverage Analysis "Coverage by persona" section from a grid into a responsive, drop-shadowed card interface - [Mattias Melkersen]
    2026-06-25 - v3.5 - Replaced the Duplicate Check tab with a Coverage Analysis tab: scores how many imported unmanaged elevations are already covered by existing EPM persona rules, breaks coverage down per persona, and recommends which persona each user should be assigned to - [Mattias Melkersen]
    2026-06-25 - v3.4 - Import and Ingest now detects when a rule name already exists in the target policy and prompts Yes (add with an auto-generated unique name like "name (2)") / No (skip) / Cancel (stop), preventing the duplicate-rule BadRequest on re-import - [Mattias Melkersen]
    2026-06-25 - v3.3 - Fixed "Duplicate References found" BadRequest when adding/replicating a rule by stripping every settingInstanceTemplateReference/settingValueTemplateReference from each new rule entry (template ids may appear only once per policy; the original rule keeps them, the added rule must not), matching the Intune portal - [Mattias Melkersen]
    2026-06-25 - v3.2 - Merged the Import CSV and Build Rule tabs into a single "Import and Ingest" tab: import builds searchable candidates, you can filter/search, multi-select (mark) the rule(s) and add them straight to a chosen EPM policy from one place - [Mattias Melkersen]
    2026-06-25 - v3.1 - Fixed reusable setting usage failing to display when exactly one rule matched (single object could not bind to the grid's ItemsSource) by forcing array results with @() on the usage, source rules and reusable settings bindings - [Mattias Melkersen]
    2026-06-25 - v3.0 - Fixed reusable settings load failing with InternalServerError by matching the Intune portal's reusablePolicySettings query (dropped 'description' from $select, added lastModifiedDateTime, $orderby=displayName asc, $top=50) - [Mattias Melkersen]
    2026-06-25 - v2.9 - Fixed reusable setting "where used" returning nothing by walking the full rule tree (references are nested inside the certificate group, not the rule's top-level children); each rule now reports all referenced reusable setting ids - [Mattias Melkersen]
    2026-06-25 - v2.8 - Bumped the EPM policy settings read to $top=1000 to match the Intune portal's request (verified via portal HAR capture) - [Mattias Melkersen]
    2026-06-25 - v2.7 - Fixed Replicate/Add rule still failing with ModelValidationFailure by switching the policy write from PATCH to PUT on configurationPolicies('id'); PUT replaces the full entity including the settings navigation property (the method the Intune portal and IntuneCD use) - [Mattias Melkersen]
    2026-06-25 - v2.6 - Removed the duplicate footer busy text; the progress bar now shares a single status line so an operation is only described once - [Mattias Melkersen]
    2026-06-25 - v2.5 - Moved the signed-in indicator to a second line beneath the Graph auth controls in the header for a cleaner layout - [Mattias Melkersen]
    2026-06-25 - v2.4 - Changed debug logging to reuse a single rolling log file (Build-EpmRules.debug.log) instead of one per run; when it exceeds 4 MB it is archived to .old and a fresh log is started - [Mattias Melkersen]
    2026-06-25 - v2.3 - Fixed Replicate/Add rule PATCH failure (ModelValidationFailure: cannot PATCH navigation property 'settings') by sending the full policy entity (name, description, platforms, technologies, roleScopeTagIds, templateReference, settings) instead of a settings-only body - [Mattias Melkersen]
    2026-06-25 - v2.2 - Modernized UI: Moved authentication controls to the top right corner (header), styled for dark background, and cleaned up the footer - [Mattias Melkersen]
    2026-06-25 - v2.1 - Fixed Replicate "Load rules" failure when a policy has a single setting/child by changing strongly typed List[object] parameters to object[] (scalar inputs now coerce correctly); gave the footer a two-row layout with more vertical space - [Mattias Melkersen]
    2026-06-25 - v2.0 - Added an explicit Graph Sign in/Sign out button with a connection-state indicator; the token is kept for the GUI session, and DeviceCode sign-in works in elevated sessions where the interactive browser fails - [Mattias Melkersen]
    2026-06-24 - v1.9 - Fixed empty reusable settings dropdown by filtering reusablePolicySettings server-side on the EPM certificate setting definition id, matching the Intune portal - [Mattias Melkersen]
    2026-06-24 - v1.8 - Fixed EPM detection and filtering by using the correct templateFamily enum value (endpointSecurityEndpointPrivilegeManagement) and tolerant token matching, resolving empty policy/rule loads and the BadRequest filter error - [Mattias Melkersen]
    2026-06-24 - v1.7 - Added always-on debug logging (Graph requests, EPM detection decisions, full error responses) to a shareable log file; removed unsupported reusablePolicySettings expand that broke reusable settings loading - [Mattias Melkersen]
    2026-06-24 - v1.6 - Limited reusable settings to EPM only and resolved reusable setting usage by reading EPM policy rules instead of the unreliable referencing-policies expand - [Mattias Melkersen]
    2026-06-24 - v1.5 - Load EPM policies straight from the EPM Graph filter and removed per-policy settings inspection and the all-policy fallback scan - [Mattias Melkersen]
    2026-06-24 - v1.4 - Added visible GUI progress/status feedback for long-running operations - [Mattias Melkersen]
    2026-06-24 - v1.3 - Optimized EPM policy loading by using EPM-specific Graph filters before fallback scanning - [Mattias Melkersen]
    2026-06-24 - v1.2 - Added fallback EPM policy discovery by inspecting policy settings when template metadata is missing - [Mattias Melkersen]
    2026-06-24 - v1.1 - Added DeviceCode Graph authentication mode for FIDO2 security key sign-in - [Mattias Melkersen]
    2026-06-24 - v1.0 - Initial creation - [Mattias Melkersen]

    References:
    - https://learn.microsoft.com/mem/intune/protect/epm-overview
    - https://learn.microsoft.com/graph/api/resources/intune-deviceconfigv2-devicemanagementconfigurationpolicy
    - https://learn.microsoft.com/graph/api/resources/intune-shared-devicemanagementreusablepolicysetting
#>

[CmdletBinding(DefaultParameterSetName = 'Gui', SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory = $false, ParameterSetName = 'Report')]
    [ValidateScript({ Test-Path -Path $_ })]
    [string]$CsvPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Replicate')]
    [string]$SourcePolicyId,

    [Parameter(Mandatory = $true, ParameterSetName = 'Replicate')]
    [string]$TargetPolicyId,

    [Parameter(Mandatory = $true, ParameterSetName = 'Replicate')]
    [string]$RuleName,

    [Parameter(Mandatory = $true, ParameterSetName = 'ReusableUsage')]
    [string]$ReusableSettingId,

    [Parameter(Mandatory = $false, ParameterSetName = 'Report')]
    [hashtable]$ColumnMap,

    [Parameter(Mandatory = $false, ParameterSetName = 'Report')]
    [ValidateSet('Auto', 'Certificate', 'Hash')]
    [string]$MatchType = 'Auto',

    [Parameter(Mandatory = $false, ParameterSetName = 'Report')]
    [Parameter(Mandatory = $false, ParameterSetName = 'Replicate')]
    [Parameter(Mandatory = $false, ParameterSetName = 'ReusableUsage')]
    [string]$OutputPath,

    [Parameter(Mandatory = $false, ParameterSetName = 'Replicate')]
    [switch]$Apply,

    [Parameter(Mandatory = $false, ParameterSetName = 'Report')]
    [Parameter(Mandatory = $false, ParameterSetName = 'Replicate')]
    [Parameter(Mandatory = $false, ParameterSetName = 'ReusableUsage')]
    [switch]$NoGui,

    [Parameter(Mandatory = $false)]
    [ValidateSet('Interactive', 'DeviceCode')]
    [string]$GraphAuthMode = 'Interactive',

    [Parameter(Mandatory = $false)]
    [string]$LogPath
)
#region Configuration

$ErrorActionPreference = 'Stop'

# The GUI's DPI-awareness is otherwise whatever the launching host (powershell.exe, pwsh.exe, the
# PowerShell ISE, VS Code's terminal) happens to declare in its own manifest - System-aware on some
# hosts, unaware on others - and an unaware or System-aware host renders WPF content bitmap-scaled
# rather than natively, which is a common reason a window looks the wrong size or slightly blurry on
# a laptop's scaled display. Requesting Per-Monitor-V2 here, before any window is created, makes the
# GUI render at native resolution and rescale correctly if dragged between monitors of different
# DPI, regardless of the host's own setting. Requires Windows 10 1703+; harmless no-op everywhere
# else (older Windows lacks the API, or the host already locked in its own awareness first - a
# process may only set this once - and either way the previous, working behavior is left alone).
try {
    Add-Type -Name NativeDpi -Namespace ZeroAdmin -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll", SetLastError = true)]
public static extern bool SetProcessDpiAwarenessContext(System.IntPtr dpiContext);
'@ -ErrorAction Stop
    # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2, per the Win32 API - not exposed as a named
    # constant to P/Invoke, so the documented sentinel value is passed directly.
    [ZeroAdmin.NativeDpi]::SetProcessDpiAwarenessContext([System.IntPtr]::new(-4)) | Out-Null
} catch {
    # Missing API (pre-1703 Windows) or awareness already set by the host - not fatal either way.
}

$scriptName = [System.IO.Path]::GetFileNameWithoutExtension($MyInvocation.MyCommand.Name)
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Reports and the debug log go next to the script when that folder is writable, and otherwise into
# the user's local app data. The Community Edition is distributed as a single file that people drop
# anywhere - including read-only locations such as Program Files or a network share - so it must not
# assume a repository layout around itself, and it must never need admin rights to write a log.
$reportsDir = Join-Path -Path $scriptDir -ChildPath 'reports'
try {
    if(-not (Test-Path -LiteralPath $reportsDir)) {
        New-Item -Path $reportsDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }
    $probeFile = Join-Path -Path $reportsDir -ChildPath ".write-probe-$PID"
    [System.IO.File]::WriteAllText($probeFile, '')
    Remove-Item -LiteralPath $probeFile -Force -ErrorAction SilentlyContinue
} catch {
    $reportsDir = Join-Path -Path ([System.Environment]::GetFolderPath('LocalApplicationData')) -ChildPath 'ZeroAdmin\reports'
    if(-not (Test-Path -LiteralPath $reportsDir)) {
        New-Item -Path $reportsDir -ItemType Directory -Force | Out-Null
    }
}

# Microsoft Graph delegated scopes required by the tool. The Community Edition only ever reads and
# writes settings-catalog configuration policies and reusable settings, so this single scope covers
# everything it does. Device, group and directory scopes were dropped along with the My Device tab -
# do not add them back without a feature that genuinely needs them, because every extra scope is
# something the consenting admin has to grant.
$graphScopes = @(
    'DeviceManagementConfiguration.ReadWrite.All'
)

# The settings-catalog "technologies" enum member that identifies EPM policies. This is the
# value used by the configurationPolicies "technologies has '...'" server-side filter.
$epmTechnologiesValue = 'endpointPrivilegeManagement'

# The settings-catalog "templateFamily" enum member for EPM. Note this differs from the
# technologies value: the templateReference/templateFamily enum uses the longer
# "endpointSecurityEndpointPrivilegeManagement" member.
$epmTemplateFamilyValue = 'endpointSecurityEndpointPrivilegeManagement'

# Lowercase substring used to recognise the EPM template family on a policy object regardless of
# which exact enum spelling a tenant returns (handles both the technologies and templateFamily
# spellings, with separators removed).
$epmTemplateFamilyToken = 'privilegemanagement'

# Substring used to distinguish the EPM *elevation rules* policy template from the EPM
# elevation *settings* policy template within the EPM template family.
$epmRulesTemplateToken = 'elevationrules'

# The settings-catalog setting definition id of the EPM reusable setting (the certificate file
# reusable setting). The Intune portal filters the reusablePolicySettings list server-side on
# this exact definition id to show only EPM reusable settings, so the tool does the same.
$epmReusableSettingDefinitionId = 'device_vendor_msft_policy_privilegemanagement_reusablesettings_certificatefile'

# The settings-catalog definition id prefix every EPM elevation rule child hangs off. Rule payloads
# are built from this prefix so a rule can be created in a policy that has no existing rule to copy.
# Captured from the Intune portal's own PUT bodies.
$epmRulePrefix = 'device_vendor_msft_policy_privilegemanagement_elevationrules_{elevationrulename}'

# Candidate CSV column headers for each normalized field, in priority order. Used for
# auto-detection when an explicit ColumnMap is not supplied.
$csvColumnCandidates = @{
    FilePath = @('FilePath', 'File Path', 'Path', 'FullPath', 'Full Path')
    FileName = @('FileName', 'File Name', 'File', 'Name', 'Process', 'ProcessName')
    FileHash = @('FileHash', 'File Hash', 'Hash', 'Sha256', 'SHA256 Hash', 'FileHashSha256')
    Publisher = @('Publisher', 'CertificatePublisher', 'Signer', 'Certificate Subject', 'PublisherName')
    Product = @('Product', 'ProductName', 'Product Name')
    InternalName = @('InternalName', 'Internal Name')
    Description = @('Description', 'FileDescription', 'File Description')
    User = @('User', 'UserName', 'UserPrincipalName', 'UPN', 'Upn')
    Device = @('Device', 'DeviceName', 'Device Name', 'ComputerName', 'Computer')
    ElevationType = @('ElevationType', 'Elevation Type', 'Type')
}

# The graph base URL used throughout the tool.
$graphBaseUrl = 'https://graph.microsoft.com/beta'

# The MSEndpointMgr brand mark, embedded as base64 PNG so the tool stays a single self-contained
# file (no separate .ico/.png to lose, and it still shows the logo when copied to a machine that
# has never seen this repository). Decoded once at GUI startup into the header badge and the
# window/taskbar icon. Source: LogoSmall_Transparent.png, 226x223, transparent background.
$script:brandLogoBase64 = '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'

# The Microsoft EPM Agent ships the EpmTools module (Get-FileAttributes) under this folder, which is
# not on the PowerShell module auto-load path. Detection imports it from here before deciding the
# tooling is missing. The availability result is cached for the run.
$epmToolsModuleSubPath = 'Microsoft EPM Agent\EpmTools'
$script:epmToolsAvailable = $null
$script:epmToolsProbeMessage = $null

# User-scoped settings and working paths (no admin rights required).
$script:userSettingsRoot = Join-Path -Path ([System.Environment]::GetFolderPath('LocalApplicationData')) -ChildPath 'ZeroAdmin'
$script:userSettingsFilePath = Join-Path -Path $script:userSettingsRoot -ChildPath 'settings.json'
$script:defaultTempWorkingDirectory = Join-Path -Path $script:userSettingsRoot -ChildPath 'Temp'
$script:runtimeSettings = $null

# One-time migration for anyone upgrading from Build-EpmRules: carry a saved temp-working-directory
# preference over to the new settings location so a rebrand does not silently reset it. Only the
# small settings.json is copied - the old Temp folder itself is just a scratch cache, not something
# worth moving. Never overwrites a settings.json that already exists at the new location.
try {
    $legacySettingsRoot = Join-Path -Path ([System.Environment]::GetFolderPath('LocalApplicationData')) -ChildPath 'Build-EpmRules'
    $legacySettingsFile = Join-Path -Path $legacySettingsRoot -ChildPath 'settings.json'
    if((Test-Path -LiteralPath $legacySettingsFile -PathType Leaf) -and -not (Test-Path -LiteralPath $script:userSettingsFilePath -PathType Leaf)) {
        if(-not (Test-Path -LiteralPath $script:userSettingsRoot -PathType Container)) {
            New-Item -Path $script:userSettingsRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
        Copy-Item -LiteralPath $legacySettingsFile -Destination $script:userSettingsFilePath -ErrorAction Stop
    }
} catch {
    # Never let a migration failure block startup - Initialize-EpmToolSettings falls back to
    # defaults regardless.
}

# Graph authentication mode. DeviceCode is useful when FIDO2/security-key sign-in is required.
$script:graphAuthModeSetting = $GraphAuthMode

# Debug logging. A single rolling diagnostic log is reused across runs so issues can be
# reproduced and shared. When the log grows past the size limit it is archived once and a fresh
# log is started. The path can be overridden with -LogPath.
if([string]::IsNullOrWhiteSpace($LogPath)) {
    $script:debugLogPath = Join-Path -Path $reportsDir -ChildPath "$scriptName.debug.log"
} else {
    $script:debugLogPath = $LogPath
}
$script:debugLogInitialized = $false
$script:debugLogMaxBytes = 4MB

#endregion Configuration

#region Functions

function Write-DebugLog {
    <#
    .SYNOPSIS
    Writes a timestamped diagnostic entry to the debug log file and the verbose stream.

    .DESCRIPTION
    The tool always writes a detailed diagnostic log so that issues (empty EPM policy lists,
    missing rules, failed reusable setting lookups) can be reproduced and shared. The log records
    every Graph request, response counts, EPM detection decisions and full Graph error responses.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [ValidateSet('INFO', 'WARN', 'ERROR', 'GRAPH', 'DEBUG')]
        [string]$Category = 'INFO'
    )

    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss.fff'
    $line = "[$timestamp] [$Category] $Message"

    try {
        if(-not $script:debugLogInitialized) {
            $logDir = Split-Path -Parent $script:debugLogPath
            if(-not [string]::IsNullOrWhiteSpace($logDir) -and -not (Test-Path -Path $logDir)) {
                New-Item -Path $logDir -ItemType Directory -Force | Out-Null
            }

            # Roll the log when it has grown beyond the size limit. The previous log is archived
            # to a single ".old" file (overwriting any earlier archive) and a fresh log is started.
            if(Test-Path -Path $script:debugLogPath) {
                $currentSize = (Get-Item -Path $script:debugLogPath -ErrorAction Stop).Length
                if($currentSize -ge $script:debugLogMaxBytes) {
                    $archivePath = "$script:debugLogPath.old"
                    Move-Item -Path $script:debugLogPath -Destination $archivePath -Force -ErrorAction Stop
                }
            }

            $header = @(
                "===== $scriptName debug log ====="
                "Run started: $timestamp"
                "PowerShell: $($PSVersionTable.PSVersion)"
                "Graph auth mode: $($script:graphAuthModeSetting)"
                "Graph base URL: $graphBaseUrl"
                '================================='
            )
            # Append the run header so the log is reused across runs; the file is only recreated
            # after a roll or when it does not yet exist.
            Add-Content -Path $script:debugLogPath -Value $header -Encoding utf8 -ErrorAction Stop
            $script:debugLogInitialized = $true
        }

        Add-Content -Path $script:debugLogPath -Value $line -Encoding utf8 -ErrorAction Stop
    } catch {
        Write-Error -Message "Failed to write debug log entry: $($_.Exception.Message)" -ErrorAction SilentlyContinue
    }

    Write-Verbose -Message $line
}

function Get-GraphErrorDetail {
    <#
    .SYNOPSIS
    Extracts the full error detail from a caught Graph error record.

    .DESCRIPTION
    Invoke-MgGraphRequest surfaces the Graph error response body (which usually contains the real
    reason for a BadRequest) in the ErrorDetails.Message property. This helper combines the
    exception message and that response body so the actual Graph error is captured in the log.
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $ErrorRecord
    )

    if($null -eq $ErrorRecord) {
        return ''
    }

    $parts = [System.Collections.Generic.List[string]]::new()

    if($null -ne $ErrorRecord.Exception -and -not [string]::IsNullOrWhiteSpace($ErrorRecord.Exception.Message)) {
        $parts.Add("Exception: $($ErrorRecord.Exception.Message)")
    }

    $errorDetails = Get-GraphResponseProperty -InputObject $ErrorRecord -PropertyName 'ErrorDetails'
    if($null -ne $errorDetails) {
        $detailsMessage = Get-GraphResponseProperty -InputObject $errorDetails -PropertyName 'Message'
        if(-not [string]::IsNullOrWhiteSpace($detailsMessage)) {
            $parts.Add("Response: $detailsMessage")
        }
    }

    if($parts.Count -eq 0) {
        return [string]$ErrorRecord
    }

    return ($parts -join ' | ')
}

function Get-DefaultOutputPath {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates an in-memory candidate object only; it does not change system or tenant state.')]
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$Extension = 'json'
    )

    $timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    return Join-Path -Path $reportsDir -ChildPath "$scriptName.$timestamp.$Extension"
}

function Assert-GraphModule {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Updates an in-memory settings payload before Graph write-back is separately gated by ShouldProcess.')]
    [CmdletBinding()]
    param()

    if ($null -eq (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        Write-Warning -Message 'Microsoft.Graph.Authentication module not found. It is required to connect to Intune.'
        $response = Read-Host -Prompt 'Install the Microsoft.Graph.Authentication module from PSGallery now? (Y/N)'
        if($response -match '^[Yy]$') {
            try {
                Install-Module -Name Microsoft.Graph.Authentication -Repository PSGallery -Scope CurrentUser -Force -ErrorAction Stop
            } catch {
                throw "Failed to install Microsoft.Graph.Authentication module: $($_.Exception.Message)"
            }
        } else {
            throw 'The Microsoft.Graph.Authentication module is required to continue.'
        }
    }
}

function Connect-IntuneGraph {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '', Justification = 'Creates an in-memory settings payload only; Graph write-back is separately gated by ShouldProcess.')]
    [CmdletBinding()]
    param()

    Assert-GraphModule

    try {
        $context = Get-MgContext -ErrorAction SilentlyContinue
        if($null -ne $context) {
            $hasScopes = $true
            foreach($scope in $graphScopes) {
                if($context.Scopes -notcontains $scope) {
                    $hasScopes = $false
                    break
                }
            }

            if($hasScopes) {
                Write-Verbose -Message 'Already connected to Microsoft Graph with the required scopes.'
                return
            }
        }
    } catch {
        Write-Verbose -Message "Unable to inspect existing Microsoft Graph context: $($_.Exception.Message)"
    }

    Write-Verbose -Message "Connecting to Microsoft Graph using $($script:graphAuthModeSetting) authentication..."
    $connectParameters = @{
        Scopes = $graphScopes
        NoWelcome = $true
        ContextScope = 'Process'
    }

    if($script:graphAuthModeSetting -eq 'DeviceCode') {
        $connectParameters['UseDeviceCode'] = $true
    }

    Connect-MgGraph @connectParameters
}

function Get-GraphResponseProperty {
    <#
    .SYNOPSIS
    Safely reads a property from an Invoke-MgGraphRequest response.

    .DESCRIPTION
    Invoke-MgGraphRequest returns a Hashtable. Under Set-StrictMode, reading a missing key
    throws instead of returning $null. This helper returns $null when the property is absent,
    handling both dictionaries and PSCustomObjects.
    #>
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $InputObject,

        [Parameter(Mandatory = $true)]
        [string]$PropertyName
    )

    if($null -eq $InputObject) {
        return $null
    }

    if($InputObject -is [System.Collections.IDictionary]) {
        if($InputObject.Contains($PropertyName)) {
            return $InputObject[$PropertyName]
        }
        return $null
    }

    $property = $InputObject.PSObject.Properties[$PropertyName]
    if($null -ne $property) {
        return $property.Value
    }

    return $null
}

function Invoke-MgGraphGetAllPage {
    <#
    .SYNOPSIS
    Retrieves all pages of a Microsoft Graph collection request.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )

    $allItems = [System.Collections.Generic.List[object]]::new()
    $nextUri = $Uri
    $pageNumber = 0

    while($null -ne $nextUri) {
        $pageNumber++
        Write-DebugLog -Category 'GRAPH' -Message "GET (page $pageNumber): $nextUri"

        try {
            $response = Invoke-MgGraphRequest -Method GET -Uri $nextUri -ErrorAction Stop
        } catch {
            $detail = Get-GraphErrorDetail -ErrorRecord $_
            Write-DebugLog -Category 'ERROR' -Message "GET failed: $nextUri -> $detail"
            throw
        }

        $value = Get-GraphResponseProperty -InputObject $response -PropertyName 'value'
        if($null -ne $value) {
            $pageItemCount = 0
            foreach($item in $value) {
                $allItems.Add($item)
                $pageItemCount++
            }
            Write-DebugLog -Category 'GRAPH' -Message "Page $pageNumber returned $pageItemCount item(s)."
        } elseif($null -ne $response) {
            $allItems.Add($response)
            Write-DebugLog -Category 'GRAPH' -Message "Page $pageNumber returned a single (non-collection) object."
        }

        $nextUri = Get-GraphResponseProperty -InputObject $response -PropertyName '@odata.nextLink'
    }

    Write-DebugLog -Category 'GRAPH' -Message "Collected $($allItems.Count) total item(s) across $pageNumber page(s) for: $Uri"
    return $allItems
}

function Test-EpmRulesPolicy {
    <#
    .SYNOPSIS
    Determines whether a configuration policy object is an EPM *elevation rules* policy.
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $PolicyObject
    )

    if($null -eq $PolicyObject) {
        return $false
    }

    $templateReference = Get-GraphResponseProperty -InputObject $PolicyObject -PropertyName 'templateReference'
    if($null -eq $templateReference) {
        return $false
    }

    $templateFamily = Get-GraphResponseProperty -InputObject $templateReference -PropertyName 'templateFamily'
    $templateId = Get-GraphResponseProperty -InputObject $templateReference -PropertyName 'templateId'
    $templateDisplayName = Get-GraphResponseProperty -InputObject $templateReference -PropertyName 'templateDisplayName'

    # The templateFamily enum can be spelled differently between tenants/endpoints (for example
    # "endpointSecurityEndpointPrivilegeManagement"). Match on the stable privilege-management
    # token (separators removed) rather than an exact string so EPM policies are not missed.
    $normalizedFamily = ''
    if(-not [string]::IsNullOrEmpty($templateFamily)) {
        $normalizedFamily = ([string]$templateFamily).ToLowerInvariant().Replace('-', '').Replace('_', '')
    }

    if([string]::IsNullOrEmpty($normalizedFamily) -or $normalizedFamily -notmatch $epmTemplateFamilyToken) {
        return $false
    }

    # Within the EPM family there is a rules template and a settings template. Both pieces of
    # metadata below are returned by the configurationPolicies list endpoint, so this decision
    # never needs an extra Graph call.

    # The elevation *settings* policy is explicitly excluded; everything else in the EPM family is
    # treated as a rules policy.
    if($null -ne $templateDisplayName -and ([string]$templateDisplayName).ToLowerInvariant() -match 'setting') {
        return $false
    }

    if($null -ne $templateDisplayName -and ([string]$templateDisplayName).ToLowerInvariant() -match 'rule') {
        return $true
    }

    if($null -ne $templateId -and ([string]$templateId).ToLowerInvariant().Replace('-', '') -match $epmRulesTemplateToken) {
        return $true
    }

    # The policy is in the EPM family but does not advertise which template it uses. Include it;
    # the rule reader simply returns no rules if it turns out to be a non-rules policy.
    return $true
}

function ConvertTo-EpmPolicyList {
    <#
    .SYNOPSIS
    Converts raw configuration policy objects into the GUI policy picker shape.

    .DESCRIPTION
    Classifies each policy as an EPM rules policy using only the metadata returned by the
    configurationPolicies list endpoint, so building the picker never costs an extra Graph call
    per policy.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Policy
    )

    $epmPolicies = [System.Collections.Generic.List[object]]::new()
    $seenPolicyIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)

    foreach($policyItem in $Policy) {
        $id = Get-GraphResponseProperty -InputObject $policyItem -PropertyName 'id'
        if([string]::IsNullOrWhiteSpace($id) -or $seenPolicyIds.Contains($id)) {
            continue
        }

        $name = Get-GraphResponseProperty -InputObject $policyItem -PropertyName 'name'
        if([string]::IsNullOrWhiteSpace($name)) {
            $name = Get-GraphResponseProperty -InputObject $policyItem -PropertyName 'displayName'
        }

        $templateReference = Get-GraphResponseProperty -InputObject $policyItem -PropertyName 'templateReference'
        $templateFamily = if($null -ne $templateReference) { Get-GraphResponseProperty -InputObject $templateReference -PropertyName 'templateFamily' } else { '(none)' }
        $templateDisplayName = if($null -ne $templateReference) { Get-GraphResponseProperty -InputObject $templateReference -PropertyName 'templateDisplayName' } else { '(none)' }
        $technologies = Get-GraphResponseProperty -InputObject $policyItem -PropertyName 'technologies'

        $isEpmRulesPolicy = Test-EpmRulesPolicy -PolicyObject $policyItem
        Write-DebugLog -Category 'DEBUG' -Message "Policy '$name' ($id): templateFamily='$templateFamily', templateDisplayName='$templateDisplayName', technologies='$technologies', isEpmRulesPolicy=$isEpmRulesPolicy"

        if($isEpmRulesPolicy) {
            $description = Get-GraphResponseProperty -InputObject $policyItem -PropertyName 'description'

            [void]$seenPolicyIds.Add($id)
            $epmPolicies.Add([PSCustomObject]@{
                    Id = $id
                    Name = $name
                    Description = $description
                    DisplayName = "$name ($id)"
                })
        }
    }

    Write-DebugLog -Category 'INFO' -Message "ConvertTo-EpmPolicyList kept $($epmPolicies.Count) of $($Policy.Count) candidate policies as EPM rules policies."
    return $epmPolicies
}

function Get-EpmRulesPolicy {
    <#
    .SYNOPSIS
    Retrieves all EPM elevation rules policies from Intune.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param()

    Connect-IntuneGraph

    # The EPM technologies filter returns only EPM policies, so the picker can be built directly
    # from the response metadata without inspecting each policy's settings (which would cost one
    # Graph call per policy and is the main cause of slow loads).
    $filteredQueries = @(
        [PSCustomObject]@{
            Name = 'technologies'
            Uri = "$graphBaseUrl/deviceManagement/configurationPolicies?`$filter=$([System.Uri]::EscapeDataString("technologies has '$epmTechnologiesValue'"))&`$top=100"
        },
        [PSCustomObject]@{
            Name = 'templateFamily'
            Uri = "$graphBaseUrl/deviceManagement/configurationPolicies?`$filter=$([System.Uri]::EscapeDataString("templateReference/templateFamily eq '$epmTemplateFamilyValue'"))&`$top=100"
        }
    )

    foreach($query in $filteredQueries) {
        try {
            Write-DebugLog -Category 'INFO' -Message "Loading EPM policies using the '$($query.Name)' filter: $($query.Uri)"
            $filteredPolicies = Invoke-MgGraphGetAllPage -Uri $query.Uri
            Write-DebugLog -Category 'INFO' -Message "The '$($query.Name)' filter returned $($filteredPolicies.Count) candidate policies."

            if($filteredPolicies.Count -gt 0) {
                $epmPolicies = ConvertTo-EpmPolicyList -Policy $filteredPolicies
                if($epmPolicies.Count -gt 0) {
                    Write-DebugLog -Category 'INFO' -Message "Detected $($epmPolicies.Count) EPM rules policies using the '$($query.Name)' filter."
                    return ($epmPolicies | Sort-Object -Property Name)
                }
                Write-DebugLog -Category 'WARN' -Message "The '$($query.Name)' filter returned policies but none classified as EPM rules policies."
            }
        } catch {
            $detail = Get-GraphErrorDetail -ErrorRecord $_
            Write-DebugLog -Category 'ERROR' -Message "The '$($query.Name)' EPM policy filter failed: $detail"
        }
    }

    Write-DebugLog -Category 'WARN' -Message 'EPM policy filters returned no EPM rules policies. The tenant may not have any EPM elevation rules policies, or the account lacks read access.'
    return ([System.Collections.Generic.List[object]]::new())
}

function Get-EpmPolicySetting {
    <#
    .SYNOPSIS
    Retrieves the raw settings-catalog settings array for a configuration policy.

    .DESCRIPTION
    The settings are returned with their definitions expanded so that setting instances can be
    correlated to their friendly definitions and reusable setting references.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyId
    )

    Connect-IntuneGraph

    # Page size of 1000 matches what the Intune portal requests for EPM policy settings.
    $uri = "$graphBaseUrl/deviceManagement/configurationPolicies('$PolicyId')/settings?`$expand=settingDefinitions&`$top=1000"
    $settings = Invoke-MgGraphGetAllPage -Uri $uri
    Write-DebugLog -Category 'INFO' -Message "Policy '$PolicyId' returned $($settings.Count) top-level setting(s)."
    return $settings
}

function Get-EpmPolicyDetail {
    <#
    .SYNOPSIS
    Retrieves the top-level metadata of a configuration policy.

    .DESCRIPTION
    Returns the scalar properties (name, description, platforms, technologies, templateReference,
    roleScopeTagIds) required to PATCH the policy. Updating an EPM policy's settings requires the
    full policy entity in the request body, because 'settings' is a navigation property that
    cannot be PATCHed on its own.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyId
    )

    Connect-IntuneGraph

    $uri = "$graphBaseUrl/deviceManagement/configurationPolicies('$PolicyId')"
    $policy = Invoke-MgGraphRequest -Method GET -Uri $uri -ErrorAction Stop
    Write-DebugLog -Category 'INFO' -Message "Retrieved policy detail for '$PolicyId'."
    return $policy
}

function Get-EpmSettingInstanceValue {
    <#
    .SYNOPSIS
    Returns the underlying value object of a settings-catalog setting instance.

    .DESCRIPTION
    Settings-catalog instances carry their value under one of several well-known properties
    depending on the instance @odata.type (simple, choice, group collection, etc.). This helper
    returns a normalized object describing the instance value so callers do not need to branch
    on every @odata.type.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $SettingInstance
    )

    if($null -eq $SettingInstance) {
        return $null
    }

    $definitionId = Get-GraphResponseProperty -InputObject $SettingInstance -PropertyName 'settingDefinitionId'
    $odataType = Get-GraphResponseProperty -InputObject $SettingInstance -PropertyName '@odata.type'

    $simpleValue = Get-GraphResponseProperty -InputObject $SettingInstance -PropertyName 'simpleSettingValue'
    $choiceValue = Get-GraphResponseProperty -InputObject $SettingInstance -PropertyName 'choiceSettingValue'
    $groupCollection = Get-GraphResponseProperty -InputObject $SettingInstance -PropertyName 'groupSettingCollectionValue'
    $simpleCollection = Get-GraphResponseProperty -InputObject $SettingInstance -PropertyName 'simpleSettingCollectionValue'
    $choiceCollection = Get-GraphResponseProperty -InputObject $SettingInstance -PropertyName 'choiceSettingCollectionValue'

    $value = $null
    $kind = 'Unknown'

    if($null -ne $simpleValue) {
        $value = Get-GraphResponseProperty -InputObject $simpleValue -PropertyName 'value'
        $kind = 'Simple'
    } elseif($null -ne $choiceValue) {
        $value = Get-GraphResponseProperty -InputObject $choiceValue -PropertyName 'value'
        $kind = 'Choice'
    } elseif($null -ne $groupCollection) {
        $value = $groupCollection
        $kind = 'GroupCollection'
    } elseif($null -ne $simpleCollection) {
        $value = $simpleCollection
        $kind = 'SimpleCollection'
    } elseif($null -ne $choiceCollection) {
        # Validation is stored this way: a ChoiceSettingCollectionInstance. Value is the raw array
        # of choiceSettingCollectionValue entries; each entry's own 'value' is the selected option.
        $value = $choiceCollection
        $kind = 'ChoiceCollection'
    } elseif($odataType -match 'ChoiceSettingCollectionInstance$') {
        $value = @()
        $kind = 'ChoiceCollection'
    } elseif($odataType -match 'GroupSettingCollectionInstance$') {
        # A group setting collection with zero entries (a target policy with no existing rules
        # yet) is lost on the way through Get-GraphResponseProperty: PowerShell unrolls a
        # function's `return @()` to $null for the caller, so $groupCollection above comes back
        # null exactly when the real value is a genuinely empty array, indistinguishable from the
        # property being absent. The instance's own @odata.type is used here instead, since that
        # survives the round-trip - without this, the elevation rules group could never be found
        # in a policy that had not yet had a first rule created some other way.
        $value = @()
        $kind = 'GroupCollection'
    } elseif($odataType -match 'SimpleSettingCollectionInstance$') {
        $value = @()
        $kind = 'SimpleCollection'
    }

    return [PSCustomObject]@{
        DefinitionId = $definitionId
        OdataType = $odataType
        Kind = $kind
        Value = $value
        Instance = $SettingInstance
    }
}

function Get-EpmGroupChildInstance {
    <#
    .SYNOPSIS
    Flattens the child setting instances of a group setting collection rule entry.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $GroupEntry
    )

    $children = [System.Collections.Generic.List[object]]::new()
    if($null -eq $GroupEntry) {
        return $children
    }

    $childInstances = Get-GraphResponseProperty -InputObject $GroupEntry -PropertyName 'children'
    if($null -eq $childInstances) {
        return $children
    }

    foreach($child in $childInstances) {
        $children.Add($child)
    }

    return $children
}

function Get-EpmChildValueByToken {
    <#
    .SYNOPSIS
    Finds a child setting instance value within a rule by matching the end of its definition id.

    .DESCRIPTION
    EPM setting definition ids are long and template-versioned, but their trailing segment is
    stable (for example "...file_name", "...file_hash", "...elevationtype"). Matching on the
    trailing token keeps the tool resilient to template version changes.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$ChildInstances,

        [Parameter(Mandatory = $true)]
        [string[]]$DefinitionIdTokens
    )

    foreach($child in $ChildInstances) {
        $definitionId = Get-GraphResponseProperty -InputObject $child -PropertyName 'settingDefinitionId'
        if([string]::IsNullOrEmpty($definitionId)) {
            continue
        }

        $loweredId = ([string]$definitionId).ToLowerInvariant()
        foreach($token in $DefinitionIdTokens) {
            if($loweredId.EndsWith($token.ToLowerInvariant())) {
                $resolved = Get-EpmSettingInstanceValue -SettingInstance $child
                return $resolved
            }
        }
    }

    return $null
}

function Get-EpmNestedChildValue {
    <#
    .SYNOPSIS
    Finds a value nested one level inside a choice child of a rule - validation under ruletype,
    certificate type under signaturesource.

    .DESCRIPTION
    A handful of EPM rule fields do not sit as direct children of the rule group entry: validation
    is nested inside the ruletype choice's own children, and certificate type is nested inside the
    signaturesource choice's own children (see New-EpmElevationRuleGroupEntry, which builds this
    same nesting). This walks to the named parent choice first, then applies
    Get-EpmChildValueByToken to that choice's children.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$ChildInstances,

        [Parameter(Mandatory = $true)]
        [string[]]$ParentTokens,

        [Parameter(Mandatory = $true)]
        [string[]]$NestedTokens
    )

    foreach($child in $ChildInstances) {
        $definitionId = Get-GraphResponseProperty -InputObject $child -PropertyName 'settingDefinitionId'
        if([string]::IsNullOrWhiteSpace($definitionId)) {
            continue
        }

        $loweredId = ([string]$definitionId).ToLowerInvariant()
        $isParentMatch = $false
        foreach($token in $ParentTokens) {
            if($loweredId.EndsWith($token.ToLowerInvariant())) {
                $isParentMatch = $true
                break
            }
        }
        if(-not $isParentMatch) {
            continue
        }

        $choiceValue = Get-GraphResponseProperty -InputObject $child -PropertyName 'choiceSettingValue'
        if($null -eq $choiceValue) {
            return $null
        }

        $nestedChildren = @(Get-GraphResponseProperty -InputObject $choiceValue -PropertyName 'children')
        if($nestedChildren.Count -eq 0) {
            return $null
        }

        return (Get-EpmChildValueByToken -ChildInstances $nestedChildren -DefinitionIdTokens $NestedTokens)
    }

    return $null
}

function Find-EpmRuleGroupInstance {
    <#
    .SYNOPSIS
    Locates the rule group setting collection entries within a policy settings array.

    .DESCRIPTION
    Returns the list of group setting collection entries that each represent a single EPM
    elevation rule, together with the parent setting instance that owns them.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Settings
    )

    foreach($settingContainer in $Settings) {
        $settingInstance = Get-GraphResponseProperty -InputObject $settingContainer -PropertyName 'settingInstance'
        if($null -eq $settingInstance) {
            continue
        }

        $resolved = Get-EpmSettingInstanceValue -SettingInstance $settingInstance
        $entryCount = if($resolved.Kind -eq 'GroupCollection' -and $null -ne $resolved.Value) { @($resolved.Value).Count } else { 0 }
        Write-DebugLog -Category 'DEBUG' -Message "Setting instance definitionId='$($resolved.DefinitionId)', kind='$($resolved.Kind)', groupEntries=$entryCount"

        if($resolved.Kind -eq 'GroupCollection' -and $null -ne $resolved.Value) {
            return [PSCustomObject]@{
                ParentContainer = $settingContainer
                ParentInstance = $settingInstance
                GroupEntries = $resolved.Value
            }
        }
    }

    return $null
}

function ConvertFrom-EpmRuleInstance {
    <#
    .SYNOPSIS
    Converts a single EPM rule group entry into a normalized rule object.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $GroupEntry
    )

    $children = Get-EpmGroupChildInstance -GroupEntry $GroupEntry

    $ruleName = Get-EpmChildValueByToken -ChildInstances $children -DefinitionIdTokens @('_rulename', '_displayname', '_name')
    $fileName = Get-EpmChildValueByToken -ChildInstances $children -DefinitionIdTokens @('_filename', '_file_name')
    $filePath = Get-EpmChildValueByToken -ChildInstances $children -DefinitionIdTokens @('_filepath', '_file_path', '_path')
    $fileHash = Get-EpmChildValueByToken -ChildInstances $children -DefinitionIdTokens @('_filehash', '_file_hash', '_hash')
    $elevationType = Get-EpmChildValueByToken -ChildInstances $children -DefinitionIdTokens @('_elevationtype', '_ruletype')
    $internalName = Get-EpmChildValueByToken -ChildInstances $children -DefinitionIdTokens @('_internalname', '_internal_name')
    $childProcessBehavior = Get-EpmChildValueByToken -ChildInstances $children -DefinitionIdTokens @('_childprocessbehavior', '_child_process_behavior')
    $appliesTo = Get-EpmChildValueByToken -ChildInstances $children -DefinitionIdTokens @('_appliesto', '_applies_to')

    # Nested one level down: certificate type lives inside the signaturesource choice, validation
    # lives inside the ruletype choice - neither is a direct child of the rule.
    $certificateType = Get-EpmNestedChildValue -ChildInstances $children -ParentTokens @('_signaturesource', '_signature_source') -NestedTokens @('_certificatetype', '_certificate_type')
    $validationNode = Get-EpmNestedChildValue -ChildInstances $children -ParentTokens @('_elevationtype', '_ruletype') -NestedTokens @('_validation', '_validationtype', '_ruletype_validation')
    $validationValues = @()
    if($null -ne $validationNode -and $validationNode.Kind -eq 'ChoiceCollection') {
        foreach($entry in @($validationNode.Value)) {
            $entryValue = Get-GraphResponseProperty -InputObject $entry -PropertyName 'value'
            if(-not [string]::IsNullOrWhiteSpace($entryValue)) {
                $validationValues += [string]$entryValue
            }
        }
    }

    $reusableRefs = @(Get-EpmReusableReferenceId -Node $GroupEntry | Sort-Object -Unique)

    return [PSCustomObject]@{
        RuleName = if($null -ne $ruleName) { [string]$ruleName.Value } else { $null }
        FileName = if($null -ne $fileName) { [string]$fileName.Value } else { $null }
        FilePath = if($null -ne $filePath) { [string]$filePath.Value } else { $null }
        FileHash = if($null -ne $fileHash) { [string]$fileHash.Value } else { $null }
        ElevationType = if($null -ne $elevationType) { [string]$elevationType.Value } else { $null }
        InternalName = if($null -ne $internalName) { [string]$internalName.Value } else { $null }
        ChildProcessBehavior = if($null -ne $childProcessBehavior) { [string]$childProcessBehavior.Value } else { $null }
        AppliesTo = if($null -ne $appliesTo) { [string]$appliesTo.Value } else { $null }
        CertificateType = if($null -ne $certificateType) { [string]$certificateType.Value } else { $null }
        ValidationValues = $validationValues
        ReusableSettingId = if($reusableRefs.Count -gt 0) { $reusableRefs[0] } else { $null }
        ReusableSettingIds = $reusableRefs
        GroupEntry = $GroupEntry
    }
}

function Get-EpmReusableReferenceId {
    <#
    .SYNOPSIS
    Recursively collects every reusable policy setting id referenced anywhere within a rule.

    .DESCRIPTION
    A rule references a reusable setting through a setting value whose @odata.type is a
    referenceSettingValue; its value carries the reusable policy setting id. In EPM elevation
    rules this reference is nested inside a child group setting collection (for example the
    certificate signature source), so the entire rule tree is walked rather than just the rule's
    top-level children. References can appear in a simpleSettingValue or inside a
    simpleSettingCollectionValue array.
    #>
    [CmdletBinding()]
    [OutputType([System.String[]])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Node
    )

    $found = [System.Collections.Generic.List[string]]::new()
    if($null -eq $Node) {
        return $found.ToArray()
    }

    if($Node -is [System.Collections.IDictionary]) {
        $odataType = Get-GraphResponseProperty -InputObject $Node -PropertyName '@odata.type'
        if($null -ne $odataType -and ([string]$odataType).ToLowerInvariant().Contains('referencesettingvalue')) {
            $refValue = Get-GraphResponseProperty -InputObject $Node -PropertyName 'value'
            if(-not [string]::IsNullOrWhiteSpace($refValue)) {
                $found.Add([string]$refValue)
            }
        }

        foreach($value in $Node.Values) {
            foreach($childRef in (Get-EpmReusableReferenceId -Node $value)) {
                $found.Add($childRef)
            }
        }

        return $found.ToArray()
    }

    if($Node -is [System.Collections.IEnumerable] -and -not ($Node -is [string])) {
        foreach($item in $Node) {
            foreach($childRef in (Get-EpmReusableReferenceId -Node $item)) {
                $found.Add($childRef)
            }
        }

        return $found.ToArray()
    }

    return $found.ToArray()
}

function Get-EpmPolicyRule {
    <#
    .SYNOPSIS
    Retrieves the normalized elevation rules contained in an EPM policy.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyId,

        [Parameter(Mandatory = $false)]
        [string]$PolicyName
    )

    $settings = Get-EpmPolicySetting -PolicyId $PolicyId
    $rules = [System.Collections.Generic.List[object]]::new()

    $ruleContainer = Find-EpmRuleGroupInstance -Settings $settings
    if($null -eq $ruleContainer) {
        Write-DebugLog -Category 'WARN' -Message "No rule group collection found in policy '$PolicyName' ($PolicyId); it has $($settings.Count) setting(s) but none is an EPM elevation rules group collection."
        return $rules
    }

    foreach($groupEntry in $ruleContainer.GroupEntries) {
        $rule = ConvertFrom-EpmRuleInstance -GroupEntry $groupEntry
        $rule | Add-Member -MemberType NoteProperty -Name 'PolicyId' -Value $PolicyId -Force
        $rule | Add-Member -MemberType NoteProperty -Name 'PolicyName' -Value $PolicyName -Force
        $rules.Add($rule)
    }

    Write-DebugLog -Category 'INFO' -Message "Policy '$PolicyName' ($PolicyId) yielded $($rules.Count) elevation rule(s)."
    return $rules
}

function Get-EpmRuleOptionDisplayLookup {
    <#
    .SYNOPSIS
    Builds a raw-choice-value to display-name lookup for one rule setting from a policy's own
    setting definitions - the same source Get-EpmRuleChoiceOption reads for the GUI drop-downs.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$PolicySettings,

        [Parameter(Mandatory = $true)]
        [string[]]$DefinitionIdTokens
    )

    $lookup = @{}
    if($PolicySettings.Count -eq 0) {
        return $lookup
    }

    foreach($option in @(Get-EpmRuleChoiceOption -Settings $PolicySettings -DefinitionIdTokens $DefinitionIdTokens)) {
        if(-not [string]::IsNullOrWhiteSpace($option.Value)) {
            $lookup[[string]$option.Value] = [string]$option.DisplayName
        }
    }
    return $lookup
}

function Get-EpmChoiceDisplayName {
    <#
    .SYNOPSIS
    Resolves a raw settings-catalog choice value to its human-readable display name.

    .DESCRIPTION
    Falls back to the value's own trailing token (for example "..._allowrunelevated" becomes
    "allowrunelevated") when the lookup has no entry, rather than showing a reader the full
    setting-catalog id or leaving the cell blank.
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [string]$RawValue,

        [Parameter(Mandatory = $true)]
        [hashtable]$Lookup
    )

    if([string]::IsNullOrWhiteSpace($RawValue)) {
        return ''
    }
    if($Lookup.ContainsKey($RawValue)) {
        return $Lookup[$RawValue]
    }

    $lastUnderscore = $RawValue.LastIndexOf('_')
    if($lastUnderscore -ge 0 -and $lastUnderscore -lt $RawValue.Length - 1) {
        return $RawValue.Substring($lastUnderscore + 1)
    }
    return $RawValue
}

function ConvertTo-EpmRuleExportRow {
    <#
    .SYNOPSIS
    Flattens one parsed EPM rule into a single documentation-ready row.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSObject])]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Rule,

        [Parameter(Mandatory = $true)]
        [hashtable]$ElevationTypeLookup,

        [Parameter(Mandatory = $true)]
        [hashtable]$ValidationLookup,

        [Parameter(Mandatory = $true)]
        [hashtable]$ChildProcessLookup,

        [Parameter(Mandatory = $true)]
        [hashtable]$CertificateTypeLookup,

        [Parameter(Mandatory = $true)]
        [hashtable]$AppliesToLookup,

        [Parameter(Mandatory = $true)]
        [hashtable]$ReusableSettingNameLookup
    )

    # A rule's match type is not stored as its own field - it is implied by whether a reusable
    # certificate is referenced, the same convention used everywhere else in the tool.
    $matchType = if(-not [string]::IsNullOrWhiteSpace($Rule.ReusableSettingId)) { 'Certificate' } else { 'Hash' }

    $certificateName = ''
    if($matchType -eq 'Certificate' -and -not [string]::IsNullOrWhiteSpace($Rule.ReusableSettingId) -and $ReusableSettingNameLookup.ContainsKey([string]$Rule.ReusableSettingId)) {
        $certificateName = $ReusableSettingNameLookup[[string]$Rule.ReusableSettingId]
    }

    $validationDisplay = (@($Rule.ValidationValues) | ForEach-Object { Get-EpmChoiceDisplayName -RawValue $_ -Lookup $ValidationLookup } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }) -join '; '

    return [PSCustomObject]@{
        PolicyName = $Rule.PolicyName
        RuleName = $Rule.RuleName
        MatchType = $matchType
        ElevationType = Get-EpmChoiceDisplayName -RawValue $Rule.ElevationType -Lookup $ElevationTypeLookup
        Validation = $validationDisplay
        ChildProcessBehavior = Get-EpmChoiceDisplayName -RawValue $Rule.ChildProcessBehavior -Lookup $ChildProcessLookup
        InternalName = $Rule.InternalName
        FileName = $Rule.FileName
        FileHash = $Rule.FileHash
        CertificateName = $certificateName
        CertificateType = Get-EpmChoiceDisplayName -RawValue $Rule.CertificateType -Lookup $CertificateTypeLookup
        AppliesTo = Get-EpmChoiceDisplayName -RawValue $Rule.AppliesTo -Lookup $AppliesToLookup
    }
}

function Get-EpmRuleExportData {
    <#
    .SYNOPSIS
    Flattens a set of parsed EPM rules into documentation-ready rows for the Export Rules tab.

    .DESCRIPTION
    Rules from different policies can reference different setting-definition versions, so the
    value -> display-name lookups (elevation type, validation, child process behavior, certificate
    type, applies to) are built once per distinct policy actually present in the rule set, never
    assumed to be identical across policies. The reusable-certificate-setting id -> display name
    lookup is read once for the whole tenant and shared, since reusable settings are tenant-scoped
    rather than per-policy.

    A policy whose setting definitions cannot be read (a transient Graph error) still contributes
    its rules to the export, with raw setting-catalog values shown instead of display names for
    that policy only, rather than dropping its rules from the export entirely.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [object[]]$Rules
    )

    $rows = [System.Collections.Generic.List[object]]::new()
    if($Rules.Count -eq 0) {
        return $rows
    }

    $reusableNameLookup = @{}
    foreach($setting in @(Get-EpmReusableSetting)) {
        if(-not [string]::IsNullOrWhiteSpace($setting.Id)) {
            $reusableNameLookup[[string]$setting.Id] = [string]$setting.DisplayName
        }
    }

    foreach($policyGroup in ($Rules | Group-Object -Property PolicyId)) {
        $policyId = $policyGroup.Name
        $policySettings = @()
        try {
            $policySettings = @(Get-EpmPolicySetting -PolicyId $policyId)
        } catch {
            $detail = Get-GraphErrorDetail -ErrorRecord $_
            Write-DebugLog -Category 'WARN' -Message "Unable to read setting definitions for policy '$policyId' while building the export; its rules will show raw setting-catalog values instead of display names: $detail"
        }

        $elevationLookup = Get-EpmRuleOptionDisplayLookup -PolicySettings $policySettings -DefinitionIdTokens @('_elevationtype', '_ruletype')
        $validationLookup = Get-EpmRuleOptionDisplayLookup -PolicySettings $policySettings -DefinitionIdTokens @('_validation', '_validationtype')
        $childProcessLookup = Get-EpmRuleOptionDisplayLookup -PolicySettings $policySettings -DefinitionIdTokens @('_childprocessbehavior', '_child_process_behavior')
        $certificateTypeLookup = Get-EpmRuleOptionDisplayLookup -PolicySettings $policySettings -DefinitionIdTokens @('_certificatetype', '_certificate_type')
        $appliesToLookup = Get-EpmRuleOptionDisplayLookup -PolicySettings $policySettings -DefinitionIdTokens @('_appliesto', '_applies_to')

        foreach($rule in $policyGroup.Group) {
            $rows.Add((ConvertTo-EpmRuleExportRow -Rule $rule -ElevationTypeLookup $elevationLookup -ValidationLookup $validationLookup -ChildProcessLookup $childProcessLookup -CertificateTypeLookup $certificateTypeLookup -AppliesToLookup $appliesToLookup -ReusableSettingNameLookup $reusableNameLookup))
        }
    }

    return $rows
}

function Resolve-CsvColumnMap {
    <#
    .SYNOPSIS
    Builds a map of normalized field names to actual CSV header names.

    .DESCRIPTION
    Uses an explicit override map where provided and falls back to auto-detection based on the
    configured candidate header names.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Headers,

        [Parameter(Mandatory = $false)]
        [hashtable]$Override
    )

    $resolved = @{}
    foreach($field in $csvColumnCandidates.Keys) {
        $matchedHeader = $null

        if($null -ne $Override -and $Override.ContainsKey($field)) {
            $candidateHeader = [string]$Override[$field]
            if($Headers -contains $candidateHeader) {
                $matchedHeader = $candidateHeader
            }
        }

        if($null -eq $matchedHeader) {
            foreach($candidate in $csvColumnCandidates[$field]) {
                $headerMatch = $Headers | Where-Object { $_ -and ($_.Trim() -ieq $candidate) } | Select-Object -First 1
                if($null -ne $headerMatch) {
                    $matchedHeader = $headerMatch
                    break
                }
            }
        }

        if($null -ne $matchedHeader) {
            $resolved[$field] = $matchedHeader
        }
    }

    return $resolved
}

function Import-EpmAuditCsv {
    <#
    .SYNOPSIS
    Imports an EPM unmanaged elevations audit CSV and normalizes each row.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path -Path $_ })]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [hashtable]$Override
    )

    $rows = @(Import-Csv -Path $Path -ErrorAction Stop)
    $normalized = [System.Collections.Generic.List[object]]::new()

    if($rows.Count -eq 0) {
        Write-Warning -Message "The CSV file '$Path' contains no rows."
        return $normalized
    }

    $headers = @($rows[0].PSObject.Properties.Name)
    $columnMap = Resolve-CsvColumnMap -Headers $headers -Override $Override

    if(-not $columnMap.ContainsKey('FileName') -and -not $columnMap.ContainsKey('FilePath')) {
        throw "Unable to detect a file name or file path column in '$Path'. Provide a ColumnMap with at least a FileName or FilePath mapping."
    }

    foreach($row in $rows) {
        $record = [ordered]@{}
        foreach($field in $csvColumnCandidates.Keys) {
            if($columnMap.ContainsKey($field)) {
                $value = $row.($columnMap[$field])
                if($null -ne $value) {
                    $value = ([string]$value).Trim()
                }
                $record[$field] = $value
            } else {
                $record[$field] = $null
            }
        }

        # Derive file name from file path when a discrete file name column is absent.
        if([string]::IsNullOrWhiteSpace($record['FileName']) -and -not [string]::IsNullOrWhiteSpace($record['FilePath'])) {
            $record['FileName'] = Split-Path -Path $record['FilePath'] -Leaf
        }

        $normalized.Add([PSCustomObject]$record)
    }

    Write-Verbose -Message "Imported $($normalized.Count) normalized elevation rows from '$Path'."
    return $normalized
}

function ConvertTo-EpmCleanString {
    <#
    .SYNOPSIS
    Normalizes a value from the EPM elevation report into a trimmed string or null.

    .DESCRIPTION
    The elevation report serialises absent values as the four-character literal text "<Null>"
    rather than a JSON null, so an unsigned binary comes back with the publisher set to that
    string. Passed through untouched it would be treated as a real publisher name, and every
    unsigned file would be built as a certificate match against a company called "<Null>".
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowNull()]
        [object]$Value
    )

    if($null -eq $Value) {
        return $null
    }

    $text = ([string]$Value).Trim()
    if($text.Length -eq 0 -or $text -eq '<Null>') {
        return $null
    }

    return $text
}

function Get-EpmElevationReport {
    <#
    .SYNOPSIS
    Reads elevation events straight from the Intune EPM elevation report in Microsoft Graph.

    .DESCRIPTION
    Replicates the request the Intune portal issues when the Endpoint Privilege Management
    elevation report is opened, so the tool can work from live tenant data instead of requiring
    an operator to export a CSV first:

        GET /deviceManagement/privilegeManagementElevations
              ?$top=50
              &$filter=(EventDateTime gt <from> and EventDateTime le <to>)
              &$orderby=eventDateTime desc

    Only the event time range is filtered server-side. That is the only filter the portal itself
    applies on this collection, so it is the only one proven to be accepted; narrowing to
    unmanaged elevations is therefore done client-side rather than guessing at a server-side
    filter that could fail the whole request with a BadRequest.

    Rows are returned in exactly the shape Import-EpmAuditCsv produces - same field names, same
    order - so candidate building, search, coverage analysis and export behave identically no
    matter which source the operator used. One row is returned per elevation EVENT, not per
    distinct binary, because the coverage analysis counts events.

    Intune retains this report for 30 days, which is why the range is capped there.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param(
        [Parameter(Mandatory = $false)]
        [ValidateRange(1, 30)]
        [int]$DayRange = 7,

        [Parameter(Mandatory = $false)]
        [switch]$UnmanagedOnly
    )

    Connect-IntuneGraph

    $toDate = [System.DateTime]::UtcNow
    $fromDate = $toDate.AddDays(-$DayRange)
    $culture = [System.Globalization.CultureInfo]::InvariantCulture
    $fromText = $fromDate.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', $culture)
    $toText = $toDate.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', $culture)

    # The portal encodes only the spaces in this query string and sends the parentheses and colons
    # literally. Building the URI the same way keeps this on a request shape Graph is known to
    # accept, rather than a fully percent-encoded variant that has not been proven against it.
    $filterText = "(EventDateTime gt $fromText and EventDateTime le $toText)".Replace(' ', '%20')
    $uri = "$graphBaseUrl/deviceManagement/privilegeManagementElevations?`$top=50&`$filter=$filterText&`$orderby=eventDateTime%20desc"

    Write-DebugLog -Category 'INFO' -Message "Reading the EPM elevation report for the last $DayRange day(s): $fromText to $toText"

    try {
        $events = @(Invoke-MgGraphGetAllPage -Uri $uri)
    } catch {
        $detail = Get-GraphErrorDetail -ErrorRecord $_
        if($detail -match '(?i)forbidden|unauthorized|authorization|insufficient|privilege') {
            throw ("Microsoft Graph refused to return the EPM elevation report. The signed-in account needs to be able to read Intune configuration data, which the tool requests as 'DeviceManagementConfiguration.ReadWrite.All'. Sign out, sign in again and accept the consent prompt; if it still fails, a Global Administrator or Intune Administrator has to consent for the tenant. Details: $detail")
        }
        throw
    }

    Write-DebugLog -Category 'INFO' -Message "The elevation report returned $($events.Count) event(s)."

    $normalized = [System.Collections.Generic.List[object]]::new()
    $filteredOut = 0

    foreach($item in $events) {
        $elevationType = ConvertTo-EpmCleanString -Value (Get-GraphResponseProperty -InputObject $item -PropertyName 'elevationType')
        if($UnmanagedOnly.IsPresent -and $elevationType -ne 'unmanagedElevation') {
            $filteredOut++
            continue
        }

        $filePath = ConvertTo-EpmCleanString -Value (Get-GraphResponseProperty -InputObject $item -PropertyName 'filePath')
        $fileName = $null
        if(-not [string]::IsNullOrWhiteSpace($filePath)) {
            $fileName = Split-Path -Path $filePath -Leaf
        }

        # companyName is the signing publisher in this report; productName is the product string.
        $fieldValues = @{
            FilePath = $filePath
            FileName = $fileName
            FileHash = ConvertTo-EpmCleanString -Value (Get-GraphResponseProperty -InputObject $item -PropertyName 'hash')
            Publisher = ConvertTo-EpmCleanString -Value (Get-GraphResponseProperty -InputObject $item -PropertyName 'companyName')
            Product = ConvertTo-EpmCleanString -Value (Get-GraphResponseProperty -InputObject $item -PropertyName 'productName')
            InternalName = ConvertTo-EpmCleanString -Value (Get-GraphResponseProperty -InputObject $item -PropertyName 'internalName')
            Description = ConvertTo-EpmCleanString -Value (Get-GraphResponseProperty -InputObject $item -PropertyName 'fileDescription')
            User = ConvertTo-EpmCleanString -Value (Get-GraphResponseProperty -InputObject $item -PropertyName 'upn')
            Device = ConvertTo-EpmCleanString -Value (Get-GraphResponseProperty -InputObject $item -PropertyName 'deviceName')
            ElevationType = $elevationType
        }

        # Built by walking the same field list the CSV path walks, so both sources produce an
        # identical column set in an identical order.
        $record = [ordered]@{}
        foreach($field in $csvColumnCandidates.Keys) {
            if($fieldValues.ContainsKey($field)) {
                $record[$field] = $fieldValues[$field]
            } else {
                $record[$field] = $null
            }
        }

        $normalized.Add([PSCustomObject]$record)
    }

    if($filteredOut -gt 0) {
        Write-DebugLog -Category 'INFO' -Message "Skipped $filteredOut managed elevation(s); only unmanaged elevations were requested."
    }

    Write-Verbose -Message "Read $($normalized.Count) normalized elevation rows from the Intune elevation report."
    return $normalized
}

function Test-EpmToolsAvailable {
    <#
    .SYNOPSIS
    Determines whether the EpmTools Get-FileAttributes cmdlet is available.

    .DESCRIPTION
    The Microsoft EPM Agent ships Get-FileAttributes in the EpmTools module under its install folder
    ("%ProgramFiles%\Microsoft EPM Agent\EpmTools"), which is not on the PowerShell module auto-load
    path. So the command is not visible to Get-Command until the module is imported - which is why a
    device that DOES have EpmTools installed otherwise looks like it does not. This helper first
    checks whether the command is already available, and if not, locates and imports the EpmTools
    module from the EPM Agent folder before deciding. The result is cached for the run.
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param()

    if($null -ne $script:epmToolsAvailable) {
        return $script:epmToolsAvailable
    }

    if($null -ne (Get-Command -Name 'Get-FileAttributes' -ErrorAction SilentlyContinue)) {
        $script:epmToolsProbeMessage = 'EpmTools Get-FileAttributes is available in the current session.'
        $script:epmToolsAvailable = $true
        return $true
    }

    $script:epmToolsProbeMessage = $null

    # Build the candidate EpmTools folders from every Program Files location, de-duplicated.
    $searchRoots = [System.Collections.Generic.List[string]]::new()
    $accessDeniedRoots = [System.Collections.Generic.List[string]]::new()
    foreach($base in @($env:ProgramW6432, $env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if(-not [string]::IsNullOrWhiteSpace($base)) {
            $candidateRoot = Join-Path -Path $base -ChildPath $epmToolsModuleSubPath
            if(-not $searchRoots.Contains($candidateRoot)) {
                $searchRoots.Add($candidateRoot)
            }
        }
    }

    foreach($root in $searchRoots) {
        if(-not (Test-Path -Path $root -PathType Container)) {
            continue
        }

        # Prefer a module manifest, then a script module, then a binary module, so the correct entry
        # point is imported rather than an arbitrary helper file.
        $moduleFile = $null
        foreach($pattern in @('*.psd1', '*.psm1', '*.dll')) {
            try {
                $moduleFile = Get-ChildItem -Path $root -Filter $pattern -File -ErrorAction Stop | Select-Object -First 1
            } catch {
                if($_.Exception -is [System.UnauthorizedAccessException] -or $_.Exception.Message -match '(?i)access.*denied') {
                    if(-not $accessDeniedRoots.Contains($root)) {
                        $accessDeniedRoots.Add($root)
                    }
                    Write-DebugLog -Category 'WARN' -Message "Access denied while probing EpmTools folder '$root'."
                    break
                }
            }
            if($null -ne $moduleFile) {
                break
            }
        }
        if($null -eq $moduleFile) {
            Write-DebugLog -Category 'WARN' -Message "EpmTools folder '$root' exists but contains no importable module."
            continue
        }

        try {
            Import-Module -Name $moduleFile.FullName -DisableNameChecking -ErrorAction Stop
            Write-DebugLog -Category 'INFO' -Message "Imported EpmTools module from '$($moduleFile.FullName)'."
        } catch {
            if($_.Exception -is [System.UnauthorizedAccessException] -or $_.Exception.Message -match '(?i)access.*denied') {
                if(-not $accessDeniedRoots.Contains($root)) {
                    $accessDeniedRoots.Add($root)
                }
            }
            Write-DebugLog -Category 'WARN' -Message "Failed to import EpmTools module from '$($moduleFile.FullName)': $($_.Exception.Message)"
            continue
        }

        if($null -ne (Get-Command -Name 'Get-FileAttributes' -ErrorAction SilentlyContinue)) {
            $script:epmToolsAvailable = $true
            return $true
        }
    }

    if($accessDeniedRoots.Count -gt 0) {
        $rootList = ($accessDeniedRoots | Select-Object -Unique) -join '; '
        if(-not (Test-IsElevated)) {
            $script:epmToolsProbeMessage = "EpmTools appears to be present, but access to '$rootList' was denied in this non-elevated session. Run PowerShell as Administrator and try again."
        } else {
            $script:epmToolsProbeMessage = "EpmTools appears to be present, but access to '$rootList' was denied. Check folder/module ACL permissions and try again."
        }
        Write-DebugLog -Category 'WARN' -Message $script:epmToolsProbeMessage
    } else {
        $script:epmToolsProbeMessage = 'EpmTools Get-FileAttributes cmdlet was not found after probing the EPM Agent folders.'
    }

    Write-DebugLog -Category 'INFO' -Message 'EpmTools Get-FileAttributes cmdlet was not found after probing the EPM Agent folders.'
    $script:epmToolsAvailable = $false
    return $false
}

function Get-EpmToolsCertificateParameterName {
    <#
    .SYNOPSIS
    Resolves the name of the EpmTools Get-FileAttributes certificate-export parameter.

    .DESCRIPTION
    Different EpmTools builds name this parameter differently, so it is resolved from the cmdlet's
    own parameter list rather than assumed. Every caller must pass it: without an explicit
    destination the cmdlet exports certificates into the current working directory. Returns $null
    when no such parameter exists.
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param()

    try {
        $command = Get-Command -Name 'Get-FileAttributes' -ErrorAction Stop
    } catch {
        return $null
    }

    foreach($candidate in @('CertOutputPath', 'CertificateOutputPath', 'CertOutput', 'OutputCertificatePath', 'CertPath')) {
        if($command.Parameters.ContainsKey($candidate)) {
            return $candidate
        }
    }

    return $null
}

function ConvertTo-EpmRuleCandidate {
    <#
    .SYNOPSIS
    Builds a normalized candidate rule object from an imported elevation row.

    .DESCRIPTION
    Determines the recommended match type using a certificate (publisher) match when the file is
    signed and a file hash match otherwise, honoring an explicit MatchType override.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$ElevationRow,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Auto', 'Certificate', 'Hash')]
        [string]$Match = 'Auto'
    )

    $fileName = $ElevationRow.FileName
    $filePath = $ElevationRow.FilePath
    $fileHash = $ElevationRow.FileHash
    $publisher = $ElevationRow.Publisher
    $product = $ElevationRow.Product
    $description = $ElevationRow.Description

    $isSigned = -not [string]::IsNullOrWhiteSpace($publisher)

    $resolvedMatch = switch($Match) {
        'Certificate' { 'Certificate' }
        'Hash' { 'Hash' }
        default {
            if($isSigned) { 'Certificate' } else { 'Hash' }
        }
    }

    if($resolvedMatch -eq 'Certificate' -and -not $isSigned) {
        Write-Warning -Message "Certificate match requested for '$fileName' but no publisher is available; falling back to hash."
        $resolvedMatch = 'Hash'
    }

    $suggestedName = if(-not [string]::IsNullOrWhiteSpace($product)) {
        "$product - $fileName"
    } elseif(-not [string]::IsNullOrWhiteSpace($publisher)) {
        "$publisher - $fileName"
    } else {
        $fileName
    }

    return [PSCustomObject]@{
        RuleName = $suggestedName
        FileName = $fileName
        FilePath = $filePath
        FileHash = $fileHash
        Publisher = $publisher
        Product = $product
        Description = $description
        IsSigned = $isSigned
        MatchType = $resolvedMatch
        ElevationType = 'UserAuthentication'
        SourceUser = $ElevationRow.User
        SourceDevice = $ElevationRow.Device
    }
}

function ConvertTo-SafeFileName {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Name
    )

    $safe = $Name
    foreach($char in [System.IO.Path]::GetInvalidFileNameChars()) {
        $safe = $safe.Replace($char, '_')
    }

    $safe = $safe.Trim()
    if([string]::IsNullOrWhiteSpace($safe)) {
        return 'unknown'
    }

    return $safe
}

function Get-EpmExtractionFolderPath {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath
    )

    $tempRoot = Get-EpmTempWorkingDirectory
    $persistRoot = Join-Path -Path $tempRoot -ChildPath 'ExtractedCertificates'
    if(-not (Test-Path -Path $persistRoot -PathType Container)) {
        New-Item -Path $persistRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    $leaf = Split-Path -Path $FilePath -Leaf
    $safeLeaf = ConvertTo-SafeFileName -Name $leaf
    return (Join-Path -Path $persistRoot -ChildPath $safeLeaf)
}

function Get-EpmExtractedCertificateInfo {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$FilePath
    )

    $folderPath = Get-EpmExtractionFolderPath -FilePath $FilePath
    $certFiles = @()
    if(Test-Path -Path $folderPath -PathType Container) {
        $certFiles = @(Get-ChildItem -Path $folderPath -Filter '*.cer' -File -ErrorAction SilentlyContinue)
    }

    return @{
        FolderPath = $folderPath
        CertificateFiles = @($certFiles)
        HasCertificates = (@($certFiles).Count -gt 0)
    }
}

function Get-CertificateBase64FromDirectory {
    [CmdletBinding()]
    [OutputType([System.String[]])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DirectoryPath
    )

    if(-not (Test-Path -Path $DirectoryPath -PathType Container)) {
        return @()
    }

    $values = [System.Collections.Generic.List[string]]::new()
    $seenThumbprints = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $files = @(Get-ChildItem -Path $DirectoryPath -Filter '*.cer' -File -ErrorAction SilentlyContinue)
    foreach($file in $files) {
        try {
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($file.FullName)
            if($seenThumbprints.Add($cert.Thumbprint)) {
                $values.Add([System.Convert]::ToBase64String($cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)))
            }
        } catch {
            Write-DebugLog -Category 'WARN' -Message "Unable to parse extracted certificate '$($file.FullName)': $($_.Exception.Message)"
        }
    }

    return $values.ToArray()
}

function New-EpmCertificateDetail {
    <#
    .SYNOPSIS
    Describes one extracted certificate for the Scan Path certificate picker.

    .DESCRIPTION
    Produces the single shape used everywhere a chain certificate is offered for selection, so a
    chain read back from disk and one produced by a fresh extraction are interchangeable.

    Role is derived from the position in the chain: element 0 is the binary's signer, the last
    element is the root, and anything between is an intermediate CA. The role matters because it
    decides how broadly a certificate rule will match - the signer covers that one publisher
    certificate, an intermediate covers everything that CA signs.

    SuggestedName is the certificate's ISSUER common name, which is the name an EPM reusable
    certificate setting is normally given.
    #>
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSObject])]
    param(
        [Parameter(Mandatory = $true)]
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$Certificate,

        [Parameter(Mandatory = $false)]
        [int]$Index = 0,

        [Parameter(Mandatory = $false)]
        [int]$ChainLength = 1,

        [Parameter(Mandatory = $false)]
        [string]$FilePath
    )

    $subjectName = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    if([string]::IsNullOrWhiteSpace($subjectName)) {
        $subjectName = $Certificate.Subject
    }

    $issuerName = $Certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $true)
    if([string]::IsNullOrWhiteSpace($issuerName)) {
        $issuerName = $Certificate.Issuer
    }

    $role = if($ChainLength -le 1) {
        'Signer'
    } elseif($Index -eq 0) {
        'Signer'
    } elseif($Index -ge ($ChainLength - 1)) {
        'Root CA'
    } else {
        'Intermediate CA'
    }

    # Self-signed roots list themselves as their own issuer, so naming one after its issuer would
    # just repeat the subject. Fall back to the subject in that case.
    $suggestedName = $issuerName
    if([string]::IsNullOrWhiteSpace($suggestedName) -or $Certificate.Subject -eq $Certificate.Issuer) {
        $suggestedName = $subjectName
    }

    return [PSCustomObject]@{
        Name = $subjectName
        SubjectName = $subjectName
        IssuerName = $issuerName
        SuggestedName = $suggestedName
        Role = $role
        Thumbprint = $Certificate.Thumbprint
        Subject = $Certificate.Subject
        Issuer = $Certificate.Issuer
        NotAfter = $Certificate.NotAfter
        FilePath = $FilePath
        Base64 = [System.Convert]::ToBase64String($Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
        ListLabel = ('{0}: {1}  (issued by {2}, expires {3})' -f $role, $subjectName, $issuerName, $Certificate.NotAfter.ToString('yyyy-MM-dd'))
    }
}

function Get-EpmCertificateDetailsFromDirectory {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DirectoryPath
    )

    $details = [System.Collections.Generic.List[object]]::new()
    if(-not (Test-Path -Path $DirectoryPath -PathType Container)) {
        return $details
    }

    # Files are written by Export-EpmFileCertificate as "01-<name>.cer", "02-..." in chain order, so
    # sorting by name restores signer-first ordering when the chain is read back from disk.
    $seenThumbprints = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $loaded = [System.Collections.Generic.List[object]]::new()
    $files = @(Get-ChildItem -Path $DirectoryPath -Filter '*.cer' -File -ErrorAction SilentlyContinue | Sort-Object -Property Name)
    foreach($file in $files) {
        try {
            $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($file.FullName)
            if(-not $seenThumbprints.Add($cert.Thumbprint)) {
                continue
            }

            $loaded.Add([PSCustomObject]@{ Certificate = $cert; FilePath = $file.FullName })
        } catch {
            Write-DebugLog -Category 'WARN' -Message "Unable to parse extracted certificate '$($file.FullName)': $($_.Exception.Message)"
        }
    }

    for($index = 0; $index -lt $loaded.Count; $index++) {
        $details.Add((New-EpmCertificateDetail -Certificate $loaded[$index].Certificate -Index $index -ChainLength $loaded.Count -FilePath $loaded[$index].FilePath))
    }

    return $details
}

function Get-CertificateInfoFromBase64 {
    [CmdletBinding()]
    [OutputType([System.Management.Automation.PSObject])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Base64Value
    )

    if([string]::IsNullOrWhiteSpace($Base64Value)) {
        return $null
    }

    try {
        $normalizedValue = ($Base64Value -replace '-----BEGIN CERTIFICATE-----', '' -replace '-----END CERTIFICATE-----', '' -replace '\s+', '')
        $bytes = [System.Convert]::FromBase64String($normalizedValue)
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($bytes)

        $simpleName = $cert.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
        if([string]::IsNullOrWhiteSpace($simpleName)) {
            $simpleName = $cert.Subject
        }

        return [PSCustomObject]@{
            Thumbprint = $cert.Thumbprint
            SimpleName = $simpleName
            Subject = $cert.Subject
        }
    } catch {
        return $null
    }
}

function Get-NormalizedCertificateName {
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Name
    )

    if([string]::IsNullOrWhiteSpace($Name)) {
        return ''
    }

    return (($Name.ToLowerInvariant()) -replace '[^a-z0-9]', '')
}

function Get-EpmReusableCertificateValues {
    [CmdletBinding()]
    [OutputType([System.String[]])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Node
    )

    $found = [System.Collections.Generic.List[string]]::new()
    if($null -eq $Node) {
        return $found.ToArray()
    }

    if($Node -is [System.Collections.IDictionary]) {
        if($Node.Contains('simpleSettingValue') -and $Node['simpleSettingValue'] -is [System.Collections.IDictionary]) {
            $simpleValue = $Node['simpleSettingValue']
            if($simpleValue.Contains('value') -and -not [string]::IsNullOrWhiteSpace([string]$simpleValue['value'])) {
                $found.Add([string]$simpleValue['value'])
            }
        }

        foreach($value in @($Node.Values)) {
            foreach($match in (Get-EpmReusableCertificateValues -Node $value)) {
                $found.Add($match)
            }
        }

        return $found.ToArray()
    }

    if($Node -is [System.Management.Automation.PSCustomObject]) {
        $nodeSimpleValue = $Node.PSObject.Properties['simpleSettingValue']
        if($null -ne $nodeSimpleValue -and $null -ne $nodeSimpleValue.Value) {
            $simpleValueValue = $nodeSimpleValue.Value.PSObject.Properties['value']
            if($null -ne $simpleValueValue -and -not [string]::IsNullOrWhiteSpace([string]$simpleValueValue.Value)) {
                $found.Add([string]$simpleValueValue.Value)
            }
        }

        foreach($property in $Node.PSObject.Properties) {
            foreach($match in (Get-EpmReusableCertificateValues -Node $property.Value)) {
                $found.Add($match)
            }
        }
    }

    if($Node -is [System.Collections.IEnumerable] -and -not ($Node -is [string])) {
        foreach($item in $Node) {
            foreach($match in (Get-EpmReusableCertificateValues -Node $item)) {
                $found.Add($match)
            }
        }
    }

    return $found.ToArray()
}

function Find-EpmReusableCertificateMatch {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$CertificateBase64Values
    )

    Connect-IntuneGraph

    $targetThumbprints = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    $targetNameTokens = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach($value in $CertificateBase64Values) {
        $certificateInfo = Get-CertificateInfoFromBase64 -Base64Value $value
        if($null -ne $certificateInfo -and -not [string]::IsNullOrWhiteSpace($certificateInfo.Thumbprint)) {
            $targetThumbprints.Add($certificateInfo.Thumbprint) | Out-Null

            $simpleToken = Get-NormalizedCertificateName -Name $certificateInfo.SimpleName
            if(-not [string]::IsNullOrWhiteSpace($simpleToken)) {
                $targetNameTokens.Add($simpleToken) | Out-Null
            }

            $subjectToken = Get-NormalizedCertificateName -Name $certificateInfo.Subject
            if(-not [string]::IsNullOrWhiteSpace($subjectToken)) {
                $targetNameTokens.Add($subjectToken) | Out-Null
            }
        }
    }

    $certificateMatches = [System.Collections.Generic.List[object]]::new()
    if($targetThumbprints.Count -eq 0) {
        return $certificateMatches
    }

    $reusableSettings = @(Get-EpmReusableSetting)
    foreach($setting in $reusableSettings) {
        try {
            $detail = Invoke-MgGraphRequest -Method GET -Uri "$graphBaseUrl/deviceManagement/reusablePolicySettings('$($setting.Id)')" -ErrorAction Stop
            $values = @(Get-EpmReusableCertificateValues -Node $detail)

            $matchedThumbprints = [System.Collections.Generic.List[string]]::new()
            foreach($candidateValue in $values) {
                $candidateInfo = Get-CertificateInfoFromBase64 -Base64Value $candidateValue
                if($null -ne $candidateInfo -and -not [string]::IsNullOrWhiteSpace($candidateInfo.Thumbprint) -and $targetThumbprints.Contains($candidateInfo.Thumbprint)) {
                    if(-not $matchedThumbprints.Contains($candidateInfo.Thumbprint)) {
                        $matchedThumbprints.Add($candidateInfo.Thumbprint)
                    }
                }
            }

            if($matchedThumbprints.Count -gt 0) {
                $certificateMatches.Add([PSCustomObject]@{
                        ReusableSettingId = $setting.Id
                        DisplayName = $setting.DisplayName
                        MatchingThumbprints = ($matchedThumbprints -join '; ')
                        MatchType = 'Thumbprint'
                        Confidence = 'High'
                    })
                continue
            }

            # Secret values can be unreadable in some tenants. Fall back to display-name matching
            # against the extracted certificate identities to provide likely re-usable candidates.
            $displayToken = Get-NormalizedCertificateName -Name $setting.DisplayName
            if(-not [string]::IsNullOrWhiteSpace($displayToken)) {
                $nameMatched = $false
                foreach($targetToken in $targetNameTokens) {
                    if([string]::IsNullOrWhiteSpace($targetToken)) {
                        continue
                    }

                    if($displayToken.Contains($targetToken) -or $targetToken.Contains($displayToken)) {
                        $nameMatched = $true
                        break
                    }
                }

                if($nameMatched) {
                    $certificateMatches.Add([PSCustomObject]@{
                            ReusableSettingId = $setting.Id
                            DisplayName = $setting.DisplayName
                            MatchingThumbprints = ''
                            MatchType = 'DisplayName'
                            Confidence = 'Medium'
                        })
                }
            }
        } catch {
            Write-DebugLog -Category 'WARN' -Message "Failed to inspect reusable setting '$($setting.Id)' for certificate matches: $($_.Exception.Message)"
        }
    }

    return $certificateMatches
}

function Get-EpmExecutableFromPath {
    <#
    .SYNOPSIS
    Scans a folder for selected file types and returns a rule candidate for each one.

    .DESCRIPTION
    Enumerates files matching the requested extensions under a path (optionally recursively) and,
    for every file, resolves the publisher, file hash, internal name and product.

    Scanning is deliberately read-only: it reads the Authenticode signature, the version resource
    and the SHA256 hash, and writes nothing. It does NOT call the EpmTools Get-FileAttributes
    cmdlet, which exports the signing certificate to disk as a side effect and, when it is not told
    where to put it, drops .cer files into the current working directory - so a plain scan used to
    litter the folder the script was started from. Certificate extraction is its own explicit step
    and writes into the configured temp working directory.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path -Path $_ -PathType Container })]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [string[]]$Extension = @('exe'),

        [Parameter(Mandatory = $false)]
        [switch]$Recurse
    )

    $candidates = [System.Collections.Generic.List[object]]::new()

    # Build a filter list (for example *.exe, *.msi, *.ps1) from the selected extensions.
    $includeFilters = foreach($ext in $Extension) {
        $trimmed = $ext.TrimStart('.').Trim()
        if(-not [string]::IsNullOrWhiteSpace($trimmed)) {
            "*.$trimmed"
        }
    }
    $includeFilters = @($includeFilters)
    if($includeFilters.Count -eq 0) {
        $includeFilters = @('*.exe')
    }

    Write-DebugLog -Category 'INFO' -Message "Scanning '$Path' for [$($includeFilters -join ', ')] (recurse=$($Recurse.IsPresent))."

    # Use -Filter per extension instead of -Include. -Include can be ignored with -LiteralPath and
    # end up returning unrelated file types, which makes the Scan Path results noisy.
    $files = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    $seenFullName = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach($filter in $includeFilters) {
        $matchedFiles = @(Get-ChildItem -LiteralPath $Path -Filter $filter -File -Recurse:$Recurse.IsPresent -ErrorAction SilentlyContinue)
        foreach($matchedFile in $matchedFiles) {
            if($seenFullName.Add($matchedFile.FullName)) {
                $files.Add($matchedFile)
            }
        }
    }

    Write-DebugLog -Category 'INFO' -Message "Found $($files.Count) matching file(s) under '$Path'."

    foreach($file in $files) {
        $publisher = $null
        $fileHash = $null
        $product = $null
        $internalName = $null

        $versionInfo = $null
        try {
            $versionInfo = $file.VersionInfo
        } catch {
            Write-Verbose -Message "Unable to read version info for '$($file.FullName)'."
        }
        if($null -ne $versionInfo) {
            $product = $versionInfo.ProductName
            $internalName = $versionInfo.InternalName
        }

        # A signer certificate is what decides whether a certificate rule is even possible, so it is
        # taken whenever one is present. Status is deliberately not required to be 'Valid': a
        # perfectly signed binary reports NotTrusted or UnknownError on a machine that does not
        # chain to the issuing CA, and treating those as unsigned would hide files that certificate
        # matching handles fine.
        $publisherName = $null
        try {
            $signature = Get-AuthenticodeSignature -LiteralPath $file.FullName -ErrorAction Stop
            if($null -ne $signature -and $null -ne $signature.SignerCertificate) {
                $publisher = $signature.SignerCertificate.Subject

                # The full subject DN is kept for the grid, but the common name is what a human
                # would call the publisher and is the only form fit for a rule name. "CN=Contoso
                # Ltd, O=Contoso, L=Oslo, C=NO - setup.exe" is not a usable rule name.
                $publisherName = $signature.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
                if([string]::IsNullOrWhiteSpace($publisherName)) {
                    $publisherName = $publisher
                }
            }
        } catch {
            Write-Verbose -Message "Authenticode check failed for '$($file.FullName)'."
        }

        try {
            $fileHash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256 -ErrorAction Stop).Hash
        } catch {
            Write-Verbose -Message "Hashing failed for '$($file.FullName)'."
        }

        $isSigned = -not [string]::IsNullOrWhiteSpace($publisher)
        $suggestedMatch = if($isSigned) { 'Certificate' } else { 'Hash' }

        # Suggested rule name: whatever identifies the software to a person, plus the file it
        # applies to. Product name first (that is what the vendor calls it), then the publisher
        # common name, and the bare file name when the binary carries neither.
        $nameQualifier = if(-not [string]::IsNullOrWhiteSpace($product)) {
            $product
        } elseif(-not [string]::IsNullOrWhiteSpace($publisherName)) {
            $publisherName
        } else {
            $null
        }

        $suggestedName = if([string]::IsNullOrWhiteSpace($nameQualifier)) {
            $file.Name
        } else {
            "$nameQualifier - $($file.Name)"
        }

        $extractedInfo = Get-EpmExtractedCertificateInfo -FilePath $file.FullName

        $candidates.Add([PSCustomObject]@{
                RuleName = $suggestedName
                FileName = $file.Name
                FilePath = $file.FullName
                FileHash = $fileHash
                Publisher = $publisher
                PublisherName = $publisherName
                Product = $product
                InternalName = $internalName
                IsSigned = $isSigned
                MatchType = $suggestedMatch
            Extracted = if($extractedInfo.HasCertificates) { 'Yes' } else { 'No' }
            ExtractedFolder = $extractedInfo.FolderPath
            })
    }

    return $candidates
}

function Export-EpmFileCertificate {
    <#
    .SYNOPSIS
    Exports the signing certificate of a binary and returns it as base64 using EpmTools.

    .DESCRIPTION
    Uses the EpmTools Get-FileAttributes cmdlet (the same data source the Intune portal uses) with
    its certificate export parameter to write the signer certificate to a temporary .cer file, then
    reads the file back as a base64 string suitable for an EPM reusable certificate setting. If a
    signed file does not yield a .cer from EpmTools (observed with some MSI packages), the function
    falls back to Authenticode and exports the signer certificate from the signature metadata.
    The temporary file is always removed. EpmTools is required for the primary path.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateScript({ Test-Path -Path $_ -PathType Leaf })]
        [string]$FilePath
    )

    if(-not (Test-EpmToolsAvailable)) {
        $probeDetail = if(-not [string]::IsNullOrWhiteSpace($script:epmToolsProbeMessage)) { $script:epmToolsProbeMessage } else { 'EpmTools Get-FileAttributes is not available in this session.' }
        throw "The EpmTools 'Get-FileAttributes' cmdlet is required to extract a certificate but is not available. $probeDetail"
    }

    # EpmTools Get-FileAttributes writes the signing certificate into the FOLDER passed to its
    # certificate-export parameter (for example "-CertOutputPath C:\temp\EPM\"), naming the file
    # itself. A dedicated temporary directory is used so the produced .cer can be found reliably and
    # removed afterwards, regardless of the name EpmTools chooses.
    $tempRoot = Get-EpmTempWorkingDirectory
    if(-not (Test-Path -Path $tempRoot -PathType Container)) {
        New-Item -Path $tempRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    $certDirectory = Join-Path -Path $tempRoot -ChildPath "epm-cert-$([System.Guid]::NewGuid().ToString('N'))"
    New-Item -Path $certDirectory -ItemType Directory -Force | Out-Null

    try {
        # EpmTools Get-FileAttributes exports the signing certificate to the supplied path. The
        # parameter is resolved dynamically so a tooling version that names it differently still
        # works without changing this code.
        $exportParameterName = Get-EpmToolsCertificateParameterName
        if([string]::IsNullOrWhiteSpace($exportParameterName)) {
            throw 'The installed EpmTools "Get-FileAttributes" cmdlet does not expose a certificate-export parameter, so the signing certificate cannot be written to a file.'
        }

        $invokeArgs = @{
            FilePath = $FilePath
            $exportParameterName = $certDirectory
            ErrorAction = 'Stop'
        }
        $attributes = Get-FileAttributes @invokeArgs

        # Pick up the certificate EpmTools produced in the output folder (newest .cer in case more
        # than one is present).
        $certFile = Get-ChildItem -Path $certDirectory -Filter '*.cer' -File -ErrorAction SilentlyContinue |
            Sort-Object -Property LastWriteTime -Descending |
            Select-Object -First 1

        $certBytes = $null
        if($null -ne $certFile) {
            $certBytes = [System.IO.File]::ReadAllBytes($certFile.FullName)
            if($certBytes.Length -eq 0) {
                $certBytes = $null
                Write-DebugLog -Category 'WARN' -Message "EpmTools exported an empty certificate file for '$FilePath'. Falling back to Authenticode signer certificate."
            }
        } else {
            Write-DebugLog -Category 'WARN' -Message "EpmTools did not produce a certificate file for '$FilePath'. Falling back to Authenticode signer certificate."
        }

        $signature = $null
        if($null -eq $certBytes) {
            try {
                $signature = Get-AuthenticodeSignature -LiteralPath $FilePath -ErrorAction Stop
                if($null -eq $signature.SignerCertificate) {
                    throw 'Authenticode returned no signer certificate.'
                }

                $certBytes = $signature.SignerCertificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
                Write-DebugLog -Category 'INFO' -Message "Used Authenticode fallback certificate export for '$FilePath'."
            } catch {
                throw "EpmTools did not produce a certificate file for '$FilePath', and Authenticode fallback failed: $($_.Exception.Message)"
            }
        }

        if($null -eq $certBytes -or $certBytes.Length -eq 0) {
            throw "No certificate bytes could be extracted for '$FilePath'. The file may be unsigned or inaccessible in this session."
        }

        # Persist the extracted signer certificate and chain in a dedicated folder named after the
        # source file, so repeat extractions for the same file stay grouped and easy to identify.
        $persistRoot = Get-EpmExtractionFolderPath -FilePath $FilePath
        if(-not (Test-Path -Path $persistRoot -PathType Container)) {
            New-Item -Path $persistRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }

        # EpmTools attributes do not include the certificate subject, so resolve the publisher from
        # the Authenticode signature, falling back to a Publisher attribute if a future version adds
        # one.
        $publisher = Get-GraphResponseProperty -InputObject $attributes -PropertyName 'Publisher'
        if([string]::IsNullOrWhiteSpace($publisher)) {
            try {
                if($null -eq $signature) {
                    $signature = Get-AuthenticodeSignature -LiteralPath $FilePath -ErrorAction Stop
                }
                if($null -ne $signature.SignerCertificate) {
                    $publisher = $signature.SignerCertificate.Subject
                }
            } catch {
                Write-DebugLog -Category 'WARN' -Message "Unable to read Authenticode publisher for '$FilePath': $($_.Exception.Message)"
            }
        }

        $certificatesToPersist = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()
        if($null -ne $signature -and $null -ne $signature.SignerCertificate) {
            try {
                $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
                $null = $chain.Build($signature.SignerCertificate)
                foreach($element in $chain.ChainElements) {
                    $certificatesToPersist.Add($element.Certificate)
                }
            } catch {
                Write-DebugLog -Category 'WARN' -Message "Unable to build certificate chain for '$FilePath': $($_.Exception.Message)"
            }
        }

        if($certificatesToPersist.Count -eq 0) {
            # If a chain is unavailable, persist at least the signer certificate bytes.
            $certificatesToPersist.Add([System.Security.Cryptography.X509Certificates.X509Certificate2]::new($certBytes))
        }

        # De-duplicate before writing so the chain index used for the Signer/Intermediate/Root role
        # matches the files actually produced.
        $seenThumbprints = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
        $uniqueCertificates = [System.Collections.Generic.List[System.Security.Cryptography.X509Certificates.X509Certificate2]]::new()
        foreach($certificate in $certificatesToPersist) {
            if($seenThumbprints.Add($certificate.Thumbprint)) {
                $uniqueCertificates.Add($certificate)
            }
        }

        $savedPaths = [System.Collections.Generic.List[string]]::new()
        $chainBase64 = [System.Collections.Generic.List[string]]::new()
        $certificateDetails = [System.Collections.Generic.List[object]]::new()
        $fileIndex = 1
        foreach($certificate in $uniqueCertificates) {
            $friendlyName = $certificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
            if([string]::IsNullOrWhiteSpace($friendlyName)) {
                $friendlyName = $certificate.Subject
            }
            $safeFriendlyName = ConvertTo-SafeFileName -Name $friendlyName

            $leafName = ('{0:D2}-{1}.cer' -f $fileIndex, $safeFriendlyName)
            $targetPath = Join-Path -Path $persistRoot -ChildPath $leafName
            $nameCollisionIndex = 2
            while(Test-Path -Path $targetPath -PathType Leaf) {
                $leafName = ('{0:D2}-{1} ({2}).cer' -f $fileIndex, $safeFriendlyName, $nameCollisionIndex)
                $targetPath = Join-Path -Path $persistRoot -ChildPath $leafName
                $nameCollisionIndex++
            }

            $exportedBytes = $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
            [System.IO.File]::WriteAllBytes($targetPath, $exportedBytes)
            $savedPaths.Add($targetPath)
            $chainBase64.Add([System.Convert]::ToBase64String($exportedBytes))
            $certificateDetails.Add((New-EpmCertificateDetail -Certificate $certificate -Index ($fileIndex - 1) -ChainLength $uniqueCertificates.Count -FilePath $targetPath))
            $fileIndex++
        }

        $primarySavedPath = if($savedPaths.Count -gt 0) { $savedPaths[0] } else { $null }

        return @{
            Base64 = [System.Convert]::ToBase64String($certBytes)
            ChainBase64 = $chainBase64.ToArray()
            ChainCount = $chainBase64.Count
            Publisher = $publisher
            FileName = Split-Path -Path $FilePath -Leaf
            SavedCertificatePath = $primarySavedPath
            SavedCertificatePaths = $savedPaths.ToArray()
            CertificateDetails = @($certificateDetails)
            SavedDirectory = $persistRoot
        }
    } finally {
        if(Test-Path -Path $certDirectory -PathType Container) {
            Remove-Item -Path $certDirectory -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
}

function Get-AllEpmRule {
    <#
    .SYNOPSIS
    Retrieves every elevation rule from every EPM policy in the tenant.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param()

    $allRules = [System.Collections.Generic.List[object]]::new()
    $policies = Get-EpmRulesPolicy

    foreach($policy in $policies) {
        $rules = Get-EpmPolicyRule -PolicyId $policy.Id -PolicyName $policy.Name
        foreach($rule in $rules) {
            $allRules.Add($rule)
        }
    }

    return $allRules
}

function Find-SimilarEpmRule {
    <#
    .SYNOPSIS
    Finds existing EPM rules that match or are similar to a candidate rule.

    .DESCRIPTION
    Compares a candidate rule against a collection of existing rules and classifies each match
    as Exact (same hash, or same file name and publisher) or Partial (same file name only). The
    result identifies the owning policy and rule name so duplicates are easy to locate.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Candidate,

        [Parameter(Mandatory = $true)]
        [object[]]$ExistingRules
    )

    $ruleMatches = [System.Collections.Generic.List[object]]::new()

    foreach($existing in $ExistingRules) {
        $matchType = $null

        $sameHash = (-not [string]::IsNullOrWhiteSpace($Candidate.FileHash)) -and
        (-not [string]::IsNullOrWhiteSpace($existing.FileHash)) -and
        ($Candidate.FileHash -ieq $existing.FileHash)

        $sameFileName = (-not [string]::IsNullOrWhiteSpace($Candidate.FileName)) -and
        (-not [string]::IsNullOrWhiteSpace($existing.FileName)) -and
        ($Candidate.FileName -ieq $existing.FileName)

        if($sameHash) {
            $matchType = 'Exact'
        } elseif($sameFileName) {
            $matchType = 'Partial'
        }

        if($null -ne $matchType) {
            $ruleMatches.Add([PSCustomObject]@{
                    MatchType = $matchType
                    RuleName = $existing.RuleName
                    FileName = $existing.FileName
                    FileHash = $existing.FileHash
                    PolicyName = $existing.PolicyName
                    PolicyId = $existing.PolicyId
                })
        }
    }

    return $ruleMatches
}

function Get-EpmPersonaName {
    <#
    .SYNOPSIS
    Derives a short persona name from an EPM rules policy name.

    .DESCRIPTION
    Persona policies are named like "TEST-User-CMW-EndpointSecurity-ElevationRules-Developer v1.0".
    The persona is the segment after "ElevationRules-" with any trailing version suffix removed
    (for example "Developer", "FieldEngineer", "ITPro", "PowerUser", "StandardUser").
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [string]$PolicyName
    )

    if([string]::IsNullOrWhiteSpace($PolicyName)) {
        return 'Unknown'
    }

    # Strip a trailing version suffix such as " v1.0" or " v2".
    $name = [System.Text.RegularExpressions.Regex]::Replace($PolicyName, '\s+v\d+(\.\d+)*\s*$', '')

    $match = [System.Text.RegularExpressions.Regex]::Match($name, '(?i)elevationrules[-_ ]+(.+)$')
    if($match.Success) {
        return $match.Groups[1].Value.Trim()
    }

    $parts = $name -split '-'
    return $parts[-1].Trim()
}

function Test-EpmRuleCovers {
    <#
    .SYNOPSIS
    Determines whether an existing EPM rule covers a candidate elevation.

    .DESCRIPTION
    Returns 'Exact' when the file hash matches, 'Partial' when only the file name matches, or
    $null when the rule does not cover the candidate. This is the same matching logic used by the
    duplicate finder, expressed as a single per-pair test for the coverage analysis.
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Candidate,

        [Parameter(Mandatory = $true)]
        [PSObject]$ExistingRule
    )

    $sameHash = (-not [string]::IsNullOrWhiteSpace($Candidate.FileHash)) -and
    (-not [string]::IsNullOrWhiteSpace($ExistingRule.FileHash)) -and
    ($Candidate.FileHash -ieq $ExistingRule.FileHash)

    if($sameHash) {
        return 'Exact'
    }

    $sameFileName = (-not [string]::IsNullOrWhiteSpace($Candidate.FileName)) -and
    (-not [string]::IsNullOrWhiteSpace($ExistingRule.FileName)) -and
    ($Candidate.FileName -ieq $ExistingRule.FileName)

    if($sameFileName) {
        return 'Partial'
    }

    return $null
}

function Get-EpmCoverageColor {
    <#
    .SYNOPSIS
    Maps a coverage or confidence percentage to a hex colour used by the GUI cards and badges.

    .DESCRIPTION
    Returns a green/amber/red/grey hex colour so the coverage analysis can show match strength at
    a glance. The thresholds match the confidence bands used by the per-user recommendation:
    60% or more is strong (green), 30-59% is moderate (amber), 1-29% is weak (red) and 0% is grey.
    #>
    [CmdletBinding()]
    [OutputType([System.String])]
    param(
        [Parameter(Mandatory = $true)]
        [double]$Percent
    )

    if($Percent -ge 60) {
        return '#16a34a'
    }
    if($Percent -ge 30) {
        return '#d97706'
    }
    if($Percent -gt 0) {
        return '#dc2626'
    }
    return '#9ca3af'
}

function Get-EpmCoverageReport {
    <#
    .SYNOPSIS
    Scores how many imported unmanaged elevations are already covered by existing EPM persona rules.

    .DESCRIPTION
    Compares each imported candidate elevation against every existing EPM rule across all persona
    policies. It reports an overall coverage score, a per-persona breakdown (how many of the
    imported elevations each persona already covers), and a per-user recommendation of which
    persona a user best matches.

    The per-user recommendation uses a weighted scoring model rather than a raw covered count, so a
    persona with many broad rules no longer wins for every user by default:
      - Each of a user's elevations contributes to a persona score when that persona has a rule that
        covers it. An exact match (file hash) is worth 3 points; a partial match (file name only)
        is worth 1 point. The strongest match per persona is counted once per elevation.
      - The recommended persona is the one with the highest weighted score for that user, with ties
        broken by the number of distinct elevations covered and then by the more specific persona
        (fewer existing rules).
      - A confidence band is derived from the share of the user's elevations the recommended persona
        covers (the coverage ratio): High (>= 60%), Medium (>= 30%), Low (> 0%) or None (0%). A Low
        confidence result flags users whose elevations are not well represented by any existing
        persona and likely need a new or tailored persona.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Candidates,

        [Parameter(Mandatory = $true)]
        [object[]]$ExistingRules
    )

    # Build the list of personas from the policies represented in the existing rules.
    $personaByPolicyId = @{}
    foreach($rule in $ExistingRules) {
        $policyId = [string]$rule.PolicyId
        if([string]::IsNullOrWhiteSpace($policyId) -or $personaByPolicyId.ContainsKey($policyId)) {
            continue
        }
        $personaByPolicyId[$policyId] = [PSCustomObject]@{
            PolicyId = $policyId
            PolicyName = $rule.PolicyName
            Persona = Get-EpmPersonaName -PolicyName $rule.PolicyName
            RuleCount = 0
        }
    }
    foreach($rule in $ExistingRules) {
        $policyId = [string]$rule.PolicyId
        if($personaByPolicyId.ContainsKey($policyId)) {
            $personaByPolicyId[$policyId].RuleCount++
        }
    }

    # Per-candidate coverage: which policies cover it and with what match strength.
    $candidateDetails = [System.Collections.Generic.List[object]]::new()
    $uncoveredCandidates = [System.Collections.Generic.List[object]]::new()
    $coveredCountByPolicy = @{}
    $coveredCandidateCount = 0

    foreach($candidate in $Candidates) {
        $coveringPolicyIds = [System.Collections.Generic.List[string]]::new()
        $coveringPersonas = [System.Collections.Generic.List[string]]::new()
        $bestMatch = $null

        foreach($rule in $ExistingRules) {
            $coverage = Test-EpmRuleCovers -Candidate $candidate -ExistingRule $rule
            if($null -eq $coverage) {
                continue
            }

            $policyId = [string]$rule.PolicyId
            if(-not $coveringPolicyIds.Contains($policyId)) {
                $coveringPolicyIds.Add($policyId)
                if($personaByPolicyId.ContainsKey($policyId)) {
                    $coveringPersonas.Add($personaByPolicyId[$policyId].Persona)
                }
            }
            if($coverage -eq 'Exact' -or $null -eq $bestMatch) {
                $bestMatch = $coverage
            }
        }

        $isCovered = $coveringPolicyIds.Count -gt 0
        if($isCovered) {
            $coveredCandidateCount++
            foreach($policyId in $coveringPolicyIds) {
                if(-not $coveredCountByPolicy.ContainsKey($policyId)) {
                    $coveredCountByPolicy[$policyId] = 0
                }
                $coveredCountByPolicy[$policyId]++
            }
        } else {
            $uncoveredCandidates.Add($candidate)
        }

        $candidateDetails.Add([PSCustomObject]@{
                RuleName = $candidate.RuleName
                FileName = $candidate.FileName
                User = $candidate.SourceUser
                Covered = if($isCovered) { 'Yes' } else { 'No' }
                MatchType = if($null -ne $bestMatch) { $bestMatch } else { '' }
                CoveredByPersonas = ($coveringPersonas | Sort-Object -Unique) -join ', '
            })
    }

    $totalCandidates = @($Candidates).Count
    $overallPct = if($totalCandidates -gt 0) { [math]::Round(($coveredCandidateCount / $totalCandidates) * 100, 1) } else { 0 }

    # Per-user recommendation: for each user, score every persona by how well its rules match the
    # user's elevations (exact hash match = 3 points, partial file-name match = 1 point) and
    # recommend the highest-scoring persona, with a confidence band derived from the coverage ratio.
    $userRecommendations = [System.Collections.Generic.List[object]]::new()
    $candidatesByUser = @{}
    foreach($candidate in $Candidates) {
        $user = if([string]::IsNullOrWhiteSpace($candidate.SourceUser)) { 'Unknown' } else { [string]$candidate.SourceUser }
        if(-not $candidatesByUser.ContainsKey($user)) {
            $candidatesByUser[$user] = [System.Collections.Generic.List[object]]::new()
        }
        $candidatesByUser[$user].Add($candidate)
    }

    foreach($user in $candidatesByUser.Keys) {
        $userCandidates = $candidatesByUser[$user]
        $userElevationCount = $userCandidates.Count
        $scorePerPolicy = @{}
        $distinctPerPolicy = @{}
        $userCoveredByAny = 0

        foreach($candidate in $userCandidates) {
            # Keep only the strongest match per persona for this single elevation so an elevation
            # is never double-counted when a persona has several rules that all match it.
            $bestCoveragePerPolicy = @{}
            foreach($rule in $ExistingRules) {
                $coverage = Test-EpmRuleCovers -Candidate $candidate -ExistingRule $rule
                if($null -eq $coverage) {
                    continue
                }
                $policyId = [string]$rule.PolicyId
                if((-not $bestCoveragePerPolicy.ContainsKey($policyId)) -or ($coverage -eq 'Exact')) {
                    $bestCoveragePerPolicy[$policyId] = $coverage
                }
            }

            if($bestCoveragePerPolicy.Count -gt 0) {
                $userCoveredByAny++
            }
            foreach($policyId in $bestCoveragePerPolicy.Keys) {
                $weight = if($bestCoveragePerPolicy[$policyId] -eq 'Exact') { 3 } else { 1 }
                if(-not $scorePerPolicy.ContainsKey($policyId)) {
                    $scorePerPolicy[$policyId] = 0
                    $distinctPerPolicy[$policyId] = 0
                }
                $scorePerPolicy[$policyId] += $weight
                $distinctPerPolicy[$policyId]++
            }
        }

        # Highest weighted score wins; break ties on distinct elevations covered, then on the more
        # specific persona (the one defined by fewer rules).
        $bestPolicyId = $null
        $bestScore = 0
        $bestDistinct = 0
        foreach($policyId in $scorePerPolicy.Keys) {
            $score = $scorePerPolicy[$policyId]
            $distinct = $distinctPerPolicy[$policyId]
            $isBetter = $false
            if($score -gt $bestScore) {
                $isBetter = $true
            }
            elseif($score -eq $bestScore -and $distinct -gt $bestDistinct) {
                $isBetter = $true
            }
            elseif($score -eq $bestScore -and $distinct -eq $bestDistinct -and $null -ne $bestPolicyId) {
                if($personaByPolicyId[$policyId].RuleCount -lt $personaByPolicyId[$bestPolicyId].RuleCount) {
                    $isBetter = $true
                }
            }
            if($isBetter) {
                $bestScore = $score
                $bestDistinct = $distinct
                $bestPolicyId = $policyId
            }
        }

        $coverageRatio = if($userElevationCount -gt 0) { [math]::Round(($bestDistinct / $userElevationCount) * 100, 1) } else { 0 }

        $confidence = 'None'
        if($coverageRatio -ge 60) {
            $confidence = 'High'
        }
        elseif($coverageRatio -ge 30) {
            $confidence = 'Medium'
        }
        elseif($coverageRatio -gt 0) {
            $confidence = 'Low'
        }

        $recommendedPersona = 'None - no existing persona covers these elevations'
        $recommendedPolicy = ''
        if($null -ne $bestPolicyId -and $personaByPolicyId.ContainsKey($bestPolicyId)) {
            $recommendedPersona = $personaByPolicyId[$bestPolicyId].Persona
            $recommendedPolicy = $personaByPolicyId[$bestPolicyId].PolicyName
        }

        $recommendation = switch($confidence) {
            'High' { "Strong match - $bestDistinct of $userElevationCount elevations ($coverageRatio%) covered" }
            'Medium' { "Moderate match - $bestDistinct of $userElevationCount elevations ($coverageRatio%) covered" }
            'Low' { "Weak match - only $bestDistinct of $userElevationCount elevations ($coverageRatio%) covered; consider a tailored persona" }
            default { 'No persona match - needs a new persona' }
        }

        $userRecommendations.Add([PSCustomObject]@{
                User = $user
                Elevations = $userElevationCount
                CoveredByExisting = $userCoveredByAny
                RecommendedPersona = $recommendedPersona
                CoveredByRecommended = $bestDistinct
                CoveragePercent = $coverageRatio
                Confidence = $confidence
                ConfidenceColor = Get-EpmCoverageColor -Percent $coverageRatio
                Recommendation = $recommendation
                RecommendedPolicy = $recommendedPolicy
            })
    }
    $userRecommendations = @($userRecommendations | Sort-Object -Property Elevations -Descending)

    # Overall quality score for the recommendation model: among elevations assigned to a persona,
    # how many are covered by that recommended persona.
    $assignedElevationsTotal = 0
    $assignedCoveredTotal = 0
    foreach($row in $userRecommendations) {
        if([string]::IsNullOrWhiteSpace([string]$row.RecommendedPolicy)) {
            continue
        }

        $assignedElevationsTotal += [int]$row.Elevations
        $assignedCoveredTotal += [int]$row.CoveredByRecommended
    }
    $overallPersonaCoveragePercent = if($assignedElevationsTotal -gt 0) {
        [math]::Round(($assignedCoveredTotal / $assignedElevationsTotal) * 100, 1)
    } else {
        0
    }

    # Per-persona summary rows aligned with the recommendation model: each user's covered
    # elevations are attributed only to that user's recommended persona/policy.
    $coveredByRecommendedPolicy = @{}
    $assignedByRecommendedPolicy = @{}
    foreach($row in $userRecommendations) {
        $policyName = [string]$row.RecommendedPolicy
        if([string]::IsNullOrWhiteSpace($policyName)) {
            continue
        }

        $policy = $personaByPolicyId.Values | Where-Object { [string]$_.PolicyName -eq $policyName } | Select-Object -First 1
        if($null -eq $policy) {
            continue
        }

        $policyId = [string]$policy.PolicyId
        if(-not $coveredByRecommendedPolicy.ContainsKey($policyId)) {
            $coveredByRecommendedPolicy[$policyId] = 0
        }
        if(-not $assignedByRecommendedPolicy.ContainsKey($policyId)) {
            $assignedByRecommendedPolicy[$policyId] = 0
        }

        $coveredByRecommendedPolicy[$policyId] += [int]$row.CoveredByRecommended
        $assignedByRecommendedPolicy[$policyId] += [int]$row.Elevations
    }

    $personaSummary = [System.Collections.Generic.List[object]]::new()
    foreach($policyId in $personaByPolicyId.Keys) {
        $persona = $personaByPolicyId[$policyId]
        $covered = if($coveredByRecommendedPolicy.ContainsKey($policyId)) { $coveredByRecommendedPolicy[$policyId] } else { 0 }
        $assigned = if($assignedByRecommendedPolicy.ContainsKey($policyId)) { $assignedByRecommendedPolicy[$policyId] } else { 0 }
        $allPct = if($totalCandidates -gt 0) { [math]::Round(($covered / $totalCandidates) * 100, 1) } else { 0 }
        $personaPct = if($assigned -gt 0) { [math]::Round(($covered / $assigned) * 100, 1) } else { 0 }
        $personaSummary.Add([PSCustomObject]@{
                Persona = $persona.Persona
                PolicyName = $persona.PolicyName
                ExistingRules = $persona.RuleCount
                ElevationsCovered = $covered
                GlobalSharePercent = $allPct
                GlobalShareColor = Get-EpmCoverageColor -Percent $allPct
                AssignedElevations = $assigned
                PersonaCoveragePercent = $personaPct
                PersonaCoverageColor = Get-EpmCoverageColor -Percent $personaPct
            })
    }
    $personaSummary = @($personaSummary | Sort-Object -Property ElevationsCovered -Descending)

    # Uncovered elevations grouped by file (and publisher) so the user can see, at a glance, which
    # applications are not yet represented by any existing persona rule and how widespread each is.
    $uncoveredGroups = @{}
    foreach($candidate in $uncoveredCandidates) {
        $fileName = if([string]::IsNullOrWhiteSpace($candidate.FileName)) { '(unknown)' } else { [string]$candidate.FileName }
        $publisher = if([string]::IsNullOrWhiteSpace($candidate.Publisher)) { '' } else { [string]$candidate.Publisher }
        $groupKey = "$($fileName.ToLowerInvariant())|$($publisher.ToLowerInvariant())"
        if(-not $uncoveredGroups.ContainsKey($groupKey)) {
            $uncoveredGroups[$groupKey] = [PSCustomObject]@{
                FileName = $fileName
                Publisher = $publisher
                Product = if([string]::IsNullOrWhiteSpace($candidate.Product)) { '' } else { [string]$candidate.Product }
                MatchType = if([string]::IsNullOrWhiteSpace($candidate.MatchType)) { '' } else { [string]$candidate.MatchType }
                SampleHash = if([string]::IsNullOrWhiteSpace($candidate.FileHash)) { '' } else { [string]$candidate.FileHash }
                Occurrences = 0
                Users = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
                Devices = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
            }
        }
        $group = $uncoveredGroups[$groupKey]
        $group.Occurrences++
        if(-not [string]::IsNullOrWhiteSpace($candidate.SourceUser)) { [void]$group.Users.Add([string]$candidate.SourceUser) }
        if(-not [string]::IsNullOrWhiteSpace($candidate.SourceDevice)) { [void]$group.Devices.Add([string]$candidate.SourceDevice) }
        if([string]::IsNullOrWhiteSpace($group.Product) -and -not [string]::IsNullOrWhiteSpace($candidate.Product)) { $group.Product = [string]$candidate.Product }
        if([string]::IsNullOrWhiteSpace($group.SampleHash) -and -not [string]::IsNullOrWhiteSpace($candidate.FileHash)) { $group.SampleHash = [string]$candidate.FileHash }
    }

    $uncoveredSummary = [System.Collections.Generic.List[object]]::new()
    foreach($group in $uncoveredGroups.Values) {
        $uncoveredSummary.Add([PSCustomObject]@{
                FileName = $group.FileName
                Publisher = $group.Publisher
                Product = $group.Product
                SuggestedMatch = if([string]::IsNullOrWhiteSpace($group.Publisher)) { 'Hash' } else { 'Certificate' }
                Occurrences = $group.Occurrences
                DistinctUsers = $group.Users.Count
                DistinctDevices = $group.Devices.Count
                SampleHash = $group.SampleHash
            })
    }
    $uncoveredSummary = @($uncoveredSummary | Sort-Object -Property Occurrences -Descending)

    # Flat per-elevation list of everything not covered, suitable for CSV export.
    $uncoveredDetails = [System.Collections.Generic.List[object]]::new()
    foreach($candidate in $uncoveredCandidates) {
        $uncoveredDetails.Add([PSCustomObject]@{
                FileName = $candidate.FileName
                Publisher = $candidate.Publisher
                Product = $candidate.Product
                FileHash = $candidate.FileHash
                MatchType = $candidate.MatchType
                User = $candidate.SourceUser
                Device = $candidate.SourceDevice
                RuleName = $candidate.RuleName
            })
    }

    return @{
        TotalElevations = $totalCandidates
        CoveredElevations = $coveredCandidateCount
        UncoveredElevations = $uncoveredCandidates.Count
        OverallCoveragePercent = $overallPct
        OverallPersonaCoveragePercent = $overallPersonaCoveragePercent
        OverallPersonaCoveredElevations = $assignedCoveredTotal
        OverallPersonaAssignedElevations = $assignedElevationsTotal
        PersonaSummary = $personaSummary
        UserRecommendations = $userRecommendations
        CandidateDetails = @($candidateDetails)
        UncoveredSummary = @($uncoveredSummary)
        UncoveredDetails = @($uncoveredDetails)
    }
}

function Test-EpmRuleBestPractice {
    <#
    .SYNOPSIS
    Evaluates a candidate rule against EPM rule authoring best practices.

    .DESCRIPTION
    Returns a list of findings, each with a severity and message, covering certificate vs hash
    matching, overly broad file paths, least-privilege elevation types and naming conventions.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param(
        [Parameter(Mandatory = $true)]
        [PSObject]$Candidate
    )

    $findings = [System.Collections.Generic.List[object]]::new()

    if($Candidate.MatchType -eq 'Hash') {
        if($Candidate.IsSigned) {
            $findings.Add([PSCustomObject]@{
                    Severity = 'Warning'
                    Message = 'File is signed but a hash match was selected. A certificate (publisher) match is more resilient to application updates.'
                })
        } else {
            $findings.Add([PSCustomObject]@{
                    Severity = 'Info'
                    Message = 'File is unsigned, so a hash match is appropriate. The rule will need updating whenever the binary changes.'
                })
        }
    }

    if(-not [string]::IsNullOrWhiteSpace($Candidate.FilePath)) {
        if($Candidate.FilePath -match '\*' -or $Candidate.FilePath -match '%\w+%') {
            $findings.Add([PSCustomObject]@{
                    Severity = 'Warning'
                    Message = 'File path contains a wildcard or environment variable. Broad paths increase risk; scope the path as narrowly as possible.'
                })
        }

        if($Candidate.FilePath -match '(?i)\\(Users|Temp|Downloads|AppData\\Local\\Temp)\\') {
            $findings.Add([PSCustomObject]@{
                    Severity = 'Warning'
                    Message = 'File path is in a user-writable location. Prefer requiring a certificate match for binaries that run from user-writable paths.'
                })
        }
    }

    if($Candidate.ElevationType -match '(?i)automatic') {
        $findings.Add([PSCustomObject]@{
                Severity = 'Warning'
                Message = 'Automatic elevation grants elevation silently. Prefer user-confirmed elevation (with justification or authentication) unless silent elevation is explicitly required.'
            })
    }

    if([string]::IsNullOrWhiteSpace($Candidate.RuleName) -or $Candidate.RuleName.Length -lt 3) {
        $findings.Add([PSCustomObject]@{
                Severity = 'Warning'
                Message = 'Rule name is missing or very short. Use a descriptive name (for example "Publisher - Application - FileName") for easier identification.'
            })
    }

    if($findings.Count -eq 0) {
        $findings.Add([PSCustomObject]@{
                Severity = 'Info'
                Message = 'No best-practice concerns detected for this rule.'
            })
    }

    return $findings
}

function Get-EpmReusableSetting {
    <#
    .SYNOPSIS
    Retrieves the EPM reusable policy settings from Intune.

    .DESCRIPTION
    The reusablePolicySettings endpoint returns reusable settings for every settings-catalog
    technology (EPM, device control, and others). This function uses the same server-side filter
    as the Intune portal (settingDefinitionId eq the EPM certificate reusable setting definition
    id) so only EPM reusable settings are returned.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param()

    Connect-IntuneGraph

    # Filter and project exactly like the Intune portal does. Including 'description' in $select
    # makes the DeviceConfigV2 backend return InternalServerError, so the portal omits it and
    # selects id, displayName, referencingConfigurationPolicyCount and lastModifiedDateTime, ordered
    # by displayName. The description is read per-setting only when needed.
    $filter = [System.Uri]::EscapeDataString("settingDefinitionId eq '$epmReusableSettingDefinitionId'")
    $select = [System.Uri]::EscapeDataString('id,displayName,referencingConfigurationPolicyCount,lastModifiedDateTime')
    $orderBy = [System.Uri]::EscapeDataString('displayName asc')
    $uri = "$graphBaseUrl/deviceManagement/reusablePolicySettings?`$filter=$filter&`$select=$select&`$orderby=$orderBy&`$top=50"
    $settings = Invoke-MgGraphGetAllPage -Uri $uri
    Write-DebugLog -Category 'INFO' -Message "reusablePolicySettings (EPM filter) returned $($settings.Count) reusable setting(s)."

    $result = [System.Collections.Generic.List[object]]::new()
    foreach($setting in $settings) {
        $id = Get-GraphResponseProperty -InputObject $setting -PropertyName 'id'
        $displayName = Get-GraphResponseProperty -InputObject $setting -PropertyName 'displayName'
        $referencingCount = Get-GraphResponseProperty -InputObject $setting -PropertyName 'referencingConfigurationPolicyCount'

        if([string]::IsNullOrWhiteSpace($id)) {
            continue
        }

        $result.Add([PSCustomObject]@{
                Id = $id
                DisplayName = $displayName
                Description = $null
                ReferencingConfigurationPolicyCount = $referencingCount
                ListLabel = "$displayName ($id)"
            })
    }

    Write-DebugLog -Category 'INFO' -Message "Kept $($result.Count) EPM reusable setting(s)."
    return ($result | Sort-Object -Property DisplayName)
}

function Get-EpmReusableSettingUsage {
    <#
    .SYNOPSIS
    Lists the policies and rules that reference a specific EPM reusable setting.

    .DESCRIPTION
    Reads every EPM elevation rules policy and inspects each rule's child setting instances for a
    reference to the reusable setting id. This identifies usage by rule name and policy without
    depending on the reusablePolicySettings referencing-policies expand, which is not reliable on
    all tenants.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$ReusableSettingId
    )

    Connect-IntuneGraph

    $usage = [System.Collections.Generic.List[object]]::new()

    Write-DebugLog -Category 'INFO' -Message "Resolving usage for reusable setting '$ReusableSettingId'."

    # Resolve the reusable setting's friendly name for the report. This is a simple GET with no
    # expand, so it works even where the referencing-policies navigation property does not.
    $reusableName = $null
    try {
        $reusable = Invoke-MgGraphRequest -Method GET -Uri "$graphBaseUrl/deviceManagement/reusablePolicySettings('$ReusableSettingId')?`$select=id,displayName" -ErrorAction Stop
        $reusableName = Get-GraphResponseProperty -InputObject $reusable -PropertyName 'displayName'
    } catch {
        $detail = Get-GraphErrorDetail -ErrorRecord $_
        Write-DebugLog -Category 'WARN' -Message "Unable to resolve reusable setting name for '$ReusableSettingId': $detail"
    }

    $policies = Get-EpmRulesPolicy
    Write-DebugLog -Category 'INFO' -Message "Scanning $($policies.Count) EPM rules policy(ies) for references to reusable setting '$ReusableSettingId'."
    foreach($policy in $policies) {
        $policyId = $policy.Id
        $policyName = $policy.Name
        if([string]::IsNullOrWhiteSpace($policyId)) {
            continue
        }

        try {
            $rules = Get-EpmPolicyRule -PolicyId $policyId -PolicyName $policyName
            foreach($rule in $rules) {
                $ruleRefs = @($rule.ReusableSettingIds)
                if($ruleRefs.Count -gt 0) {
                    Write-DebugLog -Category 'DEBUG' -Message "Rule '$($rule.RuleName)' in policy '$policyName' references reusable setting(s): $($ruleRefs -join ', ')"
                }

                if($ruleRefs -contains $ReusableSettingId) {
                    Write-DebugLog -Category 'INFO' -Message "Match: rule '$($rule.RuleName)' in policy '$policyName' references reusable setting '$ReusableSettingId'."
                    $usage.Add([PSCustomObject]@{
                            ReusableSettingName = $reusableName
                            ReusableSettingId = $ReusableSettingId
                            PolicyName = $policyName
                            PolicyId = $policyId
                            RuleName = $rule.RuleName
                        })
                }
            }
        } catch {
            $detail = Get-GraphErrorDetail -ErrorRecord $_
            Write-DebugLog -Category 'ERROR' -Message "Unable to enumerate rules for policy '$policyId': $detail"
        }
    }

    Write-DebugLog -Category 'INFO' -Message "Reusable setting usage scan complete: $($usage.Count) referencing rule(s) found."
    return $usage
}

function New-EpmReusableCertificateSetting {
    <#
    .SYNOPSIS
    Creates an EPM reusable certificate setting from a base64-encoded certificate.

    .DESCRIPTION
    Builds the reusablePolicySettings entity for the EPM certificate file setting definition and
    POSTs it to Microsoft Graph so the certificate can be referenced by EPM elevation rules.

    The body is the one the Intune portal itself sends, captured from a portal HAR. Two details in
    it are load-bearing and were previously wrong, which is why uploads failed:

      - The certificate is a deviceManagementConfigurationStringSettingValue, NOT a
        SecretSettingValue. Sending it as a secret (with a valueState) is rejected.
      - settingDefinitionId is required at the top level of the entity as well as on the setting
        instance, and the entity needs its own @odata.type.

    An earlier version tried to clone an existing reusable setting to stay aligned with the
    tenant's template version. That is what produced the secret-value shape: reading a stored
    certificate back returns it as a secret value, so the clone carried a type that cannot be
    written. The body is now constructed outright, which is both correct and works when the tenant
    has no reusable setting to copy. Honors -WhatIf via SupportsShouldProcess.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.Collections.Hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$DisplayName,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$CertificateBase64,

        [Parameter(Mandatory = $false)]
        [string]$Description
    )

    Connect-IntuneGraph

    # The certificate must be raw DER base64 (what an X509Certificate2 export produces), not PEM.
    # Strip PEM armour and whitespace if a caller passes an armoured value, then prove it parses -
    # a malformed value is accepted by Graph and only fails later when a rule references it.
    $normalizedCertificate = ($CertificateBase64 -replace '-----BEGIN CERTIFICATE-----', '' -replace '-----END CERTIFICATE-----', '' -replace '\s+', '')
    try {
        $probe = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new([System.Convert]::FromBase64String($normalizedCertificate))
        Write-DebugLog -Category 'INFO' -Message "Uploading reusable certificate '$DisplayName' (subject '$($probe.Subject)', thumbprint $($probe.Thumbprint))."
    } catch {
        throw "The supplied certificate value is not a valid base64-encoded certificate: $($_.Exception.Message)"
    }

    $body = [ordered]@{
        displayName = $DisplayName
        description = if($PSBoundParameters.ContainsKey('Description') -and $null -ne $Description) { $Description } else { '' }
        settingDefinitionId = $epmReusableSettingDefinitionId
        settingInstance = [ordered]@{
            '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
            settingDefinitionId = $epmReusableSettingDefinitionId
            simpleSettingValue = [ordered]@{
                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationStringSettingValue'
                value = $normalizedCertificate
            }
        }
        '@odata.type' = '#microsoft.graph.deviceManagementReusablePolicySetting'
    }

    $uri = "$graphBaseUrl/deviceManagement/reusablePolicySettings"

    if($PSCmdlet.ShouldProcess($DisplayName, 'Create EPM reusable certificate setting')) {
        $jsonBody = $body | ConvertTo-Json -Depth 40
        $response = Invoke-MgGraphRequest -Method POST -Uri $uri -Body $jsonBody -ContentType 'application/json' -ErrorAction Stop
        $newId = Get-GraphResponseProperty -InputObject $response -PropertyName 'id'
        Write-DebugLog -Category 'INFO' -Message "Created reusable certificate setting '$DisplayName' (id '$newId')."
        return @{
            Id = $newId
            DisplayName = $DisplayName
        }
    }

    return @{
        Id = $null
        DisplayName = $DisplayName
    }
}

function ConvertTo-PlainObject {
    <#
    .SYNOPSIS
    Recursively converts a Graph response (hashtables/arrays) into plain objects.

    .DESCRIPTION
    Produces a deep copy stripped of any object identity so that a rule entry read from one
    policy can be safely re-submitted as part of another policy's settings payload.
    #>
    [CmdletBinding()]
    [OutputType([System.Object], [System.Object[]])]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $InputObject
    )

    if($null -eq $InputObject) {
        return $null
    }

    if($InputObject -is [System.Collections.IDictionary]) {
        $copy = @{}
        foreach($key in $InputObject.Keys) {
            $copy[$key] = ConvertTo-PlainObject -InputObject $InputObject[$key]
        }
        return $copy
    }

    if($InputObject -is [System.Collections.IEnumerable] -and -not ($InputObject -is [string])) {
        $list = @()
        foreach($item in $InputObject) {
            $list += , (ConvertTo-PlainObject -InputObject $item)
        }
        return , $list
    }

    return $InputObject
}

function ConvertTo-DataTable {
    <#
    .SYNOPSIS
    Converts a collection of objects to a System.Data.DataTable.

    .DESCRIPTION
    A DataTable bound to a WPF DataGrid enables out-of-the-box column sorting, and binds cleanly
    to WPF DataTemplates, which regular [PSCustomObject] arrays do not natively support.
    #>
    [CmdletBinding()]
    [OutputType([System.Data.DataTable])]
    param(
        [Parameter(Mandatory = $true)]
        [array]$Array,

        # When set, a zero-based integer column with this name is added so callers can resolve a
        # bound DataRowView back to the original object by its position in $Array.
        [Parameter(Mandatory = $false)]
        [string]$IndexColumnName
    )

    $dt = New-Object System.Data.DataTable
    if($null -eq $Array -or $Array.Count -eq 0) {
        # The comma operator returns the DataTable as a single object. Without it PowerShell
        # enumerates the DataTable (it is IEnumerable) and the caller receives its DataRows instead,
        # losing DefaultView/RowFilter and breaking the WPF DataGrid binding.
        return , $dt
    }

    if(-not [string]::IsNullOrEmpty($IndexColumnName)) {
        $dt.Columns.Add($IndexColumnName, [int]) | Out-Null
    }

    # Cache the column/property names once so the row loop avoids repeated PSObject reflection per row.
    $firstItem = $Array[0]
    $propertyNames = [System.Collections.Generic.List[string]]::new()
    foreach($prop in $firstItem.psobject.Properties) {
        $columnType = if($null -ne $prop.Value) { $prop.Value.GetType() } else { [string] }
        $dt.Columns.Add($prop.Name, $columnType) | Out-Null
        $propertyNames.Add($prop.Name)
    }

    # BeginLoadData/EndLoadData turns off index maintenance, constraint checking and change
    # notifications while bulk-loading, which is dramatically faster for large imports.
    $hasIndexColumn = -not [string]::IsNullOrEmpty($IndexColumnName)
    $dt.BeginLoadData()
    try {
        for($i = 0; $i -lt $Array.Count; $i++) {
            $item = $Array[$i]
            $row = $dt.NewRow()
            if($hasIndexColumn) {
                $row[$IndexColumnName] = $i
            }
            foreach($name in $propertyNames) {
                $value = $item.$name
                $row[$name] = if($null -ne $value) { $value } else { [DBNull]::Value }
            }
            $dt.Rows.Add($row)
        }
    } finally {
        $dt.EndLoadData()
    }

    # Comma operator prevents PowerShell from enumerating the DataTable into its DataRows on return.
    return , $dt
}

function Get-EpmRuleChoiceOption {
    <#
    .SYNOPSIS
    Reads the selectable options of a rule choice setting from the policy setting definitions.

    .DESCRIPTION
    EPM choice settings (elevation type, validation, child process behavior) carry their selectable
    options inside the expanded settingDefinitions of a policy. This helper finds the definition whose
    id ends with one of the supplied tokens and returns its options as objects with a friendly display
    name and the value to write into a rule, so the GUI can offer the exact tenant-correct options
    instead of hardcoding option strings.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.List[object]])]
    param(
        [Parameter(Mandatory = $true)]
        [object[]]$Settings,

        [Parameter(Mandatory = $true)]
        [string[]]$DefinitionIdTokens
    )

    $options = [System.Collections.Generic.List[object]]::new()

    foreach($container in $Settings) {
        $definitions = Get-GraphResponseProperty -InputObject $container -PropertyName 'settingDefinitions'
        if($null -eq $definitions) {
            continue
        }

        foreach($definition in $definitions) {
            $definitionId = Get-GraphResponseProperty -InputObject $definition -PropertyName 'id'
            if([string]::IsNullOrWhiteSpace($definitionId)) {
                continue
            }

            $loweredId = ([string]$definitionId).ToLowerInvariant()
            $isMatch = $false
            foreach($token in $DefinitionIdTokens) {
                if($loweredId.EndsWith($token.ToLowerInvariant())) {
                    $isMatch = $true
                    break
                }
            }
            if(-not $isMatch) {
                continue
            }

            $definitionOptions = Get-GraphResponseProperty -InputObject $definition -PropertyName 'options'
            if($null -eq $definitionOptions) {
                continue
            }

            $defaultOptionId = Get-GraphResponseProperty -InputObject $definition -PropertyName 'defaultOptionId'

            foreach($option in $definitionOptions) {
                $optionDisplay = Get-GraphResponseProperty -InputObject $option -PropertyName 'displayName'

                # An EPM choice rule stores the option's FULL itemId in choiceSettingValue.value
                # (for example device_vendor_msft_policy_privilegemanagement_elevationrules_
                # {elevationrulename}_supportarbitrated), NOT the short optionValue.value
                # (for example "supportarbitrated"). Writing the short form makes Graph reject the
                # rule with "Selected Option ... does not match with the list of expected options".
                # So the itemId is the authoritative value to write; optionValue.value is only a
                # last-resort fallback for definitions that do not expose an itemId.
                $optionValue = Get-GraphResponseProperty -InputObject $option -PropertyName 'itemId'
                if([string]::IsNullOrWhiteSpace($optionValue)) {
                    $optionValueObject = Get-GraphResponseProperty -InputObject $option -PropertyName 'optionValue'
                    if($null -ne $optionValueObject) {
                        $optionValue = Get-GraphResponseProperty -InputObject $optionValueObject -PropertyName 'value'
                    }
                }
                if([string]::IsNullOrWhiteSpace($optionValue)) {
                    continue
                }

                # Definitions frequently ship with an empty displayName, so fall back to the option's
                # readable trailing token (for example "_supportarbitrated" -> "supportarbitrated")
                # rather than showing the full setting id in the combo box.
                $friendlyDisplay = $optionDisplay
                if([string]::IsNullOrWhiteSpace($friendlyDisplay)) {
                    $lastUnderscore = ([string]$optionValue).LastIndexOf('_')
                    if($lastUnderscore -ge 0 -and $lastUnderscore -lt ([string]$optionValue).Length - 1) {
                        $friendlyDisplay = ([string]$optionValue).Substring($lastUnderscore + 1)
                    } else {
                        $friendlyDisplay = $optionValue
                    }
                }

                $options.Add([PSCustomObject]@{
                        DisplayName = $friendlyDisplay
                        Value = $optionValue
                        DefinitionId = $definitionId
                    IsDefault = (-not [string]::IsNullOrWhiteSpace($defaultOptionId) -and ([string]$optionValue -ieq [string]$defaultOptionId))
                    })
            }

            if($options.Count -gt 0) {
                return $options
            }
        }
    }

    return $options
}

function Remove-EpmTemplateReference {
    <#
    .SYNOPSIS
    Recursively removes settingInstanceTemplateReference and settingValueTemplateReference keys.

    .DESCRIPTION
    Template reference ids (settingInstanceTemplateReference / settingValueTemplateReference) may
    only appear once per policy. When a rule is cloned from an existing rule and appended to the
    same or another policy, those template references collide with the original rule and Graph
    rejects the PUT with "Duplicate References found". The Intune portal therefore strips every
    template reference from a newly added rule (the original keeps them), so this helper does the
    same for each new group entry before it is appended.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $Node
    )

    if($null -eq $Node) {
        return
    }

    if($Node -is [System.Collections.IDictionary]) {
        foreach($key in @('settingInstanceTemplateReference', 'settingValueTemplateReference')) {
            if($Node.Contains($key)) {
                [void]$Node.Remove($key)
            }
        }

        foreach($value in @($Node.Values)) {
            Remove-EpmTemplateReference -Node $value
        }

        return
    }

    if($Node -is [System.Collections.IEnumerable] -and -not ($Node -is [string])) {
        foreach($item in $Node) {
            Remove-EpmTemplateReference -Node $item
        }
    }
}

function Set-EpmPolicyRule {
    <#
    .SYNOPSIS
    Writes an updated rule collection back to an EPM policy via Microsoft Graph.

    .DESCRIPTION
    Reads the policy settings, appends the supplied group entries to the rule collection and
    writes the full policy entity back to Intune with PUT. Honors -WhatIf via SupportsShouldProcess.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyId,

        [Parameter(Mandatory = $true)]
        [object[]]$NewGroupEntries
    )

    Connect-IntuneGraph

    $policy = Get-EpmPolicyDetail -PolicyId $PolicyId
    $settings = Get-EpmPolicySetting -PolicyId $PolicyId
    $ruleContainer = Find-EpmRuleGroupInstance -Settings $settings
    if($null -eq $ruleContainer) {
        throw "Unable to locate the elevation rules collection in policy '$PolicyId'."
    }

    # Template reference ids may only appear once per policy. A new rule cloned from an existing
    # rule still carries the source rule's template references, which would collide with the
    # original ("Duplicate References found"). Strip them from every new entry, exactly as the
    # Intune portal does when adding a rule.
    $sanitizedEntries = @()
    foreach($entry in $NewGroupEntries) {
        $plainEntry = ConvertTo-PlainObject -InputObject $entry
        Remove-EpmTemplateReference -Node $plainEntry
        $sanitizedEntries += , $plainEntry
    }

    # Updating an EPM policy requires sending the full policy entity, because 'settings' is a
    # navigation property and cannot be PATCHed in isolation. The whole entity is rewritten with
    # PUT below. Rebuild the complete settings array, strip the read-only expanded definitions, and
    # append the new rule(s) to the elevation rules group collection.
    $settingsPayload = @()
    $appended = $false
    foreach($container in $settings) {
        $plainContainer = ConvertTo-PlainObject -InputObject $container
        if($plainContainer -isnot [System.Collections.IDictionary]) {
            continue
        }

        if($plainContainer.ContainsKey('settingDefinitions')) {
            [void]$plainContainer.Remove('settingDefinitions')
        }

        $settingInstance = $plainContainer['settingInstance']
        if(-not $appended -and
            $settingInstance -is [System.Collections.IDictionary] -and
            $settingInstance.ContainsKey('groupSettingCollectionValue') -and
            $null -ne $settingInstance['groupSettingCollectionValue']) {
            $existingEntries = @($settingInstance['groupSettingCollectionValue'])
            $settingInstance['groupSettingCollectionValue'] = @($existingEntries) + @($sanitizedEntries)
            $appended = $true
        }

        if(-not $plainContainer.ContainsKey('@odata.type')) {
            $plainContainer['@odata.type'] = '#microsoft.graph.deviceManagementConfigurationSetting'
        }

        $settingsPayload += , $plainContainer
    }

    if(-not $appended) {
        throw "Unable to locate the elevation rules group collection in policy '$PolicyId'."
    }

    $roleScopeTagIds = Get-GraphResponseProperty -InputObject $policy -PropertyName 'roleScopeTagIds'
    if($null -eq $roleScopeTagIds) {
        $roleScopeTagIds = @('0')
    }

    # creationSource is echoed back exactly as the portal does. It is normally null, but sending the
    # policy's own value keeps the entity a faithful round-trip rather than silently dropping a
    # field that a full-entity PUT would otherwise clear.
    $body = [ordered]@{
        creationSource = Get-GraphResponseProperty -InputObject $policy -PropertyName 'creationSource'
        name = Get-GraphResponseProperty -InputObject $policy -PropertyName 'name'
        description = Get-GraphResponseProperty -InputObject $policy -PropertyName 'description'
        platforms = Get-GraphResponseProperty -InputObject $policy -PropertyName 'platforms'
        technologies = Get-GraphResponseProperty -InputObject $policy -PropertyName 'technologies'
        roleScopeTagIds = @($roleScopeTagIds)
        templateReference = ConvertTo-PlainObject -InputObject (Get-GraphResponseProperty -InputObject $policy -PropertyName 'templateReference')
        settings = $settingsPayload
    }

    $uri = "$graphBaseUrl/deviceManagement/configurationPolicies('$PolicyId')"

    if($PSCmdlet.ShouldProcess($PolicyId, "Add $($NewGroupEntries.Count) EPM rule(s)")) {
        $jsonBody = $body | ConvertTo-Json -Depth 40
        # Settings-catalog/EPM policies must be updated with PUT, not PATCH. 'settings' is an OData
        # navigation property: PATCH on it returns ModelValidationFailure ("Cannot apply PATCH to
        # navigation property 'settings'"), whereas PUT replaces the whole policy entity (including
        # its settings) and is the method the Intune portal and IntuneCD use.
        Invoke-MgGraphRequest -Method PUT -Uri $uri -Body $jsonBody -ContentType 'application/json' -ErrorAction Stop | Out-Null
        Write-Verbose -Message "Updated policy '$PolicyId' with $($NewGroupEntries.Count) new rule(s)."
        return $true
    }

    return $false
}

function Set-EpmPolicyRuleByName {
    <#
    .SYNOPSIS
    Replaces a named rule in an EPM policy (or appends when the name does not exist).

    .DESCRIPTION
    Reads the full policy, removes all existing rule entries whose rule name matches RuleName
    (case-insensitive), appends the supplied replacement entry, and writes the full policy entity
    back with PUT.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyId,

        [Parameter(Mandatory = $true)]
        [string]$RuleName,

        [Parameter(Mandatory = $true)]
        [AllowNull()]
        $ReplacementGroupEntry
    )

    Connect-IntuneGraph

    $policy = Get-EpmPolicyDetail -PolicyId $PolicyId
    $settings = Get-EpmPolicySetting -PolicyId $PolicyId
    $ruleContainer = Find-EpmRuleGroupInstance -Settings $settings
    if($null -eq $ruleContainer) {
        throw "Unable to locate the elevation rules collection in policy '$PolicyId'."
    }

    $replacement = ConvertTo-PlainObject -InputObject $ReplacementGroupEntry
    Remove-EpmTemplateReference -Node $replacement

    $settingsPayload = @()
    $updated = $false
    $replacedCount = 0
    foreach($container in $settings) {
        $plainContainer = ConvertTo-PlainObject -InputObject $container
        if($plainContainer -isnot [System.Collections.IDictionary]) {
            continue
        }

        if($plainContainer.ContainsKey('settingDefinitions')) {
            [void]$plainContainer.Remove('settingDefinitions')
        }

        $settingInstance = $plainContainer['settingInstance']
        if(-not $updated -and
            $settingInstance -is [System.Collections.IDictionary] -and
            $settingInstance.ContainsKey('groupSettingCollectionValue') -and
            $null -ne $settingInstance['groupSettingCollectionValue']) {

            $existingEntries = @($settingInstance['groupSettingCollectionValue'])
            $keptEntries = @()
            foreach($entry in $existingEntries) {
                $entryRule = ConvertFrom-EpmRuleInstance -GroupEntry $entry
                if(-not [string]::IsNullOrWhiteSpace($entryRule.RuleName) -and $entryRule.RuleName -ieq $RuleName) {
                    $replacedCount++
                    continue
                }
                $keptEntries += , $entry
            }

            $settingInstance['groupSettingCollectionValue'] = @($keptEntries) + @($replacement)
            $updated = $true
        }

        if(-not $plainContainer.ContainsKey('@odata.type')) {
            $plainContainer['@odata.type'] = '#microsoft.graph.deviceManagementConfigurationSetting'
        }

        $settingsPayload += , $plainContainer
    }

    if(-not $updated) {
        throw "Unable to locate the elevation rules group collection in policy '$PolicyId'."
    }

    $roleScopeTagIds = Get-GraphResponseProperty -InputObject $policy -PropertyName 'roleScopeTagIds'
    if($null -eq $roleScopeTagIds) {
        $roleScopeTagIds = @('0')
    }

    # creationSource is echoed back exactly as the portal does. It is normally null, but sending the
    # policy's own value keeps the entity a faithful round-trip rather than silently dropping a
    # field that a full-entity PUT would otherwise clear.
    $body = [ordered]@{
        creationSource = Get-GraphResponseProperty -InputObject $policy -PropertyName 'creationSource'
        name = Get-GraphResponseProperty -InputObject $policy -PropertyName 'name'
        description = Get-GraphResponseProperty -InputObject $policy -PropertyName 'description'
        platforms = Get-GraphResponseProperty -InputObject $policy -PropertyName 'platforms'
        technologies = Get-GraphResponseProperty -InputObject $policy -PropertyName 'technologies'
        roleScopeTagIds = @($roleScopeTagIds)
        templateReference = ConvertTo-PlainObject -InputObject (Get-GraphResponseProperty -InputObject $policy -PropertyName 'templateReference')
        settings = $settingsPayload
    }

    $uri = "$graphBaseUrl/deviceManagement/configurationPolicies('$PolicyId')"
    $action = if($replacedCount -gt 0) { "Overwrite existing rule '$RuleName'" } else { "Add rule '$RuleName'" }
    if($PSCmdlet.ShouldProcess($PolicyId, $action)) {
        $jsonBody = $body | ConvertTo-Json -Depth 40
        Invoke-MgGraphRequest -Method PUT -Uri $uri -Body $jsonBody -ContentType 'application/json' -ErrorAction Stop | Out-Null
        return $true
    }

    return $false
}

function New-EpmSimpleSettingInstance {
    <#
    .SYNOPSIS
    Builds one simple (string or reference) child setting for an EPM elevation rule.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DefinitionId,

        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter(Mandatory = $false)]
        [switch]$AsReference
    )

    $valueType = if($AsReference.IsPresent) {
        '#microsoft.graph.deviceManagementConfigurationReferenceSettingValue'
    } else {
        '#microsoft.graph.deviceManagementConfigurationStringSettingValue'
    }

    return [ordered]@{
        '@odata.type' = '#microsoft.graph.deviceManagementConfigurationSimpleSettingInstance'
        settingDefinitionId = $DefinitionId
        simpleSettingValue = [ordered]@{
            '@odata.type' = $valueType
            value = $Value
        }
    }
}

function New-EpmChoiceSettingInstance {
    <#
    .SYNOPSIS
    Builds one choice child setting for an EPM elevation rule, optionally with nested children.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$DefinitionId,

        [Parameter(Mandatory = $true)]
        [string]$Value,

        [Parameter(Mandatory = $false)]
        [object[]]$Children = @()
    )

    return [ordered]@{
        '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingInstance'
        settingDefinitionId = $DefinitionId
        choiceSettingValue = [ordered]@{
            '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
            value = $Value
            children = @($Children)
        }
    }
}

function New-EpmElevationRuleGroupEntry {
    <#
    .SYNOPSIS
    Builds a complete EPM elevation rule group entry from scratch.

    .DESCRIPTION
    Constructs the rule payload the Intune portal produces, rather than cloning an existing rule
    and mutating it. Cloning required the target policy to already contain a rule of the right
    shape (a certificate rule to make a certificate rule), so the first rule in a policy could
    never be created by the tool, and any mismatch in the source rule leaked into the new one.

    The structure below was captured from portal PUT bodies for three rule variants:

      certificate + user confirmed : internalname, signaturesource(certificate ref + certificatetype),
                                     ruletype=self, childprocessbehavior, name, appliesto
      hash + user confirmed        : filehash, ruletype=self(+validation), filename,
                                     childprocessbehavior, name, appliesto
      certificate + automatic      : internalname, signaturesource(...), ruletype=automatic,
                                     filename, childprocessbehavior, name, appliesto

    Notes on the shape that are easy to get wrong:
      - The certificate reference is a ReferenceSettingValue holding the reusable setting id, and
        it lives under the signaturesource choice, not at the top of the rule.
      - Validation is a ChoiceSettingCollectionInstance nested inside the ruletype choice's
        children, so it only exists for a user-confirmed rule. An automatic rule sends no
        validation at all.
      - A new rule must carry no settingInstanceTemplateReference anywhere; template ids may
        appear only once per policy and the existing rules already own them.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Specialized.OrderedDictionary])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string]$RuleName,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Certificate', 'Hash')]
        [string]$MatchType,

        [Parameter(Mandatory = $false)]
        [string]$FileName,

        [Parameter(Mandatory = $false)]
        [string]$FileHash,

        [Parameter(Mandatory = $false)]
        [string]$InternalName,

        [Parameter(Mandatory = $false)]
        [string]$ReusableSettingId,

        [Parameter(Mandatory = $false)]
        [string]$ElevationTypeValue,

        [Parameter(Mandatory = $false)]
        [string[]]$ValidationValues,

        [Parameter(Mandatory = $false)]
        [string]$ChildProcessBehaviorValue,

        [Parameter(Mandatory = $false)]
        [string]$CertificateTypeValue,

        [Parameter(Mandatory = $false)]
        [string]$AppliesToValue
    )

    $prefix = $epmRulePrefix

    $elevationValue = if(-not [string]::IsNullOrWhiteSpace($ElevationTypeValue)) { $ElevationTypeValue } else { "${prefix}_self" }
    $childProcessValue = if(-not [string]::IsNullOrWhiteSpace($ChildProcessBehaviorValue)) { $ChildProcessBehaviorValue } else { "${prefix}_allowrunelevated" }
    $certificateTypeValue = if(-not [string]::IsNullOrWhiteSpace($CertificateTypeValue)) { $CertificateTypeValue } else { "${prefix}_issuingauthority" }
    $appliesToValue = if(-not [string]::IsNullOrWhiteSpace($AppliesToValue)) { $AppliesToValue } else { "${prefix}_allusers" }

    $children = [System.Collections.Generic.List[object]]::new()

    if($MatchType -eq 'Certificate') {
        if([string]::IsNullOrWhiteSpace($ReusableSettingId)) {
            throw "A certificate rule needs a reusable certificate setting id, but none was supplied for '$RuleName'."
        }

        if(-not [string]::IsNullOrWhiteSpace($InternalName)) {
            $children.Add((New-EpmSimpleSettingInstance -DefinitionId "${prefix}_internalname" -Value $InternalName))
        }

        $signatureChildren = @(
            (New-EpmSimpleSettingInstance -DefinitionId "${prefix}_certificatepayloadwithreusablesetting" -Value $ReusableSettingId -AsReference),
            (New-EpmChoiceSettingInstance -DefinitionId "${prefix}_certificatetype" -Value $certificateTypeValue)
        )
        $children.Add((New-EpmChoiceSettingInstance -DefinitionId "${prefix}_signaturesource" -Value "${prefix}_signaturesource_0" -Children $signatureChildren))
    } else {
        if([string]::IsNullOrWhiteSpace($FileHash)) {
            throw "A hash rule needs a SHA256 file hash, but none was supplied for '$RuleName'."
        }
        $children.Add((New-EpmSimpleSettingInstance -DefinitionId "${prefix}_filehash" -Value $FileHash))
    }

    # Validation belongs to the user-confirmed rule type only; an automatic rule carries none.
    $ruleTypeChildren = @()
    $isAutomatic = $elevationValue -imatch '_automatic$'
    if(-not $isAutomatic -and $null -ne $ValidationValues -and @($ValidationValues).Count -gt 0) {
        $validationEntries = @()
        foreach($validationValue in @($ValidationValues)) {
            if([string]::IsNullOrWhiteSpace($validationValue)) {
                continue
            }
            $validationEntries += , [ordered]@{
                '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingValue'
                value = $validationValue
                children = @()
            }
        }

        if($validationEntries.Count -gt 0) {
            $ruleTypeChildren = @(
                [ordered]@{
                    '@odata.type' = '#microsoft.graph.deviceManagementConfigurationChoiceSettingCollectionInstance'
                    settingDefinitionId = "${prefix}_ruletype_validation"
                    choiceSettingCollectionValue = @($validationEntries)
                }
            )
        }
    }

    $children.Add((New-EpmChoiceSettingInstance -DefinitionId "${prefix}_ruletype" -Value $elevationValue -Children $ruleTypeChildren))

    if(-not [string]::IsNullOrWhiteSpace($FileName)) {
        $children.Add((New-EpmSimpleSettingInstance -DefinitionId "${prefix}_filename" -Value $FileName))
    }

    $children.Add((New-EpmChoiceSettingInstance -DefinitionId "${prefix}_childprocessbehavior" -Value $childProcessValue))
    $children.Add((New-EpmSimpleSettingInstance -DefinitionId "${prefix}_name" -Value $RuleName))
    $children.Add((New-EpmChoiceSettingInstance -DefinitionId "${prefix}_appliesto" -Value $appliesToValue))

    return [ordered]@{
        children = @($children)
    }
}

function Add-EpmScannedRuleToPolicy {
    <#
    .SYNOPSIS
    Adds a scanned file to an EPM policy as a fully configured elevation rule.

    .DESCRIPTION
    Builds the rule payload outright with New-EpmElevationRuleGroupEntry and writes it to the
    policy. Nothing is copied from an existing rule, so a rule can be created in a policy that is
    still empty, and a certificate rule no longer requires the policy to already contain one.

    Supports the rule shapes the Intune portal produces: certificate or hash matching, user
    confirmed (with optional validation) or automatic elevation, an optional file name and internal
    name. Honors -WhatIf via SupportsShouldProcess.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$PolicyId,

        [Parameter(Mandatory = $true)]
        [PSObject]$Candidate,

        [Parameter(Mandatory = $false)]
        [string]$ElevationTypeValue,

        [Parameter(Mandatory = $false)]
        [string[]]$ValidationValues,

        [Parameter(Mandatory = $false)]
        [string]$ChildProcessBehaviorValue,

        [Parameter(Mandatory = $false)]
        [string]$InternalName,

        [Parameter(Mandatory = $false)]
        [string]$ReusableSettingId,

        [Parameter(Mandatory = $false)]
        [string]$RuleNameOverride,

        [Parameter(Mandatory = $false)]
        [string]$ReplaceRuleName,

        [Parameter(Mandatory = $false)]
        [switch]$IncludeFileName
    )

    $candidateMatchType = 'Hash'
    if($null -ne $Candidate.PSObject.Properties['MatchType'] -and ([string]$Candidate.MatchType) -imatch 'cert') {
        $candidateMatchType = 'Certificate'
    }

    $ruleName = if(-not [string]::IsNullOrWhiteSpace($RuleNameOverride)) { $RuleNameOverride } else { [string]$Candidate.RuleName }
    if([string]::IsNullOrWhiteSpace($ruleName)) {
        throw 'A rule name is required.'
    }

    # A hash rule always carries the file name: the portal sends both, and a hash on its own gives
    # the operator nothing readable to identify the rule by in the policy.
    $fileName = $null
    if($IncludeFileName.IsPresent -or $candidateMatchType -eq 'Hash') {
        $fileName = [string]$Candidate.FileName
    }

    $entryParameters = @{
        RuleName = $ruleName
        MatchType = $candidateMatchType
        ElevationTypeValue = $ElevationTypeValue
        ValidationValues = $ValidationValues
        ChildProcessBehaviorValue = $ChildProcessBehaviorValue
    }

    if(-not [string]::IsNullOrWhiteSpace($fileName)) { $entryParameters['FileName'] = $fileName }
    if(-not [string]::IsNullOrWhiteSpace($InternalName)) { $entryParameters['InternalName'] = $InternalName }

    if($candidateMatchType -eq 'Certificate') {
        if([string]::IsNullOrWhiteSpace($ReusableSettingId)) {
            throw "Certificate match was selected for '$ruleName', but no reusable certificate setting was selected."
        }
        $entryParameters['ReusableSettingId'] = $ReusableSettingId
    } else {
        if([string]::IsNullOrWhiteSpace($Candidate.FileHash)) {
            throw "Hash match was selected for '$ruleName', but no file hash was provided. Extract the hash first and try again."
        }
        $entryParameters['FileHash'] = [string]$Candidate.FileHash
    }

    $newEntry = New-EpmElevationRuleGroupEntry @entryParameters

    if(-not [string]::IsNullOrWhiteSpace($ReplaceRuleName)) {
        return (Set-EpmPolicyRuleByName -PolicyId $PolicyId -RuleName $ReplaceRuleName -ReplacementGroupEntry $newEntry)
    }

    return (Set-EpmPolicyRule -PolicyId $PolicyId -NewGroupEntries @($newEntry))
}
function Copy-EpmRuleToPolicy {
    <#
    .SYNOPSIS
    Replicates a named rule from a source EPM policy into a target EPM policy.

    .DESCRIPTION
    Reads the source rule's group setting collection entry and appends a deep copy of it to the
    target policy so the same rule does not have to be recreated for different persona types.
    #>
    [CmdletBinding(SupportsShouldProcess = $true)]
    [OutputType([System.Boolean])]
    param(
        [Parameter(Mandatory = $true)]
        [string]$SourcePolicyId,

        [Parameter(Mandatory = $true)]
        [string]$TargetPolicyId,

        [Parameter(Mandatory = $true)]
        [string]$RuleName
    )

    $sourceRules = Get-EpmPolicyRule -PolicyId $SourcePolicyId
    $sourceRule = $sourceRules | Where-Object { $_.RuleName -ieq $RuleName } | Select-Object -First 1

    if($null -eq $sourceRule) {
        throw "Rule '$RuleName' was not found in source policy '$SourcePolicyId'."
    }

    $clonedEntry = ConvertTo-PlainObject -InputObject $sourceRule.GroupEntry

    return (Set-EpmPolicyRule -PolicyId $TargetPolicyId -NewGroupEntries @($clonedEntry))
}

function Test-IsElevated {
    <#
    .SYNOPSIS
    Determines whether the current session is running with administrative privileges.
    #>
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param()

    $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Invoke-EpmRuleBuildCli {
    <#
    .SYNOPSIS
    Headless report that imports a CSV, builds candidate rules and reports duplicates.

    .DESCRIPTION
    Imports the audit CSV, builds a candidate rule per row, and evaluates each candidate against
    the existing EPM rules for duplicates and against the best-practice checks. Rule payloads are
    exported to the output path.

    This is a reporting workflow only - it never writes to the tenant. Audit rows describe an
    elevation event, not the binary, so they cannot yield a certificate or hash that is safe to
    turn into a rule. Rules are created from the real files on the Scan Path tab of the GUI.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,

        [Parameter(Mandatory = $false)]
        [hashtable]$Override,

        [Parameter(Mandatory = $false)]
        [ValidateSet('Auto', 'Certificate', 'Hash')]
        [string]$Match = 'Auto',

        [Parameter(Mandatory = $false)]
        [string]$ExportPath
    )

    $rows = Import-EpmAuditCsv -Path $Path -Override $Override
    if($rows.Count -eq 0) {
        Write-Warning -Message 'No rows to process.'
        return
    }

    $existingRules = $null
    try {
        $existingRules = Get-AllEpmRule
    } catch {
        Write-Warning -Message "Unable to retrieve existing EPM rules for duplicate detection: $($_.Exception.Message)"
        $existingRules = [System.Collections.Generic.List[object]]::new()
    }

    $candidates = [System.Collections.Generic.List[object]]::new()

    foreach($row in $rows) {
        $candidate = ConvertTo-EpmRuleCandidate -ElevationRow $row -Match $Match
        $duplicates = Find-SimilarEpmRule -Candidate $candidate -ExistingRules $existingRules
        $bestPractice = Test-EpmRuleBestPractice -Candidate $candidate

        Write-Output "Rule: $($candidate.RuleName)"
        Write-Output "  Match type   : $($candidate.MatchType)"
        Write-Output "  File name    : $($candidate.FileName)"
        Write-Output "  Publisher    : $($candidate.Publisher)"

        if($duplicates.Count -gt 0) {
            foreach($duplicate in $duplicates) {
                Write-Output "  Duplicate    : [$($duplicate.MatchType)] '$($duplicate.RuleName)' in policy '$($duplicate.PolicyName)'"
            }
        } else {
            Write-Output '  Duplicate    : none found'
        }

        foreach($finding in $bestPractice) {
            Write-Output "  [$($finding.Severity)] $($finding.Message)"
        }

        $candidate | Add-Member -MemberType NoteProperty -Name 'Duplicates' -Value $duplicates -Force
        $candidate | Add-Member -MemberType NoteProperty -Name 'BestPractice' -Value $bestPractice -Force
        $candidates.Add($candidate)
    }

    if(-not [string]::IsNullOrWhiteSpace($ExportPath)) {
        try {
            if(-not (Test-Path -Path $reportsDir)) {
                New-Item -Path $reportsDir -ItemType Directory -Force | Out-Null
            }
            $candidates | ConvertTo-Json -Depth 10 | Out-File -FilePath $ExportPath -Encoding UTF8
            Write-Output "Exported $($candidates.Count) candidate rule(s) to '$ExportPath'."
        } catch {
            Write-Warning -Message "Failed to export candidate rules: $($_.Exception.Message)"
        }
    }

    return $candidates
}

function Get-EpmToolDefaultSettings {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param()

    return @{
        TempWorkingDirectory = $script:defaultTempWorkingDirectory
        UiZoom = 1.0
    }
}

function Initialize-EpmToolSettings {
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param()

    $defaults = Get-EpmToolDefaultSettings
    $resolved = @{
        TempWorkingDirectory = [string]$defaults.TempWorkingDirectory
        UiZoom = [double]$defaults.UiZoom
    }

    try {
        if(Test-Path -Path $script:userSettingsFilePath -PathType Leaf) {
            $raw = Get-Content -Path $script:userSettingsFilePath -Raw -ErrorAction Stop
            if(-not [string]::IsNullOrWhiteSpace($raw)) {
                $loaded = $raw | ConvertFrom-Json -ErrorAction Stop
                if($null -ne $loaded -and -not [string]::IsNullOrWhiteSpace($loaded.TempWorkingDirectory)) {
                    $resolved.TempWorkingDirectory = [string]$loaded.TempWorkingDirectory
                }
                if($null -ne $loaded -and $null -ne $loaded.PSObject.Properties['UiZoom'] -and $loaded.UiZoom -is [ValueType]) {
                    # Clamp on load too - a hand-edited or older settings.json could carry a value
                    # outside the range Set-GuiZoom itself enforces.
                    $resolved.UiZoom = [Math]::Min(1.6, [Math]::Max(0.6, [double]$loaded.UiZoom))
                }
            }
        }
    } catch {
        Write-DebugLog -Category 'WARN' -Message "Failed to read settings from '$($script:userSettingsFilePath)': $($_.Exception.Message). Falling back to defaults."
    }

    if(-not [System.IO.Path]::IsPathRooted($resolved.TempWorkingDirectory)) {
        $resolved.TempWorkingDirectory = [System.IO.Path]::GetFullPath((Join-Path -Path $env:USERPROFILE -ChildPath $resolved.TempWorkingDirectory))
    }

    try {
        if(-not (Test-Path -Path $resolved.TempWorkingDirectory -PathType Container)) {
            New-Item -Path $resolved.TempWorkingDirectory -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
    } catch {
        Write-DebugLog -Category 'WARN' -Message "Unable to create temp working directory '$($resolved.TempWorkingDirectory)': $($_.Exception.Message). Using default path '$($defaults.TempWorkingDirectory)'."
        $resolved.TempWorkingDirectory = [string]$defaults.TempWorkingDirectory
        if(-not (Test-Path -Path $resolved.TempWorkingDirectory -PathType Container)) {
            New-Item -Path $resolved.TempWorkingDirectory -ItemType Directory -Force | Out-Null
        }
    }

    $script:runtimeSettings = $resolved
    return $script:runtimeSettings
}

function Save-EpmToolSettings {
    <#
    .DESCRIPTION
    Both parameters are optional and each defaults to the currently loaded value (falling back to
    the tool default if nothing has been loaded yet) rather than to a hardcoded default, so saving
    one setting - the temp working directory from the Settings tab, say - never resets the other
    one - the zoom level, changed from the footer - back to a default the operator did not ask for.
    #>
    [CmdletBinding()]
    [OutputType([System.Collections.Hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [string]$TempWorkingDirectory,

        [Parameter(Mandatory = $false)]
        [Nullable[double]]$UiZoom
    )

    $current = if($null -ne $script:runtimeSettings) { $script:runtimeSettings } else { Get-EpmToolDefaultSettings }

    $effectiveTempPath = if($PSBoundParameters.ContainsKey('TempWorkingDirectory') -and -not [string]::IsNullOrWhiteSpace($TempWorkingDirectory)) {
        $TempWorkingDirectory
    } else {
        [string]$current.TempWorkingDirectory
    }
    $effectiveZoom = if($PSBoundParameters.ContainsKey('UiZoom') -and $null -ne $UiZoom) {
        [Math]::Min(1.6, [Math]::Max(0.6, [double]$UiZoom))
    } elseif($null -ne $current.UiZoom) {
        [double]$current.UiZoom
    } else {
        1.0
    }

    $resolvedPath = [System.Environment]::ExpandEnvironmentVariables($effectiveTempPath.Trim())
    if(-not [System.IO.Path]::IsPathRooted($resolvedPath)) {
        $resolvedPath = [System.IO.Path]::GetFullPath((Join-Path -Path $env:USERPROFILE -ChildPath $resolvedPath))
    }

    if(-not (Test-Path -Path $resolvedPath -PathType Container)) {
        New-Item -Path $resolvedPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    if(-not (Test-Path -Path $script:userSettingsRoot -PathType Container)) {
        New-Item -Path $script:userSettingsRoot -ItemType Directory -Force -ErrorAction Stop | Out-Null
    }

    $settings = @{
        TempWorkingDirectory = $resolvedPath
        UiZoom = $effectiveZoom
    }

    $settings | ConvertTo-Json -Depth 5 | Set-Content -Path $script:userSettingsFilePath -Encoding utf8 -ErrorAction Stop
    $script:runtimeSettings = $settings
    Write-DebugLog -Category 'INFO' -Message "Saved user settings to '$($script:userSettingsFilePath)': temp working directory '$resolvedPath', zoom $([Math]::Round($effectiveZoom * 100))%."
    return $settings
}

function Get-EpmTempWorkingDirectory {
    [CmdletBinding()]
    [OutputType([System.String])]
    param()

    if($null -eq $script:runtimeSettings) {
        Initialize-EpmToolSettings | Out-Null
    }

    if($null -ne $script:runtimeSettings -and -not [string]::IsNullOrWhiteSpace($script:runtimeSettings.TempWorkingDirectory)) {
        return [string]$script:runtimeSettings.TempWorkingDirectory
    }

    return [string]$script:defaultTempWorkingDirectory
}

#endregion Functions

#region GUI Definition

function Show-WpfGui {
    [CmdletBinding()]
    param()

    # WPF requires a single-threaded apartment (STA) thread. Several hosts run the pipeline thread as
    # MTA - notably a standalone PowerShell 7 console (pwsh defaults to MTA) and the VS Code PowerShell
    # Integrated Console - and there XamlReader.Load fails with "Initialization of '<control>' threw an
    # exception" whose inner cause is "The calling thread must be STA". (VS Code's integrated pwsh and
    # "powershell.exe -File" happen to be STA, which is why it works in some places but not others.)
    # In-process STA-runspace relaunches are unreliable across hosts, so when the current thread is not
    # STA the GUI is relaunched in a separate STA process. The same host executable is reused with -STA
    # (both pwsh.exe and powershell.exe support -STA) so the runtime and loaded modules stay consistent;
    # Windows PowerShell 5.1 is used as a guaranteed fallback. This blocks until the GUI window closes.
    if([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne [System.Threading.ApartmentState]::STA) {
        if([string]::IsNullOrWhiteSpace($PSCommandPath)) {
            throw 'The GUI requires an STA thread. Run the script with "pwsh -STA -File <path>" (or "powershell.exe -STA -File <path>") instead of dot-sourcing it from an MTA console.'
        }

        $currentApartment = [System.Threading.Thread]::CurrentThread.GetApartmentState()

        # Prefer relaunching with the same host executable so a pwsh 7 session stays on pwsh 7.
        $staHost = $null
        try {
            $staHost = (Get-Process -Id $PID -ErrorAction Stop).Path
        } catch {
            Write-Error -Message "Could not resolve the current host path: $($_.Exception.Message)" -ErrorAction SilentlyContinue
        }
        if([string]::IsNullOrWhiteSpace($staHost) -or -not (Test-Path -LiteralPath $staHost)) {
            $staHost = Join-Path -Path $env:SystemRoot -ChildPath 'System32\WindowsPowerShell\v1.0\powershell.exe'
            if(-not (Test-Path -LiteralPath $staHost)) {
                $staHost = 'powershell.exe'
            }
        }

        Write-DebugLog -Category 'INFO' -Message "Current thread is $currentApartment; relaunching the GUI in a separate STA process: $staHost"

        $hostArguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-STA', '-File', $PSCommandPath)
        try {
            $staProcess = Start-Process -FilePath $staHost -ArgumentList $hostArguments -PassThru -Wait -ErrorAction Stop
            if($null -ne $staProcess -and $staProcess.ExitCode -ne 0) {
                Write-DebugLog -Category 'WARN' -Message "The STA GUI process exited with code $($staProcess.ExitCode)."
            }
        } catch {
            Write-Error -Message "Failed to relaunch the GUI in an STA process. Start the tool directly with: pwsh -STA -File `"$PSCommandPath`". Error: $($_.Exception.Message)" -ErrorAction Stop
        }
        return
    }

    Add-Type -AssemblyName PresentationFramework
    Add-Type -AssemblyName PresentationCore
    Add-Type -AssemblyName WindowsBase
    Add-Type -AssemblyName System.Windows.Forms

    [xml]$xaml = @"
<Window
    xmlns="http://schemas.microsoft.com/winfx/2006/xaml/presentation"
    xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml"
    Title="ZeroAdmin - Community Edition"
    Height="940" Width="1220" MinHeight="600" MinWidth="900"
    WindowStartupLocation="CenterScreen"
    FontFamily="Segoe UI Variable Text, Segoe UI"
    FontSize="13"
    Foreground="#16192b"
    UseLayoutRounding="True"
    Background="#f3f5f9">

    <Window.Resources>

        <!-- Design tokens. Every brush used by the shell is defined here so the whole tool can be
             re-skinned from one place. The brand navy stays the accent colour, everything else is a
             neutral surface/border/text ramp. -->
        <SolidColorBrush x:Key="AccentBrush" Color="#8A0E0C"/>
        <SolidColorBrush x:Key="AccentHoverBrush" Color="#B01210"/>
        <SolidColorBrush x:Key="AccentPressedBrush" Color="#600A08"/>
        <SolidColorBrush x:Key="AccentTintBrush" Color="#F7E3E2"/>
        <SolidColorBrush x:Key="AccentTintBorderBrush" Color="#EEC2C0"/>
        <SolidColorBrush x:Key="SurfaceBrush" Color="#ffffff"/>
        <SolidColorBrush x:Key="SurfaceAltBrush" Color="#f8fafd"/>
        <SolidColorBrush x:Key="BorderSoftBrush" Color="#e6e9f2"/>
        <SolidColorBrush x:Key="BorderStrongBrush" Color="#cbd2e0"/>
        <SolidColorBrush x:Key="TextPrimaryBrush" Color="#16192b"/>
        <SolidColorBrush x:Key="TextSecondaryBrush" Color="#5a6376"/>
        <SolidColorBrush x:Key="TextMutedBrush" Color="#8a92a5"/>
        <SolidColorBrush x:Key="TextDisabledBrush" Color="#a7aebe"/>

        <!-- Scroll bars: thin, chromeless, no arrow buttons. -->
        <Style x:Key="ScrollPageButtonStyle" TargetType="RepeatButton">
            <Setter Property="OverridesDefaultStyle" Value="True"/>
            <Setter Property="Focusable" Value="False"/>
            <Setter Property="IsTabStop" Value="False"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="RepeatButton">
                        <Border Background="Transparent"/>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style x:Key="ScrollThumbStyle" TargetType="Thumb">
            <Setter Property="OverridesDefaultStyle" Value="True"/>
            <Setter Property="IsTabStop" Value="False"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Thumb">
                        <Border x:Name="thumbBd" Background="#c3cad8" CornerRadius="4" Margin="2"/>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="thumbBd" Property="Background" Value="#98a2b6"/>
                            </Trigger>
                            <Trigger Property="IsDragging" Value="True">
                                <Setter TargetName="thumbBd" Property="Background" Value="#7b869c"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style TargetType="ScrollBar">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="Width" Value="11"/>
            <Setter Property="MinWidth" Value="11"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ScrollBar">
                        <Grid Background="Transparent" SnapsToDevicePixels="True">
                            <Track x:Name="PART_Track" IsDirectionReversed="True" Orientation="{TemplateBinding Orientation}">
                                <Track.DecreaseRepeatButton>
                                    <RepeatButton Command="ScrollBar.PageUpCommand" Style="{StaticResource ScrollPageButtonStyle}"/>
                                </Track.DecreaseRepeatButton>
                                <Track.Thumb>
                                    <Thumb Style="{StaticResource ScrollThumbStyle}"/>
                                </Track.Thumb>
                                <Track.IncreaseRepeatButton>
                                    <RepeatButton Command="ScrollBar.PageDownCommand" Style="{StaticResource ScrollPageButtonStyle}"/>
                                </Track.IncreaseRepeatButton>
                            </Track>
                        </Grid>
                        <ControlTemplate.Triggers>
                            <Trigger Property="Orientation" Value="Horizontal">
                                <Setter TargetName="PART_Track" Property="IsDirectionReversed" Value="False"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="Orientation" Value="Horizontal">
                    <Setter Property="Width" Value="Auto"/>
                    <Setter Property="MinWidth" Value="0"/>
                    <Setter Property="Height" Value="11"/>
                    <Setter Property="MinHeight" Value="11"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <!-- Buttons. The implicit style is the quiet secondary button so every tab can have exactly
             one accented primary action; AccentButton and HeaderButton are opt-in. -->
        <Style TargetType="Button">
            <Setter Property="Background" Value="#ffffff"/>
            <Setter Property="Foreground" Value="#1f2637"/>
            <Setter Property="BorderBrush" Value="#cbd2e0"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Padding" Value="14,7"/>
            <Setter Property="MinHeight" Value="32"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="SnapsToDevicePixels" Value="True"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" CornerRadius="6" Padding="{TemplateBinding Padding}" SnapsToDevicePixels="True">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="bd" Property="Background" Value="#FDF3F2"/>
                                <Setter TargetName="bd" Property="BorderBrush" Value="#D99795"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="bd" Property="Background" Value="#F9DEDC"/>
                                <Setter TargetName="bd" Property="BorderBrush" Value="#8A0E0C"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="bd" Property="Background" Value="#f1f3f7"/>
                                <Setter TargetName="bd" Property="BorderBrush" Value="#e6e9f2"/>
                                <Setter Property="Foreground" Value="#a7aebe"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="AccentButton" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
            <Setter Property="Background" Value="#8A0E0C"/>
            <Setter Property="Foreground" Value="#ffffff"/>
            <Setter Property="BorderBrush" Value="#8A0E0C"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" CornerRadius="6" Padding="{TemplateBinding Padding}" SnapsToDevicePixels="True">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="bd" Property="Background" Value="#B01210"/>
                                <Setter TargetName="bd" Property="BorderBrush" Value="#B01210"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="bd" Property="Background" Value="#600A08"/>
                                <Setter TargetName="bd" Property="BorderBrush" Value="#600A08"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="bd" Property="Background" Value="#D9BAB9"/>
                                <Setter TargetName="bd" Property="BorderBrush" Value="#D9BAB9"/>
                                <Setter Property="Foreground" Value="#f4f6fb"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="HeaderButton" TargetType="Button" BasedOn="{StaticResource {x:Type Button}}">
            <Setter Property="Background" Value="#33ffffff"/>
            <Setter Property="Foreground" Value="#ffffff"/>
            <Setter Property="BorderBrush" Value="#59ffffff"/>
            <Setter Property="Padding" Value="12,6"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="Button">
                        <Border x:Name="bd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="1" CornerRadius="6" Padding="{TemplateBinding Padding}" SnapsToDevicePixels="True">
                            <ContentPresenter HorizontalAlignment="Center" VerticalAlignment="Center"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="bd" Property="Background" Value="#4dffffff"/>
                                <Setter TargetName="bd" Property="BorderBrush" Value="#8cffffff"/>
                            </Trigger>
                            <Trigger Property="IsPressed" Value="True">
                                <Setter TargetName="bd" Property="Background" Value="#26ffffff"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="bd" Property="Background" Value="#1affffff"/>
                                <Setter TargetName="bd" Property="BorderBrush" Value="#33ffffff"/>
                                <Setter Property="Foreground" Value="#D99795"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Text input -->
        <Style TargetType="TextBox">
            <Setter Property="Background" Value="#ffffff"/>
            <Setter Property="Foreground" Value="#16192b"/>
            <Setter Property="BorderBrush" Value="#cbd2e0"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="CaretBrush" Value="#8A0E0C"/>
            <Setter Property="SelectionBrush" Value="#8A0E0C"/>
            <Setter Property="Padding" Value="10,6"/>
            <Setter Property="MinHeight" Value="32"/>
            <Setter Property="SnapsToDevicePixels" Value="True"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TextBox">
                        <Border x:Name="tbBd" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" CornerRadius="6" SnapsToDevicePixels="True">
                            <ScrollViewer x:Name="PART_ContentHost" Margin="{TemplateBinding Padding}" Focusable="False" HorizontalScrollBarVisibility="Hidden" VerticalScrollBarVisibility="Hidden"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="tbBd" Property="BorderBrush" Value="#D99795"/>
                            </Trigger>
                            <Trigger Property="IsKeyboardFocusWithin" Value="True">
                                <Setter TargetName="tbBd" Property="BorderBrush" Value="#8A0E0C"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="tbBd" Property="Background" Value="#f1f3f7"/>
                                <Setter Property="Foreground" Value="#a7aebe"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Read-only result panes are rendered as a quiet console surface. -->
        <Style x:Key="ConsoleTextBox" TargetType="TextBox" BasedOn="{StaticResource {x:Type TextBox}}">
            <Setter Property="FontFamily" Value="Cascadia Mono, Consolas, Courier New"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="Background" Value="#fafbfe"/>
            <Setter Property="Foreground" Value="#2b3244"/>
            <Setter Property="BorderBrush" Value="#e6e9f2"/>
            <Setter Property="Padding" Value="11,8"/>
        </Style>

        <!-- Combo box -->
        <Style x:Key="ComboToggleStyle" TargetType="ToggleButton">
            <Setter Property="OverridesDefaultStyle" Value="True"/>
            <Setter Property="IsTabStop" Value="False"/>
            <Setter Property="Focusable" Value="False"/>
            <Setter Property="ClickMode" Value="Press"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ToggleButton">
                        <Border x:Name="cbBd" Background="#ffffff" BorderBrush="#cbd2e0" BorderThickness="1" CornerRadius="6" SnapsToDevicePixels="True">
                            <Path x:Name="cbArrow" HorizontalAlignment="Right" VerticalAlignment="Center" Margin="0,0,11,0" Data="M 0 0 L 4.5 4.5 L 9 0" Stroke="#5a6376" StrokeThickness="1.6" StrokeStartLineCap="Round" StrokeEndLineCap="Round" StrokeLineJoin="Round"/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="cbBd" Property="BorderBrush" Value="#D99795"/>
                            </Trigger>
                            <Trigger Property="IsChecked" Value="True">
                                <Setter TargetName="cbBd" Property="BorderBrush" Value="#8A0E0C"/>
                                <Setter TargetName="cbArrow" Property="Stroke" Value="#8A0E0C"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter TargetName="cbBd" Property="Background" Value="#f1f3f7"/>
                                <Setter TargetName="cbBd" Property="BorderBrush" Value="#e6e9f2"/>
                                <Setter TargetName="cbArrow" Property="Stroke" Value="#a7aebe"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style TargetType="ComboBox">
            <Setter Property="Foreground" Value="#16192b"/>
            <Setter Property="MinHeight" Value="32"/>
            <Setter Property="Padding" Value="11,0,30,0"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="MaxDropDownHeight" Value="360"/>
            <Setter Property="SnapsToDevicePixels" Value="True"/>
            <Setter Property="ScrollViewer.HorizontalScrollBarVisibility" Value="Disabled"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ComboBox">
                        <Grid>
                            <ToggleButton x:Name="PART_ToggleButton" Style="{StaticResource ComboToggleStyle}" IsChecked="{Binding IsDropDownOpen, Mode=TwoWay, RelativeSource={RelativeSource TemplatedParent}}"/>
                            <ContentPresenter x:Name="contentSite" Content="{TemplateBinding SelectionBoxItem}" ContentTemplate="{TemplateBinding SelectionBoxItemTemplate}" ContentTemplateSelector="{TemplateBinding ItemTemplateSelector}" Margin="{TemplateBinding Padding}" VerticalAlignment="Center" HorizontalAlignment="Left" IsHitTestVisible="False"/>
                            <Popup x:Name="PART_Popup" Placement="Bottom" IsOpen="{TemplateBinding IsDropDownOpen}" AllowsTransparency="True" Focusable="False" PopupAnimation="Fade">
                                <Border x:Name="popupBd" Background="#ffffff" BorderBrush="#e6e9f2" BorderThickness="1" CornerRadius="8" MinWidth="{TemplateBinding ActualWidth}" MaxHeight="{TemplateBinding MaxDropDownHeight}" Margin="0,4,10,12" SnapsToDevicePixels="True">
                                    <Border.Effect>
                                        <DropShadowEffect Color="#3D1210" Opacity="0.18" BlurRadius="16" ShadowDepth="3"/>
                                    </Border.Effect>
                                    <ScrollViewer Margin="4" SnapsToDevicePixels="True">
                                        <ItemsPresenter KeyboardNavigation.DirectionalNavigation="Contained"/>
                                    </ScrollViewer>
                                </Border>
                            </Popup>
                        </Grid>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Foreground" Value="#a7aebe"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style TargetType="ComboBoxItem">
            <Setter Property="Padding" Value="10,7"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="SnapsToDevicePixels" Value="True"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ComboBoxItem">
                        <Border x:Name="itemBd" Background="Transparent" CornerRadius="5" Padding="{TemplateBinding Padding}" SnapsToDevicePixels="True">
                            <ContentPresenter/>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsSelected" Value="True">
                                <Setter TargetName="itemBd" Property="Background" Value="#F7E3E2"/>
                                <Setter Property="Foreground" Value="#8A0E0C"/>
                                <Setter Property="FontWeight" Value="SemiBold"/>
                            </Trigger>
                            <Trigger Property="IsHighlighted" Value="True">
                                <Setter TargetName="itemBd" Property="Background" Value="#8A0E0C"/>
                                <Setter Property="Foreground" Value="#ffffff"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Check box -->
        <Style TargetType="CheckBox">
            <Setter Property="Foreground" Value="#1f2637"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="SnapsToDevicePixels" Value="True"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="CheckBox">
                        <StackPanel Orientation="Horizontal" Background="Transparent">
                            <Border x:Name="box" Width="18" Height="18" CornerRadius="5" Background="#ffffff" BorderBrush="#cbd2e0" BorderThickness="1.4" VerticalAlignment="Center" SnapsToDevicePixels="True">
                                <Path x:Name="check" Data="M 0 3.6 L 3.4 7 L 9 0.8" Stroke="#ffffff" StrokeThickness="1.9" StrokeStartLineCap="Round" StrokeEndLineCap="Round" StrokeLineJoin="Round" HorizontalAlignment="Center" VerticalAlignment="Center" Visibility="Collapsed"/>
                            </Border>
                            <ContentPresenter Margin="8,0,0,0" VerticalAlignment="Center"/>
                        </StackPanel>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="box" Property="BorderBrush" Value="#D99795"/>
                            </Trigger>
                            <Trigger Property="IsChecked" Value="True">
                                <Setter TargetName="box" Property="Background" Value="#8A0E0C"/>
                                <Setter TargetName="box" Property="BorderBrush" Value="#8A0E0C"/>
                                <Setter TargetName="check" Property="Visibility" Value="Visible"/>
                            </Trigger>
                            <Trigger Property="IsEnabled" Value="False">
                                <Setter Property="Opacity" Value="0.5"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Tabs: flat header strip with an accent underline instead of folder tabs. -->
        <Style TargetType="TabControl">
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Padding" Value="0"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TabControl">
                        <Grid SnapsToDevicePixels="True">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="Auto"/>
                                <RowDefinition Height="*"/>
                            </Grid.RowDefinitions>
                            <Border Grid.Row="0" BorderBrush="#e0e4ee" BorderThickness="0,0,0,1">
                                <TabPanel x:Name="HeaderPanel" IsItemsHost="True" Panel.ZIndex="1" KeyboardNavigation.TabIndex="1"/>
                            </Border>
                            <!-- Deliberately NOT a ScrollViewer here. Every tab has a Height="*" row
                                 holding a virtualizing DataGrid (see the DataGrid style below,
                                 "CanContentScroll must stay True to keep UI virtualization on"); a
                                 ScrollViewer measures its child with infinite available height, so a
                                 "*" row loses its bound and the DataGrid inside renders every row
                                 unvirtualized - silently reintroducing the exact slow-CSV-import bug
                                 fixed in v4.2, just one level up. Small screens are handled instead
                                 by the zoom control (a LayoutTransform on the whole window, applied
                                 after layout/measure, so it never touches how much space a "*" row
                                 or the grid inside it computes) and by the window's own lower
                                 MinHeight/MinWidth plus start-up sizing that fits the actual screen. -->
                            <ContentPresenter Grid.Row="1" x:Name="PART_SelectedContentHost" ContentSource="SelectedContent" Margin="{TemplateBinding Padding}"/>
                        </Grid>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <Style TargetType="TabItem">
            <Setter Property="Padding" Value="16,10"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Cursor" Value="Hand"/>
            <Setter Property="SnapsToDevicePixels" Value="True"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="TabItem">
                        <Grid x:Name="tabRoot" Background="Transparent">
                            <Grid.RowDefinitions>
                                <RowDefinition Height="*"/>
                                <RowDefinition Height="3"/>
                            </Grid.RowDefinitions>
                            <Border x:Name="tabHover" Grid.Row="0" Background="Transparent" CornerRadius="6,6,0,0"/>
                            <ContentPresenter x:Name="tabContent" Grid.Row="0" ContentSource="Header" Margin="{TemplateBinding Padding}" HorizontalAlignment="Center" VerticalAlignment="Center" TextElement.Foreground="#5a6376"/>
                            <Border x:Name="tabUnderline" Grid.Row="1" Background="Transparent" CornerRadius="2" Margin="8,0"/>
                        </Grid>
                        <ControlTemplate.Triggers>
                            <MultiTrigger>
                                <MultiTrigger.Conditions>
                                    <Condition Property="IsSelected" Value="False"/>
                                    <Condition Property="IsMouseOver" Value="True"/>
                                </MultiTrigger.Conditions>
                                <Setter TargetName="tabHover" Property="Background" Value="#F7E3E2"/>
                                <Setter TargetName="tabContent" Property="TextElement.Foreground" Value="#16192b"/>
                            </MultiTrigger>
                            <Trigger Property="IsSelected" Value="True">
                                <Setter TargetName="tabContent" Property="TextElement.Foreground" Value="#8A0E0C"/>
                                <Setter TargetName="tabUnderline" Property="Background" Value="#8A0E0C"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Data grid: light header, no vertical rules, tinted hover and selection. -->
        <Style TargetType="DataGrid">
            <!-- CanContentScroll must stay True to keep UI virtualization on. With it False the grid
                 renders every row at once, which makes large imports (thousands of rows) very slow.
                 Virtualization with container recycling keeps even 6000+ row imports responsive. -->
            <Setter Property="ScrollViewer.CanContentScroll" Value="True"/>
            <Setter Property="EnableRowVirtualization" Value="True"/>
            <Setter Property="EnableColumnVirtualization" Value="True"/>
            <Setter Property="VirtualizingPanel.IsVirtualizing" Value="True"/>
            <Setter Property="VirtualizingPanel.VirtualizationMode" Value="Recycling"/>
            <Setter Property="VirtualizingPanel.ScrollUnit" Value="Pixel"/>
            <Setter Property="Background" Value="#ffffff"/>
            <Setter Property="RowBackground" Value="#ffffff"/>
            <Setter Property="AlternatingRowBackground" Value="#fafbfe"/>
            <Setter Property="GridLinesVisibility" Value="Horizontal"/>
            <Setter Property="HorizontalGridLinesBrush" Value="#eef0f6"/>
            <Setter Property="BorderBrush" Value="#e6e9f2"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="HeadersVisibility" Value="Column"/>
            <Setter Property="RowHeight" Value="32"/>
            <Setter Property="ColumnHeaderHeight" Value="38"/>
        </Style>
        <Style TargetType="DataGridColumnHeader">
            <Setter Property="Background" Value="#f5f7fb"/>
            <Setter Property="Foreground" Value="#5a6376"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="Padding" Value="9,0"/>
            <Setter Property="SnapsToDevicePixels" Value="True"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="DataGridColumnHeader">
                        <Grid>
                            <Border x:Name="hdrBd" Background="{TemplateBinding Background}" BorderBrush="#e0e4ee" BorderThickness="0,0,0,1" Padding="{TemplateBinding Padding}" SnapsToDevicePixels="True">
                                <ContentPresenter VerticalAlignment="Center" HorizontalAlignment="Left"/>
                            </Border>
                            <Thumb x:Name="PART_LeftHeaderGripper" HorizontalAlignment="Left" Width="8" Cursor="SizeWE">
                                <Thumb.Template>
                                    <ControlTemplate TargetType="Thumb">
                                        <Border Background="Transparent"/>
                                    </ControlTemplate>
                                </Thumb.Template>
                            </Thumb>
                            <Thumb x:Name="PART_RightHeaderGripper" HorizontalAlignment="Right" Width="8" Cursor="SizeWE">
                                <Thumb.Template>
                                    <ControlTemplate TargetType="Thumb">
                                        <Border Background="Transparent"/>
                                    </ControlTemplate>
                                </Thumb.Template>
                            </Thumb>
                        </Grid>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsMouseOver" Value="True">
                                <Setter TargetName="hdrBd" Property="Background" Value="#eceff7"/>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>
        <Style TargetType="DataGridRow">
            <Style.Triggers>
                <Trigger Property="IsMouseOver" Value="True">
                    <Setter Property="Background" Value="#FAEBEA"/>
                </Trigger>
            </Style.Triggers>
        </Style>
        <Style TargetType="DataGridCell">
            <Setter Property="Padding" Value="9,2"/>
            <Setter Property="Background" Value="Transparent"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Foreground" Value="#1f2637"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="DataGridCell">
                        <Border Padding="{TemplateBinding Padding}" Background="{TemplateBinding Background}" BorderBrush="{TemplateBinding BorderBrush}" BorderThickness="{TemplateBinding BorderThickness}" SnapsToDevicePixels="True">
                            <ContentPresenter VerticalAlignment="Center"/>
                        </Border>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
            <Style.Triggers>
                <Trigger Property="IsSelected" Value="True">
                    <Setter Property="Background" Value="#F2C9C7"/>
                    <Setter Property="Foreground" Value="#3D0F0D"/>
                </Trigger>
            </Style.Triggers>
        </Style>

        <!-- Progress: slim accent bar with a real indeterminate sweep. -->
        <Style TargetType="ProgressBar">
            <Setter Property="Background" Value="#e2e7f1"/>
            <Setter Property="Foreground" Value="#8A0E0C"/>
            <Setter Property="BorderThickness" Value="0"/>
            <Setter Property="Template">
                <Setter.Value>
                    <ControlTemplate TargetType="ProgressBar">
                        <Border x:Name="progTrack" Background="{TemplateBinding Background}" CornerRadius="4" SnapsToDevicePixels="True" ClipToBounds="True">
                            <Grid x:Name="PART_Track" ClipToBounds="True">
                                <Rectangle x:Name="PART_Indicator" Fill="{TemplateBinding Foreground}" RadiusX="4" RadiusY="4" HorizontalAlignment="Left"/>
                                <Rectangle x:Name="progGlow" Fill="{TemplateBinding Foreground}" RadiusX="4" RadiusY="4" Width="72" HorizontalAlignment="Left" Visibility="Collapsed">
                                    <Rectangle.RenderTransform>
                                        <TranslateTransform x:Name="progGlowMove" X="0"/>
                                    </Rectangle.RenderTransform>
                                </Rectangle>
                            </Grid>
                        </Border>
                        <ControlTemplate.Triggers>
                            <Trigger Property="IsIndeterminate" Value="True">
                                <Setter TargetName="PART_Indicator" Property="Visibility" Value="Collapsed"/>
                                <Setter TargetName="progGlow" Property="Visibility" Value="Visible"/>
                                <Trigger.EnterActions>
                                    <BeginStoryboard Name="progSweep">
                                        <Storyboard RepeatBehavior="Forever">
                                            <DoubleAnimation Storyboard.TargetName="progGlowMove" Storyboard.TargetProperty="X" From="-80" To="230" Duration="0:0:1.3"/>
                                        </Storyboard>
                                    </BeginStoryboard>
                                </Trigger.EnterActions>
                                <Trigger.ExitActions>
                                    <StopStoryboard BeginStoryboardName="progSweep"/>
                                </Trigger.ExitActions>
                            </Trigger>
                        </ControlTemplate.Triggers>
                    </ControlTemplate>
                </Setter.Value>
            </Setter>
        </Style>

        <!-- Reusable surfaces -->
        <Style x:Key="CardPanel" TargetType="Border">
            <Setter Property="Background" Value="#ffffff"/>
            <Setter Property="BorderBrush" Value="#e6e9f2"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="CornerRadius" Value="10"/>
            <Setter Property="Padding" Value="18"/>
            <Setter Property="Margin" Value="0,14,0,0"/>
            <Setter Property="Effect">
                <Setter.Value>
                    <DropShadowEffect Color="#3D1210" Opacity="0.07" BlurRadius="14" ShadowDepth="2"/>
                </Setter.Value>
            </Setter>
        </Style>

        <Style x:Key="InfoBar" TargetType="Border">
            <Setter Property="Background" Value="#FAEBEA"/>
            <Setter Property="BorderBrush" Value="#EEC2C0"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="CornerRadius" Value="8"/>
            <Setter Property="Padding" Value="14,11"/>
        </Style>

        <Style x:Key="ToolBarPanel" TargetType="Border">
            <Setter Property="Background" Value="#f8fafd"/>
            <Setter Property="BorderBrush" Value="#e6e9f2"/>
            <Setter Property="BorderThickness" Value="1"/>
            <Setter Property="CornerRadius" Value="8"/>
            <Setter Property="Padding" Value="11,8"/>
        </Style>

        <Style x:Key="FieldLabel" TargetType="TextBlock">
            <Setter Property="Foreground" Value="#5a6376"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="VerticalAlignment" Value="Center"/>
        </Style>

        <Style x:Key="SectionHeading" TargetType="TextBlock">
            <Setter Property="Foreground" Value="#16192b"/>
            <Setter Property="FontWeight" Value="SemiBold"/>
            <Setter Property="FontSize" Value="14"/>
        </Style>

        <Style x:Key="HintText" TargetType="TextBlock">
            <Setter Property="Foreground" Value="#8a92a5"/>
            <Setter Property="FontSize" Value="12"/>
            <Setter Property="VerticalAlignment" Value="Center"/>
            <Setter Property="TextWrapping" Value="Wrap"/>
        </Style>
    </Window.Resources>

    <Grid Name="rootGrid">
        <Grid.RowDefinitions>
            <RowDefinition Height="Auto"/>
            <RowDefinition Height="*"/>
            <RowDefinition Height="Auto"/>
        </Grid.RowDefinitions>

        <Border Grid.Row="0" Padding="24,18">
            <Border.Background>
                <LinearGradientBrush StartPoint="0,0" EndPoint="1,1">
                    <GradientStop Color="#8A0E0C" Offset="0"/>
                    <GradientStop Color="#D01412" Offset="1"/>
                </LinearGradientBrush>
            </Border.Background>
            <Grid>
                <Grid.ColumnDefinitions>
                    <ColumnDefinition Width="*"/>
                    <ColumnDefinition Width="Auto"/>
                </Grid.ColumnDefinitions>
                <StackPanel Grid.Column="0" Orientation="Horizontal" VerticalAlignment="Center">
                    <Image Name="imgBrandLogo" Width="46" Height="46" Stretch="Uniform" VerticalAlignment="Center" SnapsToDevicePixels="True"/>
                    <StackPanel VerticalAlignment="Center" Margin="14,0,0,0">
                        <StackPanel Orientation="Horizontal">
                            <TextBlock Text="ZeroAdmin" Foreground="White" FontSize="21" FontWeight="SemiBold" VerticalAlignment="Center"/>
                            <Border Background="#33ffffff" BorderBrush="#59ffffff" BorderThickness="1" CornerRadius="9" Padding="8,2" Margin="10,2,0,0" VerticalAlignment="Center">
                                <TextBlock Text="COMMUNITY EDITION" Foreground="White" FontSize="10" FontWeight="Bold"/>
                            </Border>
                        </StackPanel>
                        <TextBlock Text="Helps you build the EPM rules that eliminate local administrative usage in your environment." Foreground="#FAE8E7" FontSize="12" Margin="0,4,0,0"/>
                    </StackPanel>
                </StackPanel>
                <StackPanel Grid.Column="1" VerticalAlignment="Center">
                    <StackPanel Orientation="Horizontal" HorizontalAlignment="Right">
                        <TextBlock Text="Graph auth" VerticalAlignment="Center" Margin="0,0,8,0" Foreground="#FAE8E7" FontSize="12" FontWeight="SemiBold"/>
                        <ComboBox Name="cbGraphAuthMode" Width="120" SelectedIndex="0" VerticalAlignment="Center">
                            <ComboBoxItem Content="Interactive"/>
                            <ComboBoxItem Content="DeviceCode"/>
                        </ComboBox>
                        <Button Name="btnConnectGraph" Content="Sign in" Width="86" Margin="8,0,0,0" Style="{StaticResource HeaderButton}"/>
                        <Button Name="btnDisconnectGraph" Content="Sign out" Width="86" Margin="8,0,0,0" IsEnabled="False" Style="{StaticResource HeaderButton}"/>
                    </StackPanel>
                    <Border Background="#26ffffff" BorderBrush="#40ffffff" BorderThickness="1" CornerRadius="11" Padding="10,4" HorizontalAlignment="Right" Margin="0,9,0,0">
                        <StackPanel Orientation="Horizontal">
                            <Ellipse Name="elConnState" Width="9" Height="9" Fill="#c0392b" VerticalAlignment="Center" Margin="0,0,7,0"/>
                            <TextBlock Name="txtConnState" Text="Not signed in" VerticalAlignment="Center" Foreground="White" FontSize="12" FontWeight="SemiBold"/>
                        </StackPanel>
                    </Border>
                </StackPanel>
            </Grid>
        </Border>

        <TabControl Grid.Row="1" Margin="20,16,20,0">
            <TabItem Header="Audit Import">
                <Border Style="{StaticResource CardPanel}">
                    <Grid>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="*" MinHeight="120"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                        </Grid.RowDefinitions>
                        <Border Grid.Row="0" Style="{StaticResource ToolBarPanel}" Margin="0,0,0,12">
                            <StackPanel>
                                <WrapPanel Orientation="Horizontal">
                                    <TextBlock Text="From Intune" Style="{StaticResource FieldLabel}" Margin="0,4,10,4"/>
                                    <ComboBox Name="cbElevationRange" Width="150" DisplayMemberPath="DisplayName" SelectedValuePath="Value" Margin="0,4,0,4"/>
                                    <CheckBox Name="chkUnmanagedOnly" Content="Unmanaged elevations only" IsChecked="True" VerticalAlignment="Center" Margin="14,4,0,4"/>
                                    <Button Name="btnFetchElevations" Content="Fetch elevation report" Width="180" Margin="14,4,0,4" Style="{StaticResource AccentButton}"/>
                                    <TextBlock Text="Same report the Intune portal shows. No CSV export needed." Style="{StaticResource HintText}" Margin="14,4,0,4"/>
                                </WrapPanel>
                                <Border Height="1" Background="#e6e9f2" Margin="0,9,0,9"/>
                                <WrapPanel Orientation="Horizontal">
                                    <TextBlock Text="Or from CSV" Style="{StaticResource FieldLabel}" Margin="0,4,10,4"/>
                                    <TextBox Name="txtCsvPath" Width="560" Margin="0,4,0,4"/>
                                    <Button Name="btnBrowseCsv" Content="Browse" Width="90" Margin="8,4,0,4"/>
                                    <Button Name="btnImportCsv" Content="Import" Width="90" Margin="8,4,0,4"/>
                                </WrapPanel>
                            </StackPanel>
                        </Border>
                        <Border Grid.Row="1" Style="{StaticResource ToolBarPanel}" Margin="0,0,0,12">
                            <WrapPanel Orientation="Horizontal">
                                <TextBlock Text="Search" Style="{StaticResource FieldLabel}" Margin="0,4,8,4"/>
                                <TextBox Name="txtCandidateSearch" Width="320" Margin="0,4,0,4"/>
                                <TextBlock Name="txtCandidateCount" Text="" Style="{StaticResource HintText}" Margin="12,4,0,4"/>
                            </WrapPanel>
                        </Border>
                        <Border Grid.Row="2" Style="{StaticResource InfoBar}" Margin="0,0,0,12">
                            <StackPanel>
                                <TextBlock Text="Mostly read-only: it turns audit data into candidates you can analyse." Foreground="#8A0E0C" FontWeight="SemiBold" TextWrapping="Wrap"/>
                                <TextBlock Text="Audit data describes what was elevated, not the binary itself, so it cannot produce a trustworthy publisher certificate - that still requires the real file, on the Scan Path tab. The hash is different: it was computed by the EPM agent from the actual binary at the moment it elevated, so it is exact. Mark one row below to add it straight to a policy as a hash rule." Foreground="#5C2624" TextWrapping="Wrap" Margin="0,5,0,0"/>
                            </StackPanel>
                        </Border>
                        <DataGrid Name="dgCandidates" Grid.Row="3" AutoGenerateColumns="True" IsReadOnly="True" SelectionMode="Extended" SelectionUnit="FullRow"/>

                        <Border Grid.Row="4" Style="{StaticResource ToolBarPanel}" Margin="0,10,0,0">
                            <StackPanel>
                                <TextBlock Text="Add the marked row as a hash rule" Style="{StaticResource SectionHeading}" Margin="0,0,0,6"/>
                                <WrapPanel Orientation="Horizontal">
                                    <Button Name="btnLoadAuditPolicies" Content="Load policies and options" Width="185" Margin="0,4,0,4"/>
                                    <TextBlock Text="Target policy" Style="{StaticResource FieldLabel}" Margin="14,4,8,4"/>
                                    <ComboBox Name="cbAuditPolicy" Width="260" DisplayMemberPath="DisplayName" SelectedValuePath="Id" Margin="0,4,0,4"/>
                                    <TextBlock Text="Elevation type" Style="{StaticResource FieldLabel}" Margin="14,4,8,4"/>
                                    <ComboBox Name="cbAuditElevationType" Width="165" DisplayMemberPath="DisplayName" SelectedValuePath="Value" Margin="0,4,0,4"/>
                                    <TextBlock Text="Child process" Style="{StaticResource FieldLabel}" Margin="14,4,8,4"/>
                                    <ComboBox Name="cbAuditChildProcess" Width="155" DisplayMemberPath="DisplayName" SelectedValuePath="Value" Margin="0,4,0,4"/>
                                    <Button Name="btnCreateAuditRule" Content="Create rule" Width="130" Margin="16,4,0,4" Style="{StaticResource AccentButton}"/>
                                </WrapPanel>
                            </StackPanel>
                        </Border>

                        <TextBox Name="txtBuildOutput" Grid.Row="5" Height="84" Margin="0,12,0,0" AcceptsReturn="True" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" Style="{StaticResource ConsoleTextBox}"/>
                    </Grid>
                </Border>
            </TabItem>

            <TabItem Header="Coverage Analysis">
                <Border Style="{StaticResource CardPanel}">
                    <Grid>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="*"/>
                        </Grid.RowDefinitions>
                        <StackPanel Grid.Row="0" Orientation="Horizontal" Margin="0,0,0,12">
                            <Button Name="btnRunCoverage" Content="Run Coverage Analysis" Width="190" HorizontalAlignment="Left" Style="{StaticResource AccentButton}"/>
                            <Button Name="btnExportUncovered" Content="Export Uncovered (CSV)" Width="190" Margin="8,0,0,0" IsEnabled="False"/>
                            <TextBlock Text="Scores imported elevations against existing EPM persona rules and recommends a persona per user." Style="{StaticResource HintText}" Margin="16,0,0,0" Width="420"/>
                        </StackPanel>
                        <Border Grid.Row="1" Name="brdCoverageScore" Background="#FAEBEA" BorderBrush="#EEC2C0" BorderThickness="1" CornerRadius="8" Padding="14,12" Margin="0,0,0,14">
                            <TextBlock Name="txtCoverageScore" Text="Import an audit CSV on the Audit Import tab, then run the analysis to see the coverage score." FontSize="15" FontWeight="SemiBold" Foreground="#8A0E0C" TextWrapping="Wrap"/>
                        </Border>

                        <TextBlock Grid.Row="2" Text="Coverage by persona" Style="{StaticResource SectionHeading}" Margin="0,0,0,8"/>
                        <ScrollViewer Grid.Row="3" HorizontalScrollBarVisibility="Auto" VerticalScrollBarVisibility="Disabled" Margin="0,0,0,14">
                            <ItemsControl Name="icPersonaCards">
                                <ItemsControl.ItemsPanel>
                                    <ItemsPanelTemplate>
                                        <WrapPanel Orientation="Horizontal"/>
                                    </ItemsPanelTemplate>
                                </ItemsControl.ItemsPanel>
                                <ItemsControl.ItemTemplate>
                                    <DataTemplate>
                                        <Border Background="White" BorderBrush="#e6e9f2" BorderThickness="1" CornerRadius="10" Margin="0,2,12,10" Width="262">
                                            <Border.Effect>
                                                <DropShadowEffect Color="#3D1210" Opacity="0.08" BlurRadius="12" ShadowDepth="2"/>
                                            </Border.Effect>
                                            <StackPanel>
                                                <Border Height="5" Background="{Binding PersonaCoverageColor}" CornerRadius="10,10,0,0"/>
                                                <StackPanel Margin="16,14,16,16">
                                                    <TextBlock Text="{Binding Persona}" FontSize="16" FontWeight="SemiBold" Foreground="#8A0E0C" TextTrimming="CharacterEllipsis" ToolTip="{Binding PolicyName}"/>
                                                    <Border Background="{Binding GlobalShareColor}" CornerRadius="10" Padding="9,3" HorizontalAlignment="Left" Margin="0,10,0,0">
                                                        <TextBlock Text="{Binding GlobalSharePercent, StringFormat='{}{0}% of all discovered elevations'}" FontSize="11" FontWeight="SemiBold" Foreground="White"/>
                                                    </Border>
                                                    <Border Background="{Binding PersonaCoverageColor}" CornerRadius="10" Padding="9,3" HorizontalAlignment="Left" Margin="0,6,0,0">
                                                        <TextBlock Text="{Binding PersonaCoveragePercent, StringFormat='{}{0}% covered within assigned elevations'}" FontSize="11" FontWeight="SemiBold" Foreground="White"/>
                                                    </Border>
                                                    <Border Height="1" Background="#eef0f6" Margin="0,12,0,10"/>
                                                    <StackPanel Orientation="Horizontal">
                                                        <TextBlock Text="Elevations" FontSize="12" Foreground="#8a92a5" Width="94"/>
                                                        <TextBlock Text="{Binding ElevationsCovered}" FontSize="13" FontWeight="SemiBold"/>
                                                    </StackPanel>
                                                    <StackPanel Orientation="Horizontal" Margin="0,4,0,0">
                                                        <TextBlock Text="Assigned" FontSize="12" Foreground="#8a92a5" Width="94"/>
                                                        <TextBlock Text="{Binding AssignedElevations}" FontSize="13" FontWeight="SemiBold"/>
                                                    </StackPanel>
                                                    <StackPanel Orientation="Horizontal" Margin="0,4,0,0">
                                                        <TextBlock Text="Existing rules" FontSize="12" Foreground="#8a92a5" Width="94"/>
                                                        <TextBlock Text="{Binding ExistingRules}" FontSize="13" FontWeight="SemiBold"/>
                                                    </StackPanel>
                                                </StackPanel>
                                            </StackPanel>
                                        </Border>
                                    </DataTemplate>
                                </ItemsControl.ItemTemplate>
                            </ItemsControl>
                        </ScrollViewer>

                        <TabControl Grid.Row="4">
                            <TabItem Header="Recommended persona per user">
                                <DataGrid Name="dgUserRecommendation" AutoGenerateColumns="True" IsReadOnly="True" Margin="0,12,0,0"/>
                            </TabItem>
                            <TabItem Header="Uncovered elevations">
                                <Grid Margin="0,12,0,0">
                                    <Grid.RowDefinitions>
                                        <RowDefinition Height="Auto"/>
                                        <RowDefinition Height="*"/>
                                    </Grid.RowDefinitions>
                                    <TextBlock Name="txtUncoveredSummary" Grid.Row="0" Text="Run the analysis to see which applications are not covered by any existing persona rule." Style="{StaticResource HintText}" Margin="0,0,0,10"/>
                                    <DataGrid Name="dgUncovered" Grid.Row="1" AutoGenerateColumns="True" IsReadOnly="True"/>
                                </Grid>
                            </TabItem>
                        </TabControl>
                    </Grid>
                </Border>
            </TabItem>

            <TabItem Header="Replicate and Reusable Settings">
                <Border Style="{StaticResource CardPanel}">
                    <Grid>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="*" MinHeight="160"/>
                        </Grid.RowDefinitions>

                        <Border Grid.Row="0" Style="{StaticResource ToolBarPanel}" Margin="0,0,0,10">
                            <StackPanel>
                                <TextBlock Text="Replicate a rule between policies" Style="{StaticResource SectionHeading}" Margin="0,0,0,6"/>
                                <WrapPanel Orientation="Horizontal">
                                    <Button Name="btnLoadPoliciesReplicate" Content="Load EPM Policies" Width="150" Margin="0,4,0,4"/>
                                    <TextBlock Text="Source" Style="{StaticResource FieldLabel}" Margin="14,4,8,4"/>
                                    <ComboBox Name="cbSourcePolicy" Width="260" DisplayMemberPath="DisplayName" SelectedValuePath="Id" Margin="0,4,0,4"/>
                                    <TextBlock Text="Target" Style="{StaticResource FieldLabel}" Margin="14,4,8,4"/>
                                    <ComboBox Name="cbTargetPolicy" Width="260" DisplayMemberPath="DisplayName" SelectedValuePath="Id" Margin="0,4,0,4"/>
                                </WrapPanel>
                                <WrapPanel Orientation="Horizontal">
                                    <Button Name="btnLoadSourceRules" Content="Load Source Rules" Width="150" Margin="0,6,0,4"/>
                                    <TextBlock Text="Rule" Style="{StaticResource FieldLabel}" Margin="14,6,8,4"/>
                                    <ComboBox Name="cbSourceRule" Width="430" DisplayMemberPath="RuleName" SelectedValuePath="RuleName" Margin="0,6,0,4"/>
                                    <Button Name="btnReplicateRule" Content="Replicate" Width="130" Margin="10,6,0,4" Style="{StaticResource AccentButton}"/>
                                </WrapPanel>
                            </StackPanel>
                        </Border>

                        <TextBox Name="txtReplicateOutput" Grid.Row="1" Height="80" Margin="0,0,0,14" AcceptsReturn="True" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" Style="{StaticResource ConsoleTextBox}"/>

                        <Border Grid.Row="2" Height="1" Background="#e6e9f2" Margin="0,0,0,14"/>

                        <TextBlock Grid.Row="3" Text="Reusable settings" Style="{StaticResource SectionHeading}" Margin="0,0,0,6"/>

                        <Border Grid.Row="4" Style="{StaticResource ToolBarPanel}" Margin="0,0,0,10">
                            <WrapPanel Orientation="Horizontal">
                                <Button Name="btnLoadReusable" Content="Load Reusable Settings" Width="180" Margin="0,4,0,4"/>
                                <ComboBox Name="cbReusable" Width="480" Margin="10,4,0,4" DisplayMemberPath="ListLabel" SelectedValuePath="Id"/>
                                <Button Name="btnFindReusableUsage" Content="Show Usage" Width="130" Margin="10,4,0,4" Style="{StaticResource AccentButton}"/>
                            </WrapPanel>
                        </Border>

                        <DataGrid Name="dgReusableUsage" Grid.Row="5" AutoGenerateColumns="True" IsReadOnly="True"/>
                    </Grid>
                </Border>
            </TabItem>

            <TabItem Header="Scan Path">
                <Border Style="{StaticResource CardPanel}">
                    <Grid>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="*" MinHeight="120"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="92"/>
                        </Grid.RowDefinitions>

                        <!-- The scan toolbars hold a lot of controls, so they wrap instead of running
                             off the edge of the card when the window is narrow. -->
                        <Border Grid.Row="0" Style="{StaticResource ToolBarPanel}" Margin="0,0,0,10">
                            <StackPanel>
                                <TextBlock Text="1. Scan a folder for the files you want to cover" Style="{StaticResource SectionHeading}" Margin="0,0,0,6"/>
                                <WrapPanel Orientation="Horizontal">
                                    <TextBlock Text="Path" Style="{StaticResource FieldLabel}" Margin="0,4,8,4"/>
                                    <TextBox Name="txtScanPath" Width="400" VerticalAlignment="Center" Margin="0,4,0,4"/>
                                    <Button Name="btnBrowseScanPath" Content="Browse" Width="90" Margin="8,4,0,4"/>
                                    <CheckBox Name="chkScanExe" Content=".exe" IsChecked="True" VerticalAlignment="Center" Margin="16,4,0,4"/>
                                    <CheckBox Name="chkScanMsi" Content=".msi" IsChecked="True" VerticalAlignment="Center" Margin="10,4,0,4"/>
                                    <CheckBox Name="chkScanPs1" Content=".ps1" IsChecked="True" VerticalAlignment="Center" Margin="10,4,0,4"/>
                                    <CheckBox Name="chkScanRecurse" Content="Recurse" IsChecked="True" VerticalAlignment="Center" Margin="16,4,0,4"/>
                                    <Button Name="btnScanPath" Content="Scan" Width="90" Margin="16,4,0,4" Style="{StaticResource AccentButton}"/>
                                    <TextBlock Name="txtScanCount" Text="0 item(s)" Style="{StaticResource HintText}" Margin="14,4,0,4"/>
                                </WrapPanel>
                            </StackPanel>
                        </Border>

                        <DataGrid Name="dgScanResults" Grid.Row="1" AutoGenerateColumns="False" IsReadOnly="True" SelectionMode="Extended" SelectionUnit="FullRow" ClipboardCopyMode="IncludeHeader">
                            <DataGrid.ContextMenu>
                                <ContextMenu>
                                    <MenuItem Name="mnuScanCopyRow" Header="Copy row(s)"/>
                                    <MenuItem Name="mnuScanCopyCell" Header="Copy cell"/>
                                </ContextMenu>
                            </DataGrid.ContextMenu>
                            <DataGrid.Columns>
                                <DataGridTextColumn Header="File" Binding="{Binding FileName}" Width="160"/>
                                <DataGridTextColumn Header="Extracted" Binding="{Binding Extracted}" Width="90"/>
                                <DataGridTextColumn Header="Signed" Binding="{Binding IsSigned}" Width="72"/>
                                <DataGridTextColumn Header="Publisher" Binding="{Binding Publisher}" Width="200"/>
                                <DataGridTextColumn Header="Product" Binding="{Binding Product}" Width="140"/>
                                <DataGridTextColumn Header="Internal name" Binding="{Binding InternalName}" Width="140"/>
                                <DataGridTextColumn Header="Match" Binding="{Binding MatchType}" Width="96"/>
                                <DataGridTextColumn Header="File hash" Binding="{Binding FileHash}" Width="190"/>
                                <DataGridTextColumn Header="Path" Binding="{Binding FilePath}" Width="*"/>
                            </DataGrid.Columns>
                        </DataGrid>

                        <Border Grid.Row="2" Style="{StaticResource ToolBarPanel}" Margin="0,10,0,0">
                            <StackPanel>
                                <TextBlock Text="2. Extract the signing certificate, pick the one to reuse, and upload it to Intune" Style="{StaticResource SectionHeading}" Margin="0,0,0,6"/>
                                <WrapPanel Orientation="Horizontal">
                                    <Button Name="btnExtractCert" Content="Extract certificate(s)" Width="170" Margin="0,4,0,4"/>
                                    <Button Name="btnExtractHash" Content="Extract hash" Width="130" Margin="8,4,0,4"/>
                                    <Button Name="btnCheckReusableMatch" Content="Check if already in Intune" Width="190" Margin="8,4,0,4"/>
                                    <TextBlock Name="txtExtractFolder" Text="" Style="{StaticResource HintText}" Margin="16,4,0,4"/>
                                </WrapPanel>
                                <WrapPanel Orientation="Horizontal">
                                    <TextBlock Text="Certificate" Style="{StaticResource FieldLabel}" Margin="0,6,8,4"/>
                                    <ComboBox Name="cbExtractedCertificate" Width="430" DisplayMemberPath="ListLabel" Margin="0,6,0,4"/>
                                    <TextBlock Text="Name" Style="{StaticResource FieldLabel}" Margin="16,6,8,4"/>
                                    <TextBox Name="txtReusableName" Width="230" VerticalAlignment="Center" Margin="0,6,0,4"/>
                                    <Button Name="btnUploadReusable" Content="Upload to Intune" Width="150" Margin="8,6,0,4" IsEnabled="False"/>
                                </WrapPanel>
                            </StackPanel>
                        </Border>

                        <Border Grid.Row="3" Style="{StaticResource ToolBarPanel}" Margin="0,8,0,0">
                            <StackPanel>
                                <TextBlock Text="3. Choose the target policy and create the rule" Style="{StaticResource SectionHeading}" Margin="0,0,0,6"/>
                                <WrapPanel Orientation="Horizontal">
                                    <Button Name="btnLoadScanPolicies" Content="Load policies and options" Width="180" Margin="0,4,0,4"/>
                                    <TextBlock Text="Target policy" Style="{StaticResource FieldLabel}" Margin="16,4,8,4"/>
                                    <ComboBox Name="cbScanPolicy" Width="270" DisplayMemberPath="DisplayName" SelectedValuePath="Id" Margin="0,4,0,4"/>
                                    <TextBlock Text="Match type" Style="{StaticResource FieldLabel}" Margin="14,4,8,4"/>
                                    <ComboBox Name="cbScanMatchType" Width="130" SelectedIndex="0" DisplayMemberPath="DisplayName" SelectedValuePath="Value" Margin="0,4,0,4"/>
                                    <TextBlock Name="txtScanCertificateLabel" Text="Certificate" Style="{StaticResource FieldLabel}" Margin="14,4,8,4"/>
                                    <ComboBox Name="cbScanReusable" Width="250" DisplayMemberPath="ListLabel" SelectedValuePath="Id" Margin="0,4,0,4"/>
                                </WrapPanel>
                                <WrapPanel Orientation="Horizontal">
                                    <TextBlock Text="Rule name" Style="{StaticResource FieldLabel}" Margin="0,6,8,4"/>
                                    <TextBox Name="txtScanRuleName" Width="290" VerticalAlignment="Center" Margin="0,6,0,4" ToolTip="Suggested from the marked file. Edit it to name the rule whatever you like."/>
                                    <TextBlock Text="Internal name" Style="{StaticResource FieldLabel}" Margin="16,6,8,4"/>
                                    <TextBox Name="txtScanInternalName" Width="160" VerticalAlignment="Center" Margin="0,6,0,4"/>
                                    <CheckBox Name="chkScanIncludeFileName" Content="Include file name" IsChecked="True" VerticalAlignment="Center" Margin="16,6,0,4" ToolTip="Adds the file name to the rule. Always included for a hash rule, because that is what the Intune portal writes."/>
                                </WrapPanel>
                                <WrapPanel Orientation="Horizontal">
                                    <TextBlock Text="Elevation type" Style="{StaticResource FieldLabel}" Margin="0,6,8,4"/>
                                    <ComboBox Name="cbScanElevationType" Width="165" DisplayMemberPath="DisplayName" SelectedValuePath="Value" Margin="0,6,0,4"/>
                                    <TextBlock Text="Validation" Style="{StaticResource FieldLabel}" Margin="14,6,8,4"/>
                                    <ComboBox Name="cbScanValidation" Width="145" DisplayMemberPath="DisplayName" SelectedValuePath="Value" Margin="0,6,0,4"/>
                                    <TextBlock Text="Child process" Style="{StaticResource FieldLabel}" Margin="14,6,8,4"/>
                                    <ComboBox Name="cbScanChildProcess" Width="155" DisplayMemberPath="DisplayName" SelectedValuePath="Value" Margin="0,6,0,4"/>
                                    <Button Name="btnCreateScanRule" Content="Create rule(s)" Width="140" Margin="16,6,0,4" Style="{StaticResource AccentButton}"/>
                                </WrapPanel>
                            </StackPanel>
                        </Border>

                        <TextBox Name="txtScanOutput" Grid.Row="4" AcceptsReturn="True" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" Margin="0,10,0,0" Style="{StaticResource ConsoleTextBox}"/>
                    </Grid>
                </Border>
            </TabItem>

            <TabItem Header="Export Rules">
                <Border Style="{StaticResource CardPanel}">
                    <Grid>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="*" MinHeight="160"/>
                            <RowDefinition Height="84"/>
                        </Grid.RowDefinitions>

                        <Border Grid.Row="0" Style="{StaticResource ToolBarPanel}" Margin="0,0,0,10">
                            <StackPanel>
                                <TextBlock Text="Export EPM policy rules for documentation" Style="{StaticResource SectionHeading}" Margin="0,0,0,6"/>
                                <WrapPanel Orientation="Horizontal">
                                    <Button Name="btnLoadExportPolicies" Content="Load EPM Policies" Width="150" Margin="0,4,0,4"/>
                                    <TextBlock Text="Scope" Style="{StaticResource FieldLabel}" Margin="14,4,8,4"/>
                                    <ComboBox Name="cbExportPolicy" Width="320" DisplayMemberPath="DisplayName" SelectedValuePath="Id" Margin="0,4,0,4"/>
                                    <Button Name="btnPreviewExport" Content="Preview" Width="110" Margin="10,4,0,4"/>
                                    <Button Name="btnExportRules" Content="Export to CSV" Width="130" Margin="8,4,0,4" Style="{StaticResource AccentButton}" IsEnabled="False"/>
                                </WrapPanel>
                            </StackPanel>
                        </Border>

                        <Border Grid.Row="1" Style="{StaticResource InfoBar}" Margin="0,0,0,10">
                            <TextBlock TextWrapping="Wrap" Foreground="#5C2624">
                                <Run Text="Pick a single policy, or " FontWeight="SemiBold" Foreground="#8A0E0C"/>
                                <Run Text="All EPM Policies" FontWeight="SemiBold" Foreground="#8A0E0C"/>
                                <Run Text=", then Preview. One row per rule: policy, rule name, match type, elevation type, validation, child process behavior, internal name, file name/hash, and the reusable certificate's own name for certificate rules - every choice value shown as the words the policy itself defines, not the raw setting id. Opens straight into Excel."/>
                            </TextBlock>
                        </Border>

                        <DataGrid Name="dgExportPreview" Grid.Row="2" AutoGenerateColumns="True" IsReadOnly="True" SelectionMode="Extended" SelectionUnit="FullRow"/>

                        <TextBox Name="txtExportOutput" Grid.Row="3" AcceptsReturn="True" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" Margin="0,10,0,0" Style="{StaticResource ConsoleTextBox}"/>
                    </Grid>
                </Border>
            </TabItem>

            <TabItem Header="Settings">
                <Border Style="{StaticResource CardPanel}">
                    <Grid>
                        <Grid.RowDefinitions>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="Auto"/>
                            <RowDefinition Height="*"/>
                        </Grid.RowDefinitions>

                        <Border Grid.Row="0" Style="{StaticResource InfoBar}" Margin="0,0,0,14">
                            <TextBlock Text="Configure user-scoped working folders. Paths are stored per user in your profile and do not require local admin rights." Foreground="#8A0E0C" TextWrapping="Wrap"/>
                        </Border>

                        <WrapPanel Grid.Row="1" Orientation="Horizontal" Margin="0,0,0,14">
                            <TextBlock Text="Temp working directory" Style="{StaticResource FieldLabel}" Margin="0,4,10,4"/>
                            <TextBox Name="txtSettingsTempPath" Width="540" VerticalAlignment="Center" Margin="0,4,0,4"/>
                            <Button Name="btnSettingsBrowseTempPath" Content="Browse" Width="90" Margin="8,4,0,4"/>
                            <Button Name="btnSettingsSave" Content="Save" Width="90" Margin="8,4,0,4" Style="{StaticResource AccentButton}"/>
                            <Button Name="btnSettingsResetDefault" Content="Reset Default" Width="120" Margin="8,4,0,4"/>
                        </WrapPanel>

                        <TextBox Name="txtSettingsOutput" Grid.Row="2" AcceptsReturn="True" IsReadOnly="True" TextWrapping="Wrap" VerticalScrollBarVisibility="Auto" Style="{StaticResource ConsoleTextBox}"/>
                    </Grid>
                </Border>
            </TabItem>
        </TabControl>

        <Border Grid.Row="2" Background="#ffffff" BorderBrush="#e0e4ee" BorderThickness="0,1,0,0" Padding="24,10" Margin="0,16,0,0">
            <DockPanel LastChildFill="True">
                <ProgressBar Name="pbProgress" DockPanel.Dock="Left" Width="220" Height="8" Margin="0,0,14,0" IsIndeterminate="True" Visibility="Collapsed" VerticalAlignment="Center"/>
                <StackPanel DockPanel.Dock="Right" Orientation="Horizontal" VerticalAlignment="Center" Margin="14,0,0,0" ToolTip="Ctrl + mouse wheel, or Ctrl+Plus / Ctrl+Minus / Ctrl+0, also zoom">
                    <TextBlock Text="Zoom" Style="{StaticResource FieldLabel}" Margin="0,0,8,0"/>
                    <Button Name="btnZoomOut" Content="-" Width="30" Padding="0" FontWeight="Bold"/>
                    <TextBlock Name="txtZoomLevel" Text="100%" Width="42" TextAlignment="Center" VerticalAlignment="Center" Foreground="#5a6376" FontWeight="SemiBold"/>
                    <Button Name="btnZoomIn" Content="+" Width="30" Padding="0" Margin="0,0,8,0" FontWeight="Bold"/>
                    <Button Name="btnZoomReset" Content="Reset" Width="60" Padding="0" FontSize="11"/>
                </StackPanel>
                <TextBlock Name="txtStatus" Text="Ready" Foreground="#5a6376" TextWrapping="Wrap" VerticalAlignment="Center"/>
            </DockPanel>
        </Border>
    </Grid>
</Window>
"@

    $reader = New-Object -TypeName System.Xml.XmlNodeReader -ArgumentList $xaml
    $window = [Windows.Markup.XamlReader]::Load($reader)

    # Decode the embedded brand mark once and use it for both the header badge and the
    # window/taskbar icon, rather than shipping a separate .ico the script could be separated from.
    try {
        $logoBytes = [System.Convert]::FromBase64String($script:brandLogoBase64)
        $logoStream = New-Object System.IO.MemoryStream (,$logoBytes)
        $logoImage = New-Object System.Windows.Media.Imaging.BitmapImage
        $logoImage.BeginInit()
        $logoImage.CacheOption = [System.Windows.Media.Imaging.BitmapCacheOption]::OnLoad
        $logoImage.StreamSource = $logoStream
        $logoImage.EndInit()
        $logoImage.Freeze()

        $imgBrandLogo = $window.FindName('imgBrandLogo')
        if($null -ne $imgBrandLogo) {
            $imgBrandLogo.Source = $logoImage
        }
        $window.Icon = $logoImage
    } catch {
        Write-DebugLog -Category 'WARN' -Message "Unable to decode the embedded brand logo: $($_.Exception.Message)"
    }

    $txtCsvPath = $window.FindName('txtCsvPath')
    $btnBrowseCsv = $window.FindName('btnBrowseCsv')
    $btnImportCsv = $window.FindName('btnImportCsv')
    $cbElevationRange = $window.FindName('cbElevationRange')
    $chkUnmanagedOnly = $window.FindName('chkUnmanagedOnly')
    $btnFetchElevations = $window.FindName('btnFetchElevations')
    $dgCandidates = $window.FindName('dgCandidates')
    $txtCandidateSearch = $window.FindName('txtCandidateSearch')
    $txtCandidateCount = $window.FindName('txtCandidateCount')
    $btnLoadAuditPolicies = $window.FindName('btnLoadAuditPolicies')
    $cbAuditPolicy = $window.FindName('cbAuditPolicy')
    $cbAuditElevationType = $window.FindName('cbAuditElevationType')
    $cbAuditChildProcess = $window.FindName('cbAuditChildProcess')
    $btnCreateAuditRule = $window.FindName('btnCreateAuditRule')
    $txtBuildOutput = $window.FindName('txtBuildOutput')
    $btnRunCoverage = $window.FindName('btnRunCoverage')
    $btnExportUncovered = $window.FindName('btnExportUncovered')
    $txtCoverageScore = $window.FindName('txtCoverageScore')
    $brdCoverageScore = $window.FindName('brdCoverageScore')
    $icPersonaCards = $window.FindName('icPersonaCards')
    $dgUserRecommendation = $window.FindName('dgUserRecommendation')
    $txtUncoveredSummary = $window.FindName('txtUncoveredSummary')
    $dgUncovered = $window.FindName('dgUncovered')
    $btnLoadPoliciesReplicate = $window.FindName('btnLoadPoliciesReplicate')
    $cbSourcePolicy = $window.FindName('cbSourcePolicy')
    $cbTargetPolicy = $window.FindName('cbTargetPolicy')
    $btnLoadSourceRules = $window.FindName('btnLoadSourceRules')
    $cbSourceRule = $window.FindName('cbSourceRule')
    $btnReplicateRule = $window.FindName('btnReplicateRule')
    $txtReplicateOutput = $window.FindName('txtReplicateOutput')
    $btnLoadReusable = $window.FindName('btnLoadReusable')
    $cbReusable = $window.FindName('cbReusable')
    $btnFindReusableUsage = $window.FindName('btnFindReusableUsage')
    $dgReusableUsage = $window.FindName('dgReusableUsage')
    $txtScanPath = $window.FindName('txtScanPath')
    $btnBrowseScanPath = $window.FindName('btnBrowseScanPath')
    $chkScanExe = $window.FindName('chkScanExe')
    $chkScanMsi = $window.FindName('chkScanMsi')
    $chkScanPs1 = $window.FindName('chkScanPs1')
    $chkScanRecurse = $window.FindName('chkScanRecurse')
    $btnScanPath = $window.FindName('btnScanPath')
    $txtScanCount = $window.FindName('txtScanCount')
    $dgScanResults = $window.FindName('dgScanResults')
    $mnuScanCopyRow = $window.FindName('mnuScanCopyRow')
    $mnuScanCopyCell = $window.FindName('mnuScanCopyCell')
    $btnExtractCert = $window.FindName('btnExtractCert')
    $cbExtractedCertificate = $window.FindName('cbExtractedCertificate')
    $txtExtractFolder = $window.FindName('txtExtractFolder')
    $btnExtractHash = $window.FindName('btnExtractHash')
    $btnCheckReusableMatch = $window.FindName('btnCheckReusableMatch')
    $txtReusableName = $window.FindName('txtReusableName')
    $btnUploadReusable = $window.FindName('btnUploadReusable')
    $btnLoadScanPolicies = $window.FindName('btnLoadScanPolicies')
    $cbScanPolicy = $window.FindName('cbScanPolicy')
    $cbScanReusable = $window.FindName('cbScanReusable')
    $txtScanCertificateLabel = $window.FindName('txtScanCertificateLabel')
    $cbScanMatchType = $window.FindName('cbScanMatchType')
    $cbScanElevationType = $window.FindName('cbScanElevationType')
    $cbScanValidation = $window.FindName('cbScanValidation')
    $cbScanChildProcess = $window.FindName('cbScanChildProcess')
    $txtScanRuleName = $window.FindName('txtScanRuleName')
    $txtScanInternalName = $window.FindName('txtScanInternalName')
    $chkScanIncludeFileName = $window.FindName('chkScanIncludeFileName')
    $btnCreateScanRule = $window.FindName('btnCreateScanRule')
    $txtScanOutput = $window.FindName('txtScanOutput')
    $btnLoadExportPolicies = $window.FindName('btnLoadExportPolicies')
    $cbExportPolicy = $window.FindName('cbExportPolicy')
    $btnPreviewExport = $window.FindName('btnPreviewExport')
    $btnExportRules = $window.FindName('btnExportRules')
    $dgExportPreview = $window.FindName('dgExportPreview')
    $txtExportOutput = $window.FindName('txtExportOutput')
    $txtSettingsTempPath = $window.FindName('txtSettingsTempPath')
    $btnSettingsBrowseTempPath = $window.FindName('btnSettingsBrowseTempPath')
    $btnSettingsSave = $window.FindName('btnSettingsSave')
    $btnSettingsResetDefault = $window.FindName('btnSettingsResetDefault')
    $txtSettingsOutput = $window.FindName('txtSettingsOutput')
    $txtStatus = $window.FindName('txtStatus')
    $pbProgress = $window.FindName('pbProgress')
    $rootGrid = $window.FindName('rootGrid')
    $btnZoomOut = $window.FindName('btnZoomOut')
    $btnZoomIn = $window.FindName('btnZoomIn')
    $btnZoomReset = $window.FindName('btnZoomReset')
    $txtZoomLevel = $window.FindName('txtZoomLevel')
    $cbGraphAuthMode = $window.FindName('cbGraphAuthMode')
    $btnConnectGraph = $window.FindName('btnConnectGraph')
    $btnDisconnectGraph = $window.FindName('btnDisconnectGraph')
    $elConnState = $window.FindName('elConnState')
    $txtConnState = $window.FindName('txtConnState')

    $script:candidates = [System.Collections.Generic.List[object]]::new()
    $script:candidateView = $null
    $script:policies = $null
    $script:uncoveredDetails = @()
    $script:scanResults = [System.Collections.Generic.List[object]]::new()
    $script:extractedCertificate = $null
    # Set when a target policy is selected on the Scan Path tab; used as the fallback validation
    # value when the validation drop-down has no explicit selection.
    $script:scanValidationDefaultValue = $null
    # Same idea for the Audit Import hash-rule panel: there is no validation control there at all,
    # so the policy's default (or first) validation option is always applied silently.
    $script:auditValidationDefaultValue = $null
    # The reusable certificate setting most recently uploaded from this session, so switching the
    # match type to Certificate can re-select it without the operator hunting for it in the list.
    $script:lastUploadedReusableId = $null
    # The rows currently previewed on the Export Rules tab. Export writes exactly what is on
    # screen, so the operator sees the same data that lands in the CSV.
    $script:exportRows = @()
    # Guards the automatic name suggestion so it never overwrites a name the operator typed.
    $script:reusableNameIsSuggested = $true
    $script:suppressReusableNameEcho = $false
    # Same guard for the Scan Path rule name and internal name: both are suggested from the marked
    # file, and both stop being suggested the moment the operator edits them.
    $script:ruleNameIsSuggested = $true
    $script:internalNameIsSuggested = $true
    $script:suppressScanNameEcho = $false

    $loadedSettings = Initialize-EpmToolSettings
    if($null -ne $txtSettingsTempPath) {
        $txtSettingsTempPath.Text = [string]$loadedSettings.TempWorkingDirectory
    }

    function Set-GuiZoom {
        <#
        .SYNOPSIS
        Scales the whole window - header, tabs, footer - up or down together, for a small or a
        high-DPI screen.

        .DESCRIPTION
        Applied as a LayoutTransform on the outermost Grid, after the normal layout/measure pass
        has already run - unlike wrapping content in a ScrollViewer (deliberately not done; see the
        comment on the TabControl template), a LayoutTransform never changes how much space a
        Height="*" row or the DataGrid inside it computes, so grid row virtualization for a large
        CSV import is unaffected by zoom at any level.
        #>
        param(
            [Parameter(Mandatory = $true)]
            [double]$Zoom,

            [Parameter(Mandatory = $false)]
            [switch]$Persist
        )

        $clamped = [Math]::Min(1.6, [Math]::Max(0.6, $Zoom))
        $script:currentZoom = $clamped

        if($null -ne $rootGrid) {
            $rootGrid.LayoutTransform = New-Object -TypeName System.Windows.Media.ScaleTransform -ArgumentList $clamped, $clamped
        }
        if($null -ne $txtZoomLevel) {
            $txtZoomLevel.Text = "$([Math]::Round($clamped * 100))%"
        }
        if($null -ne $btnZoomOut) { $btnZoomOut.IsEnabled = ($clamped -gt 0.6) }
        if($null -ne $btnZoomIn) { $btnZoomIn.IsEnabled = ($clamped -lt 1.6) }

        if($Persist.IsPresent) {
            try {
                Save-EpmToolSettings -UiZoom $clamped | Out-Null
            } catch {
                Write-DebugLog -Category 'WARN' -Message "Failed to persist the zoom level: $($_.Exception.Message)"
            }
        }
    }

    $script:currentZoom = 1.0
    Set-GuiZoom -Zoom ([double]$loadedSettings.UiZoom)

    function Update-GuiExtractFolderHint {
        # Extraction always writes under the temp working directory configured on the Settings tab,
        # so the Scan Path tab states exactly where the .cer files land.
        if($null -eq $txtExtractFolder) {
            return
        }
        $extractRoot = Join-Path -Path (Get-EpmTempWorkingDirectory) -ChildPath 'ExtractedCertificates'
        $txtExtractFolder.Text = "Certificates are written to $extractRoot"
    }
    if($null -ne $txtSettingsOutput) {
        $txtSettingsOutput.Text = "Current temp working directory: $($loadedSettings.TempWorkingDirectory)`r`nSettings file: $($script:userSettingsFilePath)`r`n"
    }

    if($script:graphAuthModeSetting -eq 'DeviceCode') {
        $cbGraphAuthMode.SelectedIndex = 1
    }

    if($null -ne $cbElevationRange) {
        # Intune keeps the elevation report for 30 days, so nothing longer is offered.
        $cbElevationRange.ItemsSource = @(
            [PSCustomObject]@{ DisplayName = 'Last 24 hours'; Value = 1 },
            [PSCustomObject]@{ DisplayName = 'Last 7 days'; Value = 7 },
            [PSCustomObject]@{ DisplayName = 'Last 14 days'; Value = 14 },
            [PSCustomObject]@{ DisplayName = 'Last 30 days'; Value = 30 }
        )
        $cbElevationRange.SelectedValue = 7
    }

    if($null -ne $cbScanMatchType) {
        $cbScanMatchType.ItemsSource = @(
            [PSCustomObject]@{ DisplayName = 'Suggested'; Value = 'Suggested' },
            [PSCustomObject]@{ DisplayName = 'Certificate'; Value = 'Certificate' },
            [PSCustomObject]@{ DisplayName = 'Hash'; Value = 'Hash' }
        )
        $cbScanMatchType.SelectedValue = 'Suggested'
    }

    $cbGraphAuthMode.Add_SelectionChanged({
            if($null -ne $cbGraphAuthMode.SelectedItem) {
                $script:graphAuthModeSetting = $cbGraphAuthMode.SelectedItem.Content.ToString()
            }
        })

    function Write-GuiStatus {
        param([string]$Message)
        $txtStatus.Text = $Message
        $window.Dispatcher.Invoke([Action] {}, [Windows.Threading.DispatcherPriority]::Background)
    }

    function Write-GuiBusyStart {
        param(
            [string]$Message,
            $Button
        )

        if($null -ne $Button) {
            $Button.IsEnabled = $false
        }

        $pbProgress.Visibility = 'Visible'
        $window.Cursor = [System.Windows.Input.Cursors]::Wait
        Write-GuiStatus -Message "$Message..."
    }

    function Write-GuiBusyStop {
        param(
            [string]$Message = 'Ready',
            $Button
        )

        $pbProgress.Visibility = 'Collapsed'
        $window.Cursor = $null

        if($null -ne $Button) {
            $Button.IsEnabled = $true
        }

        Write-GuiStatus -Message $Message
    }

    function Invoke-GuiOperation {
        param(
            [string]$Message,
            [string]$FailureTitle,
            $Button,
            [scriptblock]$Operation
        )

        Write-GuiBusyStart -Message $Message -Button $Button
        try {
            & $Operation
        } catch {
            $detail = Get-GraphErrorDetail -ErrorRecord $_
            Write-DebugLog -Category 'ERROR' -Message "$FailureTitle while '$Message': $detail"
            $dialogMessage = "$($_.Exception.Message)`r`n`r`nA detailed diagnostic log was written to:`r`n$($script:debugLogPath)"
            [System.Windows.MessageBox]::Show($window, $dialogMessage, $FailureTitle, 'OK', 'Error') | Out-Null
            Write-GuiStatus -Message "$FailureTitle. See debug log: $($script:debugLogPath)"
        } finally {
            Write-GuiBusyStop -Message $txtStatus.Text -Button $Button
        }
    }

    function Set-GuiClipboardText {
        param([string]$Text)
        if([string]::IsNullOrEmpty($Text)) {
            return
        }
        try {
            [System.Windows.Clipboard]::SetText($Text)
        } catch {
            Write-DebugLog -Category 'WARN' -Message "Failed to set clipboard text: $($_.Exception.Message)"
        }
    }

    function Get-DataGridCellText {
        # Reads the displayed value of a single DataGrid cell. The scan grid is backed by a
        # DataRowView, so the bound column path is used to read the row value directly; otherwise the
        # rendered cell content is used as a fallback so any column type still copies.
        param(
            $Column,
            $Item
        )

        if($null -eq $Column -or $null -eq $Item) {
            return ''
        }

        if($Column -is [System.Windows.Controls.DataGridBoundColumn]) {
            $binding = $Column.Binding
            if($null -ne $binding -and $null -ne $binding.Path) {
                $path = $binding.Path.Path
                if(-not [string]::IsNullOrWhiteSpace($path) -and $Item -is [System.Data.DataRowView]) {
                    if($Item.Row.Table.Columns.Contains($path)) {
                        return [string]$Item[$path]
                    }
                }
            }
        }

        $content = $Column.GetCellContent($Item)
        if($content -is [System.Windows.Controls.TextBlock]) {
            return $content.Text
        }
        return ''
    }

    function Copy-DataGridSelection {
        # Copies the selected rows of a DataGrid to the clipboard as tab-separated text with a header
        # row, matching the column order shown on screen.
        param($Grid)

        $rows = @($Grid.SelectedItems)
        if($rows.Count -eq 0) {
            return
        }

        $columns = @($Grid.Columns | Sort-Object -Property DisplayIndex)
        $lines = [System.Collections.Generic.List[string]]::new()
        $lines.Add((($columns | ForEach-Object { [string]$_.Header }) -join "`t"))
        foreach($row in $rows) {
            $cells = foreach($column in $columns) {
                Get-DataGridCellText -Column $column -Item $row
            }
            $lines.Add(($cells -join "`t"))
        }
        Set-GuiClipboardText -Text ($lines -join "`r`n")
    }

    function Get-GuiPolicyList {
        $script:policies = Get-EpmRulesPolicy
        $cbSourcePolicy.ItemsSource = $script:policies
        $cbTargetPolicy.ItemsSource = $script:policies
        $cbAuditPolicy.ItemsSource = $script:policies

        # The export scope picker gets one synthetic entry ahead of the real policies, so a single
        # combo box covers both "export this one policy" and "export everything" without a second
        # control. '__ALL__' is not a real policy id, so the export handler checks for it by value.
        $exportScopeItems = [System.Collections.Generic.List[object]]::new()
        $exportScopeItems.Add([PSCustomObject]@{ DisplayName = 'All EPM Policies'; Id = '__ALL__' })
        foreach($policy in $script:policies) { $exportScopeItems.Add($policy) }
        $cbExportPolicy.ItemsSource = $exportScopeItems

        Write-GuiStatus -Message "Loaded $($script:policies.Count) EPM policies."
    }

    function Clear-GuiTenantData {
        # Signing out (or switching account) must not leave another tenant's policies, rules or
        # reusable settings selectable in the drop-downs - acting on a stale id would write to the
        # wrong tenant. Everything read from Graph is dropped here; locally scanned files are kept
        # because they do not belong to a tenant.
        $script:policies = $null
        foreach($combo in @($cbSourcePolicy, $cbTargetPolicy, $cbSourceRule, $cbReusable, $cbScanPolicy, $cbScanReusable, $cbScanElevationType, $cbScanValidation, $cbScanChildProcess, $cbAuditPolicy, $cbAuditElevationType, $cbAuditChildProcess, $cbExportPolicy)) {
            if($null -ne $combo) {
                $combo.ItemsSource = $null
                $combo.SelectedIndex = -1
            }
        }
        $script:scanValidationDefaultValue = $null
        $script:auditValidationDefaultValue = $null
        $script:lastUploadedReusableId = $null
        $script:exportRows = @()
        if($null -ne $dgReusableUsage) { $dgReusableUsage.ItemsSource = $null }
        if($null -ne $dgExportPreview) { $dgExportPreview.ItemsSource = $null }
        if($null -ne $btnExportRules) { $btnExportRules.IsEnabled = $false }
    }

    function Set-GuiCandidateSource {
        # Shared by both audit sources - the CSV import and the live Intune elevation report. Both
        # hand over rows in the same normalized shape, so everything from here down (candidate
        # building, grid binding, search, coverage analysis) is identical and only has to exist
        # once. Returns the number of candidates built.
        param(
            [Parameter(Mandatory = $true)]
            [AllowEmptyCollection()]
            [object[]]$Rows
        )

        # Match is always 'Auto' (certificate when the row shows a publisher, hash otherwise) and
        # enrichment is never attempted. Neither ever drove an outcome here: the audit grid's
        # MatchType column is informational only - Coverage Analysis scoring, the uncovered-
        # elevations summary and the hash-rule-from-audit-row panel below all ignore it (the last
        # one always writes a hash rule regardless of what this label says) - and local-file
        # enrichment only ever fires when this machine happens to still have the exact file at the
        # exact path an audit row recorded, which defeats the point of a centralized audit report.
        # A dropdown and a checkbox that never changed a result were just noise.
        $script:candidates = [System.Collections.Generic.List[object]]::new()
        foreach($row in $Rows) {
            $candidate = ConvertTo-EpmRuleCandidate -ElevationRow $row -Match 'Auto'
            $script:candidates.Add($candidate)
        }

        # Bind as a DataTable DefaultView so the WPF DataGrid supports clicking column headers to
        # sort. A DataView is filtered through its own RowFilter string (see the search box
        # handler) - the WPF CollectionView.Filter predicate is NOT supported on a DataView-backed
        # view and throws "Specified method is not supported". The hidden CandidateIndex column
        # lets a selected DataRowView be mapped back to the original rich candidate object.
        $dt = ConvertTo-DataTable -Array $script:candidates.ToArray() -IndexColumnName 'CandidateIndex'
        $script:candidateView = $dt.DefaultView
        $dgCandidates.ItemsSource = $script:candidateView

        # Apply any text already typed in the search box. This owns the count label.
        Update-CandidateFilter

        return $script:candidates.Count
    }

    function Update-CandidateFilter {
        # The candidate grid is backed by a DataView, which filters through a RowFilter expression
        # string (the WPF CollectionView.Filter predicate is not supported on a DataView). Search
        # across all candidate columns (except the hidden CandidateIndex helper column).
        if($null -eq $script:candidateView) {
            return
        }

        $query = $txtCandidateSearch.Text
        if([string]::IsNullOrWhiteSpace($query)) {
            $script:candidateView.RowFilter = ''
        } else {
            $escaped = $query.Replace("'", "''")
            # Escape LIKE wildcards and bracket tokens so user input is treated as literal text.
            $escaped = $escaped.Replace("[", "[[]").Replace("%", "[%]").Replace("*", "[*]").Replace("_", "[_]")

            $columns = @()
            foreach($column in $script:candidateView.Table.Columns) {
                if($null -eq $column -or [string]::IsNullOrWhiteSpace([string]$column.ColumnName)) {
                    continue
                }
                if([string]$column.ColumnName -eq 'CandidateIndex') {
                    continue
                }
                $columns += , [string]$column.ColumnName
            }

            $clauses = foreach($column in $columns) {
                "Convert([$column], 'System.String') LIKE '%$escaped%'"
            }
            if($clauses.Count -gt 0) {
                $script:candidateView.RowFilter = ($clauses -join ' OR ')
            } else {
                $script:candidateView.RowFilter = ''
            }
        }

        # Only show the "x of y" form while a search is actually narrowing the list; unfiltered it
        # would read "640 of 640 rule(s)".
        $visible = $script:candidateView.Count
        if([string]::IsNullOrWhiteSpace($query) -or $visible -eq $script:candidates.Count) {
            $txtCandidateCount.Text = "$($script:candidates.Count) rule(s)"
        } else {
            $txtCandidateCount.Text = "$visible of $($script:candidates.Count) rule(s)"
        }
    }

    function Update-GuiCertificateButtons {
        # Upload is only possible with a certificate chosen AND a Graph session, so the button state
        # says so rather than letting the operator click into an error.
        $hasCertificate = ($null -ne $cbExtractedCertificate.SelectedItem)
        $signedIn = $false
        try {
            $context = Get-MgContext -ErrorAction SilentlyContinue
            $signedIn = ($null -ne $context -and -not [string]::IsNullOrWhiteSpace($context.Account))
        } catch {
            $signedIn = $false
        }

        $btnUploadReusable.IsEnabled = ($hasCertificate -and $signedIn)
        if($hasCertificate -and -not $signedIn) {
            $btnUploadReusable.ToolTip = 'Sign in to Microsoft Graph to upload this certificate.'
        } elseif(-not $hasCertificate) {
            $btnUploadReusable.ToolTip = 'Extract a certificate and pick one from the list first.'
        } else {
            $btnUploadReusable.ToolTip = $null
        }
    }

    function Set-GuiExtractedCertificateList {
        # Binds the extracted chain to the picker. The signer is preselected because it is the
        # certificate that identifies the publisher of the scanned file; the operator can move up
        # the chain to an intermediate when they want the rule to cover everything that CA signs.
        param(
            [Parameter(Mandatory = $true)]
            [AllowEmptyCollection()]
            [object[]]$Details
        )

        $script:reusableNameIsSuggested = $true
        $cbExtractedCertificate.ItemsSource = $Details

        if($Details.Count -gt 0) {
            $cbExtractedCertificate.SelectedIndex = 0
        } else {
            $cbExtractedCertificate.SelectedIndex = -1
        }

        Update-GuiCertificateButtons
    }

    function Update-GuiSuggestedReusableName {
        # Best-practice default: name the reusable setting after the certificate's issuer. Only
        # applied while the operator has not typed their own name.
        if(-not $script:reusableNameIsSuggested) {
            return
        }

        $selected = $cbExtractedCertificate.SelectedItem
        if($null -eq $selected) {
            return
        }

        $suggested = [string]$selected.SuggestedName
        if([string]::IsNullOrWhiteSpace($suggested)) {
            $suggested = [string]$selected.SubjectName
        }

        if(-not [string]::IsNullOrWhiteSpace($suggested)) {
            # Setting .Text raises TextChanged, which would otherwise mark the name as operator-typed.
            $script:suppressReusableNameEcho = $true
            try {
                $txtReusableName.Text = $suggested
            } finally {
                $script:suppressReusableNameEcho = $false
            }
        }
    }

    function Update-GuiMatchTypeState {
        # A hash rule identifies the binary by its SHA256, which is an exact match on its own. It
        # carries no certificate at all, so leaving the reusable certificate live would imply it
        # has some effect on the rule. Certificate matching requires one, and 'Suggested' decides
        # per file, so in both of those cases the field stays available.
        $selectedMatch = if($null -ne $cbScanMatchType.SelectedValue) { [string]$cbScanMatchType.SelectedValue } else { 'Suggested' }
        $usesCertificate = ($selectedMatch -ne 'Hash')

        $cbScanReusable.IsEnabled = $usesCertificate
        $txtScanCertificateLabel.IsEnabled = $usesCertificate
        $cbScanReusable.ToolTip = if($usesCertificate) {
            $null
        } else {
            'A hash rule matches on the file SHA256 and does not use a certificate.'
        }

        if($selectedMatch -ne 'Certificate') {
            return
        }

        # Choosing a certificate match should not mean hunting for the certificate that was just
        # uploaded, or retyping an internal name that was read off the file during the scan.
        if($null -eq $cbScanReusable.SelectedValue -and -not [string]::IsNullOrWhiteSpace($script:lastUploadedReusableId)) {
            $cbScanReusable.SelectedValue = $script:lastUploadedReusableId
            if($null -ne $cbScanReusable.SelectedItem) {
                $txtScanOutput.Text += "[INFO] Certificate match selected: using the reusable setting uploaded in this session ('$($cbScanReusable.Text)').`r`n"
            }
        }

        Update-GuiScanRowContext

        if($null -eq $cbScanReusable.SelectedValue) {
            $txtScanOutput.Text += "[WARN] Certificate match needs a reusable certificate setting. Upload one in step 2, or load the policies and options to list the ones already in the tenant.`r`n"
        }
    }

    function Update-GuiScanRowContext {
        # Keeps the certificate picker and the internal name in step with the marked file. A chain
        # extracted in an earlier session is still on disk in the temp working directory, so it is
        # loaded back rather than forcing a re-extract.
        $selected = @($dgScanResults.SelectedItems)

        # One text box cannot name several rules. With more than one file marked, each rule is named
        # from its own file instead, and the box says so rather than pretending to apply.
        if($selected.Count -gt 1) {
            $script:suppressScanNameEcho = $true
            try {
                $txtScanRuleName.Text = ''
            } finally {
                $script:suppressScanNameEcho = $false
            }
            $txtScanRuleName.IsEnabled = $false
            $txtScanRuleName.ToolTip = "$($selected.Count) files are marked, so each rule is named from its own file."
            return
        }

        $txtScanRuleName.IsEnabled = $true
        $txtScanRuleName.ToolTip = 'Suggested from the marked file. Edit it to name the rule whatever you like.'

        if($selected.Count -ne 1) {
            return
        }

        $row = $selected[0]

        # The grid is bound to a DataView whose columns come from whatever the scan produced, so
        # read defensively rather than assuming a column is present.
        $readColumn = {
            param($RowView, [string]$ColumnName)
            try {
                if($RowView -is [System.Data.DataRowView] -and -not $RowView.Row.Table.Columns.Contains($ColumnName)) {
                    return ''
                }
                return [string]$RowView[$ColumnName]
            } catch {
                return ''
            }
        }

        # Suggest the rule name and internal name from the marked file, unless the operator has
        # already typed their own. Setting .Text raises TextChanged, which would otherwise mark the
        # value as operator-typed, so the echo is suppressed around the assignment.
        $script:suppressScanNameEcho = $true
        try {
            if($script:ruleNameIsSuggested) {
                $suggestedRuleName = & $readColumn $row 'RuleName'
                if([string]::IsNullOrWhiteSpace($suggestedRuleName)) {
                    $suggestedRuleName = & $readColumn $row 'FileName'
                }
                if(-not [string]::IsNullOrWhiteSpace($suggestedRuleName)) {
                    $txtScanRuleName.Text = $suggestedRuleName
                }
            }

            if($script:internalNameIsSuggested) {
                $internalName = & $readColumn $row 'InternalName'
                if(-not [string]::IsNullOrWhiteSpace($internalName)) {
                    $txtScanInternalName.Text = $internalName
                }
            }
        } finally {
            $script:suppressScanNameEcho = $false
        }

        $filePath = & $readColumn $row 'FilePath'
        if([string]::IsNullOrWhiteSpace($filePath)) {
            return
        }

        try {
            $extractInfo = Get-EpmExtractedCertificateInfo -FilePath $filePath
            if($extractInfo.HasCertificates) {
                $details = @(Get-EpmCertificateDetailsFromDirectory -DirectoryPath $extractInfo.FolderPath)
                Set-GuiExtractedCertificateList -Details $details
                Update-GuiSuggestedReusableName
            } else {
                Set-GuiExtractedCertificateList -Details @()
            }
        } catch {
            Write-DebugLog -Category 'WARN' -Message "Unable to load previously extracted certificates for '$filePath': $($_.Exception.Message)"
        }
    }

    function Update-GuiConnectionState {
        $context = $null
        try {
            $context = Get-MgContext -ErrorAction SilentlyContinue
        } catch {
            $context = $null
        }

        if($null -ne $context -and -not [string]::IsNullOrWhiteSpace($context.Account)) {
            $elConnState.Fill = '#27ae60'
            $txtConnState.Text = "Signed in: $($context.Account)"
            $btnConnectGraph.Content = 'Reconnect'
            $btnDisconnectGraph.IsEnabled = $true
        } else {
            $elConnState.Fill = '#c0392b'
            $txtConnState.Text = 'Not signed in'
            $btnConnectGraph.Content = 'Sign in'
            $btnDisconnectGraph.IsEnabled = $false
        }

        # The upload button is gated on being signed in, so it has to follow the connection state.
        Update-GuiCertificateButtons
    }

    $btnConnectGraph.Add_Click({
            Invoke-GuiOperation -Message "Signing in to Microsoft Graph ($($script:graphAuthModeSetting))" -FailureTitle 'Sign in failed' -Button $btnConnectGraph -Operation {
                if($script:graphAuthModeSetting -eq 'DeviceCode') {
                    Write-GuiStatus -Message 'Device code sign-in started. Follow the prompt in the console window to authenticate (works with FIDO2 and in elevated sessions).'
                }
                # Force a fresh sign-in so an elevated session that has no cached token can prompt.
                try {
                    Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
                } catch {
                    Write-Verbose -Message 'No existing Microsoft Graph session to disconnect.'
                }

                # The new sign-in may be a different tenant, so drop anything already loaded before
                # connecting rather than leaving the previous tenant's ids selectable.
                Clear-GuiTenantData
                Connect-IntuneGraph
                $context = Get-MgContext -ErrorAction SilentlyContinue
                $account = if($null -ne $context) { $context.Account } else { 'unknown account' }
                Write-DebugLog -Category 'INFO' -Message "Signed in to Microsoft Graph as '$account' using $($script:graphAuthModeSetting)."
                Write-GuiStatus -Message "Signed in to Microsoft Graph as $account. The token is kept until this window is closed."
            }
            Update-GuiConnectionState
        })

    $btnDisconnectGraph.Add_Click({
            Invoke-GuiOperation -Message 'Signing out of Microsoft Graph' -FailureTitle 'Sign out failed' -Button $btnDisconnectGraph -Operation {
                Disconnect-MgGraph -ErrorAction SilentlyContinue | Out-Null
                Clear-GuiTenantData
                Write-GuiStatus -Message 'Signed out of Microsoft Graph. Tenant data cleared from the drop-downs.'
            }
            Update-GuiConnectionState
        })

    $btnBrowseCsv.Add_Click({
            $dialog = New-Object -TypeName Microsoft.Win32.OpenFileDialog
            $dialog.Filter = 'CSV Files (*.csv)|*.csv|All Files (*.*)|*.*'
            if($dialog.ShowDialog($window)) {
                $txtCsvPath.Text = $dialog.FileName
            }
        })

    # Hide the internal CandidateIndex helper column from the candidate grid - it only exists so a
    # selected DataRowView can be mapped back to its source candidate object.
    $dgCandidates.Add_AutoGeneratingColumn({
            param($eventSource, $eventArgs)
            if($eventArgs.PropertyName -eq 'CandidateIndex') {
                $eventArgs.Cancel = $true
            }
        })

    $dgUserRecommendation.Add_AutoGeneratingColumn({
            param($eventSource, $eventArgs)
            if($eventArgs.PropertyName -eq 'ConfidenceColor') {
                $eventArgs.Cancel = $true
            }
        })

    $btnImportCsv.Add_Click({
            Invoke-GuiOperation -Message 'Importing CSV and building candidate rules' -FailureTitle 'Import failed' -Button $btnImportCsv -Operation {
                if(-not (Test-Path -Path $txtCsvPath.Text)) {
                    throw 'Select a CSV file before importing.'
                }

                $rows = @(Import-EpmAuditCsv -Path $txtCsvPath.Text)
                if($rows.Count -eq 0) {
                    throw "'$($txtCsvPath.Text)' contained no rows."
                }

                $count = Set-GuiCandidateSource -Rows $rows
                Write-GuiStatus -Message "Imported $count candidate rule(s) from the CSV. Run Coverage Analysis to see what existing policies already cover."
            }
        })

    $btnFetchElevations.Add_Click({
            Invoke-GuiOperation -Message 'Reading the EPM elevation report from Intune' -FailureTitle 'Fetch failed' -Button $btnFetchElevations -Operation {
                $dayRange = 7
                if($null -ne $cbElevationRange.SelectedValue) {
                    $dayRange = [int]$cbElevationRange.SelectedValue
                }

                $unmanagedOnly = ($true -eq $chkUnmanagedOnly.IsChecked)
                $rows = @(Get-EpmElevationReport -DayRange $dayRange -UnmanagedOnly:$unmanagedOnly)

                if($rows.Count -eq 0) {
                    $scopeText = if($unmanagedOnly) { 'unmanaged ' } else { '' }
                    $txtBuildOutput.Text = "No ${scopeText}elevations were reported in the last $dayRange day(s).`r`n"
                    Write-GuiStatus -Message "The elevation report returned no ${scopeText}elevations for the last $dayRange day(s)."
                    return
                }

                $count = Set-GuiCandidateSource -Rows $rows
                $scopeText = if($unmanagedOnly) { 'unmanaged elevation' } else { 'elevation' }
                $txtBuildOutput.Text = "Read $count $scopeText event(s) from the Intune elevation report (last $dayRange day(s)).`r`n"
                Write-GuiStatus -Message "Fetched $count candidate rule(s) from Intune. Run Coverage Analysis to see what existing policies already cover."
            }
        })

    $txtCandidateSearch.Add_TextChanged({
            Update-CandidateFilter
        })

    $btnLoadAuditPolicies.Add_Click({
            Invoke-GuiOperation -Message 'Loading EPM policies from Microsoft Graph' -FailureTitle 'Graph failed' -Button $btnLoadAuditPolicies -Operation {
                if($null -eq $script:policies) { Get-GuiPolicyList } else { $cbAuditPolicy.ItemsSource = $script:policies }
                Write-GuiStatus -Message "Loaded $($script:policies.Count) EPM policies. Select a target policy to load its rule options."
            }
        })

    $cbAuditPolicy.Add_SelectionChanged({
            if($null -eq $cbAuditPolicy.SelectedValue) { return }
            Invoke-GuiOperation -Message 'Reading rule options from the selected policy' -FailureTitle 'Options load failed' -Button $cbAuditPolicy -Operation {
                # Read live from the policy's expanded setting definitions, same as Scan Path, so the
                # offered options are exactly the tenant-correct values and never hardcoded.
                $policySettings = Get-EpmPolicySetting -PolicyId $cbAuditPolicy.SelectedValue

                $elevationOptions = @(Get-EpmRuleChoiceOption -Settings $policySettings -DefinitionIdTokens @('_elevationtype', '_ruletype'))
                $validationOptions = @(Get-EpmRuleChoiceOption -Settings $policySettings -DefinitionIdTokens @('_validation', '_validationtype'))
                $childProcessOptions = @(Get-EpmRuleChoiceOption -Settings $policySettings -DefinitionIdTokens @('_childprocessbehavior', '_child_process_behavior'))

                $cbAuditElevationType.ItemsSource = $elevationOptions
                $cbAuditChildProcess.ItemsSource = $childProcessOptions
                $cbAuditElevationType.SelectedIndex = -1
                $cbAuditChildProcess.SelectedIndex = -1

                # There is no validation control on this tab - keeping the panel to the three choices
                # asked for - so the policy's default validation option is captured here and applied
                # silently when the rule is a user-confirmed ("self") elevation type.
                $defaultValidation = $validationOptions | Where-Object { $_.IsDefault } | Select-Object -First 1
                if($null -eq $defaultValidation -and $validationOptions.Count -gt 0) {
                    $defaultValidation = $validationOptions[0]
                }
                $script:auditValidationDefaultValue = if($null -ne $defaultValidation) { [string]$defaultValidation.Value } else { $null }

                Write-GuiStatus -Message "Loaded rule options from the selected policy ($($elevationOptions.Count) elevation type(s), $($childProcessOptions.Count) child process)."
            }
        })

    $btnCreateAuditRule.Add_Click({
            Invoke-GuiOperation -Message 'Creating a hash rule from the marked audit row' -FailureTitle 'Create rule failed' -Button $btnCreateAuditRule -Operation {
                if($null -eq $cbAuditPolicy.SelectedValue) { throw 'Select a target policy. Use "Load policies and options" first.' }

                # The grid is bound to a DataView, so selected items are DataRowView objects. The
                # hidden CandidateIndex column maps a selected row back to the original rich
                # candidate object built by ConvertTo-EpmRuleCandidate.
                $selectedRows = @($dgCandidates.SelectedItems)
                if($selectedRows.Count -eq 0) { throw 'Mark one candidate row first.' }
                if($selectedRows.Count -gt 1) { throw 'Mark exactly one row to create a rule from it. Each rule needs its own hash, so rows cannot be batched here.' }

                $candidateIndex = [int]$selectedRows[0]['CandidateIndex']
                if($candidateIndex -lt 0 -or $candidateIndex -ge $script:candidates.Count) {
                    throw 'Could not resolve the marked row to a candidate. Re-import and try again.'
                }
                $source = $script:candidates[$candidateIndex]

                if([string]::IsNullOrWhiteSpace($source.FileName)) {
                    throw 'This row has no file name on record, so a rule cannot be built from it.'
                }
                if([string]::IsNullOrWhiteSpace($source.FileHash)) {
                    throw "This row has no file hash on record, so a hash rule cannot be created from it. A CSV import only carries a hash when the export included one; the Intune elevation report always does, since the agent computes it from the real binary. Fetch from Intune instead, or use Scan Path if the file is available locally."
                }

                $ruleName = if(-not [string]::IsNullOrWhiteSpace($source.RuleName)) { [string]$source.RuleName } else { [string]$source.FileName }
                $candidate = [PSCustomObject]@{
                    RuleName = $ruleName
                    FileName = [string]$source.FileName
                    FileHash = [string]$source.FileHash
                    Publisher = [string]$source.Publisher
                    Product = [string]$source.Product
                    MatchType = 'Hash'
                }

                $elevationValue = if($null -ne $cbAuditElevationType.SelectedValue) { [string]$cbAuditElevationType.SelectedValue } else { $null }
                $childProcessValue = if($null -ne $cbAuditChildProcess.SelectedValue) { [string]$cbAuditChildProcess.SelectedValue } else { $null }
                $validationValues = if(-not [string]::IsNullOrWhiteSpace($script:auditValidationDefaultValue)) { @($script:auditValidationDefaultValue) } else { @() }

                $targetPolicyName = $cbAuditPolicy.Text
                $replaceRuleName = $null
                $existingNames = @((Get-EpmPolicyRule -PolicyId $cbAuditPolicy.SelectedValue) | ForEach-Object { $_.RuleName })
                if($existingNames -contains $ruleName) {
                    $prompt = "A rule named '$ruleName' already exists in policy '$targetPolicyName'.`r`n`r`nYes = Overwrite existing rule`r`nNo = Cancel"
                    $choice = [System.Windows.MessageBox]::Show($window, $prompt, 'Duplicate rule name', 'YesNo', 'Warning')
                    if($choice -ne 'Yes') {
                        Write-GuiStatus -Message 'Rule creation cancelled.'
                        return
                    }
                    $replaceRuleName = $ruleName
                }

                $confirm = [System.Windows.MessageBox]::Show($window, "Create hash rule '$ruleName' in policy '$targetPolicyName' from the marked audit row?", 'Confirm write', 'YesNo', 'Question')
                if($confirm -ne 'Yes') { Write-GuiStatus -Message 'Rule creation cancelled.'; return }

                Add-EpmScannedRuleToPolicy -PolicyId $cbAuditPolicy.SelectedValue -Candidate $candidate -ElevationTypeValue $elevationValue -ValidationValues $validationValues -ChildProcessBehaviorValue $childProcessValue -RuleNameOverride $ruleName -ReplaceRuleName $replaceRuleName | Out-Null

                if($null -ne $replaceRuleName) {
                    $txtBuildOutput.Text += "[OK] Overwrote existing rule '$ruleName' (Hash match) in '$targetPolicyName'.`r`n"
                } else {
                    $txtBuildOutput.Text += "[OK] Created rule '$ruleName' (Hash match) in '$targetPolicyName'.`r`n"
                }
                Write-GuiStatus -Message "Created hash rule '$ruleName' in '$targetPolicyName'."
            }
        })

    $btnLoadPoliciesReplicate.Add_Click({
            Invoke-GuiOperation -Message 'Loading EPM policies from Microsoft Graph' -FailureTitle 'Graph failed' -Button $btnLoadPoliciesReplicate -Operation { Get-GuiPolicyList }
        })

    $btnRunCoverage.Add_Click({
            Invoke-GuiOperation -Message 'Scoring imported elevations against existing EPM persona rules' -FailureTitle 'Coverage analysis failed' -Button $btnRunCoverage -Operation {
                if($script:candidates.Count -eq 0) { throw 'Import an audit CSV on the Audit Import tab first.' }

                $existingRules = @(Get-AllEpmRule)
                if($existingRules.Count -eq 0) { throw 'No existing EPM rules were found to compare against.' }

                $report = Get-EpmCoverageReport -Candidates $script:candidates.ToArray() -ExistingRules $existingRules

                $txtCoverageScore.Text = "Coverage score: $($report.OverallCoveragePercent)% - $($report.CoveredElevations) of $($report.TotalElevations) imported elevations are already covered by an existing EPM persona rule. Persona effectiveness score: $($report.OverallPersonaCoveragePercent)% - $($report.OverallPersonaCoveredElevations) of $($report.OverallPersonaAssignedElevations) assigned elevations are covered by their recommended persona."

                $scoreColor = Get-EpmCoverageColor -Percent $report.OverallCoveragePercent
                $brdCoverageScore.Background = [System.Windows.Media.SolidColorBrush]::new([System.Windows.Media.ColorConverter]::ConvertFromString($scoreColor))
                $brdCoverageScore.BorderBrush = $brdCoverageScore.Background
                $txtCoverageScore.Foreground = [System.Windows.Media.Brushes]::White

                $dtPersonas = ConvertTo-DataTable -Array @($report.PersonaSummary)
                $icPersonaCards.ItemsSource = $dtPersonas.DefaultView

                $dtUsers = ConvertTo-DataTable -Array @($report.UserRecommendations)
                $dgUserRecommendation.ItemsSource = $dtUsers.DefaultView

                $script:uncoveredDetails = @($report.UncoveredDetails)
                $dtUncovered = ConvertTo-DataTable -Array @($report.UncoveredSummary)
                $dgUncovered.ItemsSource = $dtUncovered.DefaultView
                if($report.UncoveredElevations -gt 0) {
                    $txtUncoveredSummary.Text = "$($report.UncoveredElevations) elevation(s) across $($report.UncoveredSummary.Count) distinct application(s) are not covered by any existing persona rule. Use 'Export Uncovered (CSV)' for the full per-elevation list."
                    $btnExportUncovered.IsEnabled = $true
                } else {
                    $txtUncoveredSummary.Text = 'Every imported elevation is covered by an existing persona rule. Nothing to action here.'
                    $btnExportUncovered.IsEnabled = $false
                }

                Write-GuiStatus -Message "Coverage analysis complete: $($report.OverallCoveragePercent)% covered across $($report.PersonaSummary.Count) persona(s); $($report.UncoveredElevations) uncovered."
            }
        })

    $btnExportUncovered.Add_Click({
            Invoke-GuiOperation -Message 'Exporting uncovered elevations' -FailureTitle 'Export failed' -Button $btnExportUncovered -Operation {
                if($null -eq $script:uncoveredDetails -or $script:uncoveredDetails.Count -eq 0) {
                    throw 'Run the coverage analysis first - there are no uncovered elevations to export.'
                }

                $dialog = New-Object Microsoft.Win32.SaveFileDialog
                $dialog.Title = 'Export uncovered elevations'
                $dialog.Filter = 'CSV files (*.csv)|*.csv'
                $dialog.FileName = "UncoveredElevations.$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
                if($dialog.ShowDialog() -ne $true) {
                    Write-GuiStatus -Message 'Export cancelled.'
                    return
                }

                $script:uncoveredDetails | Export-Csv -Path $dialog.FileName -NoTypeInformation -Encoding UTF8
                Write-GuiStatus -Message "Exported $($script:uncoveredDetails.Count) uncovered elevation(s) to $($dialog.FileName)."
            }
        })

    $btnLoadSourceRules.Add_Click({
            Invoke-GuiOperation -Message 'Loading rules from selected source policy' -FailureTitle 'Load rules failed' -Button $btnLoadSourceRules -Operation {
                if($null -eq $cbSourcePolicy.SelectedValue) { throw 'Select a source policy first.' }
                $rules = @(Get-EpmPolicyRule -PolicyId $cbSourcePolicy.SelectedValue -PolicyName $cbSourcePolicy.Text)
                $cbSourceRule.ItemsSource = $rules
                Write-GuiStatus -Message "Loaded $($rules.Count) rules from source policy."
            }
        })

    $btnReplicateRule.Add_Click({
            Invoke-GuiOperation -Message 'Replicating selected rule to target policy' -FailureTitle 'Replicate failed' -Button $btnReplicateRule -Operation {
                if($null -eq $cbSourcePolicy.SelectedValue) { throw 'Select a source policy.' }
                if($null -eq $cbTargetPolicy.SelectedValue) { throw 'Select a target policy.' }
                if($null -eq $cbSourceRule.SelectedValue) { throw 'Select a source rule.' }

                $confirm = [System.Windows.MessageBox]::Show($window, 'Replicate the selected rule to the target policy?', 'Confirm write', 'YesNo', 'Question')
                if($confirm -ne 'Yes') { return }

                Copy-EpmRuleToPolicy -SourcePolicyId $cbSourcePolicy.SelectedValue -TargetPolicyId $cbTargetPolicy.SelectedValue -RuleName $cbSourceRule.SelectedValue | Out-Null
                $txtReplicateOutput.Text += "Replicated '$($cbSourceRule.SelectedValue)' to '$($cbTargetPolicy.Text)'.`r`n"
                Write-GuiStatus -Message 'Rule replicated.'
            }
        })

    $btnLoadReusable.Add_Click({
            Invoke-GuiOperation -Message 'Loading reusable settings' -FailureTitle 'Reusable settings failed' -Button $btnLoadReusable -Operation {
                $settings = @(Get-EpmReusableSetting)
                $cbReusable.ItemsSource = $settings
                Write-GuiStatus -Message "Loaded $($settings.Count) reusable settings."
            }
        })

    $btnFindReusableUsage.Add_Click({
            Invoke-GuiOperation -Message 'Resolving reusable setting usage' -FailureTitle 'Usage lookup failed' -Button $btnFindReusableUsage -Operation {
                if($null -eq $cbReusable.SelectedValue) { throw 'Select a reusable setting first.' }
                $usage = @(Get-EpmReusableSettingUsage -ReusableSettingId $cbReusable.SelectedValue)
                $dtUsage = ConvertTo-DataTable -Array $usage
                $dgReusableUsage.ItemsSource = $dtUsage.DefaultView
                Write-GuiStatus -Message "Resolved $($usage.Count) usage record(s)."
            }
        })

    $btnBrowseScanPath.Add_Click({
            # A folder picker keeps the typed path option intact: the dialog seeds from and writes
            # back to the path text box.
            $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
            $dialog.Description = 'Select a folder to scan for executables'
            $dialog.ShowNewFolderButton = $false
            if(-not [string]::IsNullOrWhiteSpace($txtScanPath.Text) -and (Test-Path -Path $txtScanPath.Text -PathType Container)) {
                $dialog.SelectedPath = $txtScanPath.Text
            }
            if($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $txtScanPath.Text = $dialog.SelectedPath
            }
        })

    $btnSettingsBrowseTempPath.Add_Click({
            $dialog = New-Object System.Windows.Forms.FolderBrowserDialog
            $dialog.Description = 'Select a folder for temporary working files used during certificate extraction.'
            $dialog.ShowNewFolderButton = $true
            if(-not [string]::IsNullOrWhiteSpace($txtSettingsTempPath.Text) -and (Test-Path -Path $txtSettingsTempPath.Text -PathType Container)) {
                $dialog.SelectedPath = $txtSettingsTempPath.Text
            }
            if($dialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
                $txtSettingsTempPath.Text = $dialog.SelectedPath
            }
        })

    $btnSettingsSave.Add_Click({
            Invoke-GuiOperation -Message 'Saving settings' -FailureTitle 'Save settings failed' -Button $btnSettingsSave -Operation {
                if([string]::IsNullOrWhiteSpace($txtSettingsTempPath.Text)) {
                    throw 'Enter or browse to a temporary working directory.'
                }

                $savedSettings = Save-EpmToolSettings -TempWorkingDirectory $txtSettingsTempPath.Text
                $txtSettingsTempPath.Text = [string]$savedSettings.TempWorkingDirectory
                $txtSettingsOutput.Text += "[OK] Saved temp working directory: $($savedSettings.TempWorkingDirectory)`r`n"
                Update-GuiExtractFolderHint
                Write-GuiStatus -Message 'Settings saved.'
            }
        })

    $btnSettingsResetDefault.Add_Click({
            Invoke-GuiOperation -Message 'Resetting settings to default' -FailureTitle 'Reset settings failed' -Button $btnSettingsResetDefault -Operation {
                $defaultSettings = Get-EpmToolDefaultSettings
                $savedSettings = Save-EpmToolSettings -TempWorkingDirectory $defaultSettings.TempWorkingDirectory
                $txtSettingsTempPath.Text = [string]$savedSettings.TempWorkingDirectory
                $txtSettingsOutput.Text += "[OK] Reset temp working directory to default: $($savedSettings.TempWorkingDirectory)`r`n"
                Update-GuiExtractFolderHint
                Write-GuiStatus -Message 'Settings reset to default.'
            }
        })

    $btnScanPath.Add_Click({
            Invoke-GuiOperation -Message 'Scanning path for selected file types' -FailureTitle 'Scan failed' -Button $btnScanPath -Operation {
                if([string]::IsNullOrWhiteSpace($txtScanPath.Text)) { throw 'Enter or browse to a path to scan.' }
                if(-not (Test-Path -Path $txtScanPath.Text -PathType Container)) { throw "The path '$($txtScanPath.Text)' does not exist or is not a folder." }

                $extensions = [System.Collections.Generic.List[string]]::new()
                if($chkScanExe.IsChecked) { $extensions.Add('exe') }
                if($chkScanMsi.IsChecked) { $extensions.Add('msi') }
                if($chkScanPs1.IsChecked) { $extensions.Add('ps1') }
                if($extensions.Count -eq 0) { throw 'Select at least one file type to scan for.' }

                $found = Get-EpmExecutableFromPath -Path $txtScanPath.Text -Extension $extensions.ToArray() -Recurse:$chkScanRecurse.IsChecked
                $script:scanResults = $found
                $dtScan = ConvertTo-DataTable -Array @($found)
                $dgScanResults.ItemsSource = $dtScan.DefaultView
                $txtScanCount.Text = "$($found.Count) item(s)"

                # A new scan invalidates the certificate and the names carried over from the
                # previous file, so suggestions start fresh against whatever is marked next.
                $script:extractedCertificate = $null
                Set-GuiExtractedCertificateList -Details @()
                $script:ruleNameIsSuggested = $true
                $script:internalNameIsSuggested = $true
                $script:suppressScanNameEcho = $true
                try {
                    $txtScanRuleName.Text = ''
                    $txtScanInternalName.Text = ''
                } finally {
                    $script:suppressScanNameEcho = $false
                }

                # The scan itself never needs EpmTools - publisher, hash and version data come from
                # Authenticode, Get-FileHash and the version resource. Only step 2 needs it, so the
                # warning is about what will not work later, not about the scan just performed.
                if(-not (Test-EpmToolsAvailable)) {
                    $probeDetail = if(-not [string]::IsNullOrWhiteSpace($script:epmToolsProbeMessage)) { $script:epmToolsProbeMessage } else { "EpmTools 'Get-FileAttributes' is not available in this session." }
                    $txtScanOutput.Text = "[WARN] $probeDetail Scan results are complete, but extracting a signing certificate in step 2 will not work until EpmTools can be loaded.`r`n"
                } else {
                    $txtScanOutput.Text = ''
                }
                Write-GuiStatus -Message "Scan complete: $($found.Count) matching file(s) found."
            }
        })

    $mnuScanCopyRow.Add_Click({
            Copy-DataGridSelection -Grid $dgScanResults
            Write-GuiStatus -Message 'Copied selected row(s) to the clipboard.'
        })

    $mnuScanCopyCell.Add_Click({
            $cell = $dgScanResults.CurrentCell
            if($null -eq $cell.Column -or $null -eq $cell.Item) {
                return
            }
            $text = Get-DataGridCellText -Column $cell.Column -Item $cell.Item
            Set-GuiClipboardText -Text $text
            Write-GuiStatus -Message 'Copied cell to the clipboard.'
        })

    $dgScanResults.Add_SelectionChanged({
            # Marking a different file is a fresh start for the suggested names.
            $script:ruleNameIsSuggested = $true
            $script:internalNameIsSuggested = $true
            Update-GuiScanRowContext
        })

    $txtScanRuleName.Add_TextChanged({
            if(-not $script:suppressScanNameEcho) {
                $script:ruleNameIsSuggested = $false
            }
        })

    $txtScanInternalName.Add_TextChanged({
            if(-not $script:suppressScanNameEcho) {
                $script:internalNameIsSuggested = $false
            }
        })

    $cbScanElevationType.Add_SelectionChanged({
            # Validation only exists under the user-confirmed rule type. An automatic rule sends no
            # validation at all, so showing a live validation choice for one would be a lie.
            $elevationValue = if($null -ne $cbScanElevationType.SelectedValue) { [string]$cbScanElevationType.SelectedValue } else { '' }
            $isAutomatic = $elevationValue -imatch '_automatic$'
            $cbScanValidation.IsEnabled = -not $isAutomatic
            $cbScanValidation.ToolTip = if($isAutomatic) { 'Automatic elevation does not use validation.' } else { $null }
        })

    $cbScanMatchType.Add_SelectionChanged({
            Update-GuiMatchTypeState
        })

    $dgScanResults.Add_MouseDoubleClick({
            $cell = $dgScanResults.CurrentCell
            if($null -ne $cell.Column -and $null -ne $cell.Item) {
                $text = Get-DataGridCellText -Column $cell.Column -Item $cell.Item
                if(-not [string]::IsNullOrEmpty($text)) {
                    Set-GuiClipboardText -Text $text
                    Write-GuiStatus -Message 'Copied cell to the clipboard.'
                    return
                }
            }
            Copy-DataGridSelection -Grid $dgScanResults
            Write-GuiStatus -Message 'Copied selected row(s) to the clipboard.'
        })

    $btnExtractCert.Add_Click({
            Invoke-GuiOperation -Message 'Extracting certificate from selected file' -FailureTitle 'Certificate extraction failed' -Button $btnExtractCert -Operation {
                $selected = @($dgScanResults.SelectedItems)
                if($selected.Count -eq 0) { throw 'Select a signed file in the scan results first.' }
                if($selected.Count -gt 1) { throw 'Select a single file to extract its certificate.' }

                $filePath = [string]$selected[0]['FilePath']
                $isSignedText = [string]$selected[0]['IsSigned']
                if($isSignedText -eq 'False') {
                    throw 'The selected file is not signed, so it has no certificate to extract. Use a hash match for unsigned files.'
                }

                $script:extractedCertificate = Export-EpmFileCertificate -FilePath $filePath
                $fileName = $script:extractedCertificate.FileName

                # Offer the whole chain so the operator decides how broad the rule should be, rather
                # than the tool silently deciding for them.
                $details = @($script:extractedCertificate.CertificateDetails)
                Set-GuiExtractedCertificateList -Details $details
                Update-GuiSuggestedReusableName

                $savedDirectory = ''
                if($script:extractedCertificate.ContainsKey('SavedDirectory') -and -not [string]::IsNullOrWhiteSpace($script:extractedCertificate.SavedDirectory)) {
                    $savedDirectory = [string]$script:extractedCertificate.SavedDirectory
                }

                $txtScanOutput.Text += "[OK] Extracted $($details.Count) certificate(s) from '$fileName' (publisher: $($script:extractedCertificate.Publisher)).`r`n"
                if(-not [string]::IsNullOrWhiteSpace($savedDirectory)) {
                    $txtScanOutput.Text += "     Saved to: $savedDirectory`r`n"
                }
                foreach($detail in $details) {
                    $txtScanOutput.Text += "     - $($detail.ListLabel)`r`n"
                }
                $txtScanOutput.Text += "     Pick the certificate to reuse, check the name, then upload it to Intune.`r`n"

                # Update the selected scan row so the UI immediately reflects known extraction state.
                $selectedRow = $selected[0]
                if($selectedRow -is [System.Data.DataRowView]) {
                    $selectedRow['Extracted'] = 'Yes'
                    if($script:extractedCertificate.ContainsKey('SavedDirectory') -and -not [string]::IsNullOrWhiteSpace($script:extractedCertificate.SavedDirectory)) {
                        $selectedRow['ExtractedFolder'] = [string]$script:extractedCertificate.SavedDirectory
                    }
                }

                Write-GuiStatus -Message "Certificate extracted from '$fileName'."
            }
        })

    $btnExtractHash.Add_Click({
            Invoke-GuiOperation -Message 'Extracting hash from selected file' -FailureTitle 'Hash extraction failed' -Button $btnExtractHash -Operation {
                $selected = @($dgScanResults.SelectedItems)
                if($selected.Count -eq 0) { throw 'Select a file in the scan results first.' }
                if($selected.Count -gt 1) { throw 'Select a single file to extract its hash.' }

                $filePath = [string]$selected[0]['FilePath']
                if([string]::IsNullOrWhiteSpace($filePath) -or -not (Test-Path -Path $filePath -PathType Leaf)) {
                    throw "The selected file path '$filePath' is not valid."
                }

                $hash = (Get-FileHash -LiteralPath $filePath -Algorithm SHA256 -ErrorAction Stop).Hash
                $selectedRow = $selected[0]
                if($selectedRow -is [System.Data.DataRowView]) {
                    $selectedRow['FileHash'] = $hash
                    $selectedRow['MatchType'] = 'Hash'
                }

                $fileName = Split-Path -Path $filePath -Leaf
                $txtScanOutput.Text += "[OK] Extracted SHA256 hash for '$fileName': $hash`r`n"
                Write-GuiStatus -Message "Hash extracted from '$fileName'."
            }
        })

    $btnCheckReusableMatch.Add_Click({
            Invoke-GuiOperation -Message 'Loading extracted certificate details and reusable settings' -FailureTitle 'Reusable review failed' -Button $btnCheckReusableMatch -Operation {
                $selected = @($dgScanResults.SelectedItems)
                if($selected.Count -eq 0) { throw 'Select a file in the scan results first.' }
                if($selected.Count -gt 1) { throw 'Select a single file to review certificates and reusable settings.' }

                $filePath = [string]$selected[0]['FilePath']
                if([string]::IsNullOrWhiteSpace($filePath)) {
                    throw 'The selected row does not contain a valid file path.'
                }

                $extractInfo = Get-EpmExtractedCertificateInfo -FilePath $filePath
                $certDetails = @(Get-EpmCertificateDetailsFromDirectory -DirectoryPath $extractInfo.FolderPath)
                if($certDetails.Count -eq 0) {
                    throw "No extracted certificates were found for '$filePath'. Extract certificates first, then review reusable settings."
                }

                $fileName = Split-Path -Path $filePath -Leaf
                $txtScanOutput.Text += "[INFO] Extracted certificates for '$fileName' (folder: $($extractInfo.FolderPath)):`r`n"
                foreach($certDetail in $certDetails) {
                    $txtScanOutput.Text += "     - $($certDetail.ListLabel)`r`n"
                }

                $reusableSettings = @(Get-EpmReusableSetting)
                $cbScanReusable.ItemsSource = $reusableSettings

                $txtScanOutput.Text += "[INFO] Available reusable certificate settings in Intune ($($reusableSettings.Count)):`r`n"
                foreach($setting in $reusableSettings) {
                    $countText = if($null -ne $setting.ReferencingConfigurationPolicyCount) { [string]$setting.ReferencingConfigurationPolicyCount } else { '0' }
                    $txtScanOutput.Text += "     - $($setting.DisplayName) (id: $($setting.Id), referenced by policies: $countText)`r`n"
                }

                # Match on the certificate itself, not on its name. A rule that points at the wrong
                # reusable certificate silently elevates a different publisher's binaries, and two
                # unrelated vendors can easily produce similar-looking display names. Thumbprint
                # comparison is authoritative; display-name matching is only reported as a lower
                # confidence fallback for tenants where the stored certificate value cannot be read
                # back. Nothing is auto-selected unless the thumbprint actually matched.
                # When one certificate is picked in step 2, only that one is checked - the question
                # being answered is "is the certificate I am about to upload already in the tenant".
                $picked = $cbExtractedCertificate.SelectedItem
                if($null -ne $picked) {
                    $certificateValues = @([string]$picked.Base64)
                    $txtScanOutput.Text += "[INFO] Checking the selected certificate ($($picked.Role) - $($picked.SubjectName)) against the tenant.`r`n"
                } else {
                    $certificateValues = @(Get-CertificateBase64FromDirectory -DirectoryPath $extractInfo.FolderPath)
                }
                $reusableMatches = @(Find-EpmReusableCertificateMatch -CertificateBase64Values $certificateValues)

                if($reusableMatches.Count -eq 0) {
                    $txtScanOutput.Text += "[INFO] No existing reusable setting matches this certificate. Upload it as a new reusable setting before creating a certificate rule.`r`n"
                } else {
                    $txtScanOutput.Text += "[INFO] Reusable settings matching this certificate ($($reusableMatches.Count)):`r`n"
                    foreach($match in $reusableMatches) {
                        $thumbText = if(-not [string]::IsNullOrWhiteSpace($match.MatchingThumbprints)) { " | thumbprint: $($match.MatchingThumbprints)" } else { '' }
                        $txtScanOutput.Text += "     - $($match.DisplayName) [$($match.MatchType) match, $($match.Confidence) confidence]$thumbText`r`n"
                    }
                }

                $exactMatch = $reusableMatches | Where-Object { $_.MatchType -eq 'Thumbprint' } | Select-Object -First 1
                if($null -ne $exactMatch) {
                    $cbScanReusable.SelectedValue = $exactMatch.ReusableSettingId
                    # Treat a thumbprint match the same as a fresh upload: it is the reusable setting
                    # for this certificate, so a later switch to Certificate match should re-use it.
                    $script:lastUploadedReusableId = [string]$exactMatch.ReusableSettingId
                    $txtScanOutput.Text += "[OK] Selected '$($exactMatch.DisplayName)' - its stored certificate has the same thumbprint as the one extracted from this file. No upload needed.`r`n"
                } elseif($reusableMatches.Count -gt 0) {
                    $txtScanOutput.Text += "[WARN] Only display-name matches were found, so nothing was selected automatically. Confirm the certificate is the right one before picking it.`r`n"
                }

                Write-GuiStatus -Message "Reviewed $($certDetails.Count) extracted certificate(s) against $($reusableSettings.Count) reusable setting(s): $($reusableMatches.Count) match(es)."
            }
        })

    $cbExtractedCertificate.Add_SelectionChanged({
            Update-GuiSuggestedReusableName
            Update-GuiCertificateButtons
        })

    $txtReusableName.Add_TextChanged({
            # Once the operator edits the name themselves, stop overwriting it with the suggestion.
            if(-not $script:suppressReusableNameEcho) {
                $script:reusableNameIsSuggested = $false
            }
        })

    $btnUploadReusable.Add_Click({
            Invoke-GuiOperation -Message 'Uploading certificate as a reusable setting' -FailureTitle 'Upload failed' -Button $btnUploadReusable -Operation {
                $certificate = $cbExtractedCertificate.SelectedItem
                if($null -eq $certificate) { throw 'Extract a certificate and pick which one to upload first.' }
                if([string]::IsNullOrWhiteSpace($txtReusableName.Text)) { throw 'Enter a name for the reusable setting.' }

                $confirmText = "Upload this certificate to Intune as a reusable setting?" + [Environment]::NewLine + [Environment]::NewLine +
                    "Name       : $($txtReusableName.Text)" + [Environment]::NewLine +
                    "Certificate: $($certificate.Role) - $($certificate.SubjectName)" + [Environment]::NewLine +
                    "Issued by  : $($certificate.IssuerName)" + [Environment]::NewLine +
                    "Thumbprint : $($certificate.Thumbprint)"
                $confirm = [System.Windows.MessageBox]::Show($window, $confirmText, 'Confirm write', 'YesNo', 'Question')
                if($confirm -ne 'Yes') { Write-GuiStatus -Message 'Upload cancelled.'; return }

                $result = New-EpmReusableCertificateSetting -DisplayName $txtReusableName.Text -CertificateBase64 $certificate.Base64
                $script:lastUploadedReusableId = [string]$result.Id
                $txtScanOutput.Text += "[OK] Uploaded '$($result.DisplayName)' (id: $($result.Id)) from the $($certificate.Role) certificate $($certificate.Thumbprint).`r`n"

                # Refresh the reusable list and select the new certificate so step 3 is ready to go.
                $settings = @(Get-EpmReusableSetting)
                $cbScanReusable.ItemsSource = $settings
                $cbScanReusable.SelectedValue = $result.Id
                Write-GuiStatus -Message "Reusable certificate setting '$($result.DisplayName)' created and selected for rule creation."
            }
        })

    $btnLoadScanPolicies.Add_Click({
            Invoke-GuiOperation -Message 'Loading policies, rule options and reusable settings' -FailureTitle 'Load failed' -Button $btnLoadScanPolicies -Operation {
                if($null -eq $script:policies) { Get-GuiPolicyList }
                $cbScanPolicy.ItemsSource = $script:policies

                $settings = @(Get-EpmReusableSetting)
                $cbScanReusable.ItemsSource = $settings

                Write-GuiStatus -Message "Loaded $($script:policies.Count) policy/policies and $($settings.Count) reusable certificate setting(s). Select a target policy to load its rule options."
            }
        })

    $cbScanPolicy.Add_SelectionChanged({
            if($null -eq $cbScanPolicy.SelectedValue) { return }
            Invoke-GuiOperation -Message 'Reading rule options from the selected policy' -FailureTitle 'Options load failed' -Button $cbScanPolicy -Operation {
                # Read the choice options (elevation type, validation, child process behavior) straight
                # from the policy's expanded setting definitions so the offered options are exactly the
                # tenant-correct values, never hardcoded.
                $policySettings = Get-EpmPolicySetting -PolicyId $cbScanPolicy.SelectedValue

                $elevationOptions = @(Get-EpmRuleChoiceOption -Settings $policySettings -DefinitionIdTokens @('_elevationtype', '_ruletype'))
                $validationOptions = @(Get-EpmRuleChoiceOption -Settings $policySettings -DefinitionIdTokens @('_validation', '_validationtype'))
                $childProcessOptions = @(Get-EpmRuleChoiceOption -Settings $policySettings -DefinitionIdTokens @('_childprocessbehavior', '_child_process_behavior'))
                $script:scanValidationDefaultValue = $null

                $cbScanElevationType.ItemsSource = $elevationOptions
                $cbScanValidation.ItemsSource = $validationOptions
                $cbScanChildProcess.ItemsSource = $childProcessOptions
                $cbScanElevationType.SelectedIndex = -1
                $cbScanChildProcess.SelectedIndex = -1

                $defaultValidation = $validationOptions | Where-Object { $_.IsDefault } | Select-Object -First 1
                if($null -eq $defaultValidation -and $validationOptions.Count -gt 0) {
                    $defaultValidation = $validationOptions[0]
                }
                if($null -ne $defaultValidation) {
                    $script:scanValidationDefaultValue = [string]$defaultValidation.Value
                    $cbScanValidation.SelectedItem = $defaultValidation
                    $cbScanValidation.SelectedValue = $defaultValidation.Value
                } else {
                    $cbScanValidation.SelectedIndex = -1
                }

                Write-GuiStatus -Message "Loaded rule options from the selected policy ($($elevationOptions.Count) elevation type(s), $($validationOptions.Count) validation, $($childProcessOptions.Count) child process)."
            }
        })

    $btnCreateScanRule.Add_Click({
            Invoke-GuiOperation -Message 'Creating elevation rule(s) from the scanned file(s)' -FailureTitle 'Create rule failed' -Button $btnCreateScanRule -Operation {
                if($null -eq $cbScanPolicy.SelectedValue) { throw 'Select a target policy. Use "Load Policies and Options" first.' }
                $selected = @($dgScanResults.SelectedItems)
                if($selected.Count -eq 0) { throw 'Select one or more files in the scan results to create rules for.' }

                $reusableId = if($null -ne $cbScanReusable.SelectedValue) { [string]$cbScanReusable.SelectedValue } else { $null }
                $selectedMatch = if($null -ne $cbScanMatchType.SelectedValue) { [string]$cbScanMatchType.SelectedValue } else { 'Suggested' }
                $elevationValue = if($null -ne $cbScanElevationType.SelectedValue) { [string]$cbScanElevationType.SelectedValue } else { $null }
                $validationValue = $script:scanValidationDefaultValue
                if($null -ne $cbScanValidation.SelectedValue) {
                    $validationValue = [string]$cbScanValidation.SelectedValue
                } elseif($null -ne $cbScanValidation.SelectedItem -and $null -ne $cbScanValidation.SelectedItem.PSObject.Properties['Value']) {
                    $validationValue = [string]$cbScanValidation.SelectedItem.Value
                }
                $childProcessValue = if($null -ne $cbScanChildProcess.SelectedValue) { [string]$cbScanChildProcess.SelectedValue } else { $null }
                $internalName = if(-not [string]::IsNullOrWhiteSpace($txtScanInternalName.Text)) { $txtScanInternalName.Text } else { $null }
                $includeFileName = ($true -eq $chkScanIncludeFileName.IsChecked)

                # The rule name box names the rule only when a single file is marked. For a batch it
                # cannot apply, so each rule keeps the name suggested from its own file.
                $explicitRuleName = $null
                if($selected.Count -eq 1 -and -not [string]::IsNullOrWhiteSpace($txtScanRuleName.Text)) {
                    $explicitRuleName = $txtScanRuleName.Text.Trim()
                }

                # Validate the whole selection before writing anything. The per-file checks used to
                # run inside the write loop, so a bad row part-way through the batch aborted after
                # some rules had already been created in the tenant - leaving the policy in a state
                # the operator never confirmed. Everything that can be known up front is checked
                # here, so the run either starts clean or does not start at all.
                $blocking = [System.Collections.Generic.List[string]]::new()
                foreach($rowView in $selected) {
                    $rowFileName = [string]$rowView['FileName']
                    $rowMatch = [string]$rowView['MatchType']
                    if($selectedMatch -eq 'Certificate' -or $selectedMatch -eq 'Hash') {
                        $rowMatch = $selectedMatch
                    }

                    if($rowMatch -eq 'Certificate' -and [string]::IsNullOrWhiteSpace($reusableId)) {
                        $blocking.Add("$rowFileName - certificate match needs a reusable certificate setting. Extract the certificate, review it, then select or upload one.")
                        continue
                    }

                    if($rowMatch -eq 'Hash' -and [string]::IsNullOrWhiteSpace([string]$rowView['FileHash'])) {
                        $rowPath = [string]$rowView['FilePath']
                        if([string]::IsNullOrWhiteSpace($rowPath) -or -not (Test-Path -LiteralPath $rowPath -PathType Leaf)) {
                            $blocking.Add("$rowFileName - hash match needs a SHA256, and the file is no longer readable at '$rowPath'.")
                        }
                    }
                }

                if($blocking.Count -gt 0) {
                    throw ("Nothing was written. Resolve these first:" + [Environment]::NewLine + "  - " + ($blocking -join ([Environment]::NewLine + "  - ")))
                }

                $confirm = [System.Windows.MessageBox]::Show($window, "Create $($selected.Count) elevation rule(s) in policy '$($cbScanPolicy.Text)'?", 'Confirm write', 'YesNo', 'Question')
                if($confirm -ne 'Yes') { Write-GuiStatus -Message 'Rule creation cancelled.'; return }

                # Resolve the current rule names once so re-created rules get a unique name.
                $existingNames = @((Get-EpmPolicyRule -PolicyId $cbScanPolicy.SelectedValue) | ForEach-Object { $_.RuleName })
                $created = 0
                $overwritten = 0
                $skipped = 0

                foreach($rowView in $selected) {
                    # The grid is bound to a DataView, so selected items are DataRowView objects. Rebuild
                    # the candidate from the row values rather than relying on object identity.
                    $fileName = [string]$rowView['FileName']

                    # Name precedence: what the operator typed, then the name the scan suggested for
                    # this file, then the bare file name.
                    $rowSuggestedName = ''
                    if($rowView -is [System.Data.DataRowView] -and $rowView.Row.Table.Columns.Contains('RuleName')) {
                        $rowSuggestedName = [string]$rowView['RuleName']
                    }
                    $ruleName = if(-not [string]::IsNullOrWhiteSpace($explicitRuleName)) {
                        $explicitRuleName
                    } elseif(-not [string]::IsNullOrWhiteSpace($rowSuggestedName)) {
                        $rowSuggestedName
                    } else {
                        $fileName
                    }

                    $candidate = [PSCustomObject]@{
                        RuleName = $ruleName
                        FileName = $fileName
                        FilePath = [string]$rowView['FilePath']
                        FileHash = [string]$rowView['FileHash']
                        Publisher = [string]$rowView['Publisher']
                        Product = [string]$rowView['Product']
                        MatchType = [string]$rowView['MatchType']
                    }

                    if($selectedMatch -eq 'Certificate' -or $selectedMatch -eq 'Hash') {
                        $candidate.MatchType = $selectedMatch
                    }

                    # The pre-flight check above already proved the file is readable, so this only
                    # fills in a hash that was never explicitly extracted.
                    if($candidate.MatchType -eq 'Hash' -and [string]::IsNullOrWhiteSpace($candidate.FileHash)) {
                        $candidate.FileHash = (Get-FileHash -LiteralPath $candidate.FilePath -Algorithm SHA256 -ErrorAction Stop).Hash
                    }

                    $targetRuleName = $ruleName
                    $replaceRuleName = $null
                    if($existingNames -contains $targetRuleName) {
                        $prompt = "A rule named '$targetRuleName' already exists in policy '$($cbScanPolicy.Text)'.`r`n`r`nYes = Overwrite existing rule`r`nNo = Skip this file`r`nCancel = Stop processing"
                        $choice = [System.Windows.MessageBox]::Show($window, $prompt, 'Duplicate rule name', 'YesNoCancel', 'Warning')
                        if($choice -eq 'Cancel') {
                            break
                        }
                        if($choice -eq 'No') {
                            $txtScanOutput.Text += "[INFO] Skipped '$targetRuleName' because a rule with the same name already exists.`r`n"
                            $skipped++
                            continue
                        }
                        $replaceRuleName = $targetRuleName
                    }

                    $validationValues = @()
                    if(-not [string]::IsNullOrWhiteSpace($validationValue)) {
                        $validationValues = @($validationValue)
                    }

                    Add-EpmScannedRuleToPolicy -PolicyId $cbScanPolicy.SelectedValue -Candidate $candidate -ElevationTypeValue $elevationValue -ValidationValues $validationValues -ChildProcessBehaviorValue $childProcessValue -InternalName $internalName -ReusableSettingId $reusableId -RuleNameOverride $targetRuleName -ReplaceRuleName $replaceRuleName -IncludeFileName:$includeFileName | Out-Null

                    if($null -ne $replaceRuleName) {
                        $txtScanOutput.Text += "[OK] Overwrote existing rule '$targetRuleName' ($($candidate.MatchType) match) in '$($cbScanPolicy.Text)'.`r`n"
                        $overwritten++
                    } else {
                        $txtScanOutput.Text += "[OK] Created rule '$targetRuleName' ($($candidate.MatchType) match) in '$($cbScanPolicy.Text)'.`r`n"
                        $created++
                        $existingNames += $targetRuleName
                    }
                }

                Write-GuiStatus -Message "Created $created, overwritten $overwritten, skipped $skipped rule(s) in '$($cbScanPolicy.Text)'."
            }
        })

    $btnLoadExportPolicies.Add_Click({
            Invoke-GuiOperation -Message 'Loading EPM policies from Microsoft Graph' -FailureTitle 'Graph failed' -Button $btnLoadExportPolicies -Operation { Get-GuiPolicyList }
        })

    $btnPreviewExport.Add_Click({
            Invoke-GuiOperation -Message 'Reading and flattening EPM policy rules' -FailureTitle 'Preview failed' -Button $btnPreviewExport -Operation {
                if($null -eq $cbExportPolicy.SelectedValue) { throw 'Select a policy, or "All EPM Policies", first. Use "Load EPM Policies" if the list is empty.' }

                $scopeId = [string]$cbExportPolicy.SelectedValue
                $scopeLabel = $cbExportPolicy.Text

                if($scopeId -eq '__ALL__') {
                    $rules = @(Get-AllEpmRule)
                } else {
                    $rules = @(Get-EpmPolicyRule -PolicyId $scopeId -PolicyName $scopeLabel)
                }

                if($rules.Count -eq 0) {
                    $script:exportRows = @()
                    $dgExportPreview.ItemsSource = $null
                    $btnExportRules.IsEnabled = $false
                    $txtExportOutput.Text = "[INFO] '$scopeLabel' has no elevation rules to export.`r`n"
                    Write-GuiStatus -Message "'$scopeLabel' has no elevation rules."
                    return
                }

                $script:exportRows = @(Get-EpmRuleExportData -Rules $rules)
                $dgExportPreview.ItemsSource = $script:exportRows
                $btnExportRules.IsEnabled = ($script:exportRows.Count -gt 0)

                $certCount = @($script:exportRows | Where-Object { $_.MatchType -eq 'Certificate' }).Count
                $hashCount = $script:exportRows.Count - $certCount
                $txtExportOutput.Text = "[OK] Previewed $($script:exportRows.Count) rule(s) from '$scopeLabel' ($certCount certificate, $hashCount hash). Export to CSV to save it.`r`n"
                Write-GuiStatus -Message "Previewed $($script:exportRows.Count) rule(s) from '$scopeLabel'."
            }
        })

    $btnExportRules.Add_Click({
            Invoke-GuiOperation -Message 'Exporting EPM policy rules to CSV' -FailureTitle 'Export failed' -Button $btnExportRules -Operation {
                if($null -eq $script:exportRows -or $script:exportRows.Count -eq 0) {
                    throw 'Preview a policy (or All EPM Policies) first - there is nothing to export.'
                }

                $scopeLabel = if($null -ne $cbExportPolicy.SelectedItem) { [string]$cbExportPolicy.Text } else { 'EPM-Rules' }
                $safeScopeLabel = ConvertTo-SafeFileName -Name $scopeLabel

                $dialog = New-Object Microsoft.Win32.SaveFileDialog
                $dialog.Title = 'Export EPM policy rules'
                $dialog.Filter = 'CSV files (*.csv)|*.csv'
                $dialog.FileName = "$safeScopeLabel.$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
                if($dialog.ShowDialog() -ne $true) {
                    Write-GuiStatus -Message 'Export cancelled.'
                    return
                }

                # The CSV is exactly what is on screen in the preview grid - no hidden columns.
                $script:exportRows | Export-Csv -Path $dialog.FileName -NoTypeInformation -Encoding UTF8

                $txtExportOutput.Text += "[OK] Exported $($script:exportRows.Count) rule(s) to $($dialog.FileName)`r`n"
                Write-GuiStatus -Message "Exported $($script:exportRows.Count) rule(s) to $($dialog.FileName)."
            }
        })

    $btnZoomOut.Add_Click({ Set-GuiZoom -Zoom ($script:currentZoom - 0.1) -Persist })
    $btnZoomIn.Add_Click({ Set-GuiZoom -Zoom ($script:currentZoom + 0.1) -Persist })
    $btnZoomReset.Add_Click({ Set-GuiZoom -Zoom 1.0 -Persist })

    # Ctrl+MouseWheel and Ctrl+Plus/Minus/0 mirror the zoom gesture every browser already uses, so
    # there is nothing new to learn. Only acts - and only marks the event Handled - when Ctrl is
    # actually held, so plain scrolling over a DataGrid or a combo drop-down is completely
    # unaffected.
    $window.Add_PreviewMouseWheel({
            param($eventSender, $eventArgs)
            if([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control) {
                $step = if($eventArgs.Delta -gt 0) { 0.1 } else { -0.1 }
                Set-GuiZoom -Zoom ($script:currentZoom + $step) -Persist
                $eventArgs.Handled = $true
            }
        })

    $window.Add_PreviewKeyDown({
            param($eventSender, $eventArgs)
            if(-not ([System.Windows.Input.Keyboard]::Modifiers -band [System.Windows.Input.ModifierKeys]::Control)) {
                return
            }
            switch ($eventArgs.Key) {
                { $_ -in @([System.Windows.Input.Key]::OemPlus, [System.Windows.Input.Key]::Add) } {
                    Set-GuiZoom -Zoom ($script:currentZoom + 0.1) -Persist
                    $eventArgs.Handled = $true
                }
                { $_ -in @([System.Windows.Input.Key]::OemMinus, [System.Windows.Input.Key]::Subtract) } {
                    Set-GuiZoom -Zoom ($script:currentZoom - 0.1) -Persist
                    $eventArgs.Handled = $true
                }
                { $_ -in @([System.Windows.Input.Key]::D0, [System.Windows.Input.Key]::NumPad0) } {
                    Set-GuiZoom -Zoom 1.0 -Persist
                    $eventArgs.Handled = $true
                }
            }
        })

    # The XAML's Height/Width (940x1220) are the preferred size for a normal or large screen. On a
    # smaller one - a 1366x768 laptop is the common case, and MinHeight alone used to be taller than
    # that entire screen - clamp the startup size to the actual work area so the window never opens
    # larger than the screen it is on, rather than requiring the operator to immediately resize it
    # (or, worse, being unable to reach controls that opened off-screen). SystemParameters.WorkArea
    # already reflects the per-monitor-DPI awareness requested at the top of this script.
    try {
        $workArea = [System.Windows.SystemParameters]::WorkArea
        $margin = 40
        $fitWidth = [Math]::Max($window.MinWidth, $workArea.Width - $margin)
        $fitHeight = [Math]::Max($window.MinHeight, $workArea.Height - $margin)
        if($window.Width -gt $fitWidth) { $window.Width = $fitWidth }
        if($window.Height -gt $fitHeight) { $window.Height = $fitHeight }
    } catch {
        Write-DebugLog -Category 'WARN' -Message "Unable to read the screen work area to size the window: $($_.Exception.Message)"
    }

    Update-GuiExtractFolderHint
    # The match type is set before the handlers are wired, so the initial enabled state is applied
    # here rather than relying on a selection change that never fires.
    Update-GuiMatchTypeState
    Write-GuiStatus -Message "Ready. Debug log: $($script:debugLogPath)"
    Update-GuiConnectionState
    $window.ShowDialog() | Out-Null
}

#endregion GUI Definition

#region Main Entry Point

Write-DebugLog -Category 'INFO' -Message "Starting $scriptName (ParameterSet='$($PSCmdlet.ParameterSetName)', NoGui=$($NoGui.IsPresent)). Debug log: $($script:debugLogPath)"

if($NoGui -or $PSCmdlet.ParameterSetName -ne 'Gui') {
    if($PSCmdlet.ParameterSetName -eq 'Report') {
        if([string]::IsNullOrWhiteSpace($CsvPath)) {
            throw 'CsvPath is required when running the Report parameter set in NoGui mode.'
        }

        if([string]::IsNullOrWhiteSpace($OutputPath)) {
            $OutputPath = Get-DefaultOutputPath -Extension 'json'
        }

        Invoke-EpmRuleBuildCli -Path $CsvPath -Override $ColumnMap -Match $MatchType -ExportPath $OutputPath
    } elseif($PSCmdlet.ParameterSetName -eq 'Replicate') {
        Copy-EpmRuleToPolicy -SourcePolicyId $SourcePolicyId -TargetPolicyId $TargetPolicyId -RuleName $RuleName -WhatIf:((-not $Apply.IsPresent))
    } elseif($PSCmdlet.ParameterSetName -eq 'ReusableUsage') {
        Get-EpmReusableSettingUsage -ReusableSettingId $ReusableSettingId
    } else {
        Show-WpfGui
    }
} else {
    Show-WpfGui
}

#endregion Main Entry Point























