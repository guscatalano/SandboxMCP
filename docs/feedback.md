# Field feedback on the sandbox service

Two reviewers used the service for real work and wrote up what got in their way.
Their reports are reproduced verbatim below, each followed by an assessment:
whether it reproduces, whether the stated cause is right, and what it would take
to fix.

Assessments are dated 2026-10-10 and were checked against the live fleet.
Where something is marked **verified** there is a measurement behind it; where it
is marked **unverified** there is not.

Status legend: **confirmed** (reproduced) · **already fixed** (landed since they
tested) · **wrong cause** (real symptom, wrong diagnosis) · **needs a decision**
(not purely technical).

---

## Reviewer 1 — running demos

### Problems reported

| Issue | What happened | Their suggestion |
|---|---|---|
| No clean state to go back to | Each demo needed a brand-new sandbox (~7 minutes) because there was no snapshot from before my changes. | Take a fresh snapshot automatically when creation finishes, so `snapshot_sandbox revert` gives a clean machine in seconds. |
| One shared address hits GitHub's limit | All sandboxes share an egress address; after a day of runs, GitHub's 60 unauthenticated API requests an hour were used up and downloads from `github:` sources failed with 403. | A caching proxy for GitHub API and release downloads, or an option to inject a short-lived token per sandbox. |
| Uploads over ~32 KB stall | Known and documented on the wiki: anything larger dies after ~295 s, so every file goes in 44 KB chunks and is reassembled in the guest. | Fix the path MTU on `sbx0` and its SNAT route; until then, a `put_file` tool that chunks for the caller. |
| Calls through the service stop at ~2 minutes | Deskhand calls made through the service's MCP endpoint return "timed out" at about 2 minutes, whatever timeout the caller asked for. | Raise the proxy's timeout to match the request, or hand long calls off as jobs. |
| New sandboxes' tools need a new session | A new sandbox's `<name>__deskhand_*` tools only appeared after dropping the cached MCP session. | Send `tools/list_changed` when a sandbox is created or destroyed. |
| Windows isn't activated | Settings shows "Activate Windows" on every Personalization page. It didn't block anything Groundhog sets, but it shows in demos. | Activate the template, or note it so demo authors avoid those pages. |
| Four running sandboxes at most | Each new demo meant shutting one down first. | Fine as a guard; `create_sandbox` could offer to stop the caller's oldest idle sandbox instead of refusing. |

### Requests

1. Expose the console recordings. A `console_recording { vmid, from, to }` tool would give demos that cover boot, restarts and sign-in in one take, recorded from outside the guest.
2. Console screenshots from the host, for the moments Deskhand can't answer: during a restart, at a lock screen, or before Deskhand starts.
3. Downloads through the service: recordings and files out of a sandbox without needing a route to its address.
4. A fresh snapshot per sandbox, as above.
5. Note the Groundhog agent version in `list_sandboxes`, since its version decides which Groundhogfiles a sandbox can apply.

### Assessment

**Uploads over ~32 KB — confirmed symptom, wrong cause.** Reproduced going
straight at Deskhand, bypassing our MCP proxy so its own ceiling could not be
mistaken for a stall:

| payload | result |
|---|---|
| 32 KB | ok, 0.1 s |
| 256 KB | HTTP 500 after 274.9 s |

That matches their ~295 s. But **the path MTU fix would do nothing**, and three
things rule it out. The SDN zone is type `simple`, so there is no encapsulation
overhead to shave. Both ends are MTU 1500 (checked on the controller and, via
the guest agent, inside the guest). And decisively, the server *returned a 500*
after 275 s rather than the connection hanging — the bytes arrived. An MTU black
hole hangs and times out client-side; it does not answer.

So this is Deskhand's own handling of large base64 tool arguments, at roughly
1 KB/s, which has the shape of something quadratic in the argument length. It is
a Deskhand bug, not a sandboxctl network bug, and it should be filed there.

Note the guest-agent path does not have it: `write_guest_file` moved 2.3 MB in a
single call in 12.4 s with the SHA-256 verified. **The 44 KB chunking workaround
is only needed for the Deskhand route.** Their suggested `put_file` already
exists under another name.

**Calls stop at ~2 minutes — confirmed, in code.** `proxy_call` reaches
`deskhand_rpc(..., timeout=120)`, a hard default that ignores what the caller
asked for. Raising it is a one-line change; handing long calls off as jobs is
the better shape but a larger one.

**No clean state, and the four-sandbox guard — already fixed.** Snapshots and
power control both landed after this review. Both suggestions are now cheap:
take a snapshot at the end of provisioning, and have `create_sandbox` offer to
stop the caller's oldest idle sandbox rather than refusing.

**Recordings, host screenshots, downloads — confirmed gaps.** All three exist as
HTTP routes and none is exposed as an MCP tool, so an agent cannot reach them.
Wrapping the existing routes is mechanical.

**Groundhog agent version — confirmed gap, trivial.** `groundhog_status` already
returns `run.agent`; `list_sandboxes` does not surface it.

**GitHub rate limit — confirmed, and we have since made it worse.** Deskhand
auto-update now polls GitHub every ten minutes per sandbox. Four sandboxes is 24
requests an hour against a 60-an-hour unauthenticated budget, so roughly 40% of
it is spent on update checks before any Groundhog profile fetches anything.
Raising the interval is the cheap half. The real fix **needs a decision**: a
caching proxy on the controller, or a short-lived token injected per sandbox.
A token inside a sandbox is readable by anything running in it, which matters
more here than in most places.

**`tools/list_changed` — valid, deferred.** Our MCP server is stateless
Streamable HTTP; notifications need session state we do not keep.

**Windows activation — confirmed, cosmetic.** Worth fixing in the template for
demo work; harmless otherwise.

---

## Reviewer 2 — debugging and build work in a guest

> `write_guest_file` is the MVP; these are the rough edges.

| Issue | Why it hurt | Their suggested fix |
|---|---|---|
| `write_guest_file` can't create a new top-level dir | Had to pre-create `C:\buildsrc` via `run_command`; forward vs back-slash also matters for new-dir paths. | Create missing parent dirs (including top-level), and accept either slash. |
| Boxes expire mid-task | One box lease ended mid-session and I had to reprovision and re-stage everything. | Longer / extendable leases for long tasks, plus a keepalive. |
| Thin preinstalled tooling | Installed WinDbg (winget); w64devkit tripped Defender (`Trojan:Win32/Vigorf.A` → needed an exclusion); Node and procdump were absent. | A debug / dev image profile with these staged, and Defender exclusions preconfigured. |
| Store / UWP targets are awkward | Win11 Store Notepad launches via a stub that exits (wrong pid for attach / dump); `comsvcs` MiniDump failed on it. | Ship a classic Win32 sample target, or document the UWP gotcha. |
| Large guest-file retrieval | Pulling dumps / recordings back is chunked and slow. | A direct download URL for guest files. |
| App settings persist only on clean exit | WinDbg lost setting changes when killed — it flushes only on graceful close. | A graceful close helper, or documentation. |

### Assessment

**Parent directories — confirmed, and the error message is a second bug.**
Writing to a path whose parent does not exist fails, with either slash:

```
C:\newtop\a.txt    FAILED
C:/newtop2/b.txt   FAILED
```

Worse, it fails *illegibly*. The fast path produces the real reason —
`The system cannot find the path specified` — and then the code falls back to
exec chunks, which returns `no result line in the guest reply: #< CLIXML <Objs
Version=...`. The accurate message is discarded in favour of noise, so the
reviewer had to guess the cause. Two fixes, both small:

1. Create missing parents in `guest_write` before staging (and normalise the
   slash, which Windows accepts in most APIs but our PowerShell path does not
   always).
2. Strip CLIXML in `_marked_line`, the general helper. It was stripped in the
   config readers earlier but that fix did not cover this path, so any guest
   call that fails can still surface an XML blob instead of its error.

The second is the more valuable of the two: it affects every guest operation,
not just this one.

**Boxes expire mid-task — confirmed by design, and the design is wrong for long
work.** The reaper leaves a sandbox alone while a claim is live, but claims
themselves lapse, so a task longer than the claim outlives both. A keepalive is
the right answer and is nearly free: any tool call against a sandbox could
extend its expiry, so a box in active use never reaps. That is better than
longer leases, which just moves the cliff.

**Thin tooling — fair, and the fix is a profile, not the template.** A
`debug-kit` profile ships, but it currently only layers Heisenberg and opencode;
it has no WinDbg, Node, procdump or build toolchain. Extending it is
straightforward and is the right home for this.

Defender exclusions deserve a caveat. **This is a malware sandbox**, and baking
blanket exclusions into the template would quietly undermine detonation work.
They belong in the dev/debug profile only, where the threat model is "my build
tools trip a heuristic", not in the image everything clones from.

**UWP targets — valid, and not our bug.** A Store app launching via a stub that
exits is Windows behaviour. The cheap fix is a classic Win32 target in the debug
profile plus a line in the docs; chasing it in the service is not worth it.

**Large guest-file retrieval — confirmed, and it overlaps reviewer 1's request
3.** Two different people asked for the same thing from opposite ends, which is
usually a sign it should be built. One download route serving both guest files
and recordings answers both.

**Settings lost on kill — valid, low priority.** Also Windows behaviour rather
than ours. Deskhand can already close a window rather than kill a process, so
this is mostly documentation, with a graceful-close helper if it keeps coming up.

---

## What the two reports agree on

Three things were raised independently from different work, which makes them the
strongest candidates:

1. **Getting bytes out of a guest is awkward.** Reviewer 1 wants recordings and
   files; reviewer 2 wants dumps. One download route covers both.
2. **Large payloads are slow or broken**, in opposite directions: reviewer 1 hit
   the Deskhand upload stall, reviewer 2 hit slow retrieval.
3. **Sandboxes vanish underneath long work**, by expiry for reviewer 2 and by
   the running-limit refusal for reviewer 1. Both now have cheap answers that did
   not exist when they tested.

## Done so far (2026-10-11)

Nine items are in and verified against the live fleet:

| | item | evidence |
|---|---|---|
| 1 | Guest failures report their cause | `New-Item : Cannot find drive...` instead of a CLIXML blob |
| 2 | `write_guest_file` creates parents, takes either slash | `C:
ewtop\deep.txt` and `C:/newtop2/b.txt` both write |
| 3 | Proxy ceiling raised | 120 s to 900 s, configurable |
| 4 | `clean` snapshot at the end of every create | calls exercised; not yet seen on a real create |
| 5 | Keepalive on tool use | expiry at 4 min left, one call, 29 min left |
| 6 | Update cadence 10 min to 60 | 24 GitHub requests an hour back to 4 |
| 7 | Groundhog agent in `list_sandboxes` | two versions visible across the fleet, 0.23.0 and 0.24.0 |
| 8 | `sandbox_screenshot`, `list_recordings` | a 204 KB JPEG through MCP; 19 recordings with URLs |
| 9 | `download_guest_file` + `/api/download` | 300 KB round trip, SHA-256 matched, and again with Deskhand stopped |

Item 4 is the one with a caveat: the running limit was full, so it has not been
observed on an actual create. Both calls it makes were exercised against a live
sandbox and it cannot fail a create.

## The GitHub limit, resolved (2026-10-11)

Measured on the live controller mid-investigation: **7 of 60 requests
remaining**, which is the reported failure happening in front of us.

Built a mirror rather than either suggested option. A caching HTTP proxy is the
obvious answer and the wrong one: these are HTTPS fetches, so a proxy either
tunnels them and caches nothing, or intercepts TLS, which means installing a CA
into machines we deliberately detonate malware in. Per-sandbox tokens raise the
ceiling but put a live credential inside an untrusted box.

The mirror fetches each release asset once on the controller, pins it by
SHA-256, and serves it from the payload port. Shipped profiles are rewritten
automatically; `mirror_asset` warms one by hand. Any token stays on the
controller, where it raises *our* limit to 5000 an hour and never goes near a
guest.

Verified: heisenberg.exe mirrored at 2,292,736 bytes with the hash matching on
read-back, and both shipped profiles rewritten off `github:`.

One claim corrected by testing. The first version of this said a mirrored
profile would install with egress `local` **or** `blocked`. Only `local` is
true:

| egress | mirror on the payload port | github.com |
|---|---|---|
| open | 2,292,736 bytes | reachable |
| local | 2,292,736 bytes | unreachable |
| blocked | unreachable | unreachable |

`blocked` puts a DROP above the security group, so nothing leaves at all,
including to us. That is the point of the mode, and the comment in the code now
says so.

## Suggested order

Cheap, mechanical, no decision needed:

- strip CLIXML in `_marked_line` so guest failures are legible
- create parent directories in `guest_write`, and accept either slash
- raise the proxy's 120 s ceiling
- snapshot at the end of provisioning
- surface the Groundhog agent version in `list_sandboxes`
- wrap the existing recordings and screen routes as MCP tools
- extend expiry on any tool call against a sandbox

Larger, or needing a decision first:

- a download route for guest files and recordings
- the GitHub rate limit: caching proxy versus per-sandbox token
- a fuller `debug-kit` profile, with Defender exclusions scoped to that profile
- `create_sandbox` offering to stop the caller's oldest idle sandbox
- activating the template

Deferred: `tools/list_changed`, which needs MCP session state we do not keep.
