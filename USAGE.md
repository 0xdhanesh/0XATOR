# Using ATOR

ATOR obtains authentication values from a recorded Burp macro and replaces stale values in later requests. It can refresh those values and retry a request when a configured error response is received. This guide covers the Burp UI, automatic request handling, session rules, and calls made through Burp's separate MCP extension.

## Load and configure the extension

Build this source with `mvn clean package` and load `.localdev/target/ATOR-v2.5.2-jar-with-dependencies.jar`. In Burp, open **Extensions > Installed > Add**, select **Java**, and choose the JAR. The older v2.5 release returns extracted values in its status response.

In the **ATOR v2.5.2** suite tab:

1. In **ATOR Configuration**, record the response that indicates an expired token under **Error Condition**.
2. Add the login or refresh request under **Obtain Token** and define the values to extract from its response.
3. Define where those values belong in the target request under **Error Condition Replacement**.
4. Use **Preview** to inspect a replacement before enabling live changes. While Preview is on, the live HTTP handler and session action do not update traffic.
5. In **Settings**, choose the Burp tools and optional scope, domain, and Repeater label limits. Check **Activity** to see ATOR's decisions.

The [README walkthrough](README.md#walkthrough-with-tiredful) gives a concrete token refresh example.

## Ways to use ATOR

| Route | How to use it | What ATOR does |
| --- | --- | --- |
| Burp HTTP tools | Send traffic from an enabled tool such as Proxy, Repeater, Intruder, Scanner, Sequencer, Extensions, or Burp AI. | Replaces configured values before sending. A matching error response can trigger a fresh obtain macro and retry. |
| Repeater with a label | Set a regex in **Settings > Repeater labels** and add `X-ATOR-Repeater-Tab: <label>` to selected requests. | Processes only Repeater requests whose label matches the regex. It removes the label header before sending. |
| Burp session handling rule | Add a rule with the extension action named `ATOR`. | Obtains missing values and applies replacements before sending. The session action itself does not handle an error response or retry. |
| Burp MCP request tools | Call `send_http1_request` or `send_http2_request` in the separate Burp MCP extension. | Burp identifies these requests as **Extensions** traffic. ATOR handles them when **Extensions (burp-mcp)** is enabled. |
| ATOR command header | Send `X-ATOR-Command` from Burp MCP, Burp AI, or Repeater. | Returns a local JSON response for status, refresh, configuration export/import, or domain updates. The command request is not forwarded. |

For the live HTTP handler, Preview, disabled tool checkboxes, Burp scope, and selected domains can prevent automatic replacement. The session action checks Preview and selected domains, but does not use the tool checkboxes or **InScope** setting. The **Activity** tab records the latest 500 decisions with time, hook, tool, method, host, outcome, and reason. It stays in memory and has a **Clear activity** button; it does not store paths, bodies, or token values.

### Repeater labels

Burp does not expose an existing Repeater tab's visible title to ATOR. The request header is the label. For example, set the regex to `dhanesh` and put this line in requests that should be handled:

```http
X-ATOR-Repeater-Tab: validation-dhanesh-for-123
```

The regex uses a substring match. A missing or nonmatching label makes ATOR skip replacement and error-triggered retry for that Repeater request. A blank regex allows all Repeater requests when the Repeater checkbox is enabled. Renaming the tab does not change its request header.

The `ATOR` session action cannot identify its source Burp tool. When the label regex is set, that session action requires a matching header on every request it processes. Use the live HTTP handler's tool settings when you need tool-specific behavior.

## Burp MCP tools that work with ATOR

ATOR does **not** register its own MCP tools. These tools are provided by [PortSwigger's Burp MCP server](https://github.com/PortSwigger/mcp-server/blob/main/src/main/kotlin/net/portswigger/mcp/tools/Tools.kt); availability depends on the installed MCP version, Burp edition, and MCP settings.

| Burp MCP tool | ATOR use |
| --- | --- |
| `send_http1_request` | Send an HTTP/1.1 request through Burp. Add `X-ATOR-Command` for a local ATOR command, or send a normal target request for automatic replacement. |
| `send_http2_request` | Same use over HTTP/2; pass the command as an entry in `headers`, separate from `requestBody`. |
| `create_repeater_tab`, `create_repeater_tab_http2` | Create a Repeater tab for manual sending. Include `X-ATOR-Repeater-Tab` in the request if a Repeater label regex is set; the tab name alone has no effect on ATOR. Creating a tab does not send its request. |
| `send_to_intruder` | Place a request in Intruder. ATOR handles traffic when Intruder sends it and the Intruder checkbox is enabled. |
| `output_project_options` | Inspect the current Burp project configuration before editing a session handling rule. |
| `set_project_options` | Configure a Burp session handling rule that invokes the extension action `ATOR`. Burp MCP must have configuration editing enabled. |

Other Burp MCP tools, such as history readers, can help find requests to configure in ATOR, but they do not invoke ATOR by themselves. Requests sent with `send_http1_request` or `send_http2_request` have the **Extensions** tool source; adding a Repeater label to one does not make it a Repeater request.

### Call an ATOR command with MCP

`send_http1_request` accepts a target host, port, HTTPS flag, and raw request `content`. For a status call, use an allowed target host in your Burp MCP configuration:

```json
{
  "targetHostname": "api.example.com",
  "targetPort": 443,
  "usesHttps": true,
  "content": "GET /ator HTTP/1.1\r\nHost: api.example.com\r\nX-ATOR-Command: status\r\n\r\n"
}
```

The path and host are not used by ATOR for a command because ATOR answers it locally. Burp MCP still checks its target permission before it calls Burp's HTTP API.

For HTTP/2, keep the header separate from the body:

```json
{
  "targetHostname": "api.example.com",
  "targetPort": 443,
  "usesHttps": true,
  "pseudoHeaders": {
    ":method": "GET",
    ":scheme": "https",
    ":authority": "api.example.com",
    ":path": "/ator"
  },
  "headers": {"x-ator-command": "status"},
  "requestBody": ""
}
```

The command header is accepted only when Burp reports the tool as **Extensions**, **Burp AI**, or **Repeater**. A request from a proxied browser cannot invoke it. Command responses have `Content-Type: application/json` and `X-ATOR: 1`.

| `X-ATOR-Command` value | Request body | Action and result |
| --- | --- | --- |
| `status` | Empty | Return `ok: true` and a configuration/status snapshot with extraction names and presence, without values. |
| `refresh` | Empty | Run the obtain macro immediately, then return a status snapshot. |
| `export` | Empty | Return an object whose `config` field contains the ATOR export JSON as a string. |
| `import` | The ATOR export JSON document itself | Load error conditions, obtain steps, replacements, domains, and Repeater regex from the document. Send the value of `config` from `export`, without its response wrapper. |
| `domains` | JSON array, `{"domains":[...]}`, or one host per line | Replace the selected-domain list. `{"domains":[]}` clears the limit; `{"enabled":false}` retains saved hosts but disables the limit. |

For example, pass this body with `X-ATOR-Command: domains` to limit ATOR to two host patterns:

```json
{"domains":["api.example.com","*.lab.local"]}
```

The status response includes `preview`, `inScopeOnly`, `domainsEnabled`, `domains`, `repeaterLabelRegex`, `repeaterLabelHeader`, enabled `tools`, extraction state, rule counts, and available command names. Check its `ok` field as well as the HTTP status: unknown commands return 400, runtime failures return 500, and some input validation errors return `ok: false` in a 200 response.

`status` and `refresh` report extraction names and presence without token values or lengths. `export` can include recorded HTTP messages and authentication data; use it only through the trusted Burp UI and treat the output as sensitive configuration data.

## Check what happened

If a request was not changed, open **Activity** and read its decision and reason. Then check the tool checkbox, Preview, **InScope**, selected domains, and—only for Repeater—the request label regex. A response refreshed by ATOR is annotated `ATOR refreshed this response` in Burp.

For a complete configuration example and the release/build process, see [README.md](README.md).
