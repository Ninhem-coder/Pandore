import { ActivityPreview, ApplicationsPreview, Callout, CompliancePreview, DeviceDetailPreview, EolPreview, GroupsPreview, OverviewPreview, Section, SuspiciousActivityPreview } from "./vanitasDocsParts.jsx";

/** English body of the Vanitas documentation — a translation of VanitasDocsFr.jsx, section for
 * section (same ids, same callouts, same illustrations). Any change to one body must be mirrored
 * in the other. */
export default function VanitasDocsEn() {
  return (
    <>
      <Section id="intro">
        <p>
          Vanitas is the “endpoint” side of the dashboard: where the rest of the application reads
          Microsoft data (Intune, Defender), Vanitas talks directly to the machines of the fleet
          through a small agent installed on them. The agent runs in the background, sends a regular
          inventory to the server, runs the compliance rules it is given and waits, when needed, for
          a command — install a piece of software, open a troubleshooting session. The name comes
          from the Latin memento mori: a reminder that nothing on a connected endpoint stays out of
          sight for very long.
        </p>
        <p>
          In practice, an endpoint “exists” for Vanitas once the agent has been installed and
          enrolled on it — a one-off technical step, done at install time, that issues it its own
          certificate. Past that step, everything is driven from this dashboard: no need to log on
          to the endpoint to know whether it is up to date, whether it follows the in-house rules, or
          whether it still runs a two-year-old version of Chrome.
        </p>
        <p>
          This guide covers everyday use of the product, page by page — and, for each page, what
          actually happens when you click a row or a button, not just the top-level view. It does
          not replace security training or a PowerShell manual: it explains what each screen shows,
          what each button really triggers, and where the real points of attention are.
        </p>
      </Section>

      <Section id="roles">
        <p>
          An account first sits at one of two <b>levels</b>: <b>administrator</b> or{" "}
          <b>read-only</b>. An administrator sees and does everything, without exception —
          including opening a terminal on an endpoint or deleting a group — and needs no profile. A
          read-only account, on the other hand, has no access to Vanitas at all by default, without
          an assigned profile. But that level says nothing about what such an account can actually
          do once configured: the <b>role</b> assigned through a profile defines that, not the
          account level itself.
        </p>
        <p>
          The real role of a read-only account is therefore its <b>profile</b> — assigned by an
          administrator from the “Profiles” tab — not a fixed label. A profile is a grid: for each
          of the <b>six</b> areas (endpoints, terminal, applications, compliance, groups,
          suspicious activity), you choose “no access”, “read” or “read and write”. An account can
          therefore have full write access on several areas while remaining “read-only” at the
          account level — the level only caps the theoretical maximum (never more than an
          administrator), the profile decides the concrete role. The same profile can be reused on
          several accounts: it is the mechanism meant to build a tailor-made role for a team's real
          needs — a support desk that sees endpoints and compliance but never opens a terminal or
          pushes an application, for instance — rather than a binary choice between all rights and
          none.
        </p>
        <p>
          The “Profiles” page has two sub-tabs: <b>Profiles</b> (create/edit the grid, see how
          many accounts use each one) and <b>Accounts</b> (create an account, assign it a profile,
          reset its password). A profile cannot be deleted while at least one account still uses it
          — reassign those accounts from the Accounts tab first.
        </p>
        <p>
          Two areas deliberately escape this fine-grained split. Read-write on the terminal amounts
          to granting PowerShell access as SYSTEM on every targeted endpoint — a profile can grant
          it, but it is worth thinking twice before doing so; note too that plain <i>read</i>{" "}
          access on this area unlocks nothing at all, unlike the other areas: for the terminal, it is
          write or nothing. And the “Profiles” page itself stays reserved to administrators: an
          account can never grant itself more rights than it has — it is also impossible to demote
          or delete the last remaining administrator account, so nobody is ever left without
          someone in charge.
        </p>
      </Section>

      <Section id="overview">
        <p>
          This is the Vanitas home screen, designed for a ten-second glance rather than an in-depth
          read. The top strip gives the state of the fleet in six figures, deliberately narrowed to
          what calls for a decision rather than a full inventory — each one clickable to jump
          straight to the matching page: the total number of endpoints (with the number online just
          below), untriaged suspicious activity, silent endpoints in the alert sense (a stricter
          threshold than the one in the endpoint list, see below), certificates close to expiry,
          end-of-life software detected, and an overall compliance rate for the fleet.
        </p>
        <p>
          Below, a posture banner shows either “Nominal posture” — nothing to report — or a summary
          of the current problems as soon as there are any, followed by a seven-day command activity
          chart and then a single “Signals to handle” list: silent endpoints, certificates close to
          expiry, the most widespread CVEs, end-of-life software and untriaged suspicious activity,
          all mixed together and sorted by real urgency rather than compared side by side in
          separate cards. A rail on the right groups the rest into a single sectioned card:
          online/silent split, a preview of the first groups, upcoming certificate expiries, recent
          command breakdown, and the list of recent alerts described later in this guide.
        </p>
        <p>
          This page does not replace any other one: it is a starting point to know where to go
          next, not a definitive dashboard. Everything it shows is recomputed client-side from data
          already loaded elsewhere — with one exception, “Top vulnerabilities”, which comes from a
          dedicated endpoint.
        </p>
        <OverviewPreview />
      </Section>

      <Section id="devices">
        <p>
          The “Endpoints” tab lists the whole enrolled fleet: name, connection state, time since
          last contact, days left before the certificate expires, number of installed applications,
          group memberships (with direct add/remove from the list), and the last command sent.
          Search by name, quick filters (All/Online/Silent/Certificate &lt; 30 d) and sorting on
          every column.
        </p>
        <p>
          An endpoint turns “silent” once it has not contacted the server for a while — two
          thresholds deliberately coexist, and they must be told apart. The first, wider one (seven
          days) is a simple visual indicator in this list and in the Overview strip. The second,
          much tighter one (twelve hours by default) raises a real logged alert, described further
          down (“Automatic alerts”): an endpoint switched off over the weekend does not deserve the
          same attention as one that stopped answering in the middle of the day.
        </p>
        <p>
          Clicking a row opens the endpoint's full page — the heart of this section, with far more
          material than the list row. At the top, an identity banner (name, availability,
          enrollment date, number of applications) carries two buttons with real and very different
          consequences, never to be confused:
        </p>
        <Callout tone="high" title="“Uninstall remotely” and “Remove from inventory” do NOT do the same thing">
          <p>
            <b>Uninstall remotely</b> queues a real MSI uninstall command, run by the agent on the
            endpoint itself (<code>msiexec /X{"{productCode}"} /qn</code>). It is irreversible and
            cannot be confirmed from the dashboard: the service stops and removes itself from the
            endpoint before the result can even be sent back, so there is no way to check afterwards
            that it worked.
          </p>
          <p>
            <b>Remove from inventory</b>, on the contrary, only acts server-side: it erases the
            endpoint's page and its whole history from the dashboard, and revokes its certificate
            (the agent will never be able to authenticate again). If the agent is still actually
            running on the physical machine, it keeps running — it is only an inventory deletion,
            not an uninstall. Keep it for an endpoint already decommissioned by other means.
          </p>
          <p>
            A pitfall to know: the “Uninstall remotely” button stays visible even for an account
            that only has read access on the “endpoints” area — the click will fail with an error,
            the server rejecting the command. Hiding by profile only exists today on “Remove from
            inventory”.
          </p>
        </Callout>
        <p>
          Below this banner, five clickable health tiles (Certificate, Vulnerabilities, System disk,
          Applications, Commands over the last 7 days) give an at-a-glance summary and jump straight
          to the right pane. The full navigation, on the left, covers eleven panes in four groups:
        </p>
        <ul>
          <li>
            <b>Overview</b> — a grid of summary tiles (identity, availability, certificate, disk,
            vulnerabilities, Windows updates, applications, agent version with an update button if a
            newer one exists in the catalog, latest commands), each linking to the matching detailed
            pane.
          </li>
          <li>
            <b>System</b> → <i>Operating system</i> (build, architecture, pending Windows updates),{" "}
            <i>Hardware</i> (manufacturer, BIOS, memory, disks, graphics cards, PCI devices — with an
            explicit warning: the WMI disk type does not reliably tell SSD from HDD, so no badge is
            ever made up) and <i>Identity &amp; network</i> (session user, network interfaces).
          </li>
          <li>
            <b>Security</b> → <i>Certificate &amp; enrollment</i> (automatic renewal under 30 days,
            no manual action required), <i>Vulnerabilities</i> and <i>Compliance</i> (results
            described further down, but filtered to this endpoint only), and{" "}
            <i>Suspicious activity</i> (the same log as the fleet-wide tab, filtered to this
            endpoint).
          </li>
          <li>
            <b>Inventory</b> → <i>Applications</i>, the list of detected installed software.
          </li>
          <li>
            <b>Administration</b> → <i>Commands</i> (full history, not only the last 7 days) and{" "}
            <i>Terminal</i> (described in its own section further down).
          </li>
        </ul>
        <p>
          Many fields stay at “—” as long as a diagnostic command has never run on this endpoint
          (hardware inventory, system diagnostic) — a deliberate graceful degradation, not an
          anomaly: a form to run the missing command appears directly in the pane concerned.
        </p>
        <DeviceDetailPreview />
      </Section>

      <Section id="groups">
        <p>
          A group is used to target several endpoints at once — push an application, or push an
          agent update. There are two ways to build one, chosen at creation and not changeable
          afterwards without recreating the group:
        </p>
        <ul>
          <li>
            <b>Static group</b> — membership is managed endpoint by endpoint, from each endpoint's
            page (never from the Groups page itself) or from the group detail. An endpoint can belong
            to several static groups at once.
          </li>
          <li>
            <b>Dynamic group</b> — one or more conditions (endpoint name, operating system,
            online/silent status, agent version), combined with AND or OR, decide on their own who
            belongs to it. No manual assignment is possible: the rule, and only the rule, decides —
            the group page says so explicitly (“Automatic member (rule)” replaces the remove
            button).
          </li>
        </ul>
        <p>
          A group can also <b>nest other groups</b>: the members of the nested group are added to
          the union of the parent group, which lets you compose sets without duplicating rules. A
          group's page also shows two indicators aggregated over its members — the average number of
          detected vulnerabilities and an average risk rate computed on the standard CVSS scale (0 to
          10). These are not home-made scores: a plain average, useful to spot at a glance that a
          group is degrading, not a certified security rating.
        </p>
        <p>
          A group's page is also where you push an application (picking an installer from the
          catalog) or an agent update to all its members at once — each action asks for a double
          confirmation and turns into queued commands, visible afterwards in “Commands” (per
          endpoint) or the “Log” (for the change itself).
        </p>
        <GroupsPreview />
      </Section>

      <Section id="compliance">
        <p>
          A compliance rule is a PowerShell script that runs periodically on each targeted endpoint
          and returns a verdict: compliant, non-compliant, or <i>error</i> (the script crashed or
          returned no usable code — a distinct state, never confused with a real rule failure). You
          create it from the “Compliance” tab by pasting the script and giving it a name; the script
          must end explicitly with <code>exit 0</code> (compliant) or <code>exit 1</code>{" "}
          (non-compliant).
        </p>
        <Callout tone="warn" title="A newly created rule stays disabled by default">
          <p>
            This is deliberate, not an oversight. A newly created rule — or one whose script has
            just been edited — runs on no endpoint until it has been explicitly enabled, through a
            second, separate action. The idea is simple: a typo in a compliance script must never go
            to production on its own, through a slightly hasty save. Review, then enable — in that
            order.
          </p>
        </Callout>
        <p>
          Once enabled, a rule produces one result per targeted endpoint, viewable in its detail as
          well as in each endpoint's page. That detail shows either the raw text returned by the
          script or — if the script emits a small structured JSON as its last line (reason, expected
          value, actual value) — a readable view with both values compared side by side. Editing the
          script of an already enabled rule automatically switches it back to disabled, for the same
          reason: a behavior change is never pushed without going through the deliberate enabling
          step again.
        </p>
        <p>
          What this page does <b>not</b> do, to be precise: no severity on a rule (unlike CVEs),
          no export button, no automated remediation and no history of previous checks — only the
          latest result per endpoint is kept. The only possible “remediation” is the text or JSON
          returned by the script itself.
        </p>
        <CompliancePreview />
      </Section>

      <Section id="vulnerabilities">
        <p>
          Two complementary angles, two separate tabs. “Vulnerabilities” matches the software
          inventory reported by each endpoint against known CVEs, one row per distinct CVE across
          the whole fleet (product, CVSS score, severity, publication date, number of exposed
          endpoints). Its detail goes further than a plain CVE reminder: when a recent CERT-FR
          advisory covers it, its summary and action plan show up directly, with a link to the
          original advisory; otherwise, an invitation to check on NVD. The list of exposed devices
          distinguishes three statuses — affected, excluded, undetermined — depending on whether the
          installed version matches the actually vulnerable version.
        </p>
        <Callout tone="warn" title="A very large CVE count is not necessarily an alarm signal">
          <p>
            The matching does not filter by publication date: software with a heavy exposure history
            (a browser, an Adobe suite) can bring up several hundred, even thousands, of old CVEs
            with no direct link to the version actually installed today. Look at severity and date
            before drawing a conclusion from a raw total.
          </p>
        </Callout>
        <p>
          “End-of-life software” (EOL) looks at another deadline: products — operating system, .NET
          Framework, software — whose end-of-support date has already passed or is less than 90 days
          away, with the real end-of-life date published by endoflife.date, not an estimate. When an
          approximate name match finds an installer for the same product already in the catalog, an
          “Update in catalog” button appears at the end of the row — it starts <b>no</b>{" "}
          installation by itself, it merely switches to the Applications tab so you push the
          installer yourself, and the match stays approximate (check it before trusting it
          blindly).
        </p>
        <EolPreview />
      </Section>

      <Section id="applications">
        <p>
          The application catalog gathers the installers ready to be deployed. You add a{" "}
          <code>.msi</code> file, a <code>.ps1</code> script or an executable, by uploading it
          directly or fetching it from a GitHub release — once: it then stays available to be
          pushed to as many endpoints or groups as you like. A read-only account (without write
          rights) sees a pure read-only catalog, with no possible action; adding, editing and
          deploying live in the write-only “Applications” version.
        </p>
        <p>
          For an MSI installer, the wizard asks for the install mode — <i>Interactive display</i>{" "}
          (the user can defer up to three times), <i>Display</i> (a visible notification, with no
          possible interaction) or <i>Silent</i> (no notification) — and the restart behavior
          (installer default, never, with confirmation, or forced). For a PowerShell script or an
          executable, the install command stays free-form, with a pre-filled template for
          PowerShell; there is then no install mode or restart behavior to choose, since those
          notions only make sense for an MSI.
        </p>
        <p>
          Deploying is done from two places: a group's page (“Push an application”), or the
          “Deploy” popup opened from a catalog card, which lets you pick the target (a whole group or
          a specific endpoint). The outcome is then tracked in “Deployed applications”: overall
          success rate, and per endpoint the exact detail returned by the agent (Succeeded / Failed /
          Pending until the agent's next check-in) — rebuilt from the commands already sent, with no
          new stored data: an installer only shows up there after it has been pushed at least once.
        </p>
        <Callout tone="high" title="A deployment runs as SYSTEM, with no confirmation on the endpoint">
          <p>
            Unlike the terminal, an application deployment opens no interactive session: it runs
            directly, with the machine's highest privileges, without any window asking the user for
            confirmation. Before pushing an installer to a whole group, test it on a single endpoint
            — preferably a test endpoint, never a production endpoint picked at random.
          </p>
        </Callout>
        <ApplicationsPreview />
      </Section>

      <Section id="terminal">
        <p>
          The terminal opens a real interactive PowerShell session on a targeted endpoint, with the
          privileges of the service running there — that is, the machine's highest privileges,
          SYSTEM. It is the most powerful Vanitas feature, and the most dangerous when misused:
          everything typed there really runs, right away, on someone's endpoint. Only one session can
          be active at a time on a given endpoint.
        </p>
        <Callout tone="high" title="Unlike the other areas, read access alone opens nothing here">
          <p>
            A profile's “terminal” module only has two useful states: write, or nothing at all. A
            profile with “read” only on this area does NOT show the Terminal tab — unlike every
            other module, where read access at least gives a browsing view. There is currently no
            “watch without typing” mode.
          </p>
        </Callout>
        <p>
          Opening a session queues a command like any other (pick-up delay by the agent, up to about
          five minutes), with an explicit waiting message meanwhile. Once active: a history area
          shows every line typed and every output received live, an input line sends commands one by
          one, and a button closes the session at will. Leaving the endpoint's page and coming back
          does not reopen the previous session: you have to click “Open a PowerShell terminal”
          again, which starts a new one.
        </p>
        <p>
          Every session opened, every command going through it, is recorded in the activity log{" "}
          <b>permanently</b> — unlike the rest of the log, purged after 90 days, the full history of
          a terminal session (line by line, including error output) is never deleted: it is not a
          discreet channel, and it must never be one. Keep it for one-off troubleshooting — an
          endpoint that no longer reports its inventory correctly, a diagnostic no other page can
          run remotely — rather than for actions that could go through a compliance rule or an
          application deployment, both traced and replayable more cleanly.
        </p>
      </Section>

      <Section id="activity">
        <p>
          Every action that changes something on the Vanitas side leaves a trace here, as a
          sentence rather than a column table: “{"{"}actor{"}"} {"{"}verb{"}"} {"{"}target{"}"}” —
          for example <i>“Nicolas pushed the installer “7-Zip 24.08””</i> or{" "}
          <i>“Nicolas disabled the rule “BitLocker on””</i>. Entries are sorted into four categories
          — <b>Endpoint</b>, <b>Application</b>, <b>Compliance</b>, <b>Group</b> — each filterable,
          with a free-text search on the actor, verb, target or detail.
        </p>
        <p>
          The period filter offers four quick presets (7, 14, 30, 90 days) or a custom period
          through a real two-month calendar — dates beyond the 90-day retention are greyed out and
          cannot be selected. Clicking a row opens the full detail: source (endpoint command or audit
          log), exact timestamp, decoded JSON parameters, and the full detail with a button to copy
          it.
        </p>
        <p>
          History older than ninety days is purged automatically on the server, so the database does
          not grow forever without anyone touching it — <b>except the content of terminal
          sessions</b>, kept indefinitely (see “Remote terminal”). This log is not just a command
          history: it answers the question “who did what”, useful both to understand an incident and
          to check that an expected change was actually applied.
        </p>
        <ActivityPreview />
      </Section>

      <Section id="alerts">
        <p>
          Vanitas watches four situations in the background and logs them as soon as they appear,
          visible in the “Recent alerts” block of the Overview: an endpoint that went silent (default
          alert threshold: twelve hours — not to be confused with the seven-day threshold used as a
          simple visual indicator in the endpoint list, two distinct notions configurable
          independently), a certificate approaching expiry (fewer than thirty days by default), a
          new <i>critical</i> vulnerability detected on an endpoint, or a new compliance failure on
          a rule that was previously met.
        </p>
        <p>
          These alerts do not repeat at every cycle: once reported, a situation only comes back into
          the log if it changes again — an endpoint going silent again after coming back online, a
          new CVE different from the previous one. E-mail delivery can be added on top if a mail
          server is configured on the infrastructure side; without that configuration, these alerts
          remain visible only here, in the dashboard.
        </p>
      </Section>

      <Section id="suspicious-activity">
        <p>
          This milestone gives the agent a real behavioral detection capability, separate from
          inventory and compliance: four signals watched continuously on the endpoint — a process
          started from an unusual path or through a system tool diverted from its normal use
          (LOLBin), a notable Windows event log entry (local administrator account created, RDP
          logon outside usual hours, log cleared, repeated authentication failures), an outbound
          network connection to a port or address outside the allow-list, or removable media plugged
          in followed by a file copy.
        </p>
        <Callout tone="warn" title="Filtering happens on the endpoint, not on the server">
          <p>
            The agent evaluates these rules locally and only reports to the server the events that
            match one — never a raw stream of all the endpoint's activity. An event that matches no
            rule will therefore never show up here, even after the fact. This choice keeps the
            reported volume close to that of a regular inventory rather than turning each endpoint
            into a permanent stream to store, but it means this page is not an investigation tool
            over raw telemetry — the endpoint's Windows logs remain the only complete source, with
            their own retention, usually shorter.
          </p>
        </Callout>
        <p>
          Each event carries a severity — low, medium or high — on the same scale as the rest of the
          dashboard (compliance, vulnerabilities), not Microsoft Defender's own vocabulary. It starts
          with the “New” status and closes as “Acknowledged”, “False positive” or “Escalated”: an
          event already acknowledged can still be requalified as a false positive or escalated, but
          those last two statuses are final. An event's detail also shows, when the endpoint is known
          to Microsoft Defender for Endpoint, its own active alerts for that same endpoint — two
          different detection systems, a single reading pane. The same view, filtered to a single
          endpoint, is also available directly in its detail page (see “Endpoints”).
        </p>
        <Callout tone="high" title="False positives are expected at first">
          <p>
            Some of the watched rules also match perfectly legitimate IT uses — a deployment script
            invoking PowerShell with encoded arguments, an on-call engineer connecting over RDP
            outside usual hours. Do not treat every report as a confirmed incident: this page exists
            to triage, not to alert blindly.
          </p>
        </Callout>
        <SuspiciousActivityPreview />
      </Section>

      <Section id="glossary">
        <p>
          <b>Agent</b> — the program installed on an endpoint, which makes it exist for Vanitas.
          <br />
          <b>Enrollment</b> — the operation, done once per endpoint, that issues its certificate and
          attaches it to the server.
          <br />
          <b>Silent endpoint</b> — an endpoint whose agent has not contacted the server for a
          certain time (seven days as a simple indicator, twelve hours as an alert — two distinct
          thresholds configurable separately).
          <br />
          <b>Static / dynamic group</b> — respectively a list of endpoints picked by hand, or
          computed automatically from one or more conditions.
          <br />
          <b>Pane</b> — one of the sub-views of an endpoint's page (Overview, Operating system,
          Certificate, Terminal…), selected in the left-hand menu.
          <br />
          <b>CVE</b> — a standard identifier for a known vulnerability, published by the IT
          security community.
          <br />
          <b>EOL (end of life)</b> — the date from which a piece of software is no longer
          maintained by its vendor, and therefore never patched again.
          <br />
          <b>Profile</b> — a set of permissions (read, read-write or no access) per area,
          assignable to a read-only account.
        </p>
      </Section>
    </>
  );
}
