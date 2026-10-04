# Adoption

Attestium is intended for any service whose users should be able to check that it runs its published open-source code. This section describes the reference deployment at Forward Email, how other services adopt the same approach whatever their language and platform, and the insider threat that motivates it.

## Reference Adopter: [Forward Email](https://github.com/forwardemail/forwardemail.net)

[Forward Email](https://forwardemail.net) is an open-source email service. Its production servers (web, API, IMAP, POP3, SMTP, MX, CalDAV, CardDAV, job processing and SQLite storage) run Node.js applications from its public repository. Each server is deployed from git: a deploy checks out the commit, installs dependencies with the pnpm version the repository pins and a frozen lockfile, builds the browser assets and the Sieve parser, and reloads the PM2 processes. The results are published at:

> **[https://status.forwardemail.net](https://status.forwardemail.net)**

The verification is the first project of the Audit Status [public registry](https://github.com/auditstatus/auditstatus.com/blob/main/registry/forwardemail.yml), which verifies registered services as a third party:

* The **attester** is installed on each server by an Ansible playbook, as a dedicated account whose authorized keys are the registry's keys, restricted to the attester command. The same playbook records the servers' host keys, which the registry file pins, and can enroll each server's TPM.
* The **verifier** runs hourly in Audit Status's own GitHub Actions workflow. Its SSH key was generated on a GitHub-hosted runner and exists only as a secret of that workflow's environment. It compares each server with the latest GitHub release of the public `forwardemail.net` repository, the release's lockfile and the npm tarballs it pins, with their build provenance, the official Node.js release, and the global npm, pnpm and PM2 packages.
* Files the deployment generates and the repository ignores (the browser build and the generated Sieve parser) are compared with a build of the same commit that the registry reproduces in a separate job, without the SSH key, as an unprivileged account. The job that holds the key runs no code of the project.
* PM2's `node_args` and every process's runtime injection vectors are checked. A server whose deployment is in progress is collected again after ten minutes, and within an hour of a new release a server that still runs the previous one is a warning.
* The workflow publishes a JSON and a Markdown report for every run to the registry's `status` branch, signed with a GitHub artifact attestation, so the branch's history is a public record of the production state, and the badge on the status page reflects the latest result. When a server fails or the result is inconclusive, the workflow opens an issue in the Audit Status repository.

A result for a server without an enrolled TPM is at the `software` level, and the published report says so. Anyone can read the same reports the Forward Email team reads.

## How Other Services Adopt

Adoption follows the same steps for any service:

1. **Describe the service.** `auditstatus init` inspects the repository, detects its languages, package managers and container build, and writes an attester configuration, a verifier configuration and a scheduled workflow. For the public registry, the service describes itself in one YAML file instead: its repository, where it is deployed, and each server with its SSH host key.
2. **Install the attester.** On servers, with the Ansible role or the release binary and a restricted SSH key; on Kubernetes, with the Helm chart, which runs the attester as a DaemonSet and creates a service account that can only port-forward to it.
3. **Enroll hardware.** Run TPM enrollment for each server, or pin the expected launch measurements of confidential VMs. This step is optional, but it determines the level of evidence a result can reach.
4. **Check the setup.** `auditstatus doctor` confirms, on each side, that every check can run: permissions, processes, ecosystems, containers, TPM, IMA, confidential VM, monitor, and access to every reference.
5. **Publish.** Add the service to the Audit Status public registry, which verifies it every hour from Audit Status's own workflow, or run the verifier on a schedule in a public repository of the service. Link the badge from the service's status page.

How each part of a service is verified depends on how it is built and deployed, not on its language:

* **Interpreted services deployed from git** (JavaScript, Python, Ruby, PHP, Elixir): the source is compared with the commit, installed packages with the lockfile's artifacts, generated files with a reproduced build, and the interpreter with its official release or distribution package.
* **Compiled services** (Go, Rust, Java, .NET): the binary is compared with an attested release manifest, a signed checksum list or a reproduced build; the dependencies compiled into Go and Rust binaries are compared with `go.sum` and `Cargo.lock`; jars and .NET assemblies from registries with the hashes their builds pin.
* **Containers**: every file of each container is compared with its image, fetched by digest, optionally required to be attested by the project's own workflow.
* **Third-party software**: databases, proxies and other programs installed from the distribution are explained by the distribution's signed archive; others by a signed checksum list or a pinned hash.

Consider a hosted database platform similar to Supabase, whose open-source stack combines a PostgreSQL database with services written in TypeScript, Go and Elixir, often run as containers. Its PostgreSQL binaries and extensions are explained by their distribution packages or by the image they ship in; its container images by digest and by the attestations of the workflows that built them; its Go services by the build information checked against `go.sum` and by an attested binary hash; its Elixir services by the Hex packages `mix.lock` pins and a reproduced release build; and every process's runtime injection vectors are checked whatever its language. With confidential VMs, the platform can additionally show that its hosting provider cannot read or modify customer data in memory.

## A Call to the Open-Source Community

Many companies build their business on open-source services and ask users to trust that the hosted version is the published one. The following projects publish their source and would be natural candidates; for each, the website, primary repository and main languages are listed:

* **Supabase** ([supabase.com](https://supabase.com)) - [github.com/supabase/supabase](https://github.com/supabase/supabase) (TypeScript, Go)
* **Cal.com** ([cal.com](https://cal.com)) - [github.com/calcom/cal.com](https://github.com/calcom/cal.com) (TypeScript)
* **Documenso** ([documenso.com](https://documenso.com)) - [github.com/documenso/documenso](https://github.com/documenso/documenso) (TypeScript)
* **Bitwarden** ([bitwarden.com](https://bitwarden.com)) - [github.com/bitwarden/clients](https://github.com/bitwarden/clients) (TypeScript)
* **Infisical** ([infisical.com](https://infisical.com)) - [github.com/Infisical/infisical](https://github.com/Infisical/infisical) (TypeScript)
* **Jitsi** ([jitsi.org](https://jitsi.org)) - [github.com/jitsi/jitsi-meet](https://github.com/jitsi/jitsi-meet) (TypeScript, JavaScript)
* **Element** ([element.io](https://element.io)) - [github.com/element-hq/element-web](https://github.com/element-hq/element-web) (TypeScript, CSS)
* **Mattermost** ([mattermost.com](https://mattermost.com)) - [github.com/mattermost/mattermost](https://github.com/mattermost/mattermost) (Go, TypeScript)
* **Ghost** ([ghost.org](https://ghost.org)) - [github.com/TryGhost/Ghost](https://github.com/TryGhost/Ghost) (JavaScript, TypeScript)
* **Plausible Analytics** ([plausible.io](https://plausible.io)) - [github.com/plausible/analytics](https://github.com/plausible/analytics) (Elixir, React)
* **PostHog** ([posthog.com](https://posthog.com)) - [github.com/PostHog/posthog](https://github.com/PostHog/posthog) (Python, TypeScript)
* **Chatwoot** ([chatwoot.com](https://www.chatwoot.com)) - [github.com/chatwoot/chatwoot](https://github.com/chatwoot/chatwoot) (Ruby, Vue, JavaScript)
* **Twenty** ([twenty.com](https://twenty.com)) - [github.com/twentyhq/twenty](https://github.com/twentyhq/twenty) (TypeScript)
* **Gitea** ([about.gitea.com](https://about.gitea.com)) - [github.com/go-gitea/gitea](https://github.com/go-gitea/gitea) (Go, TypeScript)
* **Rocket.Chat** ([rocket.chat](https://www.rocket.chat)) - [github.com/RocketChat/Rocket.Chat](https://github.com/RocketChat/Rocket.Chat) (TypeScript)
* **Plane** ([plane.so](https://plane.so)) - [github.com/makeplane/plane](https://github.com/makeplane/plane) (TypeScript, Python)

These projects span JavaScript and TypeScript, Go, Python, Ruby and Elixir, each of which Attestium covers. By publishing continuous, independently checkable results, such a service can show its users that the code on its servers matches its public repository and the releases it depends on, and, with a TPM and IMA or a confidential VM, that this holds even against someone with root access to the server or the host.

## Preventing the Insider Threat

External attacks receive the most attention, but insiders are among the hardest threats to mitigate. An employee acting in bad faith, a compromised vendor, or a datacenter technician with physical access to a server can bypass many controls and change what a service runs.

With shell access, such a person can modify application files, install backdoors or alter dependencies. With more skill, they can work entirely in memory: `LD_PRELOAD` to hijack library calls, `ptrace` to inject code into running processes, a runtime's own loading options, or `memfd_create` to execute payloads that never touch the filesystem. File integrity monitoring does not see these.

Attestium targets this class of changes. It compares the deployed files with the public commit and the installed packages with the artifacts the lockfile pins; it compares the executable pages of every mapped file with the file on disk; it explains every running executable and library by a public reference; and it reports preloads, runtime injection options, debuggers, inspectors and `memfd` payloads.

This raises the bar for everyone with access, including the operator. Careless or casual changes appear in the next public report. A determined insider with root can defeat software-only evidence, which is why the strongest results come from hardware: with IMA, the kernel records what was loaded before the insider can intervene, and the TPM will not sign a history that was edited afterwards; with a confidential VM, the host's operators cannot read or change the guest's memory at all.
