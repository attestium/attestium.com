# Introduction

We built [Attestium](https://github.com/attestium/attestium) because we believe trust in software should be earned, not assumed. It is a **runtime code verification and integrity monitoring library** that provides cryptographic proof of your application's code integrity. Like an element in the periodic table, Attestium represents the fundamental building block of **attestation**—the ability to prove that your code is running exactly as intended, without tampering or modification.

The SolarWinds[^solarwinds] and xz-utils[^xz] attacks were not isolated failures; they were symptoms of a systemic problem. Our industry has focused heavily on build-time security—verifying code *before* it's deployed. This is essential, but it's only half the story.

What happens after deployment? How can you be certain the code running in your production environment is the same code you so carefully vetted and signed? This is the gap where trust breaks down, and it's the gap we designed Attestium to fill.

For years, we've relied on point-in-time audits. But in a world of continuous deployment, a snapshot in time is not enough. As we've argued before, true security requires continuous assurance[^forward_audit]. This isn't just a theoretical problem. A 2023 Sonatype report found over 245,000 malicious packages in open-source repositories[^sonatype]. The threat is real, and it's growing.

Projects like Mullvad's System Transparency have shown a path forward, proving that verifiable systems are possible[^mullvad_st]. Attestium builds on this foundation, but shifts the focus from the boot process to the runtime environment. We provide a practical, developer-friendly framework for continuously verifying the integrity of running applications.

The urgency of this problem is recognized at the highest levels. Executive Order 14028[^eo14028] and the NIST Secure Software Development Framework[^nist_ssdf] both call for stronger software supply chain security. Attestium is our answer: a layered, open-source architecture for verifiable runtime integrity. In the following sections, we detail the Attestium stack, demonstrate its use of TPM-based attestation, and outline our roadmap for the future.

[^solarwinds]: CISA Alert (AA20-352A): Advanced Persistent Threat Compromise of Government Agencies: https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-352a
[^xz]: Andres Freund, "Backdoor in xz-utils": https://www.openwall.com/lists/oss-security/2024/03/29/4
[^forward_audit]: Forward Email, "Best Security Audit Companies": https://forwardemail.net/en/blog/docs/best-security-audit-companies
[^sonatype]: Sonatype, "2023 State of the Software Supply Chain": https://www.sonatype.com/state-of-the-software-supply-chain/introduction
[^mullvad_st]: Mullvad VPN, "Introducing System Transparency for our VPN servers": https://mullvad.net/en/blog/diskless-infrastructure-beta-system-transparency-stboot
[^eo14028]: The White House, "Executive Order 14028: Improving the Nation's Cybersecurity": https://www.federalregister.gov/documents/2021/05/17/2021-10460/improving-the-nations-cybersecurity
[^nist_ssdf]: NIST SP 800-218, "Secure Software Development Framework (SSDF) Version 1.1": https://csrc.nist.gov/publications/detail/sp/800-218/final
