<!-- SPDX-License-Identifier: Apache-2.0 -->
# Provenance

Contributor attribution: @Jsand-187.

Project attribution: Kin / SolaraKin / AgentChain. The broader distinction
between authenticated evidence, authorization, support, enforcement, and
finality was discussed by @Jsand-187 in A2A Discussion #1734 on September 20,
2026:

<https://github.com/a2aproject/A2A/discussions/1734#discussioncomment-18528762>

This contribution develops that distinction into an optional,
implementation-independent result profile, sixteen synthetic inputs, and
zero-dependency verifiers. This attribution records conceptual provenance; it
does not assert exclusive ownership, maintainer acceptance, runtime authority,
or derivation from proprietary AgentChain, Kin, or SolaraKin code. No sponsored
claim is made for this unpaid standards contribution.

Fixture trust roots are public test data. Static signatures are checked against
the pinned public roots; private components and seeds are not checked in and
are not required to regenerate the vector output.

## License

The verifier, profile code, schema, source, generated vectors, and tests use
Apache-2.0 (LICENSE). The normative CTEF result-profile text is CC BY 4.0.
The vector directory’s own LICENSE provides Apache-2.0 coverage under the
existing CTEF-LICENSE.md rule for standalone directories with their own LICENSE.
