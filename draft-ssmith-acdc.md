---
title: "Authentic Chained Data Containers (ACDC)"
abbrev: "ACDC"
category: info

docname: draft-ssmith-acdc-latest
category: info

ipr: trust200902
area: TODO
workgroup: TODO Working Group
keyword: Internet-Draft

stand_alone: yes
smart_quotes: no
pi: [toc, sortrefs, symrefs]

author:
  -
    name: S. Smith
    organization: ProSapien LLC
    email: sam@prosapien.com

normative:

  JSON:
    target: https://www.json.org/json-en.html
    title: JavaScript Object Notation Delimeters
    
  RFC4627:
    target: https://datatracker.ietf.org/doc/rfc4627/
    title: The application/json Media Type for JavaScript Object Notation (JSON)
  
  CBOR:
    target: https://en.wikipedia.org/wiki/CBOR
    title: CBOR Mapping Object Codes
    
  RFC8949:
    target: https://datatracker.ietf.org/doc/rfc8949/
    title: Concise Binary Object Representation (CBOR)
    author:
      -
        ins: C. Bormann
        name: Carsten Bormann
      -
        ins: P. Hoffman
        name: Paul Hoffman
    date: 2020-12-04
    
MGPK:
    target: https://github.com/msgpack/msgpack/blob/master/spec.md
    title: Msgpack Mapping Object Codes
  

informative:
  KERI:
    target: https://arxiv.org/abs/1907.02143
    title: Key Event Receipt Infrastructure (KERI)
    author:
      ins: S. Smith
      name: Samuel M. Smith
      org: ProSapien LLC
    date: 2021

tags: IETF, ACDC, CESR, SAID, KERI

--- abstract

Authentic Chained Data Containers (ACDC) Standard Specification provides semantic of authentic provenance chaining of authentic data containers. This semantics include both source provenance and authorization provenance or delegation.


--- middle

# Abstract

Authentic Chained Data Containers (ACDC) Standard Specification provides semantic of authentic provenance chaining of authentic data containers. This semantics include both source provenance and authorization provenance or delegation.

# Motivation

We need a way to chain authentic data together, allowing its provenance to be traced. This is valuable in many use cases:

* Supply chain, where a valid transfer of custody downstream depends on the validity of all upstream handoffs.
* Delegation, where a delegate's privileges derive from a chain of authorizations that must extend back to a source that is empowered.
* Citation of sources (in art, in journalism, in academia, or in credential issuance), where an author wants to clarify that a particular assertion originates elsewhere. This allows the assertion to acquire (or lose) gravitas independent of the reputation of the author who includes it. It also allows analysis of license compliance.

The last of these examples deserves special comment. There is a tension between the decentralization that we want in a verifiable credential ecosystem, and the way that trust tends to centralize because knowledge and reputation are unevenly distributed. We want anyone to be able to attest to anything they like--but we know that verifiers care very much about the reputation of the parties that make those attestations.

We could say that verifiers will choose which issuers they trust. This is exactly what most practioners of VCs recommend, and it works in early pilots. However, this places a heavy burden on verifiers, over the long haul--verifiers can't afford to vet every potential issuer of credentials they might encounter. The result will be a tendency to accept credentials only from a short list of issuers, which leads back to centralization.

This tendency also creates problems with delegation. If all delegation has to be validated through a few authorities, a lot of the flexibility and power of delegation is frustrated.

We'd like a landscape where a tiny startup can issue an employment credential with holder attributes taken as seriously as one from a massive global conglomerate--and with no special setup by verifiers to trust them equally. And we'd like parents to be able to delegate childcare decisions to a babysitter on the spur of the moment--and have the babysitter be able to prove it when she calls an ambulance.

# Scope

This document describes a mechanism whereby assertions about data can be provenanced in a provably authentic chain. Evaluating the integrity of the chain is in scope -- and because such chains leads to one or more root sources, the chain provides the raw material for making judgments about the data's utility or probable veracity. However, evaluating the data's utility or veracity is out of scope.

In other words, this standard concerns itself with proving that party C got its data in a valid way from party B, who in turn got it from party A. The degree to which the origin party, A, is trustworthy in their assertions about reality is not our concern.

# Overview

An ACDC may be built up from an authentic data container (ADC) that contains an authentic provenance chain (APC). The term authentic data container (ADC) is an important abstract concept that hopefully may leverage a pre-existing open concrete
implementation standard specification. The current targeted concrete implementation specification is the W3C Verifiable Credential (VC) standard. We believe that authentic data containers (ADCs) with authentic provenance chains (APCs) that together compose an authentic chained data container (ACDC) are essential components of verifiable or authentic data supply chains which in turn are essential to what may be called the authentic data economy.

TODO: mention about informative example used across whole spec

# Informative Example


~~~
{
  "v": "ACDC10JSON00011c_",
  "d": "EBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5K0neuniccM",
  "i": "did:keri:EmkPreYpZfFk66jpf3uFv7vklXKhzBrAqjsKAn2EDIPM",
  "ri": "did:keri:EymRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt",
  "s": "E46jrVPTzlSkUPqGGeIZ8a8FWS7a6s4reAXRZOkogZ2A",
  "a": {
    "d": "EgveY4-9XgOcLxUderzwLIr9Bf7V_NHwY1lkFrn9y2PY",
    "i": "did:keri:EQzFVaMasUf4cZZBKA0pUbRc9T8yUXRFLyM1JDASYqAA",
    "n": "0ANghkDaG7OY1wjaDAE0qHcg"
    "dt": "2021-06-09T17:35:54.169967+00:00",
    "LEI": "254900OPPU84GM83MG36",
  },
  "p": [
    {
      "qualifiedvLEIIssuervLEICredential": {
        "d": "EIl3MORH3dCdoFOLe71iheqcywJcnjtJtQIYPvAu6DZA",
        "i": "Et2DOOu4ivLsjpv89vgv6auPntSLx4CvOhGUxMhxPS24"
      }
    }
  ],
  "r": [
    {
      "usageDisclaimer": "Usage of a valid Legal Entity vLEI Credential does not assert that the Legal Entity is trustworthy, honest, reputable in its business dealings, safe to do business with, or compliant with any laws."
    },
    {
      "issuanceDisclaimer": "Issuance of a valid Legal Entity vLEI Credential only establishes that the information in the requirements in the Identity Verification section 6.3 of the Credential Governance Framework were met in accordance with the vLEI Ecosystem Governance Framework."
    }
  ]
}

~~~

- `v` version string of ACDC
- `d` SAID of ACDC.
- `i` Attributable Source Identifier (Issuer, Issuee). 
- `ri` Registry Identifier (Issuance, Revocation, Transfer Registry of ACDC)
- `s` Schema SAID
- `a` Attributes
  - `n` Nonce (optional for hidded attribute ACDC)
  - `dt` Datetime of issuance
- `p` Provenance chain
- `r` Rules rules/delegation/consent/license/data agreement under which data are shared.

# ACDC as Verifiable Labeled Property Graph Fragment
The structure of an ACDC may be modeled as a fragment of a Labeled Property Graph. The `p` block is an array of edges and the `a` block is the node. The remainder of the ACDC may be metadata about the node that may also be included as special node properties. Because, the edges in labeled property graphs may also have labeled properties, a more aligned representation would make each source entry a labeled block (or at least as an option). This is illustrated in the following example:

~~~

    {
       d: "did:1209u091u9012d/attestation/1234",  // SAID
       i: "did:1209u091u9012d",
       p: 
       [
            {sourcEdgeLabel: {i: "did:kdjflkeje", tid: "did:jd892j108jd1029", ...}}, // attestation id not in namespace of testator
            {anotherSourceEdgeLabel: {i: "did:9d9j109j1d902dj19/attestation/3242", ...}},  // attestation id in namespace of testator
            {yetAnotherSourceEdgeLabel: {i: "did:h78h8d2h8d2h8hd28d/attestation/1234",...}}  // attestation id in namespace of testator
        ],
        s: {}, || SAID
        a: 
        {
           i: "SAID",
           k: v,
           k1: SAID,  // ref1
         }, || SAID
         r: {}  || SAID
     }


~~~

Because each ACDC thus composed is verifiable, a verifiable graph may be communicated via verifiable graph fragments. Given any starting node or root node in the graph, one may add onto the graph by communicating graph fragments where each fragment includes a new node and the edge or edges that connect it to one or more pre-existing nodes.  The over-the-wire communication of the fragment is secured by the immutability of the ACDC contents (SAIDs) and the signature or committment proofs on the fragment.  This drives the structure of any given ACDC to be a graph fragment not a graph in and of itself.  The semantics of who issues or testates to a fragment and who the fragment is issued to (if any) may vary. With an issuer and isuee then the fragment may be an authorization or delegation. If the isuee is the node itself then the fragment is just provenanced data in a provenanced graph.

### Benefits

TODO:
- focus on generic problem of authentic data
- do not relay on any specific network nor implementation

ACDC focus on the base semantic specification to address core properties of authentic data flows. ACDC provides semantic allowing to express:
- authenticity for any data flow
- self-describing mechanism to understand the context of data
- chaining mechanism (including delegation)
- increasing interoperability by not relaying on any specific use case and implementation


# Conventions and Definitions

{::boilerplate bcp14-tagged}

- `SAID` - Self-Addressing Identifier - any identifier which is deterministaclly generated out of the content, digest of the content


# Security Considerations

TODO Security


# IANA Considerations

This document has no IANA actions.


--- back

# Acknowledgments
{:numbered="false"}

TODO acknowledge.
