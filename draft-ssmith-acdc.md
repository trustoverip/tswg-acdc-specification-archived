---
title: "Authentic Chained Data Containers (ACDC)"
abbrev: "ACDC"
category: info

docname: draft-ssmith-acdc-latest

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

  ACDC_ID:
    target: https://github.com/trustoverip/tswg-acdc-specification
    title: IETF ACDC (Authentic Chained Data Containers) Internet Draft
    author:
      ins: S. Smith
      name: Samuel M. Smith
      org: ProSapien LLC
    date: 2022

  KERI_ID:
    target: https://github.com/WebOfTrust/ietf-keri
    title: IETF KERI (Key Event Receipt Infrastructure) Internet Draft
    author:
      ins: S. Smith
      name: Samuel M. Smith
      org: ProSapien LLC
    date: 2022
    
  CESR_ID:
    target: https://github.com/WebOfTrust/ietf-cesr
    title: IETF CESR (Composable Event Streaming Representation) Internet Draft
    author:
      ins: S. Smith
      name: Samuel M. Smith
      org: ProSapien LLC
    date: 2022
    
  SAID_ID:
    target: https://github.com/WebOfTrust/ietf-said
    title: IETF SAID (Self-Addressing IDentifier) Internet Draft
    author:
      ins: S. Smith
      name: Samuel M. Smith
      org: ProSapien LLC
    date: 2022
    
  PTEL_ID:
    target: https://github.com/WebOfTrust/ietf-ptel
    title: IETF PTEL (Public Transaction Event Log) Internet Draft
    author:
      ins: P. Feairheller
      name: Phil Feairheller
      org: GLEIF
    date: 2022
    
  Proof_ID:
    target: https://github.com/WebOfTrust/ietf-cesr-proof
    title: IETF CESR-Proof Internet Draft
    author:
      ins: P. Feairheller
      name: Phil Feairheller
      org: GLEIF
    date: 2022
 
  IPEX_ID:
    target: https://github.com/WebOfTrust/keripy/blob/master/ref/Peer2PeerCredentials.md
    title: IPEX (Issuance and Presentation EXchange) Internet Draft
    author:
      ins: P. Feairheller
      name: Phil Feairheller
      org: GLEIF
    date: 2022

  DIDK_ID:
    target: https://github.com/WebOfTrust/ietf-did-keri
    title: IETF DID-KERI Internet Draft
    author:
      ins: P. Feairheller
      name: Phil Feairheller
      org: GLEIF
    date: 2022
    
  OOBI_ID:
    target: https://github.com/WebOfTrust
    title: IETF OOBI Internet Draft
    author:
      ins: S. Smith
      name: Samuel M. Smith
      org: ProSapien LLC
    date: 2022

  JSON:
    target: https://www.json.org/json-en.html
    title: JavaScript Object Notation Delimeters
    
  RFC8259:
    target: https://datatracker.ietf.org/doc/html/rfc8259
    title: JSON (JavaScript Object Notation)
    
  RFC4627:
    target: https://datatracker.ietf.org/doc/rfc4627/
    title: The application/json Media Type for JavaScript Object Notation (JSON)
    
  JSch:
    target: https://json-schema.org
    title: JSON Schema
    
  JSch_202012:
    target: https://json-schema.org/draft/2020-12/release-notes.html
    title: "JSON Schema 2020-12"
  
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
  
  ACDC_WP: 
    target: https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/ACDC.web.pdf
    title: Authentic Chained Data Containers (ACDC) White Paper
    
  VCEnh:
    target: https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/VC_Enhancement_Strategy.md
    title: VC Spec Enhancement Strategy Proposal 

  ACDC_TF: 
    target: https://wiki.trustoverip.org/display/HOME/ACDC+%28Authentic+Chained+Data+Container%29+Task+Force
    title: ACDC (Authentic Chained Data Container) Task Force
    
  TOIP: 
    target: https://trustoverip.org
    title: Trust Over IP (ToIP) Foundation

  IETF: 
    target: https://www.ietf.org
    title: IETF (Internet Engineering Task Force
  
  KERI:
    target: https://arxiv.org/abs/1907.02143
    title: Key Event Receipt Infrastructure (KERI)
    author:
      ins: S. Smith
      name: Samuel M. Smith
      org: ProSapien LLC
    date: 2021
    
  ITPS:
    target: https://en.wikipedia.org/wiki/Information-theoretic_security
    title: Information-Theoretic and Perfect Security

  OTP: 
    target: https://en.wikipedia.org/wiki/One-time_pad
    title: One-Time-Pad

  VCphr: 
    target: https://www.ciphermachinesandcryptology.com/en/onetimepad.htm
    title: Vernom Cipher (OTP)
    
  SSplt: 
    target: https://www.ciphermachinesandcryptology.com/en/secretsplitting.htm
    title: Secret Splitting
    
  SShr: 
    target: https://en.wikipedia.org/wiki/Secret_sharing
    title: Secret Sharing
    
  CSPRNG: 
    target: https://en.wikipedia.org/wiki/Cryptographically-secure_pseudorandom_number_generator
    title: Cryptographically-secure pseudorandom number generator (CSPRNG)
  
  IThry: 
    target: https://en.wikipedia.org/wiki/Information_theory
    title: Information Theory

  CAcc: 
    target: https://en.wikipedia.org/wiki/Accumulator_(cryptography)
    title: Cryptographic Accumulator
    
  XORA: 
    target: https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/XORA.md
    title: XORA (XORed Accumulator)
    
  GLEIF:
    target: https://www.gleif.org/en/
    title: GLEIF (Global Legal Entity Identifier Foundation)
    
  vLEI: 
    target: https://github.com/WebOfTrust/vLEI
    title: vLEI (verifiable Legal Entity Identifier) Definition
    
  GLEIF_vLEI:
    target: https://www.gleif.org/en/lei-solutions/gleifs-digital-strategy-for-the-lei/introducing-the-verifiable-lei-vlei
    title: GLEIF vLEI (verifiable Legal Entity Identifier)

  GLEIF_KERI: 
    target: https://github.com/WebOfTrust/vLEI
    title: GLEIF with KERI Architecture
    
  W3C_VC:
    target: https://www.w3.org/TR/vc-data-model/
    title: W3C Verifiable Credentials Data Model v1.1 
    
  W3C_DID:
    target: https://w3c-ccg.github.io/did-spec/
    title: W3C Decentralized Identifiers (DIDs) v1.0

  Salt:
    target: https://medium.com/@fridakahsas/salt-nonces-and-ivs-whats-the-difference-d7a44724a447
    title: Salts, Nonces, and Initial Values 
    
  RB:
    target: https://en.wikipedia.org/wiki/Rainbow_table
    title: Rainbow Table 
    
  DRB:
    target: https://www.commonlounge.com/discussion/2ee3f431a19e4deabe4aa30b43710aa7
    title: Dictionary Attacks, Rainbow Table Attacks and how Password Salting defends against them
    
  BDay:
    target: https://en.wikipedia.org/wiki/Birthday_attack
    title: Birthday Attack
    
  BDC:
    target: https://auth0.com/blog/birthday-attacks-collisions-and-password-strength/
    title: Birthday Attacks, Collisions, And Password Strength
    
  HCR:
    target: https://en.wikipedia.org/wiki/Collision_resistance
    title: Hash Collision Resistance
    
  QCHC:
    target: https://cr.yp.to/hash/collisioncost-20090823.pdf
    title: "Cost analysis of hash collisions: Will quantum computers make SHARCS obsolete?"
    
  EdSC:
    target: https://eprint.iacr.org/2020/823
    title: "The Provable Security of Ed25519: Theory and Practice Report"
    
  PSEd:
    target: https://ieeexplore.ieee.org/document/9519456?denied=
    title: "The Provable Security of Ed25519: Theory and Practice"
    seriesinfo: 2021 IEEE Symposium on Security and Privacy (SP)
    author:
      -
        ins: J. Brendel  
        name: Jacqueline Brendel  
      -
        ins: C. Cremers  
        name: Cas Cremers  
      -
        ins: D. Jackson  
        name: Dennis Jackson    
      -
        ins: M. Zhao  
        name: Mang Zhao  
    date: 2021-05-24

  TmEd:
    target: https://eprint.iacr.org/2020/1244.pdf
    title: Taming the many EdDSAs  

  JS_Comp:
    target: https://json-schema.org/understanding-json-schema/reference/combining.html
    title: Schema Composition in JSON Schema 

  JS_RegEx:
    target: https://json-schema.org/understanding-json-schema/reference/regular_expressions.html
    title: Regular Expressions in JSON Schema
    
  JS_Id:
    target: https://json-schema.org/understanding-json-schema/structuring.html#schema-identification
    title: JSON Schema Identification
    
  JS_Cplx:
    target: https://json-schema.org/understanding-json-schema/structuring.html#base-uri
    title: Complex JSON Schema Structuring

  RC:
    target: https://en.wikipedia.org/wiki/Ricardian_contract
    title: Ricardian Contract 

  CLC:
    target: https://papers.ssrn.com/sol3/papers.cfm?abstract_id=2045818
    title: "Chain-Link Confidentiality" 
    
  DHKE:
    target: https://www.infoworld.com/article/3647751/understand-diffie-hellman-key-exchange.html
    title: "Diffie-Hellman Key Exchange" 

  KeyEx:
    target: https://libsodium.gitbook.io/doc/key_exchange
    title: Key Exchange  
    
  IDSys:
    target: https://github.com/SmithSamuelM/Papers/blob/master/whitepapers/Identity-System-Essentials.pdf
    title: Identity System Essentials 
    
  Hash:
    target: https://en.wikipedia.org/wiki/Cryptographic_hash_function
    title: Cryptographic Hash Function 
    
  Mrkl:
    target: https://en.wikipedia.org/wiki/Merkle_tree
    title: Merkle Tree
      
  2PI:
    target: https://flawed.net.nz/2018/02/21/attacking-merkle-trees-with-a-second-preimage-attack/
    title: Second Pre-image Attack on Merkle Trees 
    
  MTSec:
    target: https://blog.enuma.io/update/2019/06/10/merkle-trees-not-that-simple.html
    title: Merkle Tree Security

  DSig:
    target: https://en.wikipedia.org/wiki/Digital_signature
    title: Digital Signature       
    
  Level:
    target: https://en.wikipedia.org/wiki/Security_level
    title: Security Level  
    
  Twin:
    target: https://en.wikipedia.org/wiki/Digital_twin
    title: Digital Twin
    
  Mal:
    target: https://en.wikipedia.org/wiki/Transaction_malleability_problem
    title: Transaction Malleability   
    
  PGM:
    target: http://ceur-ws.org/Vol-2100/paper26.pdf
    title: The Property Graph Database Model
    author:
      ins: R. Angles
      name: Renzo Angles
    date: 2018

  Dots:
    target: https://arxiv.org/pdf/1006.2361.pdf
    title: Constructions from Dots and Lines
    author:
      -
        ins: M. Rodriguez
        name: Marko A. Rodriguez
      -
        ins: P. Neubauer
        name: Peter Neubauer
    date: 2010
      
  KG:
    target: https://arxiv.org/pdf/2003.02320.pdf
    title: Knowledge Graphs 
 

tags: IETF, ACDC, CESR, SAID, KERI

--- abstract

An authentic chained data container (ACDC)  {{ACDC_ID}}{{ACDC_WP}}{{VCEnh}} is an IETF {{IETF}} internet draft focused specification being incubated at the ToIP (Trust over IP) foundation {{TOIP}}{{ACDC_TF}}.  An ACDC is a variant of the W3C Verifiable Credential (VC) specification {{W3C_VC}}. The W3C VC specification depends on the W3C DID (Decentralized IDentifier) specification {{W3C_DID}}. A major use case for the ACDC specification is to provide GLEIF vLEIs (verifiable Legal Entity Identifiers) {{vLEI}}{{GLEIF_vLEI}}{{GLEIF_KERI}}. GLEIF is the Global Legal Entity Identifier Foundation {{GLEIF}}. ACDCs are dependent on a suite of related IETF focused standards associated with the KERI (Key Event Receipt Infrastructure) {{KERI_ID}}{{KERI}} specification. These include CESR {{CESR_ID}}, SAID {{SAID_ID}}, PTEL {{PTEL_ID}}, CESR-Proof {{Proof_ID}}, IPEX {{IPEX_ID}}, did:keri {{DIDK_ID}}, and OOBI {{OOBI_ID}}. Some of the major distinguishing features of ACDCs include normative support for chaining, use of composable JSON Schema {{JSch}}{{JS_Comp}}, multiple serialization formats, namely, JSON {{JSON}}{{RFC4627}}, CBOR {{CBOR}}{{RFC8949}}, MGPK {{MGPK}}, and CESR {{CESR_ID}}, support for Ricardian contracts {{RC}},  support for chain-link confidentiality {{CLC}}, a well defined security model derived from KERI {{KERI}}{{KERI_ID}}, *compact* formats for resource constrained applications, simple *partial disclosure* mechanisms and simple *selective disclosure* mechanisms. 

--- middle

# Introduction

The primary purpose of the ACDC protocol is to provide granular provenanced proof-of-authorship (authenticity) of their contained data via a tree or chain of linked ACDCs (technically a directed acyclic graph or DAG). Similar to the concept of a chain-of-custody, ACDCs provide a verifiable chain of proof-of-authorship of the contained data. With a little additional syntactic sugar, this primary facility of chained (treed) proof-of-authorship (authenticity) is extensible to a chained (treed) verifiable authentic proof-of-authority (proof-of-authorship-of-authority). A proof-of-authority may be used to provide verifiable authorizations or permissions or rights or credentials. A chained (treed) proof-of-authority enables delegation of authority and delegated authorizations. 

The dictionary definition of ***credential*** is *evidence of authority, status, rights, entitlement to privileges, or the like*.  Appropriately structured ACDCs may be used as credentials when their semantics provide verifiable evidence of authority. Chained ACDCs may provide delegated credentials.

Chains of ACDCs that merely provide proof-of-authorship (authenticity) of data may be appended to chains of ACDCs that provide proof-of-authority (delegation) to enable verifiable delegated authorized authorship of data. This is a vital facility for authentic data supply chains. Furthermore, any physical supply chain may be measured, monitored, regulated, audited, and/or archived by a data supply chain acting as a digital twin {{Twin}}. Therefore ACDCs provide the critical enabling facility for an authentic data economy and by association an authentic real (twinned) economy.

ACDCs act as securely attributed (authentic) fragments of a distributed *property graph* (PG) {{PGM}}{{Dots}}. Thus they may be used to construct knowledge graphs expressed as property graphs {{KG}}. ACDCs enable securely-attributed and privacy-protecting knowledge graphs.

The ACDC specification (including its partial and selective disclosure mechanisms) leverages two primary cryptographic operations namely digests and digital signatures {{Hash}}{{DSig}}. These operations when used in an ACDC MUST have a security level, cryptographic strength, or entropy of approximately 128 bits {{Level}}. (See the appendix for a discussion of cryptographic strength and security)

An important property of high-strength cryptographic digests is that a verifiable cryptographic commitment (such as a digital signature) to the digest of some data is equivalent to a commitment to the data itself. ACDCs leverage this property to enable compact chains of ACDCs that anchor data via digests. The data *contained* in an ACDC may therefore be merely its equivalent anchoring digest. The anchored data is thereby equivalently authenticated or authorized by the chain of ACDCs. 

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
