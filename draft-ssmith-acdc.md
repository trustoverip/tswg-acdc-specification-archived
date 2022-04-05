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

  TMEd:
    target: https://eprint.iacr.org/2020/1244.pdf
    title: Taming the many EdDSAs  

  JSchCp:
    target: "https://json-schema.org/understanding-json-schema/reference/combining.html"
    title: "Schema Composition in JSON Schema" 

  JSchRE:
    target: "https://json-schema.org/understanding-json-schema/reference/regular_expressions.html"
    title: "Regular Expressions in JSON Schema"
    
  JSchId:
    target: "https://json-schema.org/understanding-json-schema/structuring.html#schema-identification"
    title: "JSON Schema Identification"
    
  JSchCx:
    target: "https://json-schema.org/understanding-json-schema/structuring.html#base-uri"
    title: "Complex JSON Schema Structuring"

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
      
  TwoPI:
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
    
  TMal:
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
 

tags: "IETF, ACDC, CESR, SAID, KERI"

--- abstract

An authentic chained data container (ACDC)  {{ACDC_ID}}{{ACDC_WP}}{{VCEnh}} is an IETF {{IETF}} internet draft focused specification being incubated at the ToIP (Trust over IP) foundation {{TOIP}}{{ACDC_TF}}.  An ACDC is a variant of the W3C Verifiable Credential (VC) specification {{W3C_VC}}. The W3C VC specification depends on the W3C DID (Decentralized IDentifier) specification {{W3C_DID}}. A major use case for the ACDC specification is to provide GLEIF vLEIs (verifiable Legal Entity Identifiers) {{vLEI}}{{GLEIF_vLEI}}{{GLEIF_KERI}}. GLEIF is the Global Legal Entity Identifier Foundation {{GLEIF}}. ACDCs are dependent on a suite of related IETF focused standards associated with the KERI (Key Event Receipt Infrastructure) {{KERI_ID}}{{KERI}} specification. These include CESR {{CESR_ID}}, SAID {{SAID_ID}}, PTEL {{PTEL_ID}}, CESR-Proof {{Proof_ID}}, IPEX {{IPEX_ID}}, did:keri {{DIDK_ID}}, and OOBI {{OOBI_ID}}. Some of the major distinguishing features of ACDCs include normative support for chaining, use of composable JSON Schema {{JSch}}{{JSchCp}}, multiple serialization formats, namely, JSON {{JSON}}{{RFC4627}}, CBOR {{CBOR}}{{RFC8949}}, MGPK {{MGPK}}, and CESR {{CESR_ID}}, support for Ricardian contracts {{RC}},  support for chain-link confidentiality {{CLC}}, a well defined security model derived from KERI {{KERI}}{{KERI_ID}}, *compact* formats for resource constrained applications, simple *partial disclosure* mechanisms and simple *selective disclosure* mechanisms. 

--- middle

# Introduction

The primary purpose of the ACDC protocol is to provide granular provenanced proof-of-authorship (authenticity) of their contained data via a tree or chain of linked ACDCs (technically a directed acyclic graph or DAG). Similar to the concept of a chain-of-custody, ACDCs provide a verifiable chain of proof-of-authorship of the contained data. With a little additional syntactic sugar, this primary facility of chained (treed) proof-of-authorship (authenticity) is extensible to a chained (treed) verifiable authentic proof-of-authority (proof-of-authorship-of-authority). A proof-of-authority may be used to provide verifiable authorizations or permissions or rights or credentials. A chained (treed) proof-of-authority enables delegation of authority and delegated authorizations. 

The dictionary definition of ***credential*** is *evidence of authority, status, rights, entitlement to privileges, or the like*.  Appropriately structured ACDCs may be used as credentials when their semantics provide verifiable evidence of authority. Chained ACDCs may provide delegated credentials.

Chains of ACDCs that merely provide proof-of-authorship (authenticity) of data may be appended to chains of ACDCs that provide proof-of-authority (delegation) to enable verifiable delegated authorized authorship of data. This is a vital facility for authentic data supply chains. Furthermore, any physical supply chain may be measured, monitored, regulated, audited, and/or archived by a data supply chain acting as a digital twin {{Twin}}. Therefore ACDCs provide the critical enabling facility for an authentic data economy and by association an authentic real (twinned) economy.

ACDCs act as securely attributed (authentic) fragments of a distributed *property graph* (PG) {{PGM}}{{Dots}}. Thus they may be used to construct knowledge graphs expressed as property graphs {{KG}}. ACDCs enable securely-attributed and privacy-protecting knowledge graphs.

The ACDC specification (including its partial and selective disclosure mechanisms) leverages two primary cryptographic operations namely digests and digital signatures {{Hash}}{{DSig}}. These operations when used in an ACDC MUST have a security level, cryptographic strength, or entropy of approximately 128 bits {{Level}}. (See the appendix for a discussion of cryptographic strength and security)

An important property of high-strength cryptographic digests is that a verifiable cryptographic commitment (such as a digital signature) to the digest of some data is equivalent to a commitment to the data itself. ACDCs leverage this property to enable compact chains of ACDCs that anchor data via digests. The data *contained* in an ACDC may therefore be merely its equivalent anchoring digest. The anchored data is thereby equivalently authenticated or authorized by the chain of ACDCs. 

# ACDC Fields

An ACDC may be abstractly modeled as a nested `key: value` mapping. To avoid confusion with the cryptographic use of the term *key* we instead use the term *field* to refer to a mapping pair and the terms *field label* and *field value* for each member of a pair. These pairs can be represented by two tuples e.g `(label, value)`. We qualify this terminology when necessary by using the term *field map* to reference such a mapping. *Field maps* may be nested where a given *field value* is itself a reference to another *field map*.  We call this nested set of fields a *nested field map* or simply a *nested map* for short. A *field* may be represented by a framing code or block delimited serialization.  In a block delimited serialization, such as JSON, each *field map* is represented by an object block with block delimiters such as `{}` {{RFC8259}}{{JSON}}{{RFC4627}}. Given this equivalence, we may also use the term *block* or *nested block* as synonymous with *field map* or *nested field map*. In many programming languages, a field map is implemented as a dictionary or hash table in order to enable performant asynchronous lookup of a *field value* from its *field label*. Reproducible serialization of *field maps* requires a canonical ordering of those fields. One such canonical ordering is called insertion or field creation order. A list of `(field, value)` pairs provides an ordered representation of any field map. Most programming languages now support ordered dictionaries or hash tables that provide reproducible iteration over a list of ordered field `(label, value)` pairs where the ordering is the insertion or field creation order. This enables reproducible round trip serialization/deserialization of *field maps*.  ACDCs depend on insertion ordered field maps for canonical serialization/deserialization. ACDCs support multiple serialization types, namely JSON, CBOR, MGPK, and CESR but for the sake of simplicity, we will only use JSON herein for examples {{RFC8259}}{{JSON}}. The basic set of normative field labels in ACDC field maps is defined in the following table.

## Field Label Table

| Label | Title | Description |  
|:-:|:--|:--|  
|`v`| Version String| Regexable format: ACDCvvSSSShhhhhh_ that provides protocol type, version, serialization type, size, and terminator. | 
|`d`| Digest (SAID) | Self-referential fully qualified cryptographic digest of enclosing map. |  
|`i`| Identifier (AID)| Semantics are determined by the context of its enclosing map. | 
|`u`| UUID | Random Universally Unique IDentifier as fully qualified high entropy pseudo-random string, a salted nonce. |  
|`ri`| Registry Identifier (AID) | Issuance and/or revocation, transfer, or retraction registry for ACDC. | 
|`s`| Schema| Either the SAID of a JSON Schema block or the block itself. | 
|`a`| Attribute| Either the SAID of a block of attributes or the block itself. | 
|`A`| Attribute Aggregate| Either the Aggregate of a selectively disclosable block of attributes or the block itself. | 
|`e`| Edge| Either the SAID of a block of edges or the block itself.| 
|`r`| Rule | Either the SAID a block of rules or the block itself. | 
|`n`| Node| SAID of another ACDC as the terminating point of a directed edge that connects the encapsulating ACDC node to the specified ACDC node as a fragment of a distributed property graph (PG).| 
|`l`| Legal Language| Text of Ricardian contract clause.|  


## Compact Labels

The primary field labels are compact in that they use only one or two characters. ACDCs are meant to support resource-constrained applications such as supply chain or IoT (Internet of Things) applications. Compact labels better support resource-constrained applications in general. With compact labels, the over-the-wire verifiable signed serialization consumes a minimum amount of bandwidth. Nevertheless, without loss of generality, a one-to-one normative semantic overlay using more verbose expressive field labels may be applied to the normative compact labels after verification of the over-the-wire serialization. This approach better supports bandwidth and storage constraints on transmission while not precluding any later semantic post-processing. This is a well-known design pattern for resource-constrained applications.


## Version String Field

The version string, `v`, field MUST be the first field in any top-level ACDC field map. It provides a regular expression target for determining the serialization format and size (character count) of a serialized ACDC. A stream-parser may use the version string to extract and deserialize (deterministically) any serialized ACDC in a stream of serialized ACDCs. Each ACDC in a stream may use a different serialization type. 

The format of the version string is `ACDCvvSSSShhhhhh_`. The first four characters `ACDC` indicate the enclosing field map serialization. The next two characters, `vv` provide the lowercase hexadecimal notation for the major and minor version numbers of the version of the ACDC specification used for the serialization. The first `v` provides the major version number and the second `v` provides the minor version number. For example, `01` indicates major version 0 and minor version 1 or in dotted-decimal notation `0.1`. Likewise `1c` indicates major version 1 and minor version decimal 12 or in dotted-decimal notation `1.12`. The next four characters `SSSS` indicate the serialization type in uppercase. The four supported serialization types are `JSON`, `CBOR`, `MGPK`, and `CESR` for the JSON, CBOR, MessagePack, and CESR serialization standards respectively {{JSON}}{{RFC4627}}{{CBOR}}{{RFC8949}}{{MGPK}}{{CESR_ID}}. The next six characters provide in lowercase hexadecimal notation the total number of characters in the serialization of the ACDC. The maximum length of a given ACDC is thereby constrained to be *2<sup>24</sup> = 16,777,216* characters in length. The final character `-` is the version string terminator. This enables later versions of ACDC to change the total version string size and thereby enable versioned changes to the composition of the fields in the version string while preserving deterministic regular expression extractability of the version string. Although a given ACDC serialization type may have a field map delimiter or framing code characters that appear before (i.e. prefix) the version string field in a serialization, the set of possible prefixes is sufficiently constrained by the allowed serialization protocols to guarantee that a regular expression can determine unambiguously the start of any ordered field map serialization that includes the version string as the first field value. Given the version string, a parser may then determine the end of the serialization so that it can extract the full ACDC from the stream without first deserializing it. This enables performant stream parsing and off-loading of ACDC streams that include any or all of the supported serialization types.

## AID (Autonomic IDentifier) Fields

Some fields, such as the `i` and `ri` fields, MUST each have an AID (Autonomic IDentifier) as its value. An AID is a fully qualified Self-Certifying IDentifier (SCID) that follows the KERI protocol {{KERI}}{{KERI_ID}}. A SCID is derived from one or more `(public, private)` key pairs using asymmetric or public-key cryptography to create verifiable digital signatures {{DSig}}. Each AID has a set of one or more controllers who each control a private key. By virtue of their private key(s), the set of controllers may make statements on behalf of the associated AID that is backed by uniquely verifiable commitments via digital signatures on those statements. Any entity may then verify those signatures using the associated set of public keys. No shared or trusted relationship between the controllers and verifiers is required. The verifiable key state for AIDs is established with the KERI protocol {{KERI}}{{KERI_ID}}. The use of AIDS enables ACDCs to be used in a portable but securely attributable, fully decentralized manner in an ecosystem that spans trust domains. 

### Namespaced AIDs
Because KERI is agnostic about the namespace for any particular AID, different namespace standards may be used to express KERI AIDs within AID fields in an ACDC. The examples below use the W3C DID namespace specification with the `did:keri` method {{DIDK_ID}}. But the examples would have the same validity from a KERI perspective if some other supported namespace was used or no namespace was used at all. The latter case consists of a bare KERI AID (identifier prefix).

## SAID (Self-Addressing IDentifier) Fields

Some fields in ACDCs may have for their value either a *field map* or a SAID. A SAID follows the SAID protocol {{SAID_ID}}. Essentially a SAID is a Self-Addressing IDentifier (self-referential content addressable). A SAID is a special type of cryptographic digest of its encapsulating *field map* (block). The encapsulating block of a SAID is called a SAD (Self-Addressed Data). Using a SAID as a *field value* enables a more compact but secure representation of the associated block (SAD) from which the SAID is derived. Any nested field map that includes a SAID field (i.e. is, therefore, a SAD) may be compacted into its SAID. The uncompacted blocks for each associated SAID may be attached or cached to optimize bandwidth and availability without decreasing security. 

Several top-level ACDC fields may have for their value either a serialized *field map* or the SAID of that *field map*. Each SAID provides a stable universal cryptographically verifiable and agile reference to its encapsulating block (serialized *field map*). Specifically, the value of top-level `s`, `a`, `e`, and `r` fields may be replaced by the SAID of their associated *field map*. When replaced by their SAID, these top-level sections are in *compact* form.

Recall that a cryptographic commitment (such as a digital signature or cryptographic digest) on a given digest with sufficient cryptographic strength including collision resistance {{HCR}}{{QCHC}} is equivalent to a commitment to the block from which the given digest was derived.  Specifically, a digital signature on a SAID makes a verifiable cryptographic non-repudiable commitment that is equivalent to a commitment on the full serialization of the associated block from which the SAID was derived. This enables reasoning about ACDCs in whole or in part via their SAIDS in a fully interoperable, verifiable, compact, and secure manner. This also supports the well-known bow-tie model of Ricardian Contracts {{RC}}. This includes reasoning about the whole ACDC given by its top-level SAID, `d`, field as well as reasoning about any nested sections using their SAIDS. 

## Selectively Disclosable Attribute Aggregate Field

The top-level selectively-disclosable attribute aggregate section, `A`, field value is an aggregate of cryptographic commitments used to make a commitment to a set (bundle) of selectively-disclosable attributes. The value of the attribute aggregate, `A`, field depends on the type of selective disclosure mechanism employed. For example, the aggregate value could be the cryptographic digest of the concatenation of an ordered set of cryptographic digests, a Merkle tree root digest of an ordered set of cryptographic digests, or a cryptographic accumulator.

## UUID (Universally Unique IDentifier) Fields

The purpose of the UUID, `u`, field in any block is to provide sufficient entropy to the SAID, `d`, field of the associated block to make computationally infeasible any brute force attacks on that block that attempt to discover the block contents from the schema and the SAID. The UUID, `u`, field may be considered a salty nonce {{Salt}}. Without the entropy provided the UUID, `u`, field, an adversary may be able to reconstruct the block contents merely from the SAID of the block and the schema of the block using a rainbow or dictionary attack on the set of field values allowed by the schema {{RB}}{{DRB}}. The effective security level, entropy, or cryptographic strength of the schema-compliant field values may be much less than the cryptographic strength of the SAID digest. Another way of saying this is that the cardinality of the power set of all combinations of allowed field values may be much less than the cryptographic strength of the SAID. Thus an adversary could successfully discover via brute force the exact block by creating digests of all the elements of the power set which may be small enough to be computationally feasible instead of inverting the SAID itself. Sufficient entropy in the `u` field ensures that the cardinality of the power set allowed by the schema is at least as great as the entropy of the SAID digest algorithm itself.

A UUID, `u` field may optionally appear in any block (field map) at any level of an ACDC. Whenever a block in an ACDC includes a UUID, `u`, field then it's associated SAID, `d`, field makes a blinded commitment to the contents of that block. The UUID, `u`, field is the blinding factor. This makes that block securely partially-disclosable or even selectively-disclosable notwithstanding disclosure of the associated schema of the block. The block contents can only be discovered given disclosure of the included UUID field. Likewise when a UUID, `u`, field appears at the top level of an ACDC then that top-level SAID, `d`, field makes a blinded commitment to the contents of the whole ACDC itself. Thus the whole ACDC, not merely some block within the ACDC, may be disclosed in a privacy-preserving (correlation minimizing) manner. 

## Full, Partial, and Selective Disclosure

The difference between ***partial disclosure*** and ***selective disclosure*** of a given field map is determined by the correlatability of the disclosed field(s) after ***full disclosure*** of the detailed field value with respect to its enclosing block (map or array of fields). A *partially disclosable* field becomes correlatable after *full disclosure*. Whereas a *selectively disclosable* field may be excluded from the *full disclosure* of any other *selectively disclosable* fields in the *selectively disclosable* block (array). After such *selective disclosure*, the selectively disclosed fields are not correlatable to the so-far undisclosed but selectively disclosable fields in that block. 

When used in the context of *selective disclosure*, *full disclosure* means detailed disclosure of the selectively disclosed attributes not detailed disclosure of all selectively disclosable attributes. Whereas when used in the context of *partial disclosure*, *full disclosure* means detailed disclosure of the field map that was so far only partially disclosed.

*Partial disclosure* is an essential mechanism needed to support both performant exchange of information and chain-link confidentiality on exchanged information {{CLC}}. The exchange of only the SAID of a given field map is a type of *partial disclosure*. Another type of *partial disclosure* is the disclosure of validatable metadata about a detailed field map e.g. the schema of a field map. 

The SAID of a field map provides a *compact* cryptographically equivalent commitment to the yet to be undisclosed field map details.  A later exchange of the uncompacted field map detail provides *full disclosure*. Any later *full disclosure* is verifiable to an earlier *partial disclosure*. Partial disclosure via compact SAIDs enables the scalable repeated verifiable exchange of SAID references to cached full disclosures. Multiple SAID references to cached fully disclosed field maps may be transmitted compactly without redundant retransmission of the full details each time a new reference is transmitted. Likewise, *partial disclosure* via SAIDs also supports the bow-tie model of Ricardian contracts {{RC}}. Similarly, the schema of a field map is metadata about the structure of the field map this is validatable given the full disclosure of the field map. The details of*compact* and/or confidential exchange mechanisms that leverage partial disclosure are explained later. 

*Selective disclosure*, on the other hand, is an essential mechanism needed to unbundle in a correlation minimizing way a single commitment by an Issuer to a bundle of fields (i.e. a nested array or list or tuple of fields) as a whole. This allows separating a "stew" (bundle) of "ingredients" (attributes) into its constituent "ingredients" (attributes) without correlating the constituents via the Issuer's commitment to the "stew" (bundle) as a whole. 

# Schema Section

## Schema is Type

Notable is the fact that there are no top-level type fields in an ACDC. This is because the schema, `s`, field itself is the type field. ACDCs follow the design principle of separation of concerns between a data container's actual payload information and the type information of that container's payload. In this sense, type information is metadata, not data. The schema dialect is JSON Schema 2020-12 {{JSch}}{{JSch_202012}}. JSON Schema support for composable schema (sub-schema), conditional schema (sub-schema), and regular expressions in schema enable a validator to ask and answer complex questions about the type of even optional payload elements while maintaining isolation between payload information and type (structure) information about the payload {{JSchCp}}{{JSchRE}}{{JSchId}}{{JSchCx}}. ACDC's use of JSON Schema MUST be in accordance with the ACDC defined profile as defined herein. The exceptions are defined below.

## Schema ID Field Label

The usual field label for SAID fields in ACDCs is `d`. In the case of the schema section, however, the field label for the SAID of the schema section is `$id`. This repurposes the schema id field label, `$id` as defined by JSON Schema {{JSchId}}{{JSchCx}}.  The top-level id, `$id`, field value in a JSON Schema provides a unique identifier of the schema instance. In a usual (non-ACDC) schema the value of the id, `$id`, field is expressed as a URI. This is called the *Base URI* of the schema. In an ACDC schema, however, the top-level id, `$id`, field value is repurposed. Its value MUST include the SAID of the schema. This ensures that the ACDC schema is static and verifiable to their SAIDS. A verifiably static schema satisfies one of the essential security properties of ACDCs as discussed below. There are several ACDC supported formats for the value of the top-level id, `$id`, field but all of the formats MUST include the SAID of the schema (see below). Correspondingly, the value of the top-level schema, `s`, field MUST be the SAID included in the schema's top-level `$id` field. The detailed schema is either attached or cached and maybe discovered via its SAIDified, id, `$id`, field value.

When an id, '$id', field appears in a sub-schema it indicates a bundled sub-schema called a schema resource {{JSchId}}{{JSchCx}}. The value of the id, '$id', field in any ACDC bundled sub-schema resource MUST include the SAID of that sub-schema using one of the formats described below. The sub-schema so bundled MUST be verifiable against its referenced and embedded SAID value. This ensures secure bundling. 


## Static Schema

For security reasons, the full schema of an ACDC must be completely self-contained and statically fixed (immutable) for that ACDC. By this, we mean that no dynamic schema references or dynamic schema generation mechanisms are allowed. 

Should an adversary successfully attack the source that provides the dynamic schema resource and change the result provided by that reference, then the schema validation on any ACDC that uses that dynamic schema reference may fail. Such an attack effectively revokes all the ACDCs that use that dynamic schema reference. We call this a ***schema revocation*** attack. 

More insidiously, an attacker could shift the semantics of the dynamic schema in such a way that although the ACDC still passes its schema validation, the behavior of the downstream processing of that ACDC is changed by the semantic shift. This we call a ***semantic malleability*** attack. It may be considered a new type of *transaction malleability* attack {{TMal}}. 

To prevent both forms of attack, all schema must be static, i.e. schema MUST be SADs and therefore verifiable against their SAIDs. 

To elaborate, the serialization of a static schema may be self-contained. A compact commitment to the detailed static schema may be provided by its SAID. In other words, the SAID of a static schema is a verifiable cryptographic identifier for its SAD. Therefore all ACDC compliant schema must be SADs. In other words, they MUST therefore be *SAIDified*. The associated detailed static schema (uncompacted SAD) is cryptographically bound and verifiable to its SAID. 

The JSON Schema specification allows complex schema references that may include non-local URI references {{JSchId}}{{JSchCx}}. These references may use the `$id` or `$ref` keywords. A relative URI reference provided by a `$ref` keyword is resolved against the *Base URI* provided by the top-level `$id` field. When this top-level *Base URI* is non-local then all relative `$ref` references are therefore also non-local. A non-local URI reference provided by a `$ref` keyword may be resolved without reference to the *Base URI*. 

In general, schema indicated by non-local URI references (`$id` or `$ref`) MUST NOT be used because they are not cryptographically end-verifiable. The value of the underlying schema resource so referenced may change (mutate). To restate, a non-local URI schema resource is not end-verifiable to its URI reference because there is no cryptographic binding between URI and resource. 

This does not preclude the use of remotely cached SAIDified schema resources because those resources are end-verifiable to their embedded SAID references. Said another way, a SAIDified schema resource is itself a SAD (Self-Address Data) referenced by its SAID. A URI that includes a SAID may be used to securely reference a remote or distributed SAIDified schema resource because that resource is fixed (immutable, nonmalleable) and verifiable to both the SAID in the reference and the embedded SAID in the resource so referenced. To elaborate, a non-local URI reference that includes an embedded cryptographic commitment such as a SAID is verifiable to the underlying resource when that resource is a SAD. This applies to JSON Schema as a whole as well as bundled sub-schema resources.

There ACDC supported formats for the value of the top-level id, `$id`, field are as follows:

* Bare SAIDs may be used to refer to a SAIDified schema as long as the JSON schema validator supports bare SAID references. By default, many if not all JSON schema validators support bare strings (non-URIs) for the *Base URI* provided by the top-level `$id` field value. 

* The `sad:` URI scheme may be used to directly indicate a URI resource that safely returns a verifiable SAD. For example `sad:SAID` where *SAID* is replaced with the actual SAID of a SAD that provides a verifiable non-local reference to JSON Schema as indicated by the mime-type of `schema+json`. 

* The IETF KERI OOBI internet draft specification provides a URL syntax that references a SAD resource by its SAID at the service endpoint indicated by that URL {{OOBI_ID}}. Such remote OOBI URLs are also safe because the provided SAD resource is verifiable against the SAID in the OOBI URL. Therefore OOBI URLs are also acceptable non-local URI references for JSON Schema.

* The `did:` URI scheme may be used safely to prefix non-local URI references that act to namespace SAIDs expressed as DID URIs or DID URLs.  DID resolvers resolve DID URLs for a given DID method such as `did:keri` {{DIDK_ID}} and may return DID docs or DID doc metadata with SAIDified schema or service endpoints that return SAIDified schema. A verifiable non-local reference in the form of DID URL that includes the schema SAID is resolved safely when it dereferences to the SAD of that SAID. For example, the resolution result returns an ACDC JSON Schema whose id, `$id`, field includes the SAID and returns a resource with JSON Schema mime-type of `schema+json`.


To clarify, ACDCs MUST NOT use complex JSON Schema references which allow *dynamically generated *schema resources to be obtained from online JSON Schema Libraries {{JSchId}}{{JSchCx}}. The latter approach may be difficult or impossible to secure because a cryptographic commitment to the base schema that includes complex schema (non-relative URI-based) references only commits to the non-relative URI reference and not to the actual schema resource which may change (is dynamic, mutable, malleable). To restate, this approach is insecure because a cryptographic commitment to a complex (non-relative URI-based) reference is NOT equivalent to a commitment to the detailed associated schema resource so referenced if it may change.

ACDCs MUST use static JSON Schema (i.e. *SAIDifiable* schema). These may include internal relative references to other parts of a fully self-contained static (*SAIDified*) schema or references to static (*SAIDified*) external schema parts. As indicated above, these references may be bare SAIDs, DID URIs or URLs (`did:` scheme), SAD URIs (`sad:` scheme), or OOBI URLs. Recall that a commitment to a SAID with sufficient collision resistance makes an equivalent secure commitment to its encapsulating block SAD. Thus static schema may be either fully self-contained or distributed in parts but the value of any reference to a part must be verifiably static (immutable, nonmalleable) by virtue of either being relative to the self-contained whole or being referenced by its SAID. The static schema in whole or in parts may be attached to the ACDC itself or provided via a highly available cache or data store. To restate, this approach is securely end-verifiable (zero-trust) because a cryptographic commitment to the SAID of a SAIDified schema is equivalent to a commitment to the detailed associated schema itself (SAD).

## Schema Dialect

The schema dialect for ACDC 1.0 is JSON Schema 2020-12 and is indicated by the identifier `"https://json-schema.org/draft/2020-12/schema"`  {{JSch}}{{JSch_202012}}. This is indicated in a JSON Schema via the value of the top-level `$schema` field. Although the value of `$schema` is expressed as a URI, de-referencing does not provide dynamically downloadable schema dialect validation code. This would be an attack vector. The validator MUST control the tooling code dialect used for schema validation and hence the tooling dialect version actually used. A mismatch between the supported tooling code dialect version and the `$schema` string value should cause the validation to fail. The string is simply an identifier that communicates the intended dialect to be processed by the schema validation tool. When provided, the top-level `$schema` field value for ACDC version 1.0 must be "https://json-schema.org/draft/2020-12/schema".

## Schema Availablity

The composed detailed (uncompacted) (bundled) static schema for an ACDC may be cached or attached. But cached, and/or attached static schema is not to be confused with dynamic schema. Nonetheless, while securely verifiable, a remotely cached, *SAIDified*, schema resource may be unavailable. Availability is a separate concern. Unavailable does not mean insecure or unverifiable. ACDCs MUST be verifiable when available.  Availability is typically solvable through redundancy. Although a given ACDC application domain or eco-system governance framework may impose schema availability constraints, the ACDC specification itself does not impose any specific availability requirements on Issuers other than schema caches SHOULD be sufficiently available for the intended application of their associated ACDCs. It's up to the Issuer of an ACDC to satisfy any availability constraints on its schema that may be imposed by the application domain or eco-system. 


## Composable JSON Schema

A composable JSON Schema enables the use of any combination of compacted/uncompacted attribute, edge, and rule sections in a provided ACDC. When compact, any one of these sections may be represented merely by its SAID {{JSch}}{{JSchCp}}. When used for the top-level attribute, `a`, edge, `e`, or rule, `r`, section field values, the `oneOf` sub-schema composition operator provides both compact and uncompacted variants. The provided ACDC MUST validate against an allowed combination of the composed variants, either the compact SAID of a block or the full detailed (uncompacted) block for each section. The validator determines what decomposed variants the provided ACDC MUST also validate against. Decomposed variants may be dependent on the type of disclosure, partial, full, or selective.

Unlike the other compactifiable sections, it is impossible to define recursively the exact detailed schema as a variant of a `oneOf` composition operator contained in itself. Nonetheless, the provided schema, whether self-contained, attached, or cached MUST validate as a SAD against its provided SAID. It MUST also validate against one of its specified `oneOf` variants.  

The compliance of the provided non-schema attribute, `a`, edge, `e`, and rule, `r`,  sections MUST be enforced by validating against the composed schema. In contrast, the compliance of the provided composed schema for an expected ACDC type  MUST be enforced by the validator. This is because it is not possible to enforce strict compliance of the schema by validating it against itself. 

ACDC specific schema compliance requirements are usually specified in the eco-system governance framework for a given ACDC type.  Because the SAID of a schema is a unique content-addressable identifier of the schema itself, compliance can be enforced by comparison to the allowed schema SAID in a well-known publication or registry of ACDC types for a given ecosystem governance framework (EGF). The EGF may be solely specified by the Issuer for the ACDCs it generates or be specified by some mutually agreed upon eco-system governance mechanism. Typically the business logic for making a decision about a presentation of an ACDC starts by specifying the SAID of the composed schema for the ACDC type that the business logic is expecting from the presentation. The verified SAID of the actually presented schema is then compared against the expected SAID. If they match then the actually presented ACDC may be validated against any desired decomposition of the expected (composed) schema.

To elaborate, a validator can confirm compliance of any non-schema section of the ACDC against its schema both before and after uncompacted disclosure of that section by using a composed base schema with `oneOf` pre-disclosure and a decomposed schema post-disclosure with the compact `oneOf` option removed. This capability provides a mechanism for secure schema validation of both compact and uncompacted variants that require the Issuer to only commit to the composed schema and not to all the different schema variants for each combination of a given compact/uncompacted section in an ACDC.

One of the most important features of ACDCs is support for Chain-Link Confidentiality {{CLC}}. This provides a powerful mechanism for protecting against un-permissioned exploitation of the data disclosed via an ACDC. Essentially an exchange of information compatible with chain-link confidentiality starts with an offer by the discloser to disclose confidential information to a potential disclosee. This offer includes sufficient metadata about the information to be disclosed such that the disclosee can agree to those terms. Specifically, the metadata includes both the schema of the information to be disclosed and the terms of use of that data once disclosed. Once the disclosee has accepted the terms then full disclosure is made. A full disclosure that happens after contractual acceptance of the terms of use we call *permissioned* disclosure. The pre-acceptance disclosure of metadata is a form of partial disclosure.

As is the case for compact (uncompacted) ACDC disclosure, Composable JSON Schema, enables the use of the same base schema for both the validation of the partial disclosure of the offer metadata prior to contract acceptance and validation of full or detailed disclosure after contract acceptance {{JSch}}{{JSchCp}}. A cryptographic commitment to the base schema securely specifies the allowable semantics for both partial and full disclosure. Decomposition of the base schema enables a validator to impose more specific semantics at later stages of the exchange process. Specifically, the `oneOf` sub-schema composition operator validates against either the compact SAID of a block or the full block. Decomposing the schema to remove the optional compact variant enables a validator to ensure complaint full disclosure. To clarify, a validator can confirm schema compliance both before and after detailed disclosure by using a composed base schema pre-disclosure and a decomposed schema post-disclosure with the undisclosed options removed. These features provide a mechanism for secure schema-validated contractually-bound partial (and/or selective) disclosure of confidential data via ACDCs. 


# ACDC Variants

There are several variants of ACDCs determined by the presence/absence of certain fields and/or the value of those fields. 
At the top level, the presence (absence), of the UUID, `u`, field produces two variants. These are private (public) respectively. In addition, a present but empty UUID, `u`, field produces a private metadata variant.

## Public ACDC

Given that there is no top-level UUID, `u`, field in an ACDC, then knowledge of both the schema of the ACDC and the top-level SAID, `d`, field  may enable the discovery of the remaining contents of the ACDC via a rainbow table attack {{RB}}{{DRB}}. Therefore, although the top-level, `d`, field is a cryptographic digest, it may not securely blind the contents of the ACDC when knowledge of the schema is available.  The field values may be discoverable. Consequently, any cryptographic commitment to the top-level SAID, `d`, field may provide a fixed point of correlation potentially to the ACDC field values themselves in spite of non-disclosure of those field values. Thus an ACDC without a top-level UUID, `u`, field must be considered a ***public*** (non-confidential) ACDC.

## Private ACDC

Given a top-level UUID, `u`, field, whose value has sufficient cryptographic entropy, then the top-level SAID, `d`, field of an ACDC  may provide a secure cryptographic digest that blinds the contents of the ACDC {{Hash}}. An adversary when given both the schema of the ACDC and the top-level SAID, `d`, field, is not able to discover the remaining contents of the ACDC in a computationally feasible manner such as through a rainbow table attack {{RB}}{{DRB}}. Therefore the top-level, UUID, `u`, field may be used to securely blind the contents of the ACDC notwithstanding knowledge of the schema and top-level, SAID, `d`, field.  Moreover, a cryptographic commitment to that that top-level SAID, `d`, field does not provide a fixed point of correlation to the other ACDC field values themselves unless and until there has been a disclosure of those field values. Thus an ACDC with a sufficiently high entropy top-level UUID, `u`, field may be considered a ***private*** (confidential) ACDC. enables a verifiable commitment to the top-level SAID of a private ACDC to be made prior to the disclosure of the details of the ACDC itself without leaking those contents. This is called *partial* disclosure. Furthermore, the inclusion of a UUID, `u`, field in a block also enables *selective* disclosure mechanisms described later in the section on selective disclosure.  

## Metadata ACDC

An empty, top-level UUID, `u`, field appearing in an ACDC indicates that the ACDC is a ***metadata*** ACDC. The purpose of a *metadata* ACDC is to provide a mechanism for a *Discloser* to make cryptographic commitments to the metadata of a yet to be disclosed private ACDC without providing any point of correlation to the actual top-level SAID, `d`, field of that yet to be disclosed ACDC. The top-level SAID, `d`, field, of the metadata ACDC, is cryptographically derived from an ACDC with an empty top-level UUID, `u`, field so its value will necessarily be different from that of an ACDC with a high entropy top-level UUID, `u`, field value. Nonetheless, the *Discloser* may make a non-repudiable cryptographic commitment to the metadata SAID in order to initiate a chain-link confidentiality exchange without leaking correlation to the actual ACDC to be disclosed {{CLC}}. A *Disclosee* (verifier) may validate the other metadata information in the metadata ACDC before agreeing to any restrictions imposed by the future disclosure. The metadata includes the *Issuer*, the *schema*, the provenancing *edges*, and the *rules* (terms-of-use). The top-level attribute section, `a`, field value of a *metadata* ACDC may be empty so that its value is not correlatable across disclosures (presentations). Should the potential *Disclosee* refuse to agree to the rules then the *Discloser* has not leaked the SAID of the actual ACDC or the SAID of the attribute block that would have been disclosed. 

Given the *metadata* ACDC, the potential *Disclosee* is able to verify the *Issuer*, the schema, the provenanced edges, and rules prior to agreeing to the rules.  Similarly, an *Issuer* may use a *metadata* ACDC to get agreement to a contractual waiver expressed in the rule section with a potential *Issuee* prior to issuance. Should the *Issuee* refuse to accept the terms of the waiver then the *Issuer* has not leaked the SAID of the actual ACDC that would have been issued nor the SAID of its attributes block nor the attribute values themselves.

When a *metadata* ACDC is disclosed (presented) only the *Discloser's* signature(s) is attached not the *Issuer's* signature(s). This precludes the *Issuer's* signature(s) from being used as a point of correlation until after the *Disclosee* has agreed to the terms in the rule section. When chain-link confidentiality is used, the *Issuer's* signatures are not disclosed to the *Disclosee* until after the *Disclosee* has agreed to keep them confidential. The *Disclosee* is protected from forged *Discloser* because ultimately verification of the disclosed ACDC will fail if the *Discloser* does not eventually provide verifiable *Issuer's* signatures. Nonetheless, should the potential *Disclosee* not agree to the terms of the disclosure expressed in the rule section then the *Issuer's* signature(s) is not leaked.

# Unpermissioned Exploitation of Data

An important design goal of ACDCs is they support the sharing of provably authentic data while also protecting against the un-permissioned exploitation of that data. Often the term *privacy protection* is used to describe similar properties. But a narrow focus on "privacy protection" may lead to problematic design trade-offs. With ACDCs, the primary design goal is not *data privacy protection* per se but the more general goal of protection from the ***un-permissioned exploitation of data***. In this light, a *given privacy protection* mechanism may be employed to help protect against *unpermissioned exploitation of data* but only when it serves that more general-purpose and not as an end in and of itself. There are three primary mechanisms ACDCs use to protect against *unpermissioned exploitation of data*. These are:  

* Chain-link Confidentiality {{CLC}}  
* Partial Disclosure 
* Selective Disclosure  


## Principle of Least Disclosure

ACDCs are designed to satisfy the principle of least disclosure.

> The system should disclose only the minimum amount of information about a given party needed to facilitate a transaction and no more. {{IDSys}}

For example, the *partial disclosure* of portions of an ACDC to enable chain-link confidentiality of the subsequent full disclosure is an application of the principle of least disclosure. Likewise, unbundling only the necessary attributes from a bundled commitment using *selective disclosure* to enable a correlation minimizing disclosure from that bundle is an application of the principle of least disclosure.

## Three Party Exploitation Model
Unpermission exploitation is characterized using a three-party model. The three parties are as follows:

* First-Party = *Discloser* of data.  
* Second-Party = *Disclosee* of data received from First Party (*Discloser*).  
* Third-Party = *Observer* of data disclosed by First Party (*Discloser*) to Second Party (*Disclosee*).  

### Second-Party (Disclosee) Exploitation
* implicit permissioned correlation.
    * no contractual restrictions on the use of disclosed data. 
* explicit permissioned correlation.
    * use as permitted by contract
* explicit unpermissioned correlation with other second parties or third parties.
    * malicious use in violation of contract

### Third-Party (Observer) Exploitation
* implicit permissioned correlation. 
    * no contractual restrictions on use of observed data. 
* explicit unpermissioned correlation via collusion with second parties.
    * malicious use in violation of second party contract

## Chain-link Confidentiality Exchange

Chain-link confidentiality imposes contractual restrictions and liability on any Disclosee (Second-Party) {{CLC}}. The exchange provides a fair contract consummation mechanism. The steps in a chain-link confidentiality exchange are as follows:

* *Discloser* provides a non-repudiable *Offer* with verifiable metadata (sufficient partial disclosure) which includes any terms or restrictions on use. 
* *Disclosee* verifies *Offer* against composed schema and metadata adherence to desired data.
* *Disclosee* provides non-repudiable *Accept* of terms that are contingent on compliant disclosure.
* *Discloser* provides non-repudiable *Disclosure* with sufficient compliant detail.
* *Disclosee* verifies *Disclosure* using decomposed schema and adherence of disclosed data to *Offer*.

*Disclosee* may now engage in permissioned use and carries liability as a deterrent against unpermissioned use.


# Compact ACDC
The top-level section field values of a compact ACDC are the SAIDs of each uncompacted top-level section. The section field labels
are `s`, `a`, `e`, and `r`.

## Compact Public ACDC

A fully compact public ACDC is shown below. 

~~~json
{
  "v":  "ACDC10JSON00011c_",
  "d":  "EBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5K0neuniccM",
  "i":  "did:keri:EmkPreYpZfFk66jpf3uFv7vklXKhzBrAqjsKAn2EDIPM",
  "ri": "did:keri:EymRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt",
  "s":  "E46jrVPTzlSkUPqGGeIZ8a8FWS7a6s4reAXRZOkogZ2A",
  "a":  "EgveY4-9XgOcLxUderzwLIr9Bf7V_NHwY1lkFrn9y2PY",
  "e":  "ERH3dCdoFOLe71iheqcywJcnjtJtQIYPvAu6DZIl3MOA",
  "r":  "Ee71iheqcywJcnjtJtQIYPvAu6DZIl3MORH3dCdoFOLB"
}
~~~


## Compact Private ACDC

A fully compact private ACDC is shown below. 

~~~json
{
  "v":  "ACDC10JSON00011c_",
  "d":  "EBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5K0neuniccM",
  "u":  "0ANghkDaG7OY1wjaDAE0qHcg",
  "i":  "did:keri:EmkPreYpZfFk66jpf3uFv7vklXKhzBrAqjsKAn2EDIPM",
  "ri": "did:keri:EymRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt",
  "s":  "E46jrVPTzlSkUPqGGeIZ8a8FWS7a6s4reAXRZOkogZ2A",
  "a":  "EgveY4-9XgOcLxUderzwLIr9Bf7V_NHwY1lkFrn9y2PY",
  "e":  "ERH3dCdoFOLe71iheqcywJcnjtJtQIYPvAu6DZIl3MOA",
  "r":  "Ee71iheqcywJcnjtJtQIYPvAu6DZIl3MORH3dCdoFOLB"
}

~~~

### Compact Private ACDC Schema

The schema for the compact private ACDC example above is provided below.

~~~json
{
  "$id": "EN8i2i5ye0-xGS95pm5cg1j0GmFkarJe0zzsSrrf4XJY",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Compact Private ACDC",
  "description": "Example JSON Schema for a Compact Private ACDC.",
  "credentialType": "CompactPrivateACDCExample",
  "type": "object",
  "required": 
  [
    "v",
    "d",
    "u",
    "i",
    "ri",
    "s",
    "a",
    "e",
    "r"
  ],
  "properties": 
  {
    "v": 
    {
      "description": "ACDC version string",
      "type": "string"
    },
    "d": 
    {
     "description": "ACDC SAID",
      "type": "string"
    },
    "u": 
    {
     "description": "ACDC UUID",
      "type": "string"
    },
    "i": 
    {
      "description": "Issuer AID",
      "type": "string"
    },
    "ri": 
    {
      "description": "credential status registry AID",
      "type": "string"
    },
    "s": {
      "description": "schema SAID",
      "type": "string"
    },
    "a": {
      "description": "attribute SAID",
      "type": "string"
    },
    "e": {
      "description": "edge SAID",
      "type": "string"
    },
    "r": {
      "description": "rule SAID",
      "type": "string"
    },
  },
  "additionalProperties": false
}
~~~

# Attribute Section

The attribute section in the examples above has been compacted into its SAID. The schema of the compacted attribute section is as follows,

~~~Json
{
  "a": 
  {
    "description": "attribute section SAID",
    "type": "string"
  }
}
~~~

Two variants of an ACDC, namely, namely, ***private (public) attribute*** are defined respectively by the presence (absence) of a UUID, `u`, field in the uncompacted attribute section block. 

Two other variants of an ACDC, namely, ***targeted (untargeted)*** are defined respectively by the presence (absence) of an issuee, `i`, field in the uncompacted attribute section block. 


## Public-Attribute ACDC

Suppose that the un-compacted value of the attribute section as denoted by the attribute section, `a`, field is as follows,

~~~json
{
  "a":
  {
    "d": "EgveY4-9XgOcLxUderzwLIr9Bf7V_NHwY1lkFrn9y2PY",
    "i": "did:keri:EpZfFk66jpf3uFv7vklXKhzBrAqjsKAn2EDIPmkPreYA",
    "score": 96,
    "name": "Jane Doe"
  }
}
~~~

The SAID, `d`, field at the top level of the uncompacted attribute block is the same SAID used as the compacted value of the attribute section, `a`, field. 

Given the absence of a `u` field at the top level of the attributes block, then knowledge of both SAID, `d`, field at the top level of an attributes block and the schema of the attributes block may enable the discovery of the remaining contents of the attributes block via a rainbow table attack {{RB}}{{DRB}}. Therefore the SAID, `d`, field of the attributes block, although, a cryptographic digest, does not securely blind the contents of the attributes block given knowledge of the schema. It only provides compactness, not privacy. Moreover, any cryptographic commitment to that SAID, `d`, field provides a fixed point of correlation potentially to the attribute block field values themselves in spite of non-disclosure of those field values via a compact ACDC. Thus an ACDC without a UUID, `u`, field in its attributes block must be considered a ***public-attribute*** ACDC even when expressed in compact form.


## Public Uncompacted Attribute Section Schema

The subschema for the public uncompacted attribute section is shown below,

~~~json
{
  "a": 
  {
    "description": "attribute section",
    "type": "object",
    "required": 
    [
      "d",
      "i",
      "score",
      "name"
    ],
    "properties": 
    {
      "d": 
      {
        "description": "attribute SAID",
        "type": "string"
      },
      "i": 
      {
        "description": "Issuee AID",
        "type": "string"
      },
      "score": 
      {
        "description": "test score",
        "type": "integer"
      },
      "name": 
      {
        "description": "test taker full name",
        "type": "string"
      }
    },
    "additionalProperties": false
  }
}
~~~

## Composed Schema for both Public Compact and Uncompacted Attribute Section Variants

Through the use of the JSON Schema `oneOf` composition operator the following composed schema will validate against both the compact and un-compacted value of the attribute section field.

~~~json
{
  "a": 
  {
    "description": "attribute section",
    "oneOf":
    [
      {
        "description": "attribute SAID",
        "type": "string"
      },
      {
        "description": "uncompacted attribute section",
        "type": "object",
        "required": 
        [
          "d",
          "i",
          "score",
          "name"
        ],
        "properties": 
        {
          "d": 
          {
            "description": "attribute SAID",
            "type": "string"
          },
          "i": 
          {
            "description": "Issuee AID",
            "type": "string"
          },
          "score": 
          {
            "description": "test score",
            "type": "integer"
          },
          "name": 
          {
            "description": "test taker full name",
            "type": "string"
          }
        },
        "additionalProperties": false
      }
    ]
  }
}
~~~



## Private-Attribute ACDC

Consider the following form of an uncompacted private-attribute block,

~~~json
{
  "a":
  {
    "d": "EgveY4-9XgOcLxUderzwLIr9Bf7V_NHwY1lkFrn9y2PY",
    "u": "0AwjaDAE0qHcgNghkDaG7OY1",
    "i": "did:keri:EpZfFk66jpf3uFv7vklXKhzBrAqjsKAn2EDIPmkPreYA",
    "score": 96,
    "name": "Jane Doe"
  }
}
~~~

Given the presence of a top-level UUID, `u`, field of the attribute block whose value has sufficient cryptographic entropy, then the top-level SAID, `d`, field of the attribute block provides a secure cryptographic digest of the contents of the attribute block {{Hash}}. An adversary when given both the schema of the attribute block and its SAID, `d`, field, is not able to discover the remaining contents of the attribute block in a computationally feasible manner such as a rainbow table attack {{RB}}{{DRB}}.  Therefore the attribute block's UUID, `u`, field in a compact ACDC enables its attribute block's SAID, `d`, field to securely blind the contents of the attribute block notwithstanding knowledge of the attribute block's schema and SAID, `d` field.  Moreover, a cryptographic commitment to that attribute block's, SAID, `d`, field does not provide a fixed point of correlation to the attribute field values themselves unless and until there has been a disclosure of those field values. 

To elaborate, when an ACDC includes a sufficiently high entropy UUID, `u`, field at the top level of its attributes block then the ACDC may be considered a ***private-attributes*** ACDC when expressed in compact form, that is, the attribute block is represented by its SAID, `d`, field and the value of its top-level attribute section, `a`, field is the value of the nested SAID, `d`, field from the uncompacted version of the attribute block. A verifiable commitment may be made to the compact form of the ACDC without leaking details of the attributes. Later disclosure of the uncompacted attribute block may be verified against its SAID, `d`, field that was provided in the compact form as the value of the top-level attribute section, `a`, field.

Because the *Issuee* AID is nested in the attribute block as that block's top-level, issuee, `i`, field, a presentation exchange (disclosure) could be initiated on behalf of a different AID that has not yet been correlated to the *Issuee* AID and then only correlated to the Issuee AID after the *Disclosee* has agreed to the chain-link confidentiality provisions in the rules section of the private-attributes ACDC {{CLC}}.


### Composed Schema for Both Compact and Uncompacted Private-Attribute ACDC

Through the use of the JSON Schema `oneOf` composition operator the following composed schema will validate against both the compact and un-compacted value of the private attribute section, `a`, field.


~~~json
{
  "a": 
  {
    "description": "attribute section",
    "oneOf":
    [
      {
        "description": "attribute SAID",
        "type": "string"
      },
      {
        "description": "uncompacted attribute section",
        "type": "object",
        "required": 
        [
          "d",
          "u",
          "i",
          "score",
          "name"
        ],
        "properties": 
        {
          "d": 
          {
            "description": "attribute SAID",
            "type": "string"
          },
          "u": 
          {
            "description": "attribute UUID",
            "type": "string"
          },
          "i": 
          {
            "description": "Issuee AID",
            "type": "string"
          },
          "score": 
          {
            "description": "test score",
            "type": "integer"
          },
          "name": 
          {
            "description": "test taker full name",
            "type": "string"
          }
        },
        "additionalProperties": false,
      }
    ]
  }
}
~~~

As described above in the Schema section of this specification, the `oneOf` sub-schema composition operator validates against either the compact SAID of a block or the full block. A validator can use a composed schema that has been committed to by the Issuer to securely confirm schema compliance both before and after detailed disclosure by using the fully composed base schema pre-disclosure and a specific decomposed variant post-disclosure. Decomposing the schema to remove the optional compact variant (i.e. removing the `oneOf` compact option) enables a validator to ensure complaint full disclosure. 



## Untargeted ACDC

Consider the case where the issuee, `i`, field is absent at the top level of the attribute block as shown below,

~~~json
{
  "a":
  {
    "d": "EgveY4-9XgOcLxUderzwLIr9Bf7V_NHwY1lkFrn9y2PY",
    "temp": 45,
    "lat": "N40.3433", 
    "lon": "W111.7208"
  }
}
~~~

This ACDC has an *Issuer* but no *Issuee*. Therefore, there is no provably controllable *Target* AID. This may be thought of as an undirected verifiable attestation or observation of the data in the attributes block by the *Issuer*. One could say that the attestation is addressed to "whom it may concern". It is therefore an ***untargeted*** ACDC, or equivalently an *unissueed* ACDC. An *untargeted* ACDC enables verifiable authorship by the Issuer of the data in the attributes block but there is no specified counter-party and no verifiable mechanism for delegation of authority.  Consequently, the rule section may only provide contractual obligations of implied counter-parties.

This form of an ACDC provides a container for authentic data only (not authentic data as authorization). But authentic data is still a very important use case. To clarify, an untargeted ACDC enables verifiable authorship of data. An observer such as a sensor that controls an AID may make verifiable non-repudiable measurements and publish them as ACDCs. These may be chained together to provide provenance for or a chain-of-custody of any data.  These ACDCs could be used to provide a verifiable data supply chain for any compliance-regulated application. This provides a way to protect participants in a supply chain from imposters. Such data supply chains are also useful as a verifiable digital twin of a physical supply chain {{Twin}}.

A hybrid chain of one or more targeted ACDCs ending in a chain of one or more untargeted ACDCs enables delegated authorized attestations at the tail of that chain. This may be very useful in many regulated supply chain applications such as verifiable authorized authentic datasheets for a given pharmaceutical.


## Targeted ACDC

When present at the top level of the attribute section, the issuee, `i`, field value provides the AID of the *Issuee* of the ACDC. This *Issuee* AID is a provably controllable identifier that serves as the *Target* AID. This makes the ACDC a ***targeted*** ACDC or equivalently an *issueed* ACDC. Targeted ACDCs may be used for many different purposes such as an authorization or a delegation directed at the *Issuee* AID, i.e. the *Target*. In other words, a *targeted ACDC* provides a container for authentic data that may also be used as some form of authorization such as a credential that is verifiably bound to the *Issuee* as targeted by the *Issuer*. Furthermore, by virtue of the targeted *Issuee's* provable control over its AID, the *targeted ACDC* may be verifiably presented (disclosed) by the controller of the *Issuee* AID.

For example, the definition of the term ***credential*** is *evidence of authority, status, rights, entitlement to privileges, or the like*. To elaborate, the presence of an attribute section top-level issuee, `i`, field enables the ACDC to be used as a verifiable credential given by the *Issuer* to the *Issuee*. 

One reason the issuee, `i`, field is nested into the attribute section, `a`, block is to enable the *Issuee* AID to be private or partially or selectively disclosable. The *Issuee* may also be called the *Holder* or *Subject* of the ACDC.  But here we use the more semantically precise albeit less common terms of *Issuer* and *Issuee*. The ACDC is issued from or by an *Issuer* and is issued to or for an *Issuee*. This precise terminology does not bias or color the role (function) that an *Issuee* plays in the use of an ACDC. What the presence of *Issuee* AID does provide is a mechanism for control of the subsequent use of the ACDC once it has been issued. To elaborate, because the issuee, `i`, field value is an AID, by definition, there is a provable controller of that AID. Therefore that *Issuee* controller may make non-repudiable commitments via digital signatures on behalf of its AID.  Therefore subsequent use of the ACDC by the *Issuee* may be securely attributed to the *Issuee*.

Importantly the presence of an issuee, `i`, field enables the associated *Issuee* to make authoritative verifiable presentations or disclosures of the ACDC. A designated *Issuee*also better enables the initiation of presentation exchanges of the ACDC between that *Issuee* as *Discloser* and a *Disclosee* (verifier).

In addition, because the *Issuee* is a specified counter-party the *Issuer* may engage in a contract with the *Issuee* that the *Issuee* agrees to by virtue of its non-repudiable signature on an offer of the ACDC prior to its issuance. This agreement may be a pre-condition to the issuance and thereby impose liability waivers or other terms of use on that *Issuee*. 

Likewise, the presence of an issuee, `i`, field, enables the *Issuer* to use the ACDC as a contractual vehicle for conveying an authorization to the *Issuee*.  This enables verifiable delegation chains of authority because the *Issuee* in one ACDC may become the *Issuer* in some other ACDC. Thereby an *Issuer* may delegate authority to an *Issuee* who may then become a verifiably authorized *Issuer* that then delegates that authority (or an attenuation of that authority) to some other verifiably authorized *Issuee* and so forth.  

# Edge Section

In the compact ACDC examples above, the edge section has been compacted into merely the SAID of that section. Suppose that the un-compacted value of the edge section denoted by the top-level edge, `e`, field is as follows,

~~~json
{
  "e": 
  {
    "d": "EerzwLIr9Bf7V_NHwY1lkFrn9y2PgveY4-9XgOcLx,UdY",
    "boss":
    {
      "n": "EIl3MORH3dCdoFOLe71iheqcywJcnjtJtQIYPvAu6DZA"
    }
  }
}
~~~

The edge section's top-level SAID, `d`, field is the SAID of the edge block and is the same SAID used as the compacted value of the ACDC's top-level edge, `e`, field. Each edge in the edge section gets its field with its own local label. In the example above, the edge label is `"boss"`. Note that each edge does NOT include a type field. The type of each edge is provided by the schema vis-a-vis the label of that edge. This is in accordance with the design principle of ACDCs that may be succinctly expressed as "schema is type". This approach varies somewhat from many property graphs which often do not have a schema {{PGM}}{{Dots}}{{KG}}. Because ACDCs have a schema for other reasons, however, they leverage that schema to provide edge types with a cleaner separation of concerns.

Each edge sub-block has one required node, `n`, field. The value of the node, `n`, field is the SAID of the ACDC to which the edge connects. 

A main distinguishing feature of a *property graph* (PG) is that both nodes but edges may have a set of properties {{PGM}}{{Dots}}{{KG}}. These might include modifiers that influence how the connected node is to be used such as a weight. Weighted directed edges represent degrees of confidence or likelihood. These types of PGs are commonly used for machine learning or reasoning under uncertainty. The following example adds a weight property to the edge sub-block as indicated by the weight, `w`, field.

~~~json
{
  "e": 
  {
    "d": "EerzwLIr9Bf7V_NHwY1lkFrn9y2PgveY4-9XgOcLxUdY",
    "boss":
    {
      "n": "EIl3MORH3dCdoFOLe71iheqcywJcnjtJtQIYPvAu6DZA",
      "w": "high"
    }
  }
}
~~~

## Globally Distributed Secure Graph Fragments

Abstractly, an ACDC with one or more edges may be a fragment of a distributed property graph. However, the local label does not enable the direct unique global resolution of a given edge including its properties other than a trivial edge with only one property, its node, `n` field. To enable an edge with additional properties to be globally uniquely resolvable, that edge's block may have a SAID, `d`, field. Because a SAID is a cryptographic digest it will universally and uniquely identify an edge with a given set of properties {{Hash}}. This allows ACDCs to be used as secure fragments of a globally distributed property graph (PG). This enables a property graph to serve as a global knowledge graph in a secure manner that crosses trust domains {{PGM}}{{Dots}}{{KG}}. This is shown below.


~~~json
{
  "e": 
  {
    "d": "EerzwLIr9Bf7V_NHwY1lkFrn9y2PgveY4-9XgOcLxUdY",
    "boss":
    {
      "d": "E9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_NHwY1lkFrn",
      "n": "EIl3MORH3dCdoFOLe71iheqcywJcnjtJtQIYPvAu6DZA",
      "w": "high"
    }
  }
}
~~~

## Compact Edge

Given that an individual edge's property block includes a SAID, `d`, field then a compact representation of the edge's property block is provided by replacing it with its SAID. This may be useful for complex edges with many properties. This is called a ***compact edge***. This is shown as follows,

~~~json
{
  "e": 
  {
    "d": "EerzwLIr9Bf7V_NHwY1lkFrn9y2PgveY4-9XgOcLxUdY",
    "boss": "E9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_NHwY1lkFrn",
  }
}
~~~

## Private Edge

Each edge's properties may be blinded by its SAID, `d`, field (i.e. be private) if its properties block includes a UUID, `u` field. As with UUID, `u`, fields used elsewhere in ACDC, if the UUID, `u`, field value has sufficient entropy then the values of the properties of its enclosing block are not discoverable in a computationally feasible manner merely given the schema for the edge block and its SAID, `d` field. This is called a ***private edge***. When a private edge is provided in compact form then the edge detail is hidden and is partially disclosable. An uncompacted private edge is shown below.

~~~json
{
  "e": 
  {
    "d": "EerzwLIr9Bf7V_NHwY1lkFrn9y2PgveY4-9XgOcLxUdY",
    "boss":
    {
      "d": "E9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_NHwY1lkFrn",
      "u":  "0AG7OY1wjaDAE0qHcgNghkDa",
      "n": "EIl3MORH3dCdoFOLe71iheqcywJcnjtJtQIYPvAu6DZA",
      "w": "high"
    }
  } 
}
~~~

When an edge points to a *private* ACDC, a *Discloser* may choose to use a metadata version of that private ACDC when presenting the node, `n`, field of that edge prior to acceptance of the terms of disclosure. The *Disclosee* can verify the metadata of the private node without the *Discloser* exposing the actual node contents via the actual node SAID or other attributes.

Private ACDCs (nodes) and private edges may be used in combination to prevent an un-permissioned correlation of the distributed property graph.

## Simple Compact Edge

When an edge sub-block has only one field that is its node, `n`, field then the edge block may use an alternate simplified compact form where the labeled edge field value is the value of its node, `n`, field. The schema for that particular edge label, in this case, `"boss"`,  will indicate that the edge value is a node SAID and not the edge sub-block SAID as would be the case for the normal compact form shown above. This alternate compact form is shown below.

~~~json
{
  "e": 
  {
    "d": "EerzwLIr9Bf7V_NHwY1lkFrn9y2PgveY4-9XgOcLxUdY",
    "boss": "EIl3MORH3dCdoFOLe71iheqcywJcnjtJtQIYPvAu6DZA"
  }
}
~~~

## Node Discovery

In general, the discovery of the details of an ACDC referenced as a node, `n` field value, in an edge sub-block begins with the node SAID or the SAID of the associated edge sub-block. Because a SAID is a cryptographic digest with high collision resistance it provides a universally unique identifier to the referenced ACDC as a node. The Discovery of a service endpoint URL that provides database access to a copy of the ACDC may be bootstrapped via an OOBI (Out-Of-Band-Introduction) that links the service endpoint URL to the SAID of the ACDC {{OOBI_ID}}. Alternatively, the *Issuer* may provide as an attachment at the time of issuance a copy of the referenced ACDC. In either case, after a successful exchange, the *Issuee* or recipient of any ACDC will have either a copy or a means of obtaining a copy of any referenced ACDCs as nodes in the edge sections of all ACDCs so chained. That Issuee or recipient will then have everything it needs to make a successful disclosure to some other *Disclosee*. This is the essence of *percolated* discovery.

# Rule Section

In the compact ACDC examples above, the rule section has been compacted into merely the SAID of that section. Suppose that the un-compacted value of the rule section denoted by the top-level rule, `r`, field is as follows,

~~~json
{
  "r": 
  {
    "d": "EwY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_NA",
    "warrantyDisclaimer": 
    {
      "l": "Issuer provides this credential on an \"AS IS\" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied, including, without limitation, any warranties or conditions of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A PARTICULAR PURPOSE"
    },
    "liabilityDisclaimer": 
    {
      "l": "In no event and under no legal theory, whether in tort (including negligence), contract, or otherwise, unless required by applicable law (such as deliberate and grossly negligent acts) or agreed to in writing, shall the Issuer be liable for damages, including any direct, indirect, special, incidental, or consequential damages of any character arising as a result of this credential. "
    }
  }
}
~~~

The purpose of the rule section is to provide a Ricardian Contract {{RC}}. The important features of a Ricardian contract are that it be both human and machine-readable and referenceable by a cryptographic digest. A JSON encoded document or block such as the rule section block is a practical example of both a human and machine-readable document.  The rule section's top-level SAID, `d`, field provides the digest.  This provision supports the bow-tie model of Ricardian Contracts {{RC}}. Ricardian legal contracts may be hierarchically structured into sections and subsections with named or numbered clauses in each section. The labels on the clauses may follow such a hierarchical structure using nested maps or blocks. These provisions enable the rule section to satisfy the features of a Ricardian contract.

To elaborate, the rule section's top-level SAID, `d`, field is the SAID of that block and is the same SAID used as the compacted value of the rule section, `r`, field that appears at the top level of the ACDC. Each clause in the rule section gets its own field. Each clause also has its own local label.

The legal, `l`, field in each block provides the associated legal language.  

Note there are no type fields in the rule section. The type of a contract and the type of each clause is provided by the schema vis-a-vis the label of that clause. This follows the ACDC design principle that may be succinctly expressed as "schema is type". 

Each rule section clause may also have its own clause SAID, `d`, field. Clause SAIDs enable reference to individual clauses, not merely the whole contract as given by the rule section's top-level SAID, `d`, field.

An example rule section with clause SAIDs is provided below.

~~~json
{
  "r": 
  {
    "d": "EwY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_NA",
    "warrantyDisclaimer": 
    {
      "d": "EXgOcLxUdYerzwLIr9Bf7V_NAwY1lkFrn9y2PgveY4-9",
      "l": "Issuer provides this credential on an \"AS IS\" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied, including, without limitation, any warranties or conditions of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A PARTICULAR PURPOSE"
    },
    "liabilityDisclaimer": 
    {
      "d": "EY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_NAw",
      "l": "In no event and under no legal theory, whether in tort (including negligence), contract, or otherwise, unless required by applicable law (such as deliberate and grossly negligent acts) or agreed to in writing, shall the Issuer be liable for damages, including any direct, indirect, special, incidental, or consequential damages of any character arising as a result of this credential. "
    }
  }
}
~~~

## Compact Clauses

The use of clause SAIDS enables a compact form of a set of clauses where each clause value is the SAID of the corresponding clause. For example,

~~~json
{
  "r": 
  {
    "d": "EwY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_NA",
    "warrantyDisclaimer":  "EXgOcLxUdYerzwLIr9Bf7V_NAwY1lkFrn9y2PgveY4-9",
    "liabilityDisclaimer": "EY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_NAw"
  }
}
~~~

## Private Clause

The disclosure of some clauses may be pre-conditioned on acceptance of chain-link confidentiality. In this case, some clauses may benefit from partial disclosure. Thus clauses may be blinded by their SAID, `d`, field when the clause block includes a sufficiently high entropy UUID, `u`, field. The use of a clause UUID enables the compact form of a clause to NOT be discoverable merely from the schema for the clause and its SAID via rainbow table attack {{RB}}{{DRB}}. Therefore such a clause may be partially disclosable. These are called ***private clauses***. A private clause example is shown below.

~~~json
{
  "r": 
  {
    "d": "EwY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_NA",
    "warrantyDisclaimer": 
    {
      "d": "EXgOcLxUdYerzwLIr9Bf7V_NAwY1lkFrn9y2PgveY4-9",
      "u": "0AG7OY1wjaDAE0qHcgNghkDa",
      "l": "Issuer provides this credential on an \"AS IS\" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied, including, without limitation, any warranties or conditions of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A PARTICULAR PURPOSE"
    },
    "liabilityDisclaimer": 
    {
      "d": "EY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_NAw",
      "u": "0AHcgNghkDaG7OY1wjaDAE0q",
      "l": "In no event and under no legal theory, whether in tort (including negligence), contract, or otherwise, unless required by applicable law (such as deliberate and grossly negligent acts) or agreed to in writing, shall the Issuer be liable for damages, including any direct, indirect, special, incidental, or consequential damages of any character arising as a result of this credential. "
    }
  }
}
~~~

## Simple Compact Clause

An alternate simplified compact form uses the value of the legal, `l`, field as the value of the clause field label. The schema for a specific clause label will indicate that the field value, for a given clause label is the legal language itself and not the clause block's SAID, `d`, field as is the normal compact form shown above. This alternate simple compact form is shown below. In this form individual clauses are not compactifiable and are fully self-contained.

~~~json
{
  "r": 
  {
    "d": "EwY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_NA",
    "warrantyDisclaimer": "Issuer provides this credential on an \"AS IS\" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied, including, without limitation, any warranties or conditions of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A PARTICULAR PURPOSE",
    "liabilityDisclaimer": "In no event and under no legal theory, whether in tort (including negligence), contract, or otherwise, unless required by applicable law (such as deliberate and grossly negligent acts) or agreed to in writing, shall the Issuer be liable for damages, including any direct, indirect, special, incidental, or consequential damages of any character arising as a result of this credential. "
  }
}
~~~

## Clause Discovery

In compact form, the discovery of either the rule section as a whole or a given clause begins with the provided SAID. Because the SAID, `d`, field of any block is a cryptographic digest with high collision resistance it provides a universally unique identifier to the referenced block details (whole rule section or individual clause). The discovery of a service endpoint URL that provides database access to a copy of the rule section or to any of its clauses may be bootstrapped via an OOBI (Out-Of-Band-Introduction) that links the service endpoint URL to the SAID of the respective block. Alternatively, the issuer may provide as an attachment at issuance a copy of the referenced contract associated with the whole rule section or any clause. In either case, after a successful issuance exchange, the Issuee or holder of any ACDC will have either a copy or a means of obtaining a copy of any referenced contracts in whole or in part of all ACDCs so issued. That Issuee or recipient will then have everything it needs to subsequently make a successful presentation or disclosure to a Disclosee. This is the essence of percolated discovery.

# Informative Example of an ACDC

## Public Compact Variant

~~~json
{
  "v":  "ACDC10JSON00011c_",
  "d":  "EBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5K0neuniccM",
  "i":  "did:keri:EmkPreYpZfFk66jpf3uFv7vklXKhzBrAqjsKAn2EDIPM",
  "ri": "did:keri:EymRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt",
  "s":  "E46jrVPTzlSkUPqGGeIZ8a8FWS7a6s4reAXRZOkogZ2A",
  "a":  "EgveY4-9XgOcLxUderzwLIr9Bf7V_NHwY1lkFrn9y2PY",
  "e":  "ERH3dCdoFOLe71iheqcywJcnjtJtQIYPvAu6DZIl3MOA",
  "r":  "Ee71iheqcywJcnjtJtQIYPvAu6DZIl3MORH3dCdoFOLB"
}
~~~

## Public Uncompacted Variant

~~~json
{
  "v":  "ACDC10JSON00011c_",
  "d":  "EBdXt3gIXOf2BBWNHdSXCJnFJL5OuQPyM5K0neuniccM",
  "i":  "did:keri:EmkPreYpZfFk66jpf3uFv7vklXKhzBrAqjsKAn2EDIPM",
  "ri": "did:keri:EymRy7xMwsxUelUauaXtMxTfPAMPAI6FkekwlOjkggt",
  "s":  "E46jrVPTzlSkUPqGGeIZ8a8FWS7a6s4reAXRZOkogZ2A",
  "a":  
  {
    "d": "EgveY4-9XgOcLxUderzwLIr9Bf7V_NHwY1lkFrn9y2PY",
    "i": "did:keri:EpZfFk66jpf3uFv7vklXKhzBrAqjsKAn2EDIPmkPreYA",
    "score": 96,
    "name": "Jane Doe"
  },
  "e": 
  {
    "d": "EerzwLIr9Bf7V_NHwY1lkFrn9y2PgveY4-9XgOcLxUdY",
    "boss":
    {
      "d": "E9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_NHwY1lkFrn",
      "n": "EIl3MORH3dCdoFOLe71iheqcywJcnjtJtQIYPvAu6DZA",
      "w": "high"
    }
  },
  "r": 
  {
    "d": "EwY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_NA",
    "warrantyDisclaimer": 
    {
      "d": "EXgOcLxUdYerzwLIr9Bf7V_NAwY1lkFrn9y2PgveY4-9",
      "l": "Issuer provides this credential on an \"AS IS\" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied, including, without limitation, any warranties or conditions of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A PARTICULAR PURPOSE"
    },
    "liabilityDisclaimer": 
    {
      "d": "EY1lkFrn9y2PgveY4-9XgOcLxUdYerzwLIr9Bf7V_NAw",
      "l": "In no event and under no legal theory, whether in tort (including negligence), contract, or otherwise, unless required by applicable law (such as deliberate and grossly negligent acts) or agreed to in writing, shall the Issuer be liable for damages, including any direct, indirect, special, incidental, or consequential damages of any character arising as a result of this credential. "
    }
  }
}
~~~

## Composed Schema that Supports both Public Compact and Uncompacted Variants

~~~json
{
  "$id": "EN8i2i5ye0-xGS95pm5cg1j0GmFkarJe0zzsSrrf4XJY",
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "Public ACDC",
  "description": "Example JSON Schema Public ACDC.",
  "credentialType": "PublicACDCExample",
  "type": "object",
   "required": 
  [
    "v",
    "d",
    "i",
    "ri",
    "s",
    "a",
    "e",
    "r"
  ],
  "properties": 
  {
    "v": 
    {
      "description": "ACDC version string",
      "type": "string"
    },
    "d": 
    {
     "description": "ACDC SAID",
      "type": "string"
    },
    "i": 
    {
      "description": "Issuer AID",
      "type": "string"
    },
    "ri": 
    {
      "description": "credential status registry AID",
      "type": "string"
    },
    "s": 
    {
      "description": "schema section",
      "oneOf":
      [
        {
          "description": "schema section SAID",
          "type": "string"
        },
        {
          "description": "schema detail",
          "type": "object"
        },
      ]
    },
    "a": 
    {
      "description": "attribute section",
      "oneOf":
      [
        {
          "description": "attribute section SAID",
          "type": "string"
        },
        {
          "description": "attribute detail",
          "type": "object",
          "required": 
          [
            "d",
            "i",
            "score",
            "name"
          ],
          "properties": 
          {
            "d": 
            {
              "description": "attribute section SAID",
              "type": "string"
            },
            "i": 
            {
              "description": "Issuee AID",
              "type": "string"
            },
            "score": 
            {
              "description": "test score",
              "type": "integer"
            },
            "name": 
            {
              "description": "test taker full name",
              "type": "string"
            }
          },
          "additionalProperties": false,
        }
      ],
    },
    "e":
    {
      "description": "edge section",
      "oneOf":
      [ 
        {
          "description": "edge section SAID",
          "type": "string"
        },
        {
          "description": "edge detail",
          "type": "object",
          "required": 
          [
            "d",
            "boss"
          ],
          "properties": 
          {
            "d": 
            {
              "description": "edge section SAID",
              "type": "string"
            },
            "boss": 
            {
              "description": "boss edge",
              "type": "object",
              "required":
              [
                "d",
                "n",
                "w"
              ],
              "properties":
              {
                "d": 
                {
                  "description": "edge SAID",
                  "type": "string"
                },
                "n": 
                {
                  "description": "node SAID",
                  "type": "string"
                },
                "w": 
                {
                  "description": "edge weight",
                  "type": "string"
              },
              "additionalProperties": false
            },
          },
          "additionalProperties": false
        }
      ],
    },
    "r": 
    {
      "description": "rule section",
      "oneOf":
      [
        {
          "description": "rule section SAID",
          "type": "string"
        },
        {
          "description": "rule detail",
          "type": "object",
          "required": 
          [
            "d",
            "warrantyDisclaimer",
            "liabilityDisclaimer"
          ],
          "properties": 
          {
            "d": 
            {
              "description": "edge section SAID",
              "type": "string"
            },
            "warrantyDisclaimer": 
            {
              "description": "warranty disclaimer clause",
              "type": "object",
              "required":
              [
                "d",
                "l"
              ],
              "properties":
              {
                "d": 
                {
                  "description": "clause SAID",
                  "type": "string"
                },
                "l": 
                {
                  "description": "legal language",
                  "type": "string"
                }
              },
              "additionalProperties": false
            },
            "liabilityDisclaimer": 
            {
              "description": "liability disclaimer clause",
              "type": "object",
              "required":
              [
                "d",
                "l"
              ],
              "properties":
              {
                "d": 
                {
                  "description": "clause SAID",
                  "type": "string"
                },
                "l": 
                {
                  "description": "legal language",
                  "type": "string"
                }
              },
              "additionalProperties": false
            }
          },
          "additionalProperties": false
        }
      ]
    }
  },
  "additionalProperties": false
}
~~~

# Selective Disclosure

As explained previously, the primary difference between *partial disclosure* and *selective disclosure* is determined by the correlatability with respect to its encompassing block after *full disclosure* of the detailed field value. A *partially disclosable* field becomes correlatable to its encompassing block after its *full disclosure*. Whereas a *selectively disclosable* field may be excluded from the *full disclosure* of any other selectively disclosable fields in its encompassing block. After selective disclosure, the selectively disclosed fields are not correlatable to the so-far undisclosed but selectively disclosable fields in the same encompassing block. In this sense, *full disclosure* means detailed disclosure of the selectively disclosed attributes not detailed disclosure of all selectively disclosable attributes.

Recall that *partial* disclosure is an essential mechanism needed to support chain-link confidentiality {{CLC}}. The chain-link confidentiality exchange *offer* requires *partial disclosure*, and *full disclosure* only happens after *acceptance* of the *offer*. *Selective* disclosure, on the other hand, is an essential mechanism needed to unbundle in a correlation minimizing way a single commitment by an Issuer to a bundle of fields (i.e. a nested block or array of fields). This allows separating a "stew" of "ingredients" (attributes) into its constituent "ingredients" (attributes) without correlating the constituents via the stew. 

ACDCs, as a standard, benefit from a minimally sufficient approach to selective disclosure that is simple enough to be universally implementable and adoptable. This does not preclude support for other more sophisticated but optional approaches. But the minimally sufficient approach should be universal so that at least one selective disclosure mechanism be made available in all ACDC implementations. To clarify, not all instances of an ACDC must employ the minimal selective disclosure mechanisms as described herein but all ACDC implementations must support any instance of an ACDC that employs the minimal selective disclosure mechanisms as described above.

The ACDC chaining mechanism reduces the need for selective disclosure in some applications. Many non-ACDC verifiable credentials provide bundled precisely because there is no other way to associate the attributes in the bundle. These bundled credentials could be refactored into a graph of ACDCs. Each of which is separately disclosable and verifiable thereby obviating the need for selective disclosure. Nonetheless, some applications require bundled attributes and therefore may benefit from the independent selective disclosure of bundled attributes. This is provided by ***selectively disclosable attribute*** ACDCs.

The use of a revocation registry is an example of a type of bundling, not of attributes in a credential, but uses of a credential in different contexts. Unbundling the usage contexts may be beneficial. This is provided by ***bulk-issued*** ACDCs.

In either case, the basic selective disclosure mechanism is comprised of a single aggregated blinded commitment to a list of blinded commitments to undisclosed values. Membership of any blinded commitment to a value in the list of aggregated blinded commitments may be proven without leaking (disclosing) the unblinded value belonging to any other blinded commitment in the list. This enables provable selective disclosure of the unblinded values. When a non-repudiable digital signature is created on the aggregated blinded commitment then any disclosure of a given value belonging to a given blinded commitment in the list is also non-repudiable. This approach does not require any more complex cryptography than digests and digital signatures. This satisfies the design ethos of minimally sufficient means. The primary drawback of this approach is verbosity. It trades ease and simplicity and adoptability of implementation for size. Its verbosity may be mitigated by replacing the list of blinded commitments with a Merkle tree of those commitments where the Merkle tree root becomes the aggregated blinded commitment.

Given sufficient cryptographic entropy of the blinding factors, collision resistance of the digests, and unforgeability of the digital signatures, either inclusion proof format (list or Merkle tree digest) prevents a potential disclosee or adversary from discovering in a computationally feasible way the values of any undisclosed blinded value details from the combination of the schema of those value details and either the aggregated blinded commitment and/or the list of aggregated blinded commitments {{Hash}}{{HCR}}{{QCHC}}{{Mrkl}}{{TwoPI}}{{MTSec}}. A potential disclosee or adversary would also need both the blinding factor and the actual value details.

Selective disclosure in combination with partial disclosure for chain-link confidentiality provides comprehensive correlation minimization because a discloser may use a non-disclosing metadata ACDC prior to acceptance by the disclosee of the terms of the chain-link confidentiality expressed in the rule section {{CLC}}. Thus only malicious disclosees who violate chain-link confidentiality may correlate between independent disclosures of the value details of distinct members in the list of aggregated blinded commitments. Nonetheless, they are not able to discover any as of yet undisclosed (unblinded) value details.

## Selectively Disclosable Attribute ACDC

In a ***selectively disclosable attribute*** ACDC, the set of attributes is provided as an array of blinded blocks. Each attribute in the set has its own dedicated blinded block. Each block has its own SAID, `d`, field and UUID, `u`, field in addition to its attribute field or fields. When an attribute block has more than one attribute field then the set of fields in that block are not independently selectively disclosable but MUST be disclosed together as a set. Notable is that the field labels of the selectively disclosable attributes are also blinded because they only appear within the blinded block. This prevents un-permissioned correlation via contextualized variants of a field label that appear in a selectively disclosable block. For example, localized or internationalized variants where each variant's field label(s) each use a different language or some other context correlatable information in the field labels themselves.

A selectively-disclosable attribute section appears at the top level using the field label `A`. This is distinct from the field label `a` for a non-selectively-disclosable attribute section. This makes clear (unambiguous) the semantics of the attribute section's associated schema. This also clearly reflects the fact that the value of a compact variant of selectively-disclosable attribute section is an "aggregate" not a SAID. As described previously, the top-level selectively-disclosable attribute aggregate section, `A`, field value is an aggregate of cryptographic commitments used to make a commitment to a set (bundle) of selectively-disclosable attributes. The derivation of its value depends on the type of selective disclosure mechanism employed. For example, the aggregate value could be the cryptographic digest of the concatenation of an ordered set of cryptographic digests, a Merkle tree root digest of an ordered set of cryptographic digests, or a cryptographic accumulator.

The *Issuer* attribute block is absent from an uncompacted untargeted selectively disclosable ACDC as follows:

~~~json
{
  "A":
  [
    {
      "d": "ELIr9Bf7V_NHwY1lkgveY4-Frn9y2PY9XgOcLxUderzw",
      "u": "0AG7OY1wjaDAE0qHcgNghkDa",
      "score": 96
    },
    {
      "d": "E9XgOcLxUderzwLIr9Bf7V_NHwY1lkFrn9y2PYgveY4-",
      "u": "0AghkDaG7OY1wjaDAE0qHcgN",
      "name": "Jane Doe"
    }
  ]
}
~~~

The *Issuer* attribute block is present in an uncompacted untargeted selectively disclosable ACDC as follows:

~~~json
{
  "A":
  [
    {
      "d": "ErzwLIr9Bf7V_NHwY1lkFrn9y2PYgveY4-9XgOcLxUde",
      "u": "0AqHcgNghkDaG7OY1wjaDAE0",
      "i": "did:keri:EpZfFk66jpf3uFv7vklXKhzBrAqjsKAn2EDIPmkPreYA"
    },
    {
      "d": "ELIr9Bf7V_NHwY1lkgveY4-Frn9y2PY9XgOcLxUderzw",
      "u": "0AG7OY1wjaDAE0qHcgNghkDa",
      "score": 96
    },
    {
      "d": "E9XgOcLxUderzwLIr9Bf7V_NHwY1lkFrn9y2PYgveY4-",
      "u": "0AghkDaG7OY1wjaDAE0qHcgN",
      "name": "Jane Doe"
    }
  ]
}
~~~

### Blinded Attribute Array

Given that each attribute block's UUID, `u`, field has sufficient cryptographic entropy, then each attribute block's SAID, `d`, field provides a secure cryptographic digest of its contents that effectively blinds the attribute value from discovery given only its Schema and SAID. To clarify, the adversary despite being given both the schema of the attribute block and its  SAID, `d`, field, is not able to discover the remaining contents of the attribute block in a computationally feasible manner such as a rainbow table attack {{RB}}{{DRB}}.  Therefore the UUID, `u`, field of each attribute block enables the associated SAID, `d`, field to securely blind the block's contents notwithstanding knowledge of the block's schema and that SAID, `d`, field.  Moreover, a cryptographic commitment to that SAID, `d`, field does not provide a fixed point of correlation to the associated attribute (SAD) field values themselves unless and until there has been specific disclosure of those field values themselves. 

Given a total of *N* elements in the attributes array, let *a<sub>i</sub>* represent the SAID, `d`, field of the attribute at zero-based index *i*. More precisely the set of attributes is expressed as:

*\{a<sub>i</sub> \| i ∈ \{0, ..., N-1\}\}*. 

The ordered set of *a<sub>i</sub>*  may be also expressed as a list, that is, 



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
