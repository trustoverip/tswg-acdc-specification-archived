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

# ACDC Fields

An ACDC may be abstractly modeled as a nested `key: value` mapping. To avoid confusion with the cryptographic use of the term *key* we instead use the term *field* to refer to a mapping pair and the terms *field label* and *field value* for each member of a pair. These pairs can be represented by two tuples e.g `(label, value)`. We qualify this terminology when necessary by using the term *field map* to reference such a mapping. *Field maps* may be nested where a given *field value* is itself a reference to another *field map*.  We call this nested set of fields a *nested field map* or simply a *nested map* for short. A *field* may be represented by a framing code or block delimited serialization.  In a block delimited serialization, such as JSON, each *field map* is represented by an object block with block delimiters such as `{}` {{RFC8259}}{{JSON}}{{RFC4627}}. Given this equivalence, we may also use the term *block* or *nested block* as synonymous with *field map* or *nested field map*. In many programming languages, a field map is implemented as a dictionary or hash table in order to enable performant asynchronous lookup of a *field value* from its *field label*. Reproducible serialization of *field maps* requires a canonical ordering of those fields. One such canonical ordering is called insertion or field creation order. A list of `(field, value)` pairs provides an ordered representation of any field map. Most programming languages now support ordered dictionaries or hash tables that provide reproducible iteration over a list of ordered field `(label, value)` pairs where the ordering is the insertion or field creation order. This enables reproducible round trip serialization/deserialization of *field maps*.  ACDCs depend on insertion ordered field maps for canonical serialization/deserialization. ACDCs support multiple serialization types, namely JSON, CBOR, MGPK, and CESR but for the sake of simplicity, we will only use JSON herein for examples {{RFC8259}}{{JSON}}. The basic set of normative field labels in ACDC field maps is defined in the following table.


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
