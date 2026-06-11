# Researcher outreach email — template

**Status:** unsent. Fill in the bracketed fields per recipient and edit
the second paragraph to reflect why *that specific person* is being
asked. A generic blast will get generic responses or none.

## Who to target

Pick 3–5 researchers whose published work is close enough to PQF's
construction that they could give useful feedback in under an hour of
their time. Good candidate types (do not contact all five):

- An author of the **X-Wing draft** (draft-connolly-cfrg-xwing-kem). PQF
  uses their combiner; they'll spot misuse instantly.
- An author of a **hybrid-KEM combiner analysis** paper (Barbosa,
  Giacon, Heuer, etc.). They'll evaluate the AAD-binding glue around
  X-Wing.
- A researcher working on **file-encryption format security** (people
  who've written about age, OpenPGP, or PKCS#7 weaknesses). They'll
  spot format-layer mistakes that pure-crypto reviewers might miss.
- A researcher working on **chunked AEAD** or **streaming authenticated
  encryption** (e.g. authors of the STREAM construction or related
  work). They'll evaluate §5.2.
- A researcher with recent work on **deterministic CBOR** or signed
  structured-data canonicalization. Niche, but the spec rises or falls
  on this.

Find current emails on the researcher's personal page or institutional
page, NOT on a paper PDF (those addresses go stale).

## The email

---

Subject: Brief review request: hybrid PQ file format using X-Wing

Dear Dr. **[LAST NAME]**,

I'm Paul Clark, an independent developer working on PQF — a hybrid
post-quantum file-encryption format for long-term archival. I've put
the core spec, design rationale, and reference implementations on
GitHub under MIT, and I'm in the phase of soliciting external review
before freezing v1.

**[ONE-TO-TWO-SENTENCE REASON YOU'RE WRITING THEM SPECIFICALLY. Example
for an X-Wing author: "PQF v1 uses X-Wing as its hybrid KEM combiner,
and my draft glues per-file and per-recipient binding to it at the
AEAD layer rather than inside the combiner. I'd value your view on
whether that composition is sound or whether I've missed a subtlety
in how X-Wing's security argument carries through."]**

I'm not asking for a full security review. What would help most is
reading the **3-page reviewer overview** linked below and replying
with a single concrete reaction — "the X part looks fine; the Y
binding worries me because Z" is more useful to me than silence after
a deep dive. If a longer conversation grows from there I'd be glad to
have it.

- 3-page reviewer overview: [LINK]
- Normative spec (1300 lines, for reference, not required reading):
  [LINK]
- Design rationale with §10 "what reviewers should focus on" and §11
  "open questions": [LINK]

I'm acutely aware that asking for time from researchers I haven't met
is presumptuous; I would not be writing if I weren't trying to do
this in the open and put the format through real review before any
production claim. If you don't have bandwidth, a single-sentence
"can't, sorry" is a perfectly fine reply.

Thank you for your time.

Best regards,
Paul Clark
<paul@systemslibrarian.dev>
https://github.com/systemslibrarian/PostQuantum.FileFormat

---

## Sending notes

- Personalize the bracketed paragraph for every recipient. If you can't
  write one specific sentence about why this person, don't email them
  — they'll feel the blast and ignore it.
- Send individually, not bcc. Researchers can tell.
- Don't follow up sooner than 3 weeks. Don't follow up more than once.
- Track who you've emailed and what they said in a private file — not
  to be pushy, but so you can credit them later in the spec's
  acknowledgments section if they engage.
- If someone declines but suggests another person, thank them and ask
  if they'd mind a brief introduction.
- Plain text. No tracking pixels. No HTML signatures with images.
