// SAQR-INTEL personal email model ("email-v1", frozen contract section 4): a tiny naive-Bayes
// classifier that learns from the emails THIS user marks as "scam" or "not scam".
//
// Identical maths to saqr/intel/user_model.py so the JSON can move between the browser and the
// server (export / import). Needs lib/email_features.js loaded first (or require()d in node).
//
// Model JSON:
// {"format":"saqr-user-model","version":1,"spec":"email-v1","buckets":65536,"updated_at":"iso",
//  "classes":{"scam":{"docs":0,"total":0,"counts":{"<bucket>":n}},"ham":{...}},
//  "senders":{"<fnv1a32 hex8 of lowercased from_address>":{"scam":0,"ham":0}}}

(function (root, factory) {
  const feats =
    typeof module === "object" && module.exports ? require("./email_features.js") : root.SaqrModel;
  if (!feats || typeof feats.features !== "function") throw new Error("load lib/email_features.js before lib/user_model.js");
  const api = factory(feats);
  if (typeof module === "object" && module.exports) module.exports = Object.assign({}, feats, api);
  root.SaqrModel = Object.assign(root.SaqrModel || {}, api);
})(typeof globalThis !== "undefined" ? globalThis : this, function (F) {
  "use strict";

  const FORMAT = "saqr-user-model";
  const VERSION = 1;
  const LABELS = ["scam", "ham"];
  const MIN_DOCS = 10; // per class, before the model gives an opinion
  const SCAM_P = 0.9; // USER_MODEL_SCAM
  const TRUSTED_P = 0.1; // USER_MODEL_TRUSTED

  function now() {
    return new Date().toISOString().replace(/\.\d{3}Z$/, "Z"); // same format as the Python twin
  }

  function newModel() {
    return {
      format: FORMAT,
      version: VERSION,
      spec: F.SPEC,
      buckets: F.BUCKETS,
      updated_at: now(),
      classes: {
        scam: { docs: 0, total: 0, counts: {} },
        ham: { docs: 0, total: 0, counts: {} },
      },
      senders: {},
    };
  }

  function isCount(n) {
    return Number.isInteger(n) && n >= 0 && n <= 1e9;
  }

  /**
   * Check an imported / stored model and return a clean copy (unknown keys dropped).
   * Throws Error with a plain-language message when the JSON is not a SAQR model.
   */
  function validate(m) {
    if (!m || typeof m !== "object" || Array.isArray(m)) throw new Error("This file is not a SAQR model.");
    if (m.format !== FORMAT) throw new Error("This file is not a SAQR model (wrong format).");
    if (m.version !== VERSION) throw new Error("This SAQR model version is not supported.");
    if (m.spec !== F.SPEC) throw new Error("This SAQR model was made for a different feature set.");
    if (m.buckets !== undefined && m.buckets !== F.BUCKETS) throw new Error("This SAQR model has the wrong size.");
    const out = newModel();
    out.updated_at = typeof m.updated_at === "string" && m.updated_at.length <= 40 ? m.updated_at : out.updated_at;
    const classes = m.classes && typeof m.classes === "object" ? m.classes : {};
    for (const label of LABELS) {
      const c = classes[label];
      if (!c || typeof c !== "object") throw new Error("This SAQR model is missing the " + label + " counts.");
      if (!isCount(c.docs) || !isCount(c.total)) throw new Error("This SAQR model has invalid counts.");
      const counts = c.counts && typeof c.counts === "object" && !Array.isArray(c.counts) ? c.counts : {};
      const clean = {};
      for (const [k, v] of Object.entries(counts)) {
        const b = Number(k);
        if (!/^(0|[1-9][0-9]{0,4})$/.test(k) || b >= F.BUCKETS || !isCount(v)) throw new Error("This SAQR model has invalid counts.");
        // A bucket appears at most once per email, so more than docs is impossible: clamp it (a crafted file
        // could otherwise push any mail to p≈1; a relabel with drifted features can leave one over by a few).
        if (v > 0) clean[String(b)] = Math.min(v, c.docs);
      }
      out.classes[label] = { docs: c.docs, total: c.total, counts: clean };
    }
    const senders = m.senders && typeof m.senders === "object" && !Array.isArray(m.senders) ? m.senders : {};
    for (const [h, s] of Object.entries(senders)) {
      if (!/^[0-9a-f]{8}$/.test(h) || !s || typeof s !== "object") throw new Error("This SAQR model has invalid senders.");
      const scam = s.scam || 0;
      const ham = s.ham || 0;
      if (!isCount(scam) || !isCount(ham)) throw new Error("This SAQR model has invalid senders.");
      out.senders[h] = { scam: Math.min(scam, out.classes.scam.docs), ham: Math.min(ham, out.classes.ham.docs) };
    }
    return out;
  }

  function uniqueBuckets(features) {
    const set = new Set();
    for (const b of Array.isArray(features) ? features : []) {
      if (Number.isInteger(b) && b >= 0 && b < F.BUCKETS) set.add(b);
    }
    return Array.from(set).sort((a, b) => a - b);
  }

  /** Learn one labelled email. Mutates and returns the model. */
  function train(model, features, label, fromAddress) {
    if (!LABELS.includes(label)) throw new Error('label must be "scam" or "ham"');
    const c = model.classes[label];
    const buckets = uniqueBuckets(features);
    c.docs += 1;
    for (const b of buckets) c.counts[String(b)] = (c.counts[String(b)] || 0) + 1;
    c.total += buckets.length;
    if (fromAddress != null && String(fromAddress).trim() !== "") {
      const h = F.senderHash(fromAddress);
      const s = model.senders[h] || (model.senders[h] = { scam: 0, ham: 0 });
      s[label] = (s[label] || 0) + 1;
    }
    model.updated_at = now();
    return model;
  }

  /**
   * Undo an earlier train() with the same arguments (the user changed a label). Never goes below
   * zero, so it stays valid after an import / merge. Same as user_model.untrain in Python.
   */
  function untrain(model, features, label, fromAddress) {
    if (!LABELS.includes(label)) throw new Error('label must be "scam" or "ham"');
    const c = model.classes[label];
    if (c.docs <= 0) return model;
    c.docs -= 1;
    let removed = 0;
    for (const b of uniqueBuckets(features)) {
      const k = String(b);
      const n = c.counts[k] || 0;
      if (n > 0) {
        removed += 1;
        if (n === 1) delete c.counts[k];
        else c.counts[k] = n - 1;
      }
    }
    c.total = Math.max(0, c.total - removed);
    if (fromAddress != null && String(fromAddress).trim() !== "") {
      const h = F.senderHash(fromAddress);
      const s = model.senders[h];
      if (s && (s[label] || 0) > 0) {
        s[label] -= 1;
        if (!s.scam && !s.ham) delete model.senders[h];
      }
    }
    model.updated_at = now();
    return model;
  }

  function labelCount(model) {
    return model ? model.classes.scam.docs + model.classes.ham.docs : 0;
  }

  /** {available, p_scam, labels, spec}; p_scam is null until both classes have >= 10 emails. */
  function predict(model, features, fromAddress) {
    const labels = labelCount(model);
    const result = { available: false, p_scam: null, labels, spec: F.SPEC };
    if (!model) return result;
    const S = model.classes.scam;
    const H = model.classes.ham;
    if (S.docs < MIN_DOCS || H.docs < MIN_DOCS) return result;

    let logit = Math.log((S.docs + 1) / (H.docs + 1));
    for (const b of uniqueBuckets(features)) {
      const cs = S.counts[String(b)] || 0;
      const ch = H.counts[String(b)] || 0;
      logit += Math.log((cs + 1) / (S.docs + 2)) - Math.log((ch + 1) / (H.docs + 2));
    }
    if (fromAddress != null && String(fromAddress).trim() !== "") {
      const s = model.senders[F.senderHash(fromAddress)];
      if (s) logit += Math.log(((s.scam || 0) + 1) / ((s.ham || 0) + 1));
    }
    const z = Math.max(-30, Math.min(30, logit));
    result.available = true;
    result.p_scam = 1 / (1 + Math.exp(-z));
    return result;
  }

  /** Add the counts of b into a copy of a (import / merge). */
  function merge(a, b) {
    const out = validate(a);
    const other = validate(b);
    for (const label of LABELS) {
      const c = out.classes[label];
      const o = other.classes[label];
      c.docs += o.docs;
      c.total += o.total;
      for (const [k, v] of Object.entries(o.counts)) c.counts[k] = (c.counts[k] || 0) + v;
    }
    for (const [h, s] of Object.entries(other.senders)) {
      const t = out.senders[h] || (out.senders[h] = { scam: 0, ham: 0 });
      t.scam += s.scam;
      t.ham += s.ham;
    }
    out.updated_at = now();
    return out;
  }

  /** Flag code the model's opinion maps to (or null). */
  function flagFor(prediction) {
    if (!prediction || !prediction.available || prediction.p_scam == null) return null;
    if (prediction.p_scam >= SCAM_P) return "USER_MODEL_SCAM";
    if (prediction.p_scam <= TRUSTED_P) return "USER_MODEL_TRUSTED";
    return null;
  }

  return { FORMAT, VERSION, LABELS, MIN_DOCS, newModel, validate, train, untrain, predict, merge, labelCount, flagFor };
});
