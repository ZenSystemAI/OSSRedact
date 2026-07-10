// e-transfer / bank-ledger counterparty-name floor + Class B person-span growth (plan 049, 2026-07-08).
// TS twin of gate/tests/test_etransfer_cue.py + test_person_growth.py. Same grammar/contract, rule
// 'tier0:cue_name'. All names INVENTED; grammar derived from real statement formats.
import { describe, expect, it } from 'vitest'
import { cueNameSpans } from './tier0.js'
import { propagateRepeats } from './redaction.js'
import type { RawSpan } from './types.js'

const names = (t: string) => cueNameSpans(t).map((s) => t.slice(s.start, s.end))
const persons = (t: string) => cueNameSpans(t).filter((s) => s.label === 'person')

describe('cueNameSpans -- e-transfer / ledger counterparty names', () => {
  const CATCH: Array<[string, string]> = [
    ['VIR INTERAC RECU MARIE JEANNE DUPUIS', 'MARIE JEANNE DUPUIS'],
    ['VIR INTERAC ENVOYE JON JEAN OKAFOR', 'JON JEAN OKAFOR'],
    ['2026-05-22   E-TRANSFER 016633447755 Dianne Okafor   50.00 $', 'Dianne Okafor'],
    ['E-TRANSFER 108811224466 delyna morvan', 'delyna morvan'],
    ['E-TRANSFER 014466882200 bern', 'bern'],
    ['INTERAC ETRNSR SENT GREGORY OKAFOR', 'GREGORY OKAFOR'],
    ['INTERAC ETRNSR AD RECVD PRIYA RAMASWAMY', 'PRIYA RAMASWAMY'],
    ['Depot auto - virements par courriel OLIVIER DE FERLANDAIS CA7QzWvk', 'OLIVIER DE FERLANDAIS'],
    ['Dépôt auto - virements par courriel MAELLE DORVALINE CAZpQt4v', 'MAELLE DORVALINE'],
    ['Virement envoyé barb 9NRML3', 'barb'],
    ['Virement reçu JON OKAFOR CAu3wqe5', 'JON OKAFOR'],
    ['Interac e-Transfer from /Lucie Lemieux /', 'Lucie Lemieux'],
    ['Interac e-Transfer to /tony okafor /', 'tony okafor'],
    ['Cancellation-Interac e-Transfer to /Kevin Cote /', 'Kevin Cote'],
    ['Rent/lease /Tino Bravanese                          1075.00 $', 'Tino Bravanese'],
  ]
  it.each(CATCH)('catches %s', (text, name) => {
    expect(names(text)).toContain(name)
  })

  const NO_FP = [
    'The e-Transfer feature works well for everyone today.',
    'INTERAC e-Transfer                     700.00 $',
    'VIR INTERAC RECU FONDS admis',
  ]
  it.each(NO_FP)('no false positive: %s', (text) => {
    expect(names(text)).toEqual([])
  })

  it('never puts reference digits in the span', () => {
    for (const text of [
      'E-TRANSFER 016633447755 Dianne Okafor   50.00 $',
      'Depot auto - virements par courriel OLIVIER DE FERLANDAIS CA7QzWvk',
      'VIR INTERAC DEP AUTO REC ALMA BELROSE 401233701',
    ]) {
      for (const s of persons(text)) expect(/\d/.test(text.slice(s.start, s.end))).toBe(false)
    }
  })

  it('emits the tier-0 person contract', () => {
    const s = persons('VIR INTERAC RECU MARIE JEANNE DUPUIS')[0]
    expect([s.label, s.tier, s.conf, s.rule]).toEqual(['person', 0, 0.95, 'tier0:cue_name'])
  })
})

const span = (start: number, end: number, conf = 0.99): RawSpan => ({ start, end, label: 'person', tier: 2, conf, rule: 'gpu' })
const grown = (text: string, spans: RawSpan[]) =>
  propagateRepeats(text, spans).map((s) => [text.slice(s.start, s.end), s.rule] as [string, string])
const grownSpan = (text: string, spans: RawSpan[]) => grown(text, spans).find(([, r]) => r.endsWith('+grow'))

describe('propagateRepeats -- Class B person-span growth', () => {
  it('completes a partial token then absorbs the surname (LOVE -> LOVENA PHILOMARE)', () => {
    const text = 'cadeau LOVENA PHILOMARE merci'
    const i = text.indexOf('LOVE')
    expect(grownSpan(text, [span(i, i + 4)])).toEqual(['LOVENA PHILOMARE', 'gpu+grow'])
  })

  it('middle-token detect grows to the full run (Jean -> Jon Jean Okafor)', () => {
    const text = 'Name: Jon Jean Okafor solde'
    const i = text.indexOf('Jean')
    expect(grownSpan(text, [span(i, i + 4)])).toEqual(['Jon Jean Okafor', 'gpu+grow'])
  })

  it('does not cross a 2-space column gap', () => {
    const text = 'JON  OKAFOR extra'
    expect(grown(text, [span(0, 3)]).some(([, r]) => r.endsWith('+grow'))).toBe(false)
  })

  it('does not absorb a ledger stopword', () => {
    const text = 'ALMA FONDS admis'
    expect(grown(text, [span(0, 4)]).some(([, r]) => r.endsWith('+grow'))).toBe(false)
  })

  it('grown surname propagates doc-wide after one partial catch', () => {
    const text = 'vire LOUZA VILMA ARSTEVAN ok\nrow: ARSTEVAN total\nnote vilma encore'
    const i = text.indexOf('LOUZA')
    const got = grown(text, [span(i, i + 'LOUZA VILMA'.length)])
    expect(got).toContainEqual(['LOUZA VILMA ARSTEVAN', 'gpu+grow'])
    const repeats = new Set(got.filter(([, r]) => r === 'repeat').map(([v]) => v))
    expect(repeats.has('ARSTEVAN')).toBe(true)
    expect(repeats.has('vilma')).toBe(true)
  })

  it('does not grow a low-confidence person span', () => {
    const text = 'paye MAELLE DORVALINE au'
    const i = text.indexOf('MAELLE')
    expect(grown(text, [span(i, i + 'MAELLE DORVALIN'.length, 0.5)]).some(([, r]) => r.endsWith('+grow'))).toBe(false)
  })
})

describe('Codex adversarial-review regressions (2026-07-08)', () => {
  it('CRLF ledger lines still floor the full name (no \\r truncation)', () => {
    for (const form of [
      'VIR INTERAC RECU MARIE DUPUIS\r\nnext line',
      'E-TRANSFER 010271459817 marie dupuis\r\nnext',
      'Depot auto - virements par courriel MARIE DUPUIS\r\nnext',
    ]) {
      const names = cueNameSpans(form).map((s) => form.slice(s.start, s.end))
      expect(names.some((n) => n.toUpperCase().includes('MARIE DUPUIS')), form).toBe(true)
      expect(names.some((n) => n.includes('\r') || n.includes('next')), form).toBe(false)
    }
  })

  it('CRLF slash field stops at the line end', () => {
    const t = 'Interac e-Transfer to /Tomas Kaldera\r\nnext'
    expect(cueNameSpans(t).map((s) => t.slice(s.start, s.end))).toEqual(['Tomas Kaldera'])
  })

  it('a leading honorific is skipped, not a run terminator', () => {
    for (const [form, want] of [
      ['VIR INTERAC RECU MME MARIE DUPUIS', 'MARIE DUPUIS'],
      ['VIR INTERAC ENVOYE Monsieur Jon Okafor', 'Jon Okafor'],
      ['INTERAC ETRNSR SENT DR ALI KHAN', 'ALI KHAN'],
    ] as const) {
      expect(cueNameSpans(form).map((s) => form.slice(s.start, s.end)), form).toContain(want)
    }
  })

  it('amount prose never mints a person (short ref / currency stopword)', () => {
    expect(cueNameSpans('E-TRANSFER 1000 dollars')).toEqual([])
    expect(cueNameSpans('please e-transfer 2500 euros to the account')).toEqual([])
    expect(cueNameSpans('E-TRANSFER 123456 dollars')).toEqual([])
  })

  it('growth never absorbs log status words nor propagates them', () => {
    const text = 'INFO user=Johnathan Error Retrying now. Error again later. Retrying forever.'
    const start = text.indexOf('Johnathan')
    const spans: RawSpan[] = [{ start, end: start + 'Johnathan'.length, label: 'person', tier: 2, conf: 0.99, rule: 'gpu' }]
    for (const s of propagateRepeats(text, spans)) {
      const val = text.slice(s.start, s.end)
      expect(val.includes('Error'), val).toBe(false)
      expect(val.includes('Retrying'), val).toBe(false)
    }
  })

  it('growth edge-completion works across CRLF documents', () => {
    const text = 'payee MARC DE FERLANDAISE\r\nnext MARC DE FERLANDAISE\r\n'
    const start = text.indexOf('MARC')
    const spans: RawSpan[] = [{ start, end: start + 'MARC DE FERLANDAIS'.length, label: 'person', tier: 2, conf: 0.99, rule: 'gpu' }]
    const grown = propagateRepeats(text, spans)
      .filter((s) => s.rule?.endsWith('+grow'))
      .map((s) => text.slice(s.start, s.end))
    expect(grown[0]).toBe('MARC DE FERLANDAISE')
  })
})

describe('harness-driven regressions (real-corpus acceptance run, 2026-07-08)', () => {
  const names = (t: string) => cueNameSpans(t).map((s) => t.slice(s.start, s.end))

  it('BMO spells it ETRNSFR', () => {
    expect(names('INTERAC ETRNSFR AD RECVD DENIRA CHOLETTE 202598765004KZQ2W')).toContain('DENIRA CHOLETTE')
    expect(names('INTERAC ETRNSFR SENT AZARELLE 20265550801QRMXOD')).toContain('AZARELLE')
  })

  it('Tangerine mid-line e-Transfer To:/From: colon form', () => {
    expect(names('EFT Withdrawal to e-Transfer To: Fredrik Morvane 1,250.00')).toContain('Fredrik Morvane')
    expect(names('e-Transfer From: karelle 40.00')).toContain('karelle')
    expect(names('please e-transfer to: the account below')).toEqual([])
  })

  it('lone hyphen joins a DBA to the person (Traduction - Lise Charbonnel)', () => {
    expect(names('Virement envoye Traduction - Lise Charbonnel 8QZTKV').some((n) => n.includes('Lise Charbonnel'))).toBe(true)
  })
})

describe('middle-initial vs article stopword (harness re-run regression)', () => {
  const names = (t: string) => cueNameSpans(t).map((s) => t.slice(s.start, s.end))
  it('a bare uppercase initial inside a run is a name token', () => {
    expect(names('Depot auto - virements par courriel DEREK A MARTEL C1XyPnEvQhZk')).toContain('DEREK A MARTEL')
    expect(names('E-TRANSFER 013557799002 HELENA A MERCIER 20.00')).toContain('HELENA A MERCIER')
  })
  it('the article in prose after a colon-cue still stops the run', () => {
    expect(names('please e-transfer to: a friend')).toEqual([])
  })
})

describe('leading initials + colon-cue intent (Codex final pass)', () => {
  const names = (t: string) => cueNameSpans(t).map((s) => t.slice(s.start, s.end))
  it('a LEADING initial is a name token (dotted, or bare followed by a capitalized token)', () => {
    expect(names('E-TRANSFER 013557799002 A. MARTEL 20.00')).toContain('A. MARTEL')
    expect(names('E-TRANSFER 013557799002 A MARTEL 20.00')).toContain('A MARTEL')
    expect(names('E-TRANSFER 013557799002 J. MARTEL 20.00')).toContain('J. MARTEL')
    expect(names('please e-transfer to: a friend')).toEqual([])
    expect(names('please e-transfer to: A friend')).toEqual([])
  })
  it('colon-cue prose over-mask is the documented safe error (bounded)', () => {
    const got = names('please e-transfer to: Alice by Friday, thanks')
    expect(got.length).toBeGreaterThan(0)
    expect(got.every((n) => n.includes('Alice') && n.length <= 60)).toBe(true)
  })
})
