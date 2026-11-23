// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 ArchCracker contributors
// DSH workflow body: plan -> implement -> review -> verify for one scoped task.
// Usage: pass this file's contents as `script` to the workflow tool.
// args = {
//   task: string, role: string, scope: string,
//   acceptance: string[], branch?: string
// }
//
// The implementer may edit files; the reviewer/verifier are read-only by prompt.
// Human/agent integration still owns the commit and PR.

if (!args || typeof args.task !== 'string' || typeof args.role !== 'string' || typeof args.scope !== 'string') {
  throw new Error('feature-cycle requires args.task, args.role, args.scope');
}
const acceptance = Array.isArray(args.acceptance) ? args.acceptance : [];
const branch = args.branch || 'feat/task';

const common = [
  'Repository: D:\\AI Project\\p',
  'Read first: AGENTS.md, docs/agents/roles/' + args.role + '.md, docs/architecture.md, docs/roadmap.md.',
  'Task: ' + args.task,
  'Scope: ' + args.scope,
  'Branch: ' + branch,
  'Acceptance:',
  ...acceptance.map((x, i) => '  ' + (i + 1) + '. ' + x),
  'Rules: do not touch files outside scope; no new dependencies unless explicitly required;',
  'do not claim unrun tests passed; do not introduce unRAR/7-Zip RAR code; keep GPL-3.0-only headers.',
].join('\n');

phase('Plan');
const plan = await agent(
  common + '\n\nYou are the architect. Produce a short plan (files, steps, risks, test commands) as JSON.',
  {
    label: 'plan',
    phase: 'Plan',
    schema: {
      type: 'object',
      properties: {
        steps: { type: 'array', items: { type: 'string' } },
        files: { type: 'array', items: { type: 'string' } },
        risks: { type: 'array', items: { type: 'string' } },
      },
      required: ['steps', 'files'],
      additionalProperties: false,
    },
  }
);
if (!plan) throw new Error('plan agent failed');

phase('Implement');
const impl = await agent(
  common + '\n\nYou are the ' + args.role + '. Implement the task in scope. Run the relevant tests. Return JSON.',
  {
    label: 'implement',
    phase: 'Implement',
    schema: {
      type: 'object',
      properties: {
        status: { type: 'string', enum: ['done', 'partial', 'blocked'] },
        changed: { type: 'array', items: { type: 'string' } },
        verified: { type: 'array', items: { type: 'string' } },
        notVerified: { type: 'array', items: { type: 'string' } },
        notes: { type: 'string' },
      },
      required: ['status', 'changed'],
      additionalProperties: false,
    },
  }
);
if (!impl) throw new Error('implement agent failed');

phase('Review');
const review = await agent(
  [
    common,
    '',
    'You are the reviewer. Do not edit files. Inspect `git diff` and the changed files.',
    'Check correctness, licensing (no unRAR/RAR code), cross-platform impact, tests, performance claims.',
    'Return JSON.',
  ].join('\n'),
  {
    label: 'review',
    phase: 'Review',
    schema: {
      type: 'object',
      properties: {
        verdict: { type: 'string', enum: ['approve', 'request-changes', 'block'] },
        blocking: { type: 'array', items: { type: 'string' } },
        nonBlocking: { type: 'array', items: { type: 'string' } },
        license: { type: 'string', enum: ['ok', 'risk'] },
      },
      required: ['verdict', 'blocking'],
      additionalProperties: false,
    },
  }
);

phase('Verify');
const verify = await agent(
  [
    common,
    '',
    'You are QA. Do not edit files. Run the relevant tests/benchmarks if available.',
    'Confirm the acceptance list. Return JSON with commands and results.',
  ].join('\n'),
  {
    label: 'verify',
    phase: 'Verify',
    schema: {
      type: 'object',
      properties: {
        passed: { type: 'boolean' },
        commands: { type: 'array', items: { type: 'string' } },
        failures: { type: 'array', items: { type: 'string' } },
      },
      required: ['passed', 'commands'],
      additionalProperties: false,
    },
  }
);

return { plan, implementation: impl, review, verification: verify };
