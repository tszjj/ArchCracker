// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 ArchCracker contributors
// DSH workflow body: fan out research angles, then return a structured summary.
// Usage: pass this file's contents as `script` to the workflow tool.
// args = { question: string, angles: [{ id: string, prompt: string }] }
//
// This file is not executed by Node; it runs inside the DSH workflow runtime,
// where `agent`, `parallel`, `phase`, and `args` are provided.

if (!args || typeof args.question !== 'string' || !Array.isArray(args.angles) || args.angles.length === 0) {
  throw new Error('research-fanout requires args.question and a non-empty args.angles[]');
}

phase('Research');

const results = await parallel(
  args.angles.map((angle) => async () => {
    const text = await agent(
      [
        'You are a research subagent for ArchCracker (Apache-2.0, cross-platform archive password recovery).',
        'Repository: D:\\AI Project\\p',
        'Do not modify files. Use web search/fetch when facts matter, and cite URLs.',
        '',
        'Overall question: ' + args.question,
        '',
        'Your angle (' + angle.id + '):',
        angle.prompt,
        '',
        'Return a concise Chinese memo (<= 700 words) with: findings, recommendation, risks, sources.',
      ].join('\n'),
      { label: angle.id, phase: 'Research' }
    );
    return text ? { id: angle.id, text } : null;
  })
);

return {
  question: args.question,
  angles: results.filter(Boolean),
  failed: results.filter((r) => !r).length,
};
