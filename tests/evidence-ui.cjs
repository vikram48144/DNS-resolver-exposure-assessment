// Run against the dashboard: node tests/evidence-ui.cjs
const assert = require('node:assert/strict');
const vm = require('node:vm');

async function main() {
    const base = process.env.DASHBOARD_URL || 'http://127.0.0.1:5000';
    const html = await (await fetch(base)).text();
    const script = await (await fetch(`${base}/static/js/app.js`)).text();
    const payload = await (await fetch(`${base}/api/results`)).json();
    assert.equal(payload.success, true);
    assert.ok(payload.data.results.length > 0);

    const elements = new Map(
        [...html.matchAll(/id="([^"]+)"/g)].map(([, id]) => [id, {
            textContent: '', innerHTML: '',
            classList: { add() {}, remove() {} }
        }])
    );
    const context = vm.createContext({
        document: {
            addEventListener() {},
            getElementById(id) {
                assert.ok(elements.has(id), `Missing HTML element: ${id}`);
                return elements.get(id);
            }
        }
    });
    vm.runInContext(script, context);
    const cases = [...payload.data.results, {
        name: 'Simulated answer', ip: '192.0.2.1',
        classification: 'RECURSIVE', interpretation: 'Test interpretation',
        recursive_probe: { answers: ['example.com. 60 IN A 192.0.2.2'], attempts: 1 },
        authoritative_probe: { answers: [], error: 'TIMEOUT', attempts: 3 }
    }];
    for (const result of cases) {
        context.showEvidence(result);
        assert.equal(elements.get('recursive-answer-list').textContent,
            result.recursive_probe.answers.length
                ? result.recursive_probe.answers.join('\n') : 'No answers');
        assert.equal(elements.get('recursive-error').textContent,
            result.recursive_probe.error ?? 'None');
        assert.equal(elements.get('auth-attempts').textContent,
            result.authoritative_probe.attempts ?? '--');
        assert.ok(elements.get('evidence-classification').innerHTML.includes(result.classification));
        assert.equal(elements.get('evidence-interpretation').textContent, result.interpretation);
    }
    console.log(`Evidence rendering passed for ${cases.length} target cases.`);
}

main().catch(error => { console.error(error); process.exitCode = 1; });
