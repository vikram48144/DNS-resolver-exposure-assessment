// Live integration check: start Docker Compose, then node tests/lab-ui.cjs.
const assert = require('node:assert/strict');
const vm = require('node:vm');

async function main() {
    const base = process.env.DASHBOARD_URL || 'http://127.0.0.1:5000';
    const html = await (await fetch(base)).text();
    const script = await (await fetch(`${base}/static/js/app.js`)).text();
    const elements = new Map([...html.matchAll(/id="([^"]+)"/g)].map(([, id]) => [id, {
        textContent: '', innerHTML: '', classList: { add() {}, remove() {} }
    }]));
    const context = vm.createContext({document: {
        addEventListener() {},
        getElementById(id) { assert.ok(elements.has(id), `Missing element ${id}`); return elements.get(id); }
    }});
    vm.runInContext(script, context);
    async function post(path, data) {
        return fetch(`${base}${path}`, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(data)});
    }
    for (const [target, expected] of Object.entries({
        recursive: 'RECURSIVE', authoritative: 'AUTHORITATIVE_ONLY', refused: 'REFUSED', inconclusive: 'INCONCLUSIVE'
    })) {
        const response = await post('/api/lab-probe', {target});
        assert.equal(response.status, 200);
        const data = await response.json();
        assert.equal(data.classification, expected);
        assert.equal(data.recursive_probe.domain, 'example.com');
        assert.equal(data.authoritative_probe.domain, 'www.lab.example');
        context.renderLabResult(data);
        assert.ok(elements.get('lab-classification').innerHTML.includes(expected));
        assert.ok(elements.get('lab-selected-target').textContent.includes(data.ip));
        for (const kind of ['recursive', 'authoritative']) {
            const probe = data[`${kind}_probe`];
            assert.equal(elements.get(`lab-${kind}-answers`).textContent, probe.answers.length ? probe.answers.join('\n') : 'No answers');
            assert.equal(elements.get(`lab-${kind}-error`).textContent, probe.error || 'None');
            for (const flag of ['rd', 'ra', 'aa']) {
                assert.equal(elements.get(`lab-${kind}-${flag}`).textContent,
                    probe.responded ? String(probe[flag]).toUpperCase() : '-- (no response)');
            }
        }
        if (target === 'authoritative') {
            assert.equal(data.recursive_probe.rcode, 'REFUSED');
            assert.equal(data.recursive_probe.rd, true);
            assert.equal(data.authoritative_probe.rcode, 'NOERROR');
            assert.equal(data.authoritative_probe.rd, false);
            assert.equal(data.authoritative_probe.aa, true);
            assert.ok(data.authoritative_probe.answer_count > 0);
            assert.ok(data.authoritative_probe.answers.includes('10.10.0.100'));
        }
        if (target === 'inconclusive') {
            assert.equal(data.recursive_probe.error, 'TIMEOUT');
            assert.equal(data.authoritative_probe.attempts, 3);
        }
        console.log(`${target}: ${expected}, evidence and rendering PASS`);
    }
    for (const data of [null, [], {}, {target: []}, {target: '8.8.8.8'}, {target: 'recursive', ip: '8.8.8.8'}]) {
        assert.equal((await post('/api/lab-probe', data)).status, 400);
    }
    const external = await (await post('/api/domain-probe', {domain: 'example.com'})).json();
    assert.equal(external.domain, 'example.com');
    assert.equal(external.resolver, '10.10.0.2');
    assert.ok(external.result);
    for (const path of ['/api/results', '/download/json', '/download/csv', '/download/packet-analysis']) {
        assert.equal((await fetch(`${base}${path}`)).status, 200);
    }
    console.log('Target restrictions, external domain probe and evidence downloads PASS');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
