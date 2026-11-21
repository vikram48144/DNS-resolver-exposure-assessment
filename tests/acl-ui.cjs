// Live backend and UI renderer check: node tests/acl-ui.cjs
const assert = require('node:assert/strict');
const vm = require('node:vm');
async function main() {
    const base = process.env.DASHBOARD_URL || 'http://127.0.0.1:5000';
    const html = await (await fetch(base)).text();
    function element() {
        return {textContent: '', innerHTML: '', children: [], append(...items) { this.children.push(...items); }};
    }
    const elements = new Map([...html.matchAll(/id="([^"]+)"/g)].map(([, id]) => [id, element()]));
    const context = vm.createContext({document: {
        addEventListener() {}, createElement: element,
        getElementById(id) { assert.ok(elements.has(id), id); return elements.get(id); }
    }});
    vm.runInContext(await (await fetch(`${base}/static/js/app.js`)).text(), context);
    const response = await fetch(`${base}/api/verify-recursion-acl`, {method: 'POST'});
    assert.equal(response.status, 200);
    const {data, success} = await response.json();
    assert.equal(success, true);
    console.log(JSON.stringify(data, null, 2));
    assert.equal(data.status, 'PASS');
    assert.equal(data.tests.authorised.observed, 'ALLOWED');
    assert.equal(data.tests.unauthorised.observed, 'DENIED');
    context.renderAclResult(data);
    assert.ok(elements.get('acl-overall').textContent.includes('PASS'));
    assert.equal(elements.get('acl-tests').children.length, 2);
    assert.ok(elements.get('acl-tests').children[1].children[1].textContent.includes('REFUSED'));
    const download = await fetch(`${base}/download/recursion-acl`);
    assert.equal(download.status, 200);
    assert.deepEqual(await download.json(), data);
    const invalid = await fetch(`${base}/api/verify-recursion-acl`, {
        method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ip: '8.8.8.8'})
    });
    assert.equal(invalid.status, 400);
    console.log('Live ACL verification, UI rendering, fixed target restriction and JSON download PASS');
}
main().catch(error => { console.error(error); process.exitCode = 1; });
