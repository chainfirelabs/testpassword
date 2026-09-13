const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
function element() {
  return {children: [], value: 'plaintext', classList: {toggle() {}}, addEventListener() {},
    append(...children) {this.children.push(...children);},
    appendChild(child) {this.children.push(child);}, textContent: ''};
}
const elements = new Map();
const context = vm.createContext({document: {
  getElementById(id) {if (!elements.has(id)) elements.set(id, element()); return elements.get(id);},
  createElement: element,
}});
vm.runInContext(fs.readFileSync('src/api/static/app.js', 'utf8'), context);
const good = {format: 'sha1', hash: 'A'.repeat(40), pwned: false, count: 0, data_loaded: true, data_complete: true};
assert(context.validResult(good, 'sha1'));
for (const change of [{count: '<script>'}, {pwned: 'false'}, {data_complete: undefined}, {hash: 'bad'}, {count: -1}]) {
  assert(!context.validResult({...good, ...change}, 'sha1'));
}
assert.equal(context.resultCard(good).children[0].children[1].textContent, 'NOT PWNED');
assert.equal(context.resultCard({...good, data_complete: false}).children[0].children[1].textContent, 'INCONCLUSIVE');
assert.equal(context.resultCard({...good, pwned: true, count: 1, data_complete: false}).children[0].children[1].textContent, 'PWNED');
context.renderResults({}, ['sha1']);
assert.match(elements.get('results').children[0].textContent, /INCONCLUSIVE/);
console.log('Web result validation and inconclusive rendering passed');
