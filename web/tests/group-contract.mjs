// Contract check: does the server's /api/v1/assets payload deserialize into ZeroTerm's AssetPage?
// Mirrors core/crates/zeroterm-app/src/bastion.rs: AssetPage { items, groups, next_cursor }.
import assert from 'node:assert/strict';
import test from 'node:test';
import { groupTree, validateAssets } from '../src/api.ts';

const wire = {
  items: [{ id: 'a1', name: '应用服务器', protocol: 'ssh', tags: ['linux'], group_id: 'g-db', group_name: '数据库', revision: 3,
            accounts: [{ id: 'c1', label: 'deploy', username: 'deploy', domain: null, credential_kind: 'password' }] }],
  next_cursor: null,
  policy_revision: 7,
  // Exactly what pages.rs now emits: id / name / parent_id / sort_order, no revision.
  groups: [
    { id: 'g-root', name: '生产', parent_id: null, sort_order: 0 },
    { id: 'g-db', name: '数据库', parent_id: 'g-root', sort_order: 1 },
    { id: 'g-web', name: '网关', parent_id: 'g-root', sort_order: 0 },
  ],
};

test('asset page carries the group forest ZeroTerm parses, and nests it', () => {
  const page = validateAssets(wire);
  assert.deepEqual(page.groups.map(g => g.id), ['g-root', 'g-db', 'g-web']);
  // ZeroTerm requires every group field it deserializes; revision is not part of its struct.
  for (const group of page.groups) {
    assert.equal(typeof group.id, 'string'); assert.equal(typeof group.name, 'string');
    assert.equal(typeof group.sort_order, 'number');
    assert(group.parent_id === null || typeof group.parent_id === 'string');
  }
  assert.deepEqual(groupTree(page.groups).map(e => [e.group.id, e.depth]),
    [['g-root', 0], ['g-web', 1], ['g-db', 1]]);
  assert.equal(groupTree(page.groups)[2].group.parent_id, 'g-root');
});

test('a group whose parent is not visible still renders, and a cycle cannot hang the tree', () => {
  const orphan = groupTree([{ id: 'o', name: '孤立', parent_id: 'missing', sort_order: 0, revision: 1 }]);
  assert.deepEqual(orphan.map(e => [e.group.id, e.depth]), [['o', 0]]);
  const cycle = groupTree([
    { id: 'x', name: 'X', parent_id: 'y', sort_order: 0, revision: 1 },
    { id: 'y', name: 'Y', parent_id: 'x', sort_order: 0, revision: 1 },
  ]);
  assert.deepEqual(cycle.map(e => e.group.id), ['x', 'y']);
  const self = groupTree([{ id: 's', name: 'S', parent_id: 's', sort_order: 0, revision: 1 }]);
  assert.deepEqual(self.map(e => e.group.id), ['s']);
});

test('sibling ordering follows sort_order, then name', () => {
  const forest = [
    { id: 'r', name: 'R', parent_id: null, sort_order: 0, revision: 1 },
    { id: 'b', name: 'B', parent_id: 'r', sort_order: 5, revision: 1 },
    { id: 'a', name: 'A', parent_id: 'r', sort_order: 5, revision: 1 },
    { id: 'z', name: 'Z', parent_id: 'r', sort_order: 1, revision: 1 },
  ];
  assert.deepEqual(groupTree(forest).map(e => e.group.id), ['r', 'z', 'a', 'b']);
});
