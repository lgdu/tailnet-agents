from dataclasses import replace
import unittest
from tailnet_agents.mesh_sim import Policy, Replica


class MeshSimulationTests(unittest.TestCase):
    def setUp(self):
        self.policy = Policy('group-1', 'policy-1', frozenset({'a', 'b', 'c'}), frozenset({'owner'}))
        self.a, self.b, self.c = [Replica(self.policy, n) for n in ('a', 'b', 'c')]
        for replica in (self.a, self.b, self.c):
            replica.publish()

    def sync(self):
        for replica in (self.a, self.b, self.c):
            for peer in (self.a, self.b, self.c):
                replica.merge(peer)

    def test_creator_leaves_without_dissolving_group(self):
        self.sync()
        self.a.publish('leave')
        self.b.merge(self.a)
        self.c.merge(self.b)
        self.assertEqual(self.c.members(), {'b', 'c'})
        self.assertFalse(self.c.dissolved)

    def test_restart_preserves_group_revision_but_not_online_observations(self):
        self.sync()
        self.b.observe('c', True)
        saved_revision = self.b.revision
        restored = Replica.restore(self.policy, 'b', self.b.checkpoint())
        self.assertEqual(restored.members(), {'a', 'b', 'c'})
        self.assertEqual(restored.reachable, set())
        self.assertGreater(restored.publish().revision, saved_revision)

    def test_partition_recovery_and_replayed_old_join(self):
        self.sync()
        old = self.a.claims['a']
        self.a.publish('leave')
        self.b.publish()
        self.assertIn('a', self.b.members())  # Partition: b has not learned the leave.
        self.b.merge(self.a)
        self.a.merge(self.b)
        self.b.apply(old)
        self.assertEqual(self.a.members(), self.b.members())
        self.assertNotIn('a', self.b.members())

    def test_unauthorized_members_impersonation_and_other_groups_rejected(self):
        with self.assertRaises(PermissionError):
            Replica(self.policy, 'stranger')
        claim = self.a.claims['a']
        for invalid in (replace(claim, actor='b'), replace(claim, subject='stranger'),
                        replace(claim, group_id='other'), replace(claim, policy_id='other')):
            with self.subTest(claim=invalid), self.assertRaises(PermissionError):
                self.b.apply(invalid)

    def test_all_nodes_offline_can_restore_same_group(self):
        self.sync()
        saved = [r.checkpoint() for r in (self.a, self.b, self.c)]
        replicas = [Replica.restore(self.policy, n, s) for n, s in zip(('a', 'b', 'c'), saved)]
        for node in replicas:
            self.assertEqual(node.policy.group_id, 'group-1')
            self.assertEqual(node.members(), {'a', 'b', 'c'})
            self.assertEqual(node.reachable, set())

    def test_dissolution_is_authorized_and_terminal_after_restore(self):
        self.sync()
        with self.assertRaises(PermissionError):
            self.a.dissolve('a')
        self.a.dissolve('owner')
        self.b.merge(self.a)
        restored = Replica.restore(self.policy, 'b', self.b.checkpoint())
        with self.assertRaises(PermissionError):
            restored.publish()
        restored.merge(self.c)  # A stale member cannot undo known dissolution.
        self.assertTrue(restored.dissolved)
        self.assertEqual(restored.members(), set())

    def test_equal_revision_conflict_rejected(self):
        claim = self.a.claims['a']
        self.b.apply(claim)
        with self.assertRaises(ValueError):
            self.b.apply(replace(claim, kind='leave'))
        self.assertIn('a', self.b.members())
