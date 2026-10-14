"""Deterministic group-state simulator, not a secure networking implementation.

Actor IDs below are assertions from a trusted test harness. Production must
verify signatures, grants, expiry, revocation and possession before applying
claims. This module does not join networks or authenticate real agents.
"""
from dataclasses import asdict, dataclass
import json


@dataclass(frozen=True)
class Policy:
    group_id: str
    policy_id: str
    members: frozenset[str]
    administrators: frozenset[str]


@dataclass(frozen=True)
class Claim:
    group_id: str
    policy_id: str
    subject: str
    actor: str
    revision: int
    kind: str


class Replica:
    def __init__(self, policy, node_id):
        if node_id not in policy.members:
            raise PermissionError('node is not pre-authorized')
        self.policy, self.node_id = policy, node_id
        self.claims = {}
        self.revision = 0
        self.dissolved = False
        self.reachable = set()  # Local observation, never replicated as authority.

    def publish(self, kind='join'):
        if kind not in ('join', 'leave'):
            raise ValueError('invalid member transition')
        if self.dissolved:
            raise PermissionError('group is dissolved')
        self.revision += 1
        claim = Claim(self.policy.group_id, self.policy.policy_id, self.node_id,
                      self.node_id, self.revision, kind)
        self.apply(claim)
        return claim

    def validate(self, claim):
        if claim.group_id != self.policy.group_id or claim.policy_id != self.policy.policy_id:
            raise PermissionError('foreign group or policy')
        if type(claim.revision) is not int or claim.revision <= 0:
            raise ValueError('invalid revision')
        if claim.kind == 'dissolve':
            if claim.actor not in self.policy.administrators or claim.subject != self.policy.group_id:
                raise PermissionError('only an administrator may dissolve')
        elif claim.kind in ('join', 'leave'):
            if claim.subject not in self.policy.members or claim.actor != claim.subject:
                raise PermissionError('unauthorized member claim')
        else:
            raise ValueError('invalid claim type')

    def apply(self, claim):
        self.validate(claim)
        if claim.kind == 'dissolve':
            self.dissolved = True
            self.reachable.clear()
            return
        previous = self.claims.get(claim.subject)
        if previous and previous.revision == claim.revision and previous != claim:
            raise ValueError('conflicting equal-revision claims')
        if previous and previous.revision >= claim.revision:
            return
        self.claims[claim.subject] = claim
        if claim.subject == self.node_id:
            self.revision = max(self.revision, claim.revision)
        if claim.kind == 'leave':
            self.reachable.discard(claim.subject)

    def dissolve(self, actor):
        claim = Claim(self.policy.group_id, self.policy.policy_id, self.policy.group_id,
                      actor, 1, 'dissolve')
        self.apply(claim)
        return claim

    def merge(self, other):
        if self.policy != other.policy:
            raise PermissionError('different policies cannot merge')
        # Preflight against a copy so an invalid batch cannot partially mutate us.
        trial = Replica.restore(self.policy, self.node_id, self.checkpoint())
        for claim in other.claims.values():
            trial.apply(claim)
        if other.dissolved:
            trial.dissolved = True
        self.claims, self.revision = trial.claims, trial.revision
        self.dissolved = self.dissolved or trial.dissolved
        self.reachable.intersection_update(self.members())

    def members(self):
        if self.dissolved:
            return set()
        return {subject for subject, claim in self.claims.items() if claim.kind == 'join'}

    def observe(self, subject, reachable):
        if reachable and subject in self.members():
            self.reachable.add(subject)
        else:
            self.reachable.discard(subject)

    def checkpoint(self):
        return json.dumps({'group_id': self.policy.group_id, 'policy_id': self.policy.policy_id,
                           'node_id': self.node_id, 'revision': self.revision,
                           'claims': [asdict(c) for c in self.claims.values()],
                           'dissolved': self.dissolved})

    @classmethod
    def restore(cls, policy, node_id, checkpoint):
        data = json.loads(checkpoint)
        if (data['group_id'], data['policy_id'], data['node_id']) != (policy.group_id, policy.policy_id, node_id):
            raise PermissionError('checkpoint identity mismatch')
        replica = cls(policy, node_id)
        for record in data['claims']:
            replica.apply(Claim(**record))
        revision = data['revision']
        if type(revision) is not int or revision < replica.revision:
            raise ValueError('checkpoint revision rollback')
        replica.revision = revision
        replica.dissolved = data['dissolved']
        # Never restore old connectivity observations as current presence.
        return replica


def demo():
    policy = Policy('example-group', 'example-policy', frozenset({'a', 'b', 'c'}), frozenset({'human-owner'}))
    nodes = {n: Replica(policy, n) for n in policy.members}
    for node in nodes.values():
        node.publish()
    for node in nodes.values():
        for peer in nodes.values():
            node.merge(peer)
    print(json.dumps({'scenario': 'formed', 'members': sorted(nodes['b'].members())}))
    nodes['a'].publish('leave')
    nodes['b'].merge(nodes['a'])
    nodes['c'].merge(nodes['b'])
    print(json.dumps({'scenario': 'creator-left', 'members': sorted(nodes['b'].members())}))
    checkpoints = {n: r.checkpoint() for n, r in nodes.items()}
    nodes = {n: Replica.restore(policy, n, saved) for n, saved in checkpoints.items()}
    print(json.dumps({'scenario': 'all-restarted', 'group_id': policy.group_id,
                      'members': sorted(nodes['b'].members()), 'reachable': sorted(nodes['b'].reachable)}))
    nodes['b'].dissolve('human-owner')
    nodes['c'].merge(nodes['b'])
    print(json.dumps({'scenario': 'dissolved', 'members': sorted(nodes['c'].members())}))


if __name__ == '__main__':
    demo()
