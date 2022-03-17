import redis
import config

ISSUS_FAMILIES_KEY = 'issue_families'


class RedisOperator:
    def __init__(self):
        self.pool = redis.ConnectionPool(
            host=config.get('DEPLOYER_NODE_IP'), 
            port=config.get('REDIS_PORT'),
            decode_responses=True
        )
        self.r = redis.Redis(connection_pool=self.pool)

    def str_get(self, key):
        return self.r.get(key)

    def str_set(self, key, value):
        return self.r.set(key, value)

    def str_delete(self, key):
        value = self.get(key)
        self.r.delete(key)
        return value

    def dict_set_all(self, key, value):
        return self.r.hmset(name=key, mapping=value)
    
    def dict_set_certain(self, key, sub_key, value):
        return self.r.hset(key, sub_key, value)

    def dict_get_all(self, key):
        return self.r.hgetall(key)
    
    def dict_get_certain(self, key, sub_key):
        return self.r.hget(key, sub_key)

    def dict_delete_certain(self, key, sub_key):
        return self.r.hdel(key, sub_key)

    def list_keys(self, pattern):
        return [key for key in self.r.scan_iter(pattern)]

    def check_issue_has_son(self, issue_id):
        return self.r.hexists(ISSUS_FAMILIES_KEY, issue_id)

    def update_issue_relations(self, issue_families):
        return self.dict_set_all(ISSUS_FAMILIES_KEY, issue_families)

    def update_issue_relation(self, parent_issue_id, son_issue_ids):
        return self.dict_set_certain(ISSUS_FAMILIES_KEY, parent_issue_id, son_issue_ids)

    def remove_issue_relation(self, parent_issue_id, son_issue_id):
        son_issue_ids = self.dict_get_certain(ISSUS_FAMILIES_KEY, parent_issue_id)
        if son_issue_ids is None:
            return 
        son_issue_ids = son_issue_ids.split(",")
        if son_issue_id in son_issue_ids:
            if len(son_issue_ids) == 1:
                self.dict_delete_certain(ISSUS_FAMILIES_KEY, parent_issue_id)
            else:
                son_issue_ids.remove(son_issue_id)
                self.update_issue_relation(parent_issue_id, ",".join(son_issue_ids))

    def remove_issue_relations(self, parent_issue_id):
        self.dict_delete_certain(ISSUS_FAMILIES_KEY, parent_issue_id)

    def add_issue_relation(self, parent_issue_id, son_issue_id):
        if not self.check_issue_has_son(parent_issue_id):
            self.dict_set_certain(ISSUS_FAMILIES_KEY, parent_issue_id, str(son_issue_id))
        else:
            son_issue_ids = self.dict_get_certain(ISSUS_FAMILIES_KEY, parent_issue_id)
            son_issue_ids = son_issue_ids.split(",")
            if son_issue_id not in son_issue_ids:
                self.update_issue_relation(parent_issue_id, ",".join(son_issue_ids+[str(son_issue_id)]))

redis_op = RedisOperator()