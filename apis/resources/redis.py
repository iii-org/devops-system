import redis
import config
import json
from datetime import datetime

ISSUS_FAMILIES_KEY = 'issue_families'
PROJECT_ISSUE_CALCULATE_KEY = 'project_issue_calculation'
SERVER_ALIVE_KEY = 'system_all_alive'
TEMPLATE_CACHE = 'template_list_cache'


class RedisOperator:
    def __init__(self):
        self.redis_base_url = config.get("REDIS_BASE_URL")
        # prod
        self.pool = redis.ConnectionPool(
            host=self.redis_base_url.split(":")[0],
            port=int(self.redis_base_url.split(":")[1]),
            decode_responses=True
        )
        '''
        # local
        self.pool = redis.ConnectionPool(
            host='10.20.0.93', 
            port='31852',
            decode_responses=True
        )
        '''
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
        return self.r.hset(key, mapping=value)

    def dict_set_certain(self, key, sub_key, value):
        return self.r.hset(key, sub_key, value)

    def dict_calculate_certain(self, key, sub_key, num=1):
        return self.r.hincrby(key, sub_key, amount=num)

    def dict_get_all(self, key):
        return self.r.hgetall(key)

    def dict_get_certain(self, key, sub_key):
        return self.r.hget(key, sub_key)

    def dict_delete_certain(self, key, sub_key):
        return self.r.hdel(key, sub_key)

    def dict_delete_all(self, key):
        value = self.r.hgetall(key)
        self.r.delete(key)
        return value

    def list_keys(self, pattern):
        return [key for key in self.r.scan_iter(pattern)]

    def dict_len(self, key):
        return self.r.hlen(key)


redis_op = RedisOperator()

# Server Alive
'''
'True': Alive, 'False': Not alive
'''


def get_server_alive():
    status = redis_op.str_get(SERVER_ALIVE_KEY)
    return status == "True" if status is not None else status


def update_server_alive(alive):
    return redis_op.str_set(SERVER_ALIVE_KEY, alive)

# Issue Family Cache


def check_issue_has_son(issue_id):
    return redis_op.r.hexists(ISSUS_FAMILIES_KEY, issue_id)


def update_issue_relations(issue_families):
    redis_op.dict_delete_all(ISSUS_FAMILIES_KEY)
    if issue_families != {}:
        return redis_op.dict_set_all(ISSUS_FAMILIES_KEY, issue_families)


def update_issue_relation(parent_issue_id, son_issue_ids):
    return redis_op.dict_set_certain(ISSUS_FAMILIES_KEY, parent_issue_id, son_issue_ids)


def remove_issue_relation(parent_issue_id, son_issue_id):
    son_issue_ids = redis_op.dict_get_certain(ISSUS_FAMILIES_KEY, parent_issue_id)
    if son_issue_ids is None:
        return
    son_issue_ids = son_issue_ids.split(",")
    if son_issue_id in son_issue_ids:
        if len(son_issue_ids) == 1:
            redis_op.dict_delete_certain(ISSUS_FAMILIES_KEY, parent_issue_id)
        else:
            son_issue_ids.remove(son_issue_id)
            update_issue_relation(parent_issue_id, ",".join(son_issue_ids))


def remove_issue_relations(parent_issue_id):
    redis_op.dict_delete_certain(ISSUS_FAMILIES_KEY, parent_issue_id)


def add_issue_relation(parent_issue_id, son_issue_id):
    if not check_issue_has_son(parent_issue_id):
        redis_op.dict_set_certain(ISSUS_FAMILIES_KEY, parent_issue_id, str(son_issue_id))
    else:
        son_issue_ids = redis_op.dict_get_certain(ISSUS_FAMILIES_KEY, parent_issue_id)
        son_issue_ids = son_issue_ids.split(",")
        if son_issue_id not in son_issue_ids:
            update_issue_relation(parent_issue_id, ",".join(son_issue_ids+[str(son_issue_id)]))

# Project issue calculate Cache


def get_certain_pj_issue_calc(pj_id):
    cal_info = redis_op.dict_get_certain(PROJECT_ISSUE_CALCULATE_KEY, pj_id)
    if cal_info is None:
        return {
            "closed_count": 0,
            "overdue_count": 0,
            "total_count": 0,
            "project_status": "not_started",
            "updated_time": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
        }
    return json.loads(cal_info)


def update_pj_issue_calcs(project_issue_calculation):
    return redis_op.dict_set_all(PROJECT_ISSUE_CALCULATE_KEY, project_issue_calculation)


def update_pj_issue_calc(pj_id, total_count=0, closed_count=0):
    pj_issue_calc = get_certain_pj_issue_calc(pj_id)
    pj_issue_calc["total_count"] += int(total_count)
    pj_issue_calc["closed_count"] += int(closed_count)

    if pj_issue_calc["total_count"] == 0:
        pj_issue_calc["project_status"] = "not_started"
    elif pj_issue_calc["total_count"] == pj_issue_calc["closed_count"]:
        pj_issue_calc["project_status"] = "closed"
    else:
        pj_issue_calc["project_status"] = "in_progress"

    pj_issue_calc["updated_time"] = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    return redis_op.dict_set_certain(PROJECT_ISSUE_CALCULATE_KEY, pj_id, json.dumps(pj_issue_calc))


def update_template_cache(id, dict_val):
    redis_op.dict_set_certain(TEMPLATE_CACHE, id, json.dumps(dict_val, default=str))


def get_template_caches_all():
    out = []
    cal_infos = redis_op.dict_get_all(TEMPLATE_CACHE)
    for k, v in cal_infos.items():
        out.append({k: json.loads(v)})
    return out


def count_template_number():
    return redis_op.dict_len(TEMPLATE_CACHE)
