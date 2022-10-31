import base64
import ssl
import time
from datetime import datetime, timedelta
from datetime import time as d_time

import websocket
from flask_jwt_extended import jwt_required
from flask_restful import abort, Resource, reqparse
from flask_socketio import Namespace, emit, disconnect

import config
import resources.apiError as apiError
import util as util
from nexus import nx_get_project_plugin_relation
from model import RancherPiplineNumberEachDays, ProjectPluginRelation, db, Project, SystemParameter
from resources import kubernetesClient
from resources.logger import logger
from flask_apispec import use_kwargs
from urls import route_model


def get_ci_last_test_result(relation):
    ret = {
        'last_test_result': {'total': 0, 'success': 0},
        'last_test_time': ''
    }
    pl = rancher.rc_get_pipeline_info(relation.ci_project_id, relation.ci_pipeline_id)
    last_exec_id = pl.get('lastExecutionId')
    if last_exec_id is None:
        return ret
    try:
        last_run = rancher.rc_get_pipeline_execution(
            relation.ci_project_id, relation.ci_pipeline_id, last_exec_id)
    except apiError.DevOpsError as e:
        if e.status_code == 404:
            return ret
        else:
            raise e

    ret['last_test_result']['total'] = len(last_run['stages'])
    ret['last_test_time'] = last_run['created']
    stage_status = []
    for stage in last_run['stages']:
        if 'state' in stage:
            stage_status.append(stage['state'])
    if 'Failed' in stage_status:
        failed_item = stage_status.index('Failed')
        ret['last_test_result']['success'] = failed_item
    else:
        ret['last_test_result']['success'] = len(last_run['stages'])
    return ret


class Rancher(object):
    def __init__(self):
        self.token = 'dummy string to make API returns 401'
        self.cluster_id = None
        self.project_id = None

    def __api_request(self, method, path, headers, params=None, data=None,
                      with_token=True, retried=False):
        url = f'https://{config.get("RANCHER_IP_PORT")}' \
              f'/{config.get("RANCHER_API_VERSION")}{path}'
        if headers is None:
            headers = {'Content-Type': 'application/json'}
        final_headers = self.__auth_headers(headers, with_token)

        response = util.api_request(method, url, headers=final_headers, params=params, data=data)
        if response.status_code == 401 and not retried:
            self.token = self.__generate_token()
            return self.__api_request(method, path, headers=headers, params=params, data=data,
                                      with_token=True, retried=True)
        if int(response.status_code / 100) != 2:
            raise apiError.DevOpsError(
                response.status_code,
                'Got non-2xx response from Rancher.',
                apiError.error_3rd_party_api('Rancher', response))
        return response

    def __auth_headers(self, headers, with_token):
        if headers is not None:
            ret = headers.copy()
        else:
            ret = {}
        if with_token:
            ret['Authorization'] = "Bearer {0}".format(self.token)
        return ret

    def __api_get(self, path, params=None, headers=None, with_token=True):
        return self.__api_request('GET', path=path, params=params,
                                  headers=headers, with_token=with_token)

    def __api_post(self, path, params=None, headers=None, data=None, with_token=True,
                   retried=False):
        return self.__api_request('POST', path=path, params=params, data=data,
                                  headers=headers, with_token=with_token,
                                  retried=retried)

    def __api_put(self, path, params=None, headers=None, data=None, with_token=True,
                  retried=False):
        return self.__api_request('PUT', path=path, params=params, data=data,
                                  headers=headers, with_token=with_token,
                                  retried=retried)

    def __api_delete(self, path, params=None, headers=None, with_token=True):
        return self.__api_request('DELETE', path=path, params=params,
                                  headers=headers, with_token=with_token)

    def __generate_token(self):
        acc = "username"
        pas = "password"
        ran_am_key = 'RANCHER_ADMIN_ACCOUNT'
        ran_am_pas = 'RANCHER_ADMIN_PASSWORD'
        body = {
            acc: config.get(ran_am_key),
            pas: config.get(ran_am_pas)
        }
        params = {'action': 'login'}
        output = self.__api_post('-public/localProviders/local', params=params,
                                 data=body, with_token=False, retried=True)
        return output.json()['token']

    def rc_get_pipeline_execution(self, ci_project_id, ci_pipeline_id, execution_id):
        path = f'/projects/{ci_project_id}/pipelineExecutions/{execution_id}'
        response = self.__api_get(path)
        return response.json()

    def rc_get_pipeline_executions(self, ci_project_id, ci_pipeline_id, run=None, limit=None,
                                   page_start=None, branch=None):
        path = f'/projects/{ci_project_id}/pipelineexecutions'
        params = {
            'order': 'desc',
            'sort': 'started',
            'pipelineId': ci_pipeline_id
        }
        if limit is not None:
            params['limit'] = limit
        if page_start is not None:
            params['marker'] = f"{ci_pipeline_id}-{page_start}"
        if branch is not None:
            params['branch'] = branch
        elif run is not None:
            params['run'] = run

        response = self.__api_get(path, params=params)
        output_array = response.json()
        return output_array

    def rc_get_pipeline_executions_action(self, ci_project_id, ci_pipeline_id, pipelines_exec_run,
                                          action):
        path = '/project/{0}/pipelineExecutions/{1}-{2}'.format(ci_project_id, ci_pipeline_id,
                                                                pipelines_exec_run)
        params = {'action': 'rerun'}
        if action == 'stop':
            params = {'action': 'stop'}
        response = self.__api_post(path, params=params, data='')
        return response

    def rc_delete_pipeline_executions_run(self, ci_project_id, ci_pipeline_id, pipelines_exec_run):
        path = '/project/{0}/pipelineExecutions/{1}-{2}'.format(ci_project_id, ci_pipeline_id,
                                                                pipelines_exec_run)
        self.__api_delete(path)

    def rc_get_pipeline_info(self, ci_project_id, ci_pipeline_id):
        path = f'/project/{ci_project_id}/pipelines/{ci_pipeline_id}'
        info = self.__api_get(path)
        return info.json()

    def rc_run_pipeline(self, ci_project_id, ci_pipeline_id, branch):
        path = f'/project/{ci_project_id}/pipelines/{ci_pipeline_id}'
        params = {'action': 'run'}
        data = {"branch": branch}
        response = self.__api_post(path, params=params, data=data)
        return response.json()

    def rc_get_pipeline_config(self, ci_pipeline_id, pipelines_exec_run):
        output_dict = []
        self.token = self.__generate_token()
        self.rc_get_project_id()
        output_executions = self.rc_get_pipeline_executions(
            self.project_id, ci_pipeline_id, run=pipelines_exec_run
        )
        output_execution = output_executions['data'][0]
        for index, stage in enumerate(
                output_execution['pipelineConfig']['stages']):
            tmp_step_message = []
            for step_index, step in enumerate(stage['steps']):
                step_detail = output_execution['stages'][
                    index]['steps'][step_index]
                step_state = None
                if 'state' in step_detail:
                    step_state = step_detail['state']
                tmp_step_message.append({
                    "step_id": step_index,
                    "state": step_state
                })
            stage_state_dict = output_execution['stages'][index]
            stage_state = None
            if 'state' in stage_state_dict:
                stage_state = stage_state_dict['state']
            output_dict.append({
                "stage_id": index,
                "name": stage['name'],
                "state": stage_state,
                "steps": tmp_step_message
            })
        return output_dict[1:]

    def rc_get_pipe_log_websocket(self, data):
        self.token = self.__generate_token()
        headersandtoken = "Authorization: Bearer {0}".format(self.token)
        self.rc_get_project_id()
        url = ("wss://{0}/{1}/project/{2}/pipelineExecutions/"
               "{3}-{4}/log?stage={5}&step={6}").format(
            config.get('RANCHER_IP_PORT'), config.get('RANCHER_API_VERSION'),
            self.project_id,
            data["ci_pipeline_id"], data["pipelines_exec_run"], data["stage_index"],
            data["step_index"])
        result = None
        try:
            ws_start_time = time.time()
            ws = websocket.create_connection(url, header=[headersandtoken],
                                             sslopt={"cert_reqs": ssl.CERT_NONE})
            i = 0
            while True:
                result = ws.recv()
                emit('pipeline_log', {'data': result,
                                      'ci_pipeline_id': data["ci_pipeline_id"],
                                      'pipelines_exec_run': data["pipelines_exec_run"],
                                      'stage_index': data["stage_index"],
                                      'step_index': data["step_index"]})
                # print(f"result: {result}")
                ws_end_time = time.time() - ws_start_time
                if result == '' or ws_end_time >= 600 or i >= 100:
                    emit('pipeline_log', {'data': '',
                                          'ci_pipeline_id': data["ci_pipeline_id"],
                                          'pipelines_exec_run': data["pipelines_exec_run"],
                                          'stage_index': data["stage_index"],
                                          'step_index': data["step_index"]})
                    ws.close()
                    print(f"result: {result}, ws_end_time: {ws_end_time}, i: {i}")
                    break
                else:
                    i += 1
        except:
            if ws is not None:
                ws.close()
            disconnect()

    def rc_get_pipeline_executions_logs(self, ci_project_id, ci_pipeline_id,
                                        pipelines_exec_run):
        output_dict = []
        self.token = self.__generate_token()
        headersandtoken = "Authorization: Bearer {0}".format(self.token)
        output_executions = self.rc_get_pipeline_executions(
            ci_project_id, ci_pipeline_id, run=pipelines_exec_run
        )
        output_execution = output_executions['data'][0]
        for index, stage in enumerate(
                output_execution['pipelineConfig']['stages']):
            tmp_step_message = []
            for step_index, step in enumerate(stage['steps']):
                url = ("wss://{0}/{1}/project/{2}/pipelineExecutions/"
                       "{3}-{4}/log?stage={5}&step={6}").format(
                    config.get('RANCHER_IP_PORT'), config.get('RANCHER_API_VERSION'),
                    ci_project_id,
                    ci_pipeline_id, pipelines_exec_run, index, step_index)
                logger.info("wss url: {0}".format(url))
                result = None
                ws = websocket.create_connection(url, header=[headersandtoken],
                                                 sslopt={"cert_reqs": ssl.CERT_NONE})
                ws.settimeout(3)
                try:
                    result = ws.recv()
                    ws.close()
                except websocket.WebSocketTimeoutException:
                    ws.close()
                # logger.info("Received :'%s'" % result)
                step_detail = output_execution['stages'][
                    index]['steps'][step_index]
                if 'state' in step_detail:
                    tmp_step_message.append({
                        "state": step_detail['state'],
                        "message": result
                    })
                else:
                    tmp_step_message.append({
                        "state": None,
                        "message": result
                    })
            stage_state = output_execution['stages'][index]
            if 'state' in stage_state:
                output_dict.append({
                    "name": stage['name'],
                    "state": stage_state['state'],
                    "steps": tmp_step_message
                })
            else:
                output_dict.append({
                    "name": stage['name'],
                    "state": None,
                    "steps": tmp_step_message
                })
        return output_dict[1:], output_execution['executionState']

    def rc_get_cluster_id(self):
        if self.cluster_id is None:
            rancher_output = self.__api_get('/clusters')
            output_array = rancher_output.json()['data']
            for output in output_array:
                if output['name'] == config.get('RANCHER_CLUSTER_NAME'):
                    self.cluster_id = output['id']

    def rc_get_project_id(self):
        self.rc_get_cluster_id()
        if self.project_id is None:
            rancher_output = self.__api_get('/clusters/{0}/projects'.format(self.cluster_id))
            output_array = rancher_output.json()['data']
            for output in output_array:
                if output['name'] == "Default":
                    self.project_id = output['id']

    def rc_get_admin_user_id(self):
        rancher_output = self.__api_get('/users')
        output_array = rancher_output.json()['data']
        for output in output_array:
            if output['username'] == 'admin':
                return output['id']

    def rc_enable_project_pipeline(self, repository_url):
        self.rc_get_project_id()
        pipeline_list = self.rc_get_project_pipeline()
        for pipeline in pipeline_list:
            if pipeline['repositoryUrl'] == repository_url:
                logger.info(
                    "repository_url {0} rancher pipeline already enable".format(repository_url))
                abort(400, message='rancher pipeline already enable this repository {0}'.format(
                    repository_url))
        user_id = self.rc_get_admin_user_id()
        parameter = {
            "type": "pipeline",
            "sourceCodeCredentialId": "{0}:{1}-gitlab-root".format(user_id,
                                                                   self.project_id.split(':')[1]),
            "repositoryUrl": repository_url,
            "triggerWebhookPr": False,
            "triggerWebhookPush": True,
            "triggerWebhookTag": False,
        }
        output = self.__api_post(
            '/projects/{0}/pipelines'.format(self.project_id), data=parameter)
        logger.debug("enable_rancher_project_pipeline output: {0}".format(output.json()))
        return output.json()['id']

    def rc_disable_project_pipeline(self, project_id, pipeline_id):
        rancher_output = self.__api_delete('/projects/{0}/pipelines/{1}'.format(
            project_id, pipeline_id
        ))
        status_code = rancher_output.status_code
        if status_code == 200:
            logger.info("disable_rancher_project_pipeline successful !")
        elif status_code == 404:
            logger.info("project does not exist, don't need to delete.")
        else:
            logger.info("disable_rancher_project_pipeline error, error message: {0}".format(
                rancher_output.text))
            abort(400,
                  message='"disable_rancher_project_pipeline error, error message: {0}'.format(
                      rancher_output.text))


    def rc_get_yaml(self, project_name, pipeline_name):
        output = self.__api_get(f"/project/{project_name}/pipelines/{pipeline_name}")
        return output.json()


    def rc_get_project_pipeline(self):
        self.rc_get_project_id()
        output = self.__api_get('/projects/{0}/pipelines'.format(self.project_id))
        return output.json()['data']

    def rc_update_project_pipline(self, project_id, pipeline_id, data):
        self.__api_put(
            f'/projects/{project_id}/pipelines/{pipeline_id}', data=data)

    def rc_add_namespace_into_rc_project(self, project_name):
        self.rc_get_project_id()
        body = {
            "projectId": self.project_id
        }
        params = {'action': 'move'}
        url = '/clusters/{0}/namespaces/{1}'.format(self.cluster_id, project_name)
        self.__api_post(url, params=params, data=body)

    def rc_get_secrets_all_list(self):
        self.rc_get_project_id()
        url = f'/projects/{self.project_id}/secrets'
        output = self.__api_get(url)
        return output.json()['data']

    def rc_add_secrets_to_all_namespaces(self, secret_name, content):
        if kubernetesClient.read_namespace_secret(kubernetesClient.DEFAULT_NAMESPACE, secret_name)\
                is None:
            self.rc_add_secrets_into_rc_all({
                'name': secret_name,
                'type': 'secret',
                'data': content
            })
        else:
            self.rc_put_secrets_into_rc_all(
                secret_name,
                {
                    'type': 'secret',
                    'data': content
                })

    def rc_add_secrets_into_rc_all(self, args):
        self.rc_get_project_id()
        data = args["data"]
        for key, value in data.items():
            data[key] = base64.b64encode(bytes(value, encoding='utf-8')).decode('utf-8')
        body = {
            "type": args['type'],
            "data": data,
            "labels": {},
            "name": args['name']
        }
        url = f'/projects/{self.project_id}/secrets'
        self.__api_post(url, data=body)

    def rc_put_secrets_into_rc_all(self, secret_name, args):
        self.rc_get_project_id()
        data = args["data"]
        for key, value in data.items():
            data[key] = base64.b64encode(bytes(value, encoding='utf-8')).decode('utf-8')
        body = {
            "type": args['type'],
            "labels": {},
            "name": secret_name,
            "data": data
        }
        url = f'/projects/{self.project_id}/secrets/{self.project_id.split(":")[1]}:{secret_name}'
        self.__api_put(url, data=body)

    def rc_delete_secrets_into_rc_all(self, secret_name):
        self.rc_get_project_id()
        url = f'/projects/{self.project_id}/secrets/{self.project_id.split(":")[1]}:{secret_name}'
        output = self.__api_delete(url)
        return output.json()

    def rc_get_registry_into_rc_all(self):
        self.rc_get_project_id()
        url = f'/projects/{self.project_id}/dockercredential'
        output = self.__api_get(url)
        return output.json()['data']

    def rc_add_registry_into_rc_all(self, args):
        self.rc_get_project_id()
        registry = {args['url']: {'username': args['username'], 'password': args['password']}}
        body = {
            "type": "dockerCredential",
            "registries": registry,
            "namespaceId": "__TEMP__",
            "name": args['name']
        }
        url = f'/projects/{self.project_id}/dockercredential'
        self.__api_post(url, data=body)

    def rc_delete_registry_into_rc_all(self, registry_name):
        self.rc_get_project_id()
        url = f'/projects/{self.project_id}/dockercredential/{self.project_id.split(":")[1]}:{registry_name}'
        output = self.__api_delete(url)
        return output.json()

    def rc_get_catalogs_all(self):
        url = '/catalogs'
        output = self.__api_get(url)
        return output.json()['data']

    def rc_get_templates(self, cat_id):
        url = f'/templates?catalogId={cat_id}'
        return self.__api_get(url).json()

    def rc_add_catalogs(self, args):
        body = args
        url = '/catalogs'
        output = self.__api_post(url, data=body)
        return output.json()

    def rc_edit_catalogs(self, args, catalog_name):
        body = args
        url = f'/catalogs/{catalog_name}'
        output = self.__api_put(url, data=body)
        return output.json()

    def rc_delete_catalogs(self, catalog_name):
        url = f'/catalogs/{catalog_name}'
        self.__api_delete(url)

    def rc_refresh_catalogs(self):
        params = {"action": "refresh"}
        url = '/catalogs/iii-dev-charts3'
        output = self.__api_post(url, params=params)
        return output.json()

    def rc_get_apps_all(self):
        self.rc_get_project_id()
        url = f'/projects/{self.project_id}/apps'
        output = self.__api_get(url)
        return output.json()['data']

    def rc_get_app_by_name(self, name):
        self.rc_get_project_id()
        url = f'/projects/{self.project_id}/apps?name={name}'
        output = self.__api_get(url)
        return output.json()['data']

    def rc_create_apps(self, kwargs):
        self.rc_get_project_id()
        url = f'/project/{self.project_id}/apps'
        body = {
            "name": kwargs['name'],
            "namespace": kwargs['namespace'],
            "appRevisionId": kwargs['appRevisionId'] if kwargs.get('appRevisionId') else None,
            "targetNamespace": kwargs['targetNamespace'] if kwargs.get('targetNamespace') else None,
            "externalId": kwargs['externalId'] if kwargs.get('externalId') else None,
            "answers": kwargs['answers'] if kwargs.get('answers') else None
        }
        self.__api_post(url, data=body)

    def rc_del_app(self, app_name):
        self.rc_get_project_id()
        url = f"/projects/{self.project_id}/apps/{self.project_id.split(':')[1]}:{app_name}"
        self.__api_delete(url)

    def rc_del_app_when_devops_del_pj(self, project_name):
        apps = self.rc_get_apps_all()
        for app in apps:
            if project_name == app["targetNamespace"]:
                self.rc_del_app(app["name"])

    def rc_del_app_with_prefix(self, prefix):
        all_apps = self.rc_get_apps_all()
        delete_app_list = [app["name"] for app in all_apps if app["name"].startswith(prefix)]
        for name in delete_app_list:
            self.rc_del_app(name)
        self.__check_app_deleted(delete_app_list)

    def __check_app_deleted(self, delete_app_list):
        now_time = datetime.utcnow() + timedelta(minutes=1)
        for name in delete_app_list:
            data = self.rc_get_app_by_name(name)
            while data != []:
                if now_time <= datetime.utcnow():
                    raise TimeoutError("end in time.")
                data = self.rc_get_app_by_name(name)

    def rc_count_each_pj_piplines_by_days(self):
        day_start = datetime.combine((datetime.now() - timedelta(days=1)), d_time(00, 00))
        project_plugin_relations = ProjectPluginRelation.query.with_entities(
            ProjectPluginRelation.project_id, ProjectPluginRelation.ci_project_id,
            ProjectPluginRelation.ci_pipeline_id
        )
        for project_plugin_relation in project_plugin_relations:
            if project_plugin_relation.project_id is None:
                continue
            pipline_executions = self.rc_get_pipeline_executions(
                project_plugin_relation.ci_project_id, project_plugin_relation.ci_pipeline_id
            )
            pipline_number = 0
            if pipline_executions["data"] != []:
                pipline_number = pipline_executions["data"][0]["run"]

            one_raw_data = RancherPiplineNumberEachDays(
                project_id=project_plugin_relation.project_id,
                date=day_start.date(),
                pipline_number=pipline_number,
                created_at=str(datetime.now())
            )
            db.session.add(one_raw_data)
            db.session.commit()
            time.sleep(1)


rancher = Rancher()


def remove_pj_executions(pj_id):
    relation = nx_get_project_plugin_relation(nexus_project_id=pj_id)
    pj_executions = rancher.rc_get_pipeline_executions(
        relation.ci_project_id,
        relation.ci_pipeline_id
    )
    for data in pj_executions["data"]:
        try:
            rancher.rc_delete_pipeline_executions_run(
                relation.ci_project_id,
                relation.ci_pipeline_id,
                data["run"])
        except:
            pass


def remove_executions():
    # Get ci_project_id(All are the same) and ci_pipline_ids
    logger.info("Start to remove pipline_executions which project not exist.")
    ci_project_id = None
    ci_pipeline_id = []
    for relation in ProjectPluginRelation.query.all():
        ci_project_id = relation.ci_project_id if ci_project_id is None else ci_project_id
        ci_pipeline_id.append(relation.ci_pipeline_id)

    pj_executions = rancher.rc_get_pipeline_executions(ci_project_id, None)
    for data in pj_executions["data"]:
        if data["pipelineId"] not in ci_pipeline_id:
            try:
                rancher.rc_delete_pipeline_executions_run(
                    ci_project_id,
                    data["pipelineId"],
                    data["run"])
                logger.info(f'{ci_project_id}/{data["pipelineId"]}-{data["run"]} has been removed.')
            except Exception as e:
                logger.exception(str(e))


def remove_extra_executions():
    logger.info("Start to remove pipline_executions which out of limit.")

    condition = SystemParameter.query.filter_by(name="k8s_pipline_executions_remain_limit").one()
    if not condition.active or condition.active is None:
        return
    limit_pods = int(condition.value["limit_pods"])
    for relation in ProjectPluginRelation.query.all():
        pj_executions = rancher.rc_get_pipeline_executions(relation.ci_project_id, relation.ci_pipeline_id)
        if len(pj_executions["data"]) > limit_pods:
            for data in pj_executions["data"][limit_pods::]:
                try:
                    rancher.rc_delete_pipeline_executions_run(
                        relation.ci_project_id,
                        relation.ci_pipeline_id,
                        data["run"])
                    logger.info(f'{relation.ci_project_id}/{relation.ci_pipeline_id}-{data["run"]} has been removed.')
                except Exception as e:
                    logger.exception(str(e))


def turn_tags_off():
    logger.info("Start to turn tags off.")
    data = {"triggerWebhookTag": False}
    for relation in ProjectPluginRelation.query.all():
        try:
            rancher.rc_update_project_pipline(
                relation.ci_project_id, relation.ci_pipeline_id, data)
        except Exception as e:
            logger.exception(str(e))
    logger.info("Finish turn tags off.")


def version_list(cat_id):
    result = rancher.rc_get_templates(cat_id)
    version_dict = {}
    for key, value in result.items():
        if key == "data":
            for data in value:
                for k, v in data.items():
                    if k == "versionLinks":
                        version_dict.update({data["name"]: [version for version, url in v.items()]})
    return version_dict
# --------------------- Resources ---------------------
class Catalogs(Resource):
    @jwt_required()
    def get(self):
        catalgos_list = rancher.rc_get_catalogs_all()
        return util.success(catalgos_list)

    @jwt_required()
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('name', type=str, required=True)
        parser.add_argument('branch', type=str, required=True)
        parser.add_argument('helmVersion', type=str, required=True)
        parser.add_argument('url', type=str, required=True)
        parser.add_argument('username', type=str)
        parser.add_argument('password', type=str)
        args = parser.parse_args()
        output = rancher.rc_add_catalogs(args)
        return util.success(output)

    @jwt_required()
    def put(self, catalog_name):
        parser = reqparse.RequestParser()
        parser.add_argument('branch', type=str)
        parser.add_argument('url', type=str)
        parser.add_argument('username', type=str)
        parser.add_argument('password', type=str)
        args = parser.parse_args()
        output = rancher.rc_edit_catalogs(args, catalog_name)
        return util.success(output)

    @jwt_required()
    def delete(self, catalog_name):
        rancher.rc_delete_catalogs(catalog_name)
        return util.success()


class Catalogs_Refresh(Resource):
    @jwt_required()
    def post(self):
        return util.success(rancher.rc_refresh_catalogs())


class RancherWebsocketLog(Namespace):
    def on_connect(self):
        print('connect')

    def on_disconnect(self):
        print('Client disconnected')

    def on_get_pipe_log(self, data):
        print('get_pipe_log')
        rancher.rc_get_pipe_log_websocket(data)


class RancherCountEachPjPiplinesByDays(Resource):
    def get(self):
        return util.success(rancher.rc_count_each_pj_piplines_by_days())


class RancherDeleteAPP(Resource):
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('project_name', type=str, required=True, location="form")
        parser.add_argument('branch_name', type=str, required=True, location="form")
        args = parser.parse_args()
        prefix = f'{args["project_name"]}-{args["branch_name"]}'
        rancher.rc_del_app_with_prefix(prefix)
        
        from resources.pipeline import delete_rest_pipelines
        delete_rest_pipelines(args["project_name"], args["branch_name"])
        return util.success()


class RancherCreateAPP(Resource):
    @use_kwargs(route_model.RancherCreateAppSchema, location="json")
    def post(self, **kwargs):
        rancher.rc_create_apps(kwargs)
        return util.success()


class RancherYaml(Resource):
    @use_kwargs(route_model.RancherGetYamlRes, location="json")
    def get(self, **kwargs):
        return util.success(rancher.rc_get_yaml(kwargs['project_name'], kwargs['pipeline_name']))