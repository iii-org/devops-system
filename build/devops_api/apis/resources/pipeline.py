from model import db

class Pipeline(object):
    
    def pipeline_info(self, logger, project_id):
        result = db.engine.execute("SELECT id, name, close_at FROM public.ci_cd as ci WHERE ci.project_id = {0} \
            ORDER BY ci.id DESC".format(project_id))
        ci_cd_list = result.fetchone()
        result.close()
        logger.info("get_project_list: ci_cd_list {0}".format(ci_cd_list))
        if ci_cd_list is not None:
            is_closed = True
            if ci_cd_list["close_at"] is None:
                is_closed = False
            output = {"id": project_id, "pipeline_info": [{"id": ci_cd_list["id"], "name": ci_cd_list["name"], "is_closed": is_closed}]}
            logger.info("pipeline_info output: {0}".format(output))
        else:
            output = None
        return output

    def pipeline_exec(self, logger, project_id):
        output_array = []
        result = db.engine.execute("SELECT ci_li.*\
            FROM public.ci_cd as ci, public.ci_cd_execution_list as ci_li \
            WHERE ci.project_id = {0} AND ci.id = ci_li.ci_cd_id ORDER BY ci_li.id DESC;".format(project_id))
        pipeline_exec_list = result.fetchall()
        result.close()
        logger.info("pipeline_exec pipeline_exec_list: {0}".format(pipeline_exec_list))
        for pipeline_exec in pipeline_exec_list:
            output ={"id": pipeline_exec["times"], "status": {"total": pipeline_exec["total_stage_number"], \
                "success":  pipeline_exec["success_stage_number"]}, "commit_message": pipeline_exec["commit_message"]\
                    , "commit_branch": pipeline_exec["branch_name"], "last_test_time": pipeline_exec["create_at"].isoformat()}
            logger.info("pipeline_exec output: {0}".format(output))
            output_array.append(output)
        return output_array