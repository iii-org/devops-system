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
