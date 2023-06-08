from flask_restful import Resource
import util as util



# --------------------- Resources ---------------------

class RancherDeleteAPP(Resource):
    def post(self):
        return util.success()
