from flask_jwt_extended import JWTManager
from resources.apiError import build
from resources import role

jsonwebtoken = JWTManager()


@jsonwebtoken.expired_token_loader
def my_expired_token_callback(jwt_header, jwt_payload):
    return build(3005, jwt_header), 401


@jsonwebtoken.invalid_token_loader
def custom_error(jwt_header):
    return build(3006, jwt_header), 422


def jwt_response():
    @jsonwebtoken.additional_claims_loader
    def jwt_response_data(id, login, role_id, from_ad):
        return {
            'user_id': id,
            'user_account': login,
            'role_id': role_id,
            'role_name': role.get_role_name(role_id),
            'from_ad': from_ad
        }