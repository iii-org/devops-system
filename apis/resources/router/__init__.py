from typing import Any

from flask_jwt_extended import get_jwt_identity
from sqlalchemy.engine import Row

from model import PluginSoftware, UIRouteData

key_return_json = ["parameter"]
MAX_DEPTH: int = 50


def get_plugin_software() -> list[dict[str, Any]]:
    plugins: list[Row] = PluginSoftware.query.with_entities(
        PluginSoftware.id, PluginSoftware.name, PluginSoftware.disabled
    ).all()

    output: list[dict[str, Any]] = [
        {"id": plugin["id"], "name": plugin["name"], "disabled": plugin["disabled"]}
        for plugin in plugins
        if plugin
    ]

    return output


def get_error_route() -> dict[str, ...]:
    error_route: UIRouteData = UIRouteData.query.filter_by(role="").first()
    return error_route.ui_route


def display_by_permission() -> list[dict[str, ...]]:
    role_name: str = get_jwt_identity()["role_name"]

    route_list: list[dict[str, ...]] = []
    node: UIRouteData = UIRouteData.query.filter_by(
        parent=0, role=role_name, old_brother=0
    ).first()
    route_list.append(get_ui_route(node, role_name))

    while node.next_node:
        node: UIRouteData = node.next_node
        route_list.append(get_ui_route(node, role_name))

    route_list.append(get_error_route())
    return route_list


def get_ui_route(node: UIRouteData, role_name: str) -> dict[str, ...]:
    route: dict[str, ...] = node.ui_route

    if node.children_nodes:
        child_routes: list[dict[str, ...]] = []
        child: UIRouteData = node.children_nodes[0].first_node
        child_routes.append(get_ui_route(child, role_name))

        depth: int = 0
        while child.next_node:
            depth += 1

            if depth > MAX_DEPTH:
                break

            child: UIRouteData = child.next_node
            child_routes.append(get_ui_route(child, role_name))

        route["children"] = child_routes

    return route
