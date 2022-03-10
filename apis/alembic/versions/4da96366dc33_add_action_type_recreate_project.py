"""add_action_type_recreate_project

Revision ID: 4da96366dc33
Revises: f6dae8356b30
Create Date: 2022-03-10 17:45:39.141991

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '4da96366dc33'
down_revision = 'f6dae8356b30'
branch_labels = None
depends_on = None


def upgrade():
    with op.get_context().autocommit_block():
        op.execute("ALTER TYPE actiontype ADD VALUE 'RECREATE_PROJECT'")

def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    pass
    # ### end Alembic commands ###
